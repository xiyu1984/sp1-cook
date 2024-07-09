use std::ops::AddAssign;

use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::hazmat::PrehashVerifier};
use rand::{rngs::OsRng, Rng};
use tracing::info;
use zk_6358::utils6358::{deploy_tx::{BaseAsset, DeployTransaction}, mint_tx::MintTransaction, transaction::{generate_rand_input, generate_rand_output, GasFeeTransaction, SpendTransaction, TransactionInput, TransactionOutput}, tx_eip_712::EIP712DataHashing, utxo::{AMOUNT_LEN, TOKEN_ADDRESS_LEN, USER_ADDRESS_LEN}};
use itertools::Itertools;
use sp1_eip712_type::types::sp1_tx_types::SP1SignedOmniverseTx;
use num::{bigint::RandBigInt, BigUint, FromPrimitive, Zero};
use num::traits::ToBytes;

use plonky2::{field::{secp256k1_scalar::Secp256K1Scalar, types::Field}, hash::keccak::KeccakHash};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::PrimeField;
use plonky2_ecdsa::curve::{
    curve_types::{AffinePoint, Curve},
    ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};
use zk_6358::utils6358::{
    type_utils::SIGN_BYTES,
    utxo::HASH_LEN,
};

type EC = Secp256K1;

///////////////////////////////////////////////////////////////
/// functions
pub fn do_sign_msg_hash(sk: ECDSASecretKey<EC>, msg_hash: Secp256K1Scalar) -> [u8; SIGN_BYTES] {
    // if here we use `BigUint::from_bytes_le`, there's no need for the hash target to be reversed!!!
    let sig_value = sign_message(msg_hash, sk);
    let mut sig_bytes = Vec::new();
    sig_value.r.0.iter().for_each(|i| {
        sig_bytes.append(&mut i.to_le_bytes().to_vec());
    });
    sig_value.s.0.iter().for_each(|i| {
        sig_bytes.append(&mut i.to_le_bytes().to_vec());
    });

    sig_bytes.push(0);

    assert!(verify_message(msg_hash, sig_value, sk.to_public()), "native p2 signature verifying error!");

    sig_bytes.try_into().unwrap()
}

pub fn signature_from_bytes(sig_bytes: &[u8; SIGN_BYTES]) -> ECDSASignature<EC> {
    let r_le_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
    let s_le_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    let r =
        <EC as Curve>::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(&r_le_bytes));
    let s =
        <EC as Curve>::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(&s_le_bytes));

    ECDSASignature { r, s }
}

pub fn pk_from_bytes(
    x_le_bytes: &[u8; USER_ADDRESS_LEN],
    y_le_bytes: &[u8; USER_ADDRESS_LEN],
) -> ECDSAPublicKey<EC> {
    let x = <EC as Curve>::BaseField::from_noncanonical_biguint(BigUint::from_bytes_le(x_le_bytes));
    let y = <EC as Curve>::BaseField::from_noncanonical_biguint(BigUint::from_bytes_le(y_le_bytes));

    let affine_point = AffinePoint::<EC>::nonzero(x, y);
    assert!(
        affine_point.is_valid(),
        "Invalid coordinate of the public key"
    );

    ECDSAPublicKey(affine_point)
}

pub fn do_verify_message(
    msg: &[u8; HASH_LEN],
    sig: ECDSASignature<EC>,
    pk: ECDSAPublicKey<EC>,
) -> bool {
    let msg_hash =
        <EC as Curve>::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(msg));
    verify_message(msg_hash, sig, pk)
}

pub fn biguint_to_fixed_bytes_le<const D: usize>(v: &BigUint) -> [u8; D] {
    let mut v_le = v.to_bytes_le();

    assert!(v_le.len() <= D, "Invalid value to fixed {} size", D);

    v_le.resize(D, 0);

    v_le.try_into().unwrap()
}


pub fn p_test_generate_rand_balanced_inputs_outputs(
    x_le_bytes: [u8; USER_ADDRESS_LEN],
) -> (Vec<TransactionInput>, Vec<TransactionOutput>) {
    let i_num = 4usize;
    let inputs = (0..i_num)
        .map(|_| {
            let mut input = generate_rand_input();
            input.address = x_le_bytes.clone();
            input
        })
        .collect_vec();

    let mut output_total = BigUint::zero();
    let outputs = (0..i_num * 2)
        .map(|i: usize| {
            let mut ouput = generate_rand_output();
            if i < i_num {
                let amount = BigUint::from_usize(i).unwrap();
                let mut amount_le = amount.to_bytes_le();
                amount_le.resize(AMOUNT_LEN, 0);
                ouput.amount_le = amount_le.try_into().unwrap();
            } else {
                ouput.amount_le = inputs[i - i_num].amount_le;
            }

            output_total.add_assign(BigUint::from_bytes_le(&ouput.amount_le));

            ouput
        })
        .collect_vec();

    let mut input_total = BigUint::zero();
    let inputs = inputs
        .iter()
        .enumerate()
        .map(|(i, input_0)| {
            let mut input = input_0.clone();
            let mut amount = BigUint::from_bytes_le(&input.amount_le);
            amount.add_assign(i);
            let mut amount_le = amount.to_bytes_le();
            amount_le.resize(AMOUNT_LEN, 0);
            input.amount_le = amount_le.try_into().unwrap();

            input_total.add_assign(BigUint::from_bytes_le(&input.amount_le));

            input
        })
        .collect_vec();

    assert_eq!(input_total, output_total);

    (inputs, outputs)
}

pub fn p_test_generate_rand_spend_tx(x_le_bytes: [u8; USER_ADDRESS_LEN]) -> SpendTransaction {
    let (inputs, outputs) = p_test_generate_rand_balanced_inputs_outputs(x_le_bytes);

    SpendTransaction {
        asset_id: OsRng.gen(),
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        gas_fee_tx: GasFeeTransaction {
            fee_inputs: inputs,
            fee_outputs: outputs,
        },
    }
}

pub fn p_test_generate_rand_deploy_tx(x_le_bytes: [u8; USER_ADDRESS_LEN]) -> DeployTransaction {
    let (inputs, outputs) = p_test_generate_rand_balanced_inputs_outputs(x_le_bytes);

    DeployTransaction {
        salt: OsRng.gen(),
        // name_str_len: 24,
        name: OsRng.gen(),
        base_asset_data: BaseAsset {
            deployer: OsRng.gen(),
            total_supply_le: OsRng.gen(),
            per_mint_le: OsRng.gen(),
            per_mint_price_le: OsRng.gen(),
        },
        gas_fee_tx: GasFeeTransaction {
            fee_inputs: inputs,
            fee_outputs: outputs,
        },
    }
}

pub fn p_test_generate_rand_mint_tx(
    x_le_bytes: [u8; USER_ADDRESS_LEN],
    asset_id: [u8; TOKEN_ADDRESS_LEN],
    per_mint: u64,
    per_mint_price: u64,
) -> MintTransaction {
    let num_mint = 3usize;

    let outputs = (0..num_mint)
        .map(|_| {
            let mut output = generate_rand_output();
            output.amount_le = [0u8; AMOUNT_LEN];
            output.amount_le[..8].copy_from_slice(&per_mint.to_le_bytes());
            output.address = x_le_bytes;

            let mut fee_output = output.clone();
            fee_output.amount_le[..8].copy_from_slice(&per_mint_price.to_le_bytes());

            (output, fee_output)
        })
        .collect_vec();

    let (normal_outputs, gas_outputs) = outputs.iter().cloned().unzip();

    let gas_inputs = (0..num_mint)
        .map(|_| {
            let mut input = generate_rand_input();
            input.amount_le = [0u8; AMOUNT_LEN];
            input.amount_le[..8].copy_from_slice(&per_mint_price.to_le_bytes());
            input.address = x_le_bytes;

            input
        })
        .collect_vec();

    MintTransaction {
        asset_id,
        outputs: normal_outputs,
        gas_fee_tx: GasFeeTransaction {
            fee_inputs: gas_inputs,
            fee_outputs: gas_outputs,
        },
    }
}

pub fn p_test_generate_out_from_in(inputs: &Vec<TransactionInput>) -> Vec<TransactionOutput> {
    let o_num = inputs.len() * 2;

    let i_sum: BigUint = inputs.iter().fold(BigUint::zero(), |acc, i| {
        let amount = BigUint::from_bytes_le(&i.amount_le);
        // let mut rng = rand::thread_rng();
        // rng.gen_biguint_range(&BigUint::zero(), &amount)
        acc + amount
    });

    let average = i_sum.clone() / o_num;

    let mut remaining = i_sum.clone();

    let mut output_total = BigUint::zero();
    let outputs = (0..o_num)
        .map(|idx| {
            let amount = if idx != (o_num - 1) {
                let mut rng = rand::thread_rng();
                let value = rng.gen_biguint_range(&BigUint::zero(), &average);
                remaining -= value.clone();

                value
            } else {
                remaining.clone()
            };

            let mut amount_le = amount.to_bytes_le();
            amount_le.resize(AMOUNT_LEN, 0);

            output_total += BigUint::from_bytes_le(&amount_le);

            TransactionOutput {
                address: OsRng.gen(),
                amount_le: amount_le.try_into().unwrap(),
            }
        })
        .collect_vec();

    assert_eq!(i_sum, output_total, "Invalid outputs amount");

    outputs
}

pub fn verify_sp1_secp256k1(msg_hash: &[u8; 32], sig_bytes: &[u8; 65], sk: &ECDSASecretKey<EC>) {
    let sp1_sk_bytes = sk.0.to_canonical_biguint().to_be_bytes();
    let sign_key = SigningKey::from_slice(&sp1_sk_bytes).unwrap();
    let verify_key = VerifyingKey::from(sign_key);
    let pk_vu8 = verify_key.to_encoded_point(false).to_bytes();

    info!("sp1 pk: {:?}", pk_vu8);

    let mut sig_bytes = sig_bytes.clone();
    sig_bytes[..32].reverse();
    sig_bytes[32..64].reverse();
    let signature: Signature = Signature::from_slice(&sig_bytes[..64]).unwrap();
    let mut msg_hash = msg_hash.clone();
    msg_hash.reverse();
    assert!(verify_key.verify_prehash(&msg_hash, &signature).is_ok(), "executing verification fialed!");
}

pub fn p_test_generate_a_batch(
    sk: ECDSASecretKey<EC>,
    x_le_bytes: [u8; USER_ADDRESS_LEN],
    y_le_bytes: [u8; USER_ADDRESS_LEN],
) -> Vec<SP1SignedOmniverseTx> {
    type F = GoldilocksField;
    let total_supply: u64 = 21000000;
    let per_mint: u64 = 100;
    let per_mint_price: u64 = 1;

    let mut signed_omni_tx_vec = Vec::new();

    // generate a deploy tx
    let mut deploy_tx = p_test_generate_rand_deploy_tx(x_le_bytes);
    deploy_tx.base_asset_data.total_supply_le =
        biguint_to_fixed_bytes_le::<AMOUNT_LEN>(&BigUint::from_u64(total_supply).unwrap());
    deploy_tx.base_asset_data.per_mint_le =
        biguint_to_fixed_bytes_le::<AMOUNT_LEN>(&BigUint::from_u64(per_mint).unwrap());
    deploy_tx.base_asset_data.per_mint_price_le =
        biguint_to_fixed_bytes_le::<AMOUNT_LEN>(&BigUint::from_u64(per_mint_price).unwrap());

    let es_deploy_hash_value = deploy_tx.eip_712_signature_hash();
    let msg_hash = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(
        &es_deploy_hash_value,
    ));
    let sig_bytes = do_sign_msg_hash(sk, msg_hash);

    verify_sp1_secp256k1(&es_deploy_hash_value, &sig_bytes, &sk);

    signed_omni_tx_vec.push(SP1SignedOmniverseTx::OmniDeployTx(
        deploy_tx.sign(&y_le_bytes, &sig_bytes),
    ));

    let deployed_asset = deploy_tx.generate_deployed_asset::<F, KeccakHash<32>>();
    // generate two mint txes
    let mut minted_tx_vec = Vec::new();
    (0..1).for_each(|_| {
        let mint_tx = p_test_generate_rand_mint_tx(
            x_le_bytes,
            deployed_asset.asset_id,
            per_mint,
            per_mint_price,
        );
        let es_mint_hash_value = mint_tx.eip_712_signature_hash();
        let msg_hash = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(
            &es_mint_hash_value,
        ));
        let sig_bytes = do_sign_msg_hash(sk, msg_hash);

        signed_omni_tx_vec.push(SP1SignedOmniverseTx::OmniMintTx(
            mint_tx.sign(&y_le_bytes, &sig_bytes),
        ));
        minted_tx_vec.push(mint_tx);
    });

    let mut spend_inputs = Vec::new();
    minted_tx_vec.iter().for_each(|mint_tx| {
        let utxo_to_be_spent = mint_tx.generate_outputs_utxo::<F>();

        let mut inputs = utxo_to_be_spent
            .iter()
            .map(|utxo_tbs| TransactionInput {
                pre_txid: utxo_tbs.pre_txid,
                pre_index_le: utxo_tbs.pre_index_le,
                address: utxo_tbs.address,
                amount_le: utxo_tbs.amount_le,
            })
            .collect_vec();

        spend_inputs.append(&mut inputs);
    });

    // generate a spend tx
    let mut rng = rand::thread_rng();
    let cut_idx: usize = rng.gen_range(1..spend_inputs.len() - 1);
    (0..2).for_each(|i| {
        let spends_this_time =
            spend_inputs[i * cut_idx..spend_inputs.len() * i + (1 - i) * cut_idx].to_vec();
        let (sp_gas_inputs, sp_gas_outputs) =
            p_test_generate_rand_balanced_inputs_outputs(x_le_bytes);
        let sp_outputs = p_test_generate_out_from_in(&spends_this_time);
        let spend_tx = SpendTransaction {
            asset_id: deployed_asset.asset_id,
            inputs: spends_this_time,
            outputs: sp_outputs,
            gas_fee_tx: GasFeeTransaction {
                fee_inputs: sp_gas_inputs,
                fee_outputs: sp_gas_outputs,
            },
        };

        let es_spend_hash_value = spend_tx.eip_712_signature_hash();
        let msg_hash = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(
            &es_spend_hash_value,
        ));
        let sig_bytes = do_sign_msg_hash(sk, msg_hash);

        signed_omni_tx_vec.push(SP1SignedOmniverseTx::OmniSpendTx(
            spend_tx.sign(&y_le_bytes, &sig_bytes),
        ));
    });

    signed_omni_tx_vec
}

#[cfg(test)]
mod tests {
    use k256::{ecdsa::{signature::{hazmat::{PrehashSigner, PrehashVerifier}, Signer, Verifier}, Signature, SigningKey, VerifyingKey}, EncodedPoint};
    use tiny_keccak::{Hasher, Keccak};
    use tracing::info;

    use crate::utils::unit_tests::{do_verify_message, pk_from_bytes, signature_from_bytes};


    #[test]
    fn test_ecdsa_data_structure() {
        sp1_sdk::utils::setup_logger();

        let mut rng = rand::thread_rng();
        let sign_key = SigningKey::random(& mut rng);
        // let message = hex::decode(hex::encode("hello omniverse")).unwrap();
        let message = "hello omniverse".as_bytes();

        let mut hasher = Keccak::v256();
        hasher.update(message);
        let mut msg_digest = [0u8; 32];
        hasher.finalize(&mut msg_digest);

        // info!("keccak256 hash: {}", hex::encode(msg_digest));
        
        let signature: Signature = sign_key.sign(&msg_digest);
        info!("{}", hex::encode(signature.to_bytes()));
        let sig2: Signature = sign_key.sign_prehash(&msg_digest).unwrap();
        info!("{}", hex::encode(sig2.to_bytes()));

        let verify_key = VerifyingKey::from(sign_key);

        let v_key_vu8 = verify_key.to_encoded_point(false);
        assert_eq!(v_key_vu8.len(), 65);
        // info!("encoded point len: {}, content : {:?}", v_key_vu8.len(), v_key_vu8.to_bytes());
        let v_sec1_bytes = verify_key.to_sec1_bytes();
        // info!("sec1 bytes: {:?}", v_sec1_bytes);
        let verify_key = VerifyingKey::from_sec1_bytes(&v_sec1_bytes).unwrap();

        assert!(verify_key.verify(&msg_digest, &signature).is_ok());
        assert!(verify_key.verify_prehash(&msg_digest, &sig2).is_ok());

        let signature_vec_u8 = signature.to_bytes();
        assert_eq!(signature_vec_u8.len(), 64);
        // info!("len: {}, content: {:?}", signature_vec_u8.len(), signature_vec_u8);

        let signature: Signature = Signature::from_slice(&signature_vec_u8).unwrap();
        // info!("signature after convert: {:?}", signature.to_bytes());

        assert_eq!(signature_vec_u8, signature.to_bytes());
    }

    #[test]
    fn test_ethereum_ecdsa() {
        sp1_sdk::utils::setup_logger();

        // in `metamask` and `k256`, when signing and verifying, the input hash is reversed
        // in `p2`, when signing and verifying, it just use the input hash
        // this is why the `msg_digest` signed by the `metamask`, needs to be reversed when verifying by `p2` 
        // So we need to use `eip_712_hash` instead of `eip_712_signature_hash` for the `txid`, 
        // and use `eip_712_signature_hash` for the `p2` signature verifying circuit 

        // signature can be verified on Ethereum
        let msg_digest = hex::decode("4683e417a496ba5f2ee01b31c69dfed849c0007578ca59d69a29cd8a1df7cd94").unwrap();
        let sig = hex::decode("2b4c6e01efe8f9f40f34c02008271ce5af1cc9b894647eb1ee8af0fac2e26a5e481dba1a96ef143be3b7def5831ced476ca4393a32fe7133d7ca5242de0fafb61b").unwrap();
        // info!("{}", sig.len());
        let pk = hex::decode("04b0c4ae6f28a5579cbeddbf40b2209a5296baf7a4dc818f909e801729ecb5e663dce22598685e985a6ed1a557cf2145deba5290418b3cc00680a90accc9b93522").unwrap();
        
        let signature: Signature = Signature::from_slice(&sig[..64]).unwrap();
        let verify_key = VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(&pk).unwrap()).unwrap();

        // assert!(verify_key.verify(&msg_digest, &signature).is_ok(), "`verify` error");
        assert!(verify_key.verify_prehash(&msg_digest, &signature).is_ok(), "`verify_prehash` error");

        let mut sig = sig.clone();
        // sig.push(0);
        sig[..32].reverse();
        sig[32..64].reverse();
        let p2_sig = signature_from_bytes(&sig.try_into().unwrap());
        let mut pk = pk[1..].to_vec();
        pk[..32].reverse();
        pk[32..].reverse();
        let p2_pk = pk_from_bytes(&pk[..32].try_into().unwrap(), &pk[32..].try_into().unwrap());

        let mut msg_digest = msg_digest.clone();
        msg_digest.reverse();
        assert!(do_verify_message(&msg_digest.try_into().unwrap(), p2_sig, p2_pk), "p2 signature verify error");
    }
}
