use clap::Parser;
use fibonacci_script::utils::{fixtures::{FixtureBuilder, SP1ProofFixture, PROOF_PATH}, unit_tests::p_test_generate_a_batch};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_field::types::Sample;
use plonky2_ecdsa::curve::{curve_types::{AffinePoint, Curve, CurveScalar}, ecdsa::{ECDSAPublicKey, ECDSASecretKey}};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use tracing::info;

pub const EIP712_ELF: &[u8] = include_bytes!("../../../sp1eip712/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "false")]
    evm: bool,
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = ProveArgs::parse();
    
    type EC = Secp256K1;

    let sk = ECDSASecretKey::<EC>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * EC::GENERATOR_PROJECTIVE).to_affine());
    let AffinePoint { x, y, .. } = pk.0;
    let mut x_le_bytes = Vec::new();
    x.0.iter().for_each(|i| {
        x_le_bytes.append(&mut i.to_le_bytes().to_vec());
    });
    x_le_bytes.reverse();

    let mut y_le_bytes = Vec::new();
    y.0.iter().for_each(|i| {
        y_le_bytes.append(&mut i.to_le_bytes().to_vec());
    });

    let batch_num: usize = 4;

    let mut batched_somtx_vec = p_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap());
    // batched_somtx_vec.append(&mut p_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap()));
    // batched_somtx_vec.append(&mut p_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap()));
    // batched_somtx_vec.append(&mut p_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap()));
    (1..batch_num / 4).for_each(|_| {
        batched_somtx_vec.append(&mut p_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap()));
    });

    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write::<usize>(&batched_somtx_vec.len());
    batched_somtx_vec.iter().for_each(|somtx| {
        sp1in.write(somtx);
    });

    // call circuit
    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(EIP712_ELF);
    // let (mut _public_values, _) = client.execute(ECDSA_ELF, sp1in).unwrap();
    // info!("vk hash: {:?}", vk.hash_babybear());
    // std::fs::write(format!("{}{}", PROOF_PATH, "ecrecover-vk-hash"), vk.bytes32().to_string()).expect("write vk hash error");

    if args.evm {
        // Generate the proof.
        let proof = client
            .prove_plonk(&pk, sp1in)
            .expect("failed to generate proof");

        // Verify proof and public values
        client
            .verify_plonk(&proof, &vk)
            .expect("verification failed");

        proof
            .save("./proof-bin/ecrecover-ppis.bin")
            .expect("saving proof failed");

        std::fs::write(format!("{}{}", PROOF_PATH, "ecrecover-vk-hash"), vk.bytes32().to_string()).expect("write vk hash error");

        let ecr_fixture = SP1ProofFixture::from_sp1_plonk_bn254_proof_vk(&proof, &vk);
        ecr_fixture.save_to_local(&"ecr-fixture.json".to_string());
    } else {
        // Generate the proof.
        let proof = client.prove(&pk, sp1in).expect("failed to generate proof");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        proof
            .save("proof-with-pis.bin")
            .expect("saving proof failed");
    }

    info!("successfully generated and verified proof for the program!");
}