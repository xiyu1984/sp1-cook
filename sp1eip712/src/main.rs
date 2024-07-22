#![no_main]

use sp1_eip712_type::types::sp1_tx_types::SP1SignedOmniverseTx;
use sp1_lib::secp256k1;
use sp1eip712::eip::traits::EIP712ForSignedOmniTx;

sp1_zkvm::entrypoint!(main);

fn main() {
    let num_cases = sp1_zkvm::io::read::<usize>();
    let omni_signed_txs = (0..num_cases).map(|_| {
        sp1_zkvm::io::read::<SP1SignedOmniverseTx>()
    }).collect::<Vec<_>>();

    for omni_signed_tx in omni_signed_txs {
        let eip712_sgin_hash = omni_signed_tx.eip_712_hash();
        // println!("hash inside: {:?}", eip712_sgin_hash);
        let tx_hash = omni_signed_tx.txid_hash();

        // sp1_zkvm::io::commit(&eip712_sgin_hash);
        sp1_zkvm::io::commit(&tx_hash);

        // all the addresses of the input UTXOs are proved to be the same in the `prove_tx_balance` function of the `plonky2 proof`
        let pk_u8v = omni_signed_tx.full_pk_be();
        // println!("signature inside: {:?}", omni_signed_tx.get_sig_be());
        // println!("pk inside: {:?}", pk_u8v);
        let recovered_pk = secp256k1::ecrecover(&omni_signed_tx.get_sig_be(), &eip712_sgin_hash).unwrap();

        assert_eq!(pk_u8v, recovered_pk, "Invalid signature");
    }
}
