use sp1_precompiles::secp256k1::verify_signature;
use tiny_keccak::{Hasher, Keccak};
use k256::ecdsa::Signature;
// use k256::{ecdsa::{Signature, VerifyingKey, signature::Verifier}, PublicKey};

pub fn verify_ecdsa() {
    let msg_bytes = sp1_zkvm::io::read_vec();
    let mut hasher = Keccak::v256();
    hasher.update(&msg_bytes);
    let mut msg_digest = [0u8; 32];
    hasher.finalize(&mut msg_digest);
    // println!("circuit hash: {:?}", msg_digest);

    let pk_slice: [u8; 65] = sp1_zkvm::io::read_vec().try_into().expect("circuit reading pk error");

    let signature_vu8: [u8; 64] = sp1_zkvm::io::read_vec().try_into().expect("circuit reading signature error");
    let signature: Signature = Signature::from_slice(&signature_vu8).expect("circuit construct signature error");
    assert!(verify_signature(&pk_slice, &msg_digest, &signature, None), "Invalid signature");

    // The below is ok
    // let public_key = PublicKey::from_sec1_bytes(&pk_slice);
    // let public_key = public_key.unwrap();
    // let verify_key = VerifyingKey::from(&public_key);
    // assert!(verify_key.verify(&msg_digest, &signature).is_ok(), "executing verification fialed!");
}
