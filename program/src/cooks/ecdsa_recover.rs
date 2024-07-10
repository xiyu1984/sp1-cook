use sp1_precompiles::secp256k1;
use tiny_keccak::{Hasher, Keccak};


pub fn ecdsa_recover() {
    let sig_n = sp1_zkvm::io::read::<usize>();

    for _ in 0..sig_n {
        let msg_bytes = sp1_zkvm::io::read_vec();
        let mut hasher = Keccak::v256();
        hasher.update(&msg_bytes);
        let mut msg_digest = [0u8; 32];
        hasher.finalize(&mut msg_digest);
        // println!("circuit hash: {:?}", msg_digest);

        let pk_slice: [u8; 65] = sp1_zkvm::io::read_vec().try_into().expect("circuit reading pk error");

        let signature_vu8: [u8; 65] = sp1_zkvm::io::read_vec().try_into().expect("circuit reading signature error");

        let recovred_pk = secp256k1::ecrecover(&signature_vu8, &msg_digest).expect("recover public key error");

        assert_eq!(pk_slice, recovred_pk, "Invalid signature");
    }
}