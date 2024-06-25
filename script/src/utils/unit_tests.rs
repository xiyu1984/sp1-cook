
#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
    use tiny_keccak::{Hasher, Keccak};
    // use tracing::info;


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

        let verify_key = VerifyingKey::from(sign_key);

        let v_key_vu8 = verify_key.to_encoded_point(false);
        assert_eq!(v_key_vu8.len(), 65);
        // info!("encoded point len: {}, content : {:?}", v_key_vu8.len(), v_key_vu8.to_bytes());
        let v_sec1_bytes = verify_key.to_sec1_bytes();
        // info!("sec1 bytes: {:?}", v_sec1_bytes);
        let verify_key = VerifyingKey::from_sec1_bytes(&v_sec1_bytes).unwrap();

        assert!(verify_key.verify(&msg_digest, &signature).is_ok());

        let signature_vec_u8 = signature.to_bytes();
        assert_eq!(signature_vec_u8.len(), 64);
        // info!("len: {}, content: {:?}", signature_vec_u8.len(), signature_vec_u8);

        let signature: Signature = Signature::from_slice(&signature_vec_u8).unwrap();
        // info!("signature after convert: {:?}", signature.to_bytes());

        assert_eq!(signature_vec_u8, signature.to_bytes());
    }
}
