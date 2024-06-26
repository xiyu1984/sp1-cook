
#[cfg(test)]
mod tests {
    use k256::{ecdsa::{signature::{hazmat::{PrehashSigner, PrehashVerifier}, Signer, Verifier}, Signature, SigningKey, VerifyingKey}, EncodedPoint};
    use tiny_keccak::{Hasher, Keccak};
    use tracing::info;


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

        // let message = "Hello omniverse".as_bytes();
        // let mut hasher = Keccak::v256();
        // hasher.update(message);
        // let mut msg_digest = [0u8; 32];
        // hasher.finalize(&mut msg_digest);

        // let sig = hex::decode("d5cce3b455c4a1e0c06f242856f4e8b825c120bcd93c7f5d4e11a97b65e3bbfa1236f4a1b28a4dab20bbc0e4aa55c18196b36538d884fc1799b2dfd56e6bb914").unwrap();
        // info!("{}", sig.len());
        // let pk = hex::decode("04b0c4ae6f28a5579cbeddbf40b2209a5296baf7a4dc818f909e801729ecb5e663dce22598685e985a6ed1a557cf2145deba5290418b3cc00680a90accc9b93522").unwrap();

        // signature can be verified on Ethereum
        let msg_digest = hex::decode("4683e417a496ba5f2ee01b31c69dfed849c0007578ca59d69a29cd8a1df7cd94").unwrap();
        let sig = hex::decode("2b4c6e01efe8f9f40f34c02008271ce5af1cc9b894647eb1ee8af0fac2e26a5e481dba1a96ef143be3b7def5831ced476ca4393a32fe7133d7ca5242de0fafb61b").unwrap();
        // info!("{}", sig.len());
        let pk = hex::decode("04b0c4ae6f28a5579cbeddbf40b2209a5296baf7a4dc818f909e801729ecb5e663dce22598685e985a6ed1a557cf2145deba5290418b3cc00680a90accc9b93522").unwrap();
        
        let signature: Signature = Signature::from_slice(&sig[..64]).unwrap();
        let verify_key = VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(&pk).unwrap()).unwrap();

        // assert!(verify_key.verify(&msg_digest, &signature).is_ok(), "`verify` error");
        assert!(verify_key.verify_prehash(&msg_digest, &signature).is_ok(), "`verify_prehash` error");
    }
}
