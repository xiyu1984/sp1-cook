use clap::Parser;
use fibonacci_script::utils::fixtures::{FixtureBuilder, SP1ProofFixture, PROOF_PATH};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};
use tracing::info;

pub const ECRECOVER_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "false")]
    evm: bool,
    #[clap(long, default_value = "2")]
    n: usize
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // prepare message signature
    let mut rng = rand::thread_rng();
    let sign_key = SigningKey::random(& mut rng);
    let verify_key = VerifyingKey::from(sign_key.clone());
    let pk_vu8 = verify_key.to_encoded_point(false).to_bytes();

    let sig_n = args.n;
    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write(&sig_n);

    for i in 0..sig_n {
        let message = format!("hello omniverse {i}").as_bytes().to_vec();

        let mut hasher = Keccak::v256();
        hasher.update(&message);
        let mut msg_digest = [0u8; 32];
        hasher.finalize(&mut msg_digest);

        let signature = sign_key.sign_prehash_recoverable(&msg_digest).unwrap();
        // recoverable is 65 bytes
        let signature_vu8 = signature.0.to_bytes().append(signature.1.to_byte());
    
        assert!(verify_key.verify_prehash(&msg_digest, &signature.0).is_ok(), "executing verification fialed!");

        sp1in.write_vec(message);
        sp1in.write_vec(pk_vu8.to_vec());
        sp1in.write_vec(signature_vu8.to_vec());
    }

    // call circuit
    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ECRECOVER_ELF);
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
    }

    info!("successfully generated and verified proof for the program!");
}