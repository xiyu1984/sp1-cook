use clap::Parser;
use k256::ecdsa::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
use sp1_sdk::{ProverClient, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};

pub const ECDSA_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

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

    // prepare message signature
    let mut rng = rand::thread_rng();
    let sign_key = SigningKey::random(& mut rng);
    let message = "hello omniverse".as_bytes();

    let mut hasher = Keccak::v256();
    hasher.update(message);
    let mut msg_digest = [0u8; 32];
    hasher.finalize(&mut msg_digest);
    // info!("hash: {:?}", msg_digest);
    
    let signature: Signature = sign_key.sign(&msg_digest);
    let signature_vu8 = signature.to_bytes();

    let verify_key = VerifyingKey::from(sign_key);
    let pk_vu8 = verify_key.to_encoded_point(false).to_bytes();

    assert!(verify_key.verify(&msg_digest, &signature).is_ok(), "executing verification fialed!");

    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write_vec(message.to_vec());
    sp1in.write_vec(pk_vu8.to_vec());
    sp1in.write_vec(signature_vu8.to_vec());

    // call circuit
    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ECDSA_ELF);
    // let (mut _public_values, _) = client.execute(ECDSA_ELF, sp1in).unwrap();

    if args.evm {
        // Generate the proof.
        let _proof = client
            .prove_plonk(&pk, sp1in)
            .expect("failed to generate proof");
    } else {
        // Generate the proof.
        let proof = client.prove(&pk, sp1in).expect("failed to generate proof");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
    }
}