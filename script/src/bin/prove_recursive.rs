//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use clap::Parser;
use fibonacci_script::utils::fixtures::{FixtureBuilder, SP1ProofFixture, PROOF_PATH};
use sp1_sdk::{HashableKey, ProverClient, SP1CompressedProof, SP1Stdin, SP1VerifyingKey};
use tracing::info;

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_bytes!("../../../recursive/elf/riscv32im-succinct-zkvm-elf");

/// A program that just runs a simple computation.
const KECCAK256_ELF: &[u8] =
    include_bytes!("../../../program/elf/keccak256-riscv32im-succinct-zkvm-elf-local");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SP1CompressedProof,
    // pub proof: SP1Proof,
    pub vk: SP1VerifyingKey,
}

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "256")]
    n: usize,

    #[clap(long, default_value = "false")]
    evm: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // Setup the proving and verifying keys.
    let (aggregation_pk, r_vk) = client.setup(AGGREGATION_ELF);
    let (keccak_pk, keccak_vk) = client.setup(KECCAK256_ELF);

    let mut inputs = Vec::new();

    for k in 0..2 {
        let proof_1 = tracing::info_span!("generate keccak proof n={args.n}").in_scope(|| {
            let mut sp1in = SP1Stdin::new();
            sp1in.write(&args.n);
            (0..args.n).for_each(|i| {
                let input_msg = format!("hello omniverse {}", i * k);
                sp1in.write_vec(input_msg.as_bytes().to_vec());
            });
    
            // only compressed proof could be made into `syscall_verify_sp1_proof`
            client
                .prove_compressed(&keccak_pk, sp1in)
                .expect("proving failed")
            
            // client
            //     .prove(&keccak_pk, sp1in)
            //     .expect("proving failed")
        });

        inputs.push(AggregationInput {
            proof: proof_1,
            vk: keccak_vk.clone()
        });
    }

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = SP1Stdin::new();

        // Write the verification keys.
        let vkeys = inputs
            .iter()
            .map(|input| input.vk.hash_u32())
            .collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values = inputs
            .iter()
            .map(|input| input.proof.public_values.to_vec())
            .collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            stdin.write_proof(input.proof.proof, input.vk.vk);
        }

        if args.evm {
            // Generate the proof.
            let r_proof = client
            .prove_plonk(&aggregation_pk, stdin)
            .expect("failed to generate proof");

            // Verify proof and public values
            client
                .verify_plonk(&r_proof, &r_vk)
                .expect("verification failed");

            r_proof
                .save("./proof-bin/recursive-ppis.bin")
                .expect("saving proof failed");

            std::fs::write(format!("{}{}", PROOF_PATH, "recursive-vk-hash"), r_vk.bytes32().to_string()).expect("write vk hash error");

            let recursive_fixture = SP1ProofFixture::from_sp1_plonk_bn254_proof_vk(&r_proof, &r_vk);
            recursive_fixture.save_to_local(&"recursive-fixture.json".to_string());

        } else {
            // Generate the plonk bn254 proof.
            let r_proof = client
            .prove(&aggregation_pk, stdin)
            .expect("proving failed");

            // Verify the proof.
            client.verify(&r_proof, &r_vk).expect("failed to verify recursive proof");

            info!("successfully generated and verified recursive proof for the program!");
        }
    });
}