//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use clap::Parser;
use fibonacci_script::utils::fixtures::{FixtureBuilder, SP1ProofFixture};
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_sdk::{ProverClient, SP1Stdin};
use tracing::info;
use zkhash::ark_ff::UniformRand;


/// A program that aggregates the proofs of the simple program.
const P3_AGG: &[u8] = include_bytes!("../../../p3agg/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "256")]
    n: usize,

    // `exec`, `plonk`, `stark`
    #[clap(long, default_value = "exec")]
    exec: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    let rng = &mut rand::thread_rng();

    let test_inputs: Vec<[BabyBear; 16]> = (0..args.n)
        .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
        .collect_vec();

    // let gt: Poseidon2<
    //     BabyBear,
    //     Poseidon2ExternalMatrixGeneral,
    //     DiffusionMatrixBabyBear,
    //     16,
    //     7,
    // > = inner_perm();

    // let expected_outputs = test_inputs
    //     .iter()
    //     .map(|input| gt.permute(*input))
    //     .collect::<Vec<_>>();

    const DEGREE: usize = 3;

    let input_exec = base_sp1_p3::utils::sp1_p3_poseidon2::generate_poseidon2_execution_record(&vec![vec![BabyBear::from_canonical_usize(73)]], &test_inputs);
    let p3_proof = base_sp1_p3::utils::sp1_p3_poseidon2::prove_poseidon2_babybear::<DEGREE>(input_exec);

    // set test inputs and outputs
    let mut sp1in = SP1Stdin::new();
    sp1in.write(&p3_proof);

    if args.exec == "exec" {
        // p3agg::p3_uni_stark_verify::verify_poseidon2_wide_babybear::<DEGREE>(p3_proof);
        let (_, _) = client.execute(P3_AGG, sp1in).run().unwrap();
    } else {
        // Setup the proving and verifying keys.
        let (pk, vk) = client.setup(P3_AGG);

        if args.exec == "plonk" {
            // Generate the proof.
            let proof = client
            .prove(&pk, sp1in)
            .plonk()
            .run()
            .expect("failed to generate proof");
    
            // Verify proof and public values
            client
                .verify(&proof, &vk)
                .expect("verification failed");
    
            proof
                .save("./proof-bin/p3-agg-ppis.bin")
                .expect("saving proof failed");
    
            let recursive_fixture = SP1ProofFixture::from_sp1_plonk_bn254_proof_vk(&proof, &vk);
            recursive_fixture.save_to_local(&"p3-agg-fixture.json".to_string());
    
            info!("successfully generated and verified recursive proof by prover network!");
    
        } else if args.exec == "stark" {
            // Generate the plonk bn254 proof.
            let proof = client
                .prove(&pk, sp1in)
                .run()
                .expect("proving failed");
    
            // Verify the proof.
            client.verify(&proof, &vk).expect("failed to verify recursive proof");
    
            info!("successfully generated and verified recursive proof for the program!");
        }
    }
}