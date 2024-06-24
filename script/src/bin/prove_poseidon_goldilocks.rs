use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};
use tracing::info;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

pub const POSEIDON_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "32")]
    n: usize,

    #[clap(long, default_value = "false")]
    evm: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(POSEIDON_ELF);

    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write(&args.n);

    info!("n: {}", args.n);

    type F = GoldilocksField;
    (0..args.n).for_each(|i| {
        let input_msg = vec![F::from_canonical_usize(i); 10];
        sp1in.write(&input_msg);
    });

    // sp1in.buffer.iter().for_each(|buf| {
    //     println!("buffer length of sp1in: {}", buf.len());
    // });

    if args.evm {
        // Generate the proof.
        let _proof = client
            .prove_plonk(&pk, sp1in)
            .expect("failed to generate proof");
        // create_plonk_fixture(&proof, &vk);
    } else {
        // Generate the proof.
        let proof = client.prove(&pk, sp1in).expect("failed to generate proof");
        let pis = proof.public_values.as_slice();
        info!("Successfully generated proof!");
        assert!(pis.len() % 32 == 0, "invalid hash out");
        info!("hash number: (n): {}", pis.len() / 32);

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
    }
}
