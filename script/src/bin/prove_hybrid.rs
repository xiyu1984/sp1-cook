use clap::Parser;
use fibonacci_script::utils::{fixtures::{FixtureBuilder, SP1ProofFixture, PROOF_PATH}, p2_proof::load_p2_proof};
use plonky2::plonk::{circuit_data::VerifierOnlyCircuitData, config::{GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs};
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use tracing::info;


pub const P2_ELF: &[u8] = include_bytes!("../../../p2agg/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "false")]
    evm: bool,

    #[clap(long, default_value = "false")]
    exec: bool,

    #[clap(long, default_value = "128-tx")]
    proof: String
}

fn main() {
    const P2D: usize = 2;
    type P2C = PoseidonGoldilocksConfig;
    type P2F = <P2C as GenericConfig<P2D>>::F;

    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    let p2_proof = load_p2_proof::<P2F, P2C, P2D>(&format!("{}", args.proof)).expect("load stored p2 proof error");

    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write::<ProofWithPublicInputs<P2F, P2C, P2D>>(&p2_proof.0);
    sp1in.write::<VerifierOnlyCircuitData<P2C, P2D>>(&p2_proof.1);
    sp1in.write_vec(p2_proof.2);

    // call circuit
    // Setup the prover client.
    let client = ProverClient::new();

    // exec
    if args.exec {
        let (mut _public_values, _) = client.execute(P2_ELF, sp1in).run().unwrap();
        return;
    }

    // Setup the program.
    let (pk, vk) = client.setup(P2_ELF);
    // let (mut _public_values, _) = client.execute(P2_ELF, sp1in).unwrap();

    if args.evm {
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
            .save("./proof-bin/hybrid-ppis.bin")
            .expect("saving proof failed");

        std::fs::write(format!("{}{}", PROOF_PATH, "hybrid-vk-hash"), vk.bytes32().to_string()).expect("write vk hash error");

        let hybrid_fixture = SP1ProofFixture::from_sp1_plonk_bn254_proof_vk(&proof, &vk);
        hybrid_fixture.save_to_local(&"hybrid-fixture.json".to_string());
    } else {
        // Generate the proof.
        let proof = client.prove(&pk, sp1in).compressed().run().expect("failed to generate proof");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        proof.save("./proof-bin/p2-agg-compressed.bin").expect("saving proof failed");
    }

    info!("successfully generated and verified proof for the program!");
}