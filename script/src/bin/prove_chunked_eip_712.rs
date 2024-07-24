//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use clap::Parser;
use fibonacci_script::utils::{fixtures::{FixtureBuilder, SP1ProofFixture}, unit_tests::sp1_test_generate_a_batch};
use sp1_eip712_type::types::sp1_tx_types::SP1SignedOmniverseTx;
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use tracing::info;

use plonky2_field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_field::types::Sample;
use plonky2_ecdsa::curve::{curve_types::{AffinePoint, Curve, CurveScalar}, ecdsa::{ECDSAPublicKey, ECDSASecretKey}};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_bytes!("../../../recursive/elf/riscv32im-succinct-zkvm-elf");

/// A program that just runs a simple computation.
const EIP712_ELF: &[u8] =
    include_bytes!("../../../sp1eip712/elf/riscv32im-succinct-zkvm-elf");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    // pub proof: SP1Proof,
    pub vk: SP1VerifyingKey,
}

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "128")]
    n: usize,

    #[clap(long, default_value = "256")]
    chunk: usize,

    #[clap(long, default_value = "false")]
    exec: bool,

    #[clap(long, default_value = "false")]
    evm: bool,
}

fn generate_test_somtx_vec(batch_num: usize) -> Vec<SP1SignedOmniverseTx> {
    type EC = Secp256K1;

    let sk = ECDSASecretKey::<EC>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * EC::GENERATOR_PROJECTIVE).to_affine());
    let AffinePoint { x, y, .. } = pk.0;
    let mut x_le_bytes = Vec::new();
    x.0.iter().for_each(|i| {
        x_le_bytes.append(&mut i.to_le_bytes().to_vec());
    });
    x_le_bytes.reverse();

    let mut y_le_bytes = Vec::new();
    y.0.iter().for_each(|i| {
        y_le_bytes.append(&mut i.to_le_bytes().to_vec());
    });
    y_le_bytes.reverse();

    let mut batched_somtx_vec = sp1_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap());
    (1..batch_num).for_each(|_| {
        batched_somtx_vec.append(&mut sp1_test_generate_a_batch(sk, x_le_bytes.clone().try_into().unwrap(), y_le_bytes.clone().try_into().unwrap()));
    });

    batched_somtx_vec
}

fn prove_chunked_eip712_compressed<'a>(chunked_somtxs: &[SP1SignedOmniverseTx], exec: bool) -> Option<AggregationInput> {
    // Setup the inputs.;
    let mut sp1in = SP1Stdin::new();
    sp1in.write::<usize>(&chunked_somtxs.len());
    chunked_somtxs.iter().for_each(|somtx| {
        sp1in.write(somtx);
    });
    // sp1in.write::<usize>(&1);
    // sp1in.write(&batched_somtx_vec[0]);

    // call circuit
    // Setup the prover client.
    let client = ProverClient::new();

    if exec {
        let (mut _public_values, _) = client.execute(EIP712_ELF, sp1in).run().unwrap();
        None
    } else {
        // Setup the program.
        let (pk, vk) = client.setup(EIP712_ELF);

        let proof = client
            .prove(&pk, sp1in)
            .compressed()
            .run()
            .expect("failed to generate proof");

        // Verify proof and public values
        client
            .verify(&proof, &vk)
            .expect("verification failed");

        Some(AggregationInput { proof, vk })
    }
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

    let batched_somtx_vec = generate_test_somtx_vec(args.n);
    let mut inputs = Vec::new();
    batched_somtx_vec.chunks(args.chunk).enumerate().for_each(|(chunk_i, chunked_somtxs)| {
        info!("process chunk: {}", chunk_i);
        if let Some(proof_agg_input) = prove_chunked_eip712_compressed(chunked_somtxs, args.exec) {
            inputs.push(proof_agg_input);
        }
    });

    if args.exec {
        return;
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
            let SP1Proof::Compressed(proof) = input.proof.proof else {
                panic!()
            };
            stdin.write_proof(proof, input.vk.vk);
        }

        if args.evm {
            // Generate the proof.
            let r_proof = client
            .prove(&aggregation_pk, stdin)
            .plonk()
            .run()
            .expect("failed to generate proof");

            // Verify proof and public values
            client
                .verify(&r_proof, &r_vk)
                .expect("verification failed");

            // r_proof
            //     .save("./proof-bin/recursive-ppis.bin")
            //     .expect("saving proof failed");

            // std::fs::write(format!("{}{}", PROOF_PATH, "recursive-vk-hash"), r_vk.bytes32().to_string()).expect("write vk hash error");

            let recursive_fixture = SP1ProofFixture::from_sp1_plonk_bn254_proof_vk(&r_proof, &r_vk);
            recursive_fixture.save_to_local(&"recursive-fixture.json".to_string());

            info!("successfully generated and verified recursive proof by prover network!");

        } else {
            // Generate the plonk bn254 proof.
            let r_proof = client
                .prove(&aggregation_pk, stdin)
                .run()
                .expect("proving failed");

            // Verify the proof.
            client.verify(&r_proof, &r_vk).expect("failed to verify recursive proof");

            info!("successfully generated and verified recursive proof for the program!");
        }
    });
}