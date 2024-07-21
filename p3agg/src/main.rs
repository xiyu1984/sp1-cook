#![no_main]

use p3_uni_stark::Proof;
use p3agg::p3_uni_stark_verify;
use sp1_core::{stark::UniConfig, utils::BabyBearPoseidon2};
use tiny_keccak::{Hasher, Keccak};
sp1_zkvm::entrypoint!(main);

fn main() {
    let proof_vec = sp1_zkvm::io::read_vec();
    // let proof = sp1_zkvm::io::read::<Proof<UniConfig<BabyBearPoseidon2>>>();
    let mut hasher = Keccak::v256();
    hasher.update(&proof_vec);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    println!("in circuit: {:?}", output);

    let proof: Proof<UniConfig<BabyBearPoseidon2>> = bincode::deserialize(&proof_vec).expect("failed to deserialize");

    p3_uni_stark_verify::verify_babybear(proof);
}
