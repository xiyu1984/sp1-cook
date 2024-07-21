#![no_main]

use p3_uni_stark::Proof;
use p3agg::p3_uni_stark_verify;
use sp1_core::{stark::UniConfig, utils::BabyBearPoseidon2};
sp1_zkvm::entrypoint!(main);

fn main() {
    let proof = sp1_zkvm::io::read::<Proof<UniConfig<BabyBearPoseidon2>>>();
    p3_uni_stark_verify::verify_babybear(proof);
}
