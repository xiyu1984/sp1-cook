use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_uni_stark::Proof;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;

use sp1_core::{stark::{StarkGenericConfig, UniConfig}, utils::BabyBearPoseidon2};
use sp1_recursion_core::poseidon2::Poseidon2Chip;

pub fn verify_babybear(proof: Proof<UniConfig<BabyBearPoseidon2>>){
    let config = BabyBearPoseidon2::compressed();
    
    // todo: read public values. The values are `baby bear`s

    let mut challenger: p3_challenger::DuplexChallenger<
        BabyBear,
        Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
        16,
        8,
    > = config.challenger();

    let chip = Poseidon2Chip {
        fixed_log2_rows: None,
        // pad: true,
    };

    p3_uni_stark::verify(&UniConfig(config.clone()), &chip, &mut challenger, &proof, &vec![])
        .expect("expected proof to be valid");
}
