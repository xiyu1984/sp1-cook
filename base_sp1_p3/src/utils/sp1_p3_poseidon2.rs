use std::time::Instant;
use itertools::Itertools;
use p3_matrix::Matrix;

use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabyBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;

use p3_uni_stark::Proof;
use sp1_core::stark::UniConfig;
use sp1_core::utils::uni_stark_verify;
use sp1_recursion_core::{poseidon2::{Poseidon2Chip, Poseidon2Event}, runtime::ExecutionRecord};

use sp1_core::{air::MachineAir, stark::StarkGenericConfig, utils::BabyBearPoseidon2};

pub fn prove_babybear(inputs: Vec<[BabyBear; 16]>, outputs: Vec<[BabyBear; 16]>) -> Proof<UniConfig<BabyBearPoseidon2>> {
    let mut input_exec = ExecutionRecord::<BabyBear>::default();
    for (input, output) in inputs.into_iter().zip_eq(outputs) {
        input_exec
            .poseidon2_events
            .push(Poseidon2Event::dummy_from_input(input, output));
    }

    let chip = Poseidon2Chip {
        fixed_log2_rows: None,
        pad: true,
    };
    let trace: RowMajorMatrix<BabyBear> =
        chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
    println!(
        "trace dims is width: {:?}, height: {:?}",
        trace.width(),
        trace.height()
    );

    let start = Instant::now();
    let config = BabyBearPoseidon2::compressed();
    let mut challenger = config.challenger();
    // let proof: Proof<UniConfig<BabyBearPoseidon2>> = uni_stark_prove(&config, &chip, &mut challenger, trace);
    let proof : Proof<UniConfig<BabyBearPoseidon2>> = p3_uni_stark::prove(&UniConfig(config.clone()), &chip, &mut challenger, trace, &vec![]);
    let duration = start.elapsed().as_secs_f64();
    println!("proof duration = {:?}", duration);

    let mut challenger: p3_challenger::DuplexChallenger<
        BabyBear,
        Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
        16,
        8,
    > = config.challenger();
    let start = Instant::now();
    uni_stark_verify(&config, &chip, &mut challenger, &proof)
        .expect("expected proof to be valid");

    let duration = start.elapsed().as_secs_f64();
    println!("verify duration = {:?}", duration);

    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    use itertools::Itertools;
    use sp1_core::utils::inner_perm;
    use zkhash::ark_ff::UniformRand;

    use p3_symmetric::Permutation;

    #[test]
    fn prove_babybear_success() {
        let rng = &mut rand::thread_rng();

        let test_inputs: Vec<[BabyBear; 16]> = (0..256)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let _ = prove_babybear(test_inputs, expected_outputs);
    }

    #[test]
    #[should_panic]
    fn prove_babybear_failure() {
        let rng = &mut rand::thread_rng();
        let test_inputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        let bad_outputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        let _ = prove_babybear(test_inputs, bad_outputs);
    }
}