use std::time::Instant;
use itertools::Itertools;

use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabyBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_field::AbstractField;
use p3_symmetric::Permutation;

use p3_uni_stark::Proof;
use sp1_core::stark::UniConfig;
use sp1_core::utils::inner_perm;
use sp1_core::utils::uni_stark_verify;
use sp1_core::air::MachineAir;
use sp1_recursion_core::air::Block;
use sp1_recursion_core::poseidon2_wide::events::Poseidon2AbsorbEvent;
use sp1_recursion_core::poseidon2_wide::events::Poseidon2CompressEvent;
use sp1_recursion_core::poseidon2_wide::events::Poseidon2FinalizeEvent;
use sp1_recursion_core::poseidon2_wide::events::Poseidon2HashEvent;
use sp1_recursion_core::poseidon2_wide::Poseidon2WideChip;
use sp1_recursion_core::runtime::ExecutionRecord;
use sp1_recursion_core::memory::MemoryRecord;

use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};

////////////////////////////////////////////////////////////////////////////////////////////////////////
/// generate record from inputs
pub fn generate_poseidon2_execution_record(
    wide_inputs: &Vec<Vec<BabyBear>>,
    compressed_inputs: &Vec<[BabyBear; 16]>
) -> ExecutionRecord<BabyBear> {

    let mut input_exec = ExecutionRecord::<BabyBear>::default();

    let permuter: Poseidon2<
        BabyBear,
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear,
        16,
        7,
    > = inner_perm();

    // Generate hash test events.
    wide_inputs
        .iter()
        .enumerate()
        .for_each(|(i, wide_input)| {

            let prev_ts = BabyBear::from_canonical_usize(i);
            let absorb_ts = BabyBear::from_canonical_usize(i + 1);
            let finalize_ts = BabyBear::from_canonical_usize(i + 2);
            let hash_num = i as u32;
            let absorb_num = 0_u32;
            let hash_and_absorb_num =
                BabyBear::from_canonical_u32(hash_num * (1 << 12) + absorb_num);
            let start_addr = BabyBear::from_canonical_usize(i + 1);
            let input_len = BabyBear::from_canonical_usize(wide_input.len());

            let mut absorb_event = Poseidon2AbsorbEvent::new(absorb_ts,
                hash_and_absorb_num,
                start_addr,
                input_len,
                BabyBear::from_canonical_u32(hash_num),
                BabyBear::from_canonical_u32(absorb_num));
            // Poseidon2AbsorbEvent {
            //     clk: absorb_ts,
            //     hash_and_absorb_num,
            //     input_addr: start_addr,
            //     input_len,
            //     hash_num: BabyBear::from_canonical_u32(hash_num),
            //     absorb_num: BabyBear::from_canonical_u32(absorb_num),
            //     iterations: Vec::new(),
            // };

            let mut hash_state = [BabyBear::zero(); sp1_recursion_core::poseidon2_wide::WIDTH];
            let mut hash_state_cursor = 0;
            absorb_event.populate_iterations(
                start_addr,
                input_len,
                &dummy_memory_access_records(wide_input.clone(), prev_ts, absorb_ts),
                &permuter,
                &mut hash_state,
                &mut hash_state_cursor,
            );

            input_exec
                .poseidon2_hash_events
                .push(Poseidon2HashEvent::Absorb(absorb_event));

            let do_perm = hash_state_cursor != 0;
            let perm_output = permuter.permute(hash_state);

            let state = if do_perm { perm_output } else { hash_state };
            
            input_exec
                .poseidon2_hash_events
                .push(Poseidon2HashEvent::Finalize(Poseidon2FinalizeEvent {
                    clk: finalize_ts,
                    hash_num: BabyBear::from_canonical_u32(hash_num),
                    output_ptr: start_addr,
                    output_records: dummy_memory_access_records(
                        state.as_slice().to_vec(),
                        absorb_ts,
                        finalize_ts,
                    )[0..sp1_recursion_core::runtime::DIGEST_SIZE]
                        .try_into()
                        .unwrap(),
                    state_cursor: hash_state_cursor,
                    perm_input: hash_state,
                    perm_output,
                    previous_state: hash_state,
                    state,
                    do_perm,
                }));
        });

    compressed_inputs
        .iter()
        .enumerate()
        .for_each(|(i, input)| {
            let result_array = permuter.permute(*input);

            let prev_ts = BabyBear::from_canonical_usize(i);
            let input_ts = BabyBear::from_canonical_usize(i + 1);
            let output_ts = BabyBear::from_canonical_usize(i + 2);

            let dst = BabyBear::from_canonical_usize(i + 1);
            let left = dst + BabyBear::from_canonical_usize(sp1_recursion_core::poseidon2_wide::WIDTH / 2);
            let right = left + BabyBear::from_canonical_usize(sp1_recursion_core::poseidon2_wide::WIDTH / 2);

            let compress_event = Poseidon2CompressEvent {
                clk: input_ts,
                dst,
                left,
                right,
                input: *input,
                result_array,
                input_records: dummy_memory_access_records(input.to_vec(), prev_ts, input_ts)
                    .try_into()
                    .unwrap(),
                result_records: dummy_memory_access_records(
                    result_array.to_vec(),
                    input_ts,
                    output_ts,
                )
                .try_into()
                .unwrap(),
            };

            input_exec.poseidon2_compress_events.push(compress_event);
        });

    input_exec
}

fn dummy_memory_access_records(
    memory_values: Vec<BabyBear>,
    prev_ts: BabyBear,
    ts: BabyBear,
) -> Vec<MemoryRecord<BabyBear>> {
    memory_values
        .iter()
        .map(|value| MemoryRecord::new_read(BabyBear::zero(), Block::from(*value), ts, prev_ts))
        .collect_vec()
}

pub fn prove_poseidon2_babybear<const DEGREE: usize>(input_exec: ExecutionRecord<BabyBear>) -> Proof<UniConfig<BabyBearPoseidon2>> {

    let chip = Poseidon2WideChip::<DEGREE> {
        fixed_log2_rows: None,
        pad: true,
    };

    let trace: RowMajorMatrix<BabyBear> =
        chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

    let config = BabyBearPoseidon2::compressed();
    let mut challenger = config.challenger();

    // let start = Instant::now();
    // let config = BabyBearPoseidon2::compressed();
    // let mut challenger = config.challenger();
    // // let proof: Proof<UniConfig<BabyBearPoseidon2>> = uni_stark_prove(&config, &chip, &mut challenger, trace);
    // let proof : Proof<UniConfig<BabyBearPoseidon2>> = p3_uni_stark::prove(&UniConfig(config.clone()), &chip, &mut challenger, trace, &vec![]);
    // let duration = start.elapsed().as_secs_f64();
    // println!("proof duration = {:?}", duration);

    // let mut challenger: p3_challenger::DuplexChallenger<
    //     BabyBear,
    //     Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
    //     16,
    //     8,
    // > = config.challenger();
    // let start = Instant::now();
    // uni_stark_verify(&config, &chip, &mut challenger, &proof)
    //     .expect("expected proof to be valid");

    // let duration = start.elapsed().as_secs_f64();
    // println!("verify duration = {:?}", duration);

    let start = Instant::now();
    // let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
    let proof : Proof<UniConfig<BabyBearPoseidon2>> = p3_uni_stark::prove(&UniConfig(config.clone()), &chip, &mut challenger, trace, &vec![]);
    let duration = start.elapsed().as_secs_f64();
    println!("proof duration = {:?}", duration);

    let mut challenger = config.challenger();
    let start = Instant::now();
    uni_stark_verify(&config, &chip, &mut challenger, &proof)
        .expect("expected proof to be valid");

    let duration = start.elapsed().as_secs_f64();
    println!("verify duration = {:?}", duration);

    proof
}

#[cfg(test)]
mod tests {
    use core::array;

    use super::*;

    use itertools::Itertools;
    use rand::random;
    use sp1_core::utils::inner_perm;
    use zkhash::ark_ff::UniformRand;

    use p3_symmetric::Permutation;

    pub(crate) fn generate_test_execution_record(
        incorrect_trace: bool,
    ) -> ExecutionRecord<BabyBear> {
        const NUM_ABSORBS: usize = 1000;
        const NUM_COMPRESSES: usize = 1000;
    
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
    
        let rng = &mut rand::thread_rng();
        let permuter: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();
    
        // Generate hash test events.
        let hash_test_input_sizes: [usize; NUM_ABSORBS] =
            array::from_fn(|_| random::<usize>() % 128 + 1);
        hash_test_input_sizes
            .iter()
            .enumerate()
            .for_each(|(i, input_size)| {
                let test_input = (0..*input_size).map(|_| BabyBear::rand(rng)).collect_vec();
    
                let prev_ts = BabyBear::from_canonical_usize(i);
                let absorb_ts = BabyBear::from_canonical_usize(i + 1);
                let finalize_ts = BabyBear::from_canonical_usize(i + 2);
                let hash_num = i as u32;
                let absorb_num = 0_u32;
                let hash_and_absorb_num =
                    BabyBear::from_canonical_u32(hash_num * (1 << 12) + absorb_num);
                let start_addr = BabyBear::from_canonical_usize(i + 1);
                let input_len = BabyBear::from_canonical_usize(*input_size);
    
                let mut absorb_event = Poseidon2AbsorbEvent::new(
                    absorb_ts,
                    hash_and_absorb_num,
                    start_addr,
                    input_len,
                    BabyBear::from_canonical_u32(hash_num),
                    BabyBear::from_canonical_u32(absorb_num),
                );
    
                let mut hash_state = [BabyBear::zero(); sp1_recursion_core::poseidon2_wide::WIDTH];
                let mut hash_state_cursor = 0;
                absorb_event.populate_iterations(
                    start_addr,
                    input_len,
                    &dummy_memory_access_records(test_input.clone(), prev_ts, absorb_ts),
                    &permuter,
                    &mut hash_state,
                    &mut hash_state_cursor,
                );
    
                input_exec
                    .poseidon2_hash_events
                    .push(Poseidon2HashEvent::Absorb(absorb_event));
    
                let do_perm = hash_state_cursor != 0;
                let mut perm_output = permuter.permute(hash_state);
                if incorrect_trace {
                    perm_output = [BabyBear::rand(rng); sp1_recursion_core::poseidon2_wide::WIDTH];
                }
    
                let state = if do_perm { perm_output } else { hash_state };
                
                input_exec
                    .poseidon2_hash_events
                    .push(Poseidon2HashEvent::Finalize(Poseidon2FinalizeEvent {
                        clk: finalize_ts,
                        hash_num: BabyBear::from_canonical_u32(hash_num),
                        output_ptr: start_addr,
                        output_records: dummy_memory_access_records(
                            state.as_slice().to_vec(),
                            absorb_ts,
                            finalize_ts,
                        )[0..sp1_recursion_core::runtime::DIGEST_SIZE]
                            .try_into()
                            .unwrap(),
                        state_cursor: hash_state_cursor,
                        perm_input: hash_state,
                        perm_output,
                        previous_state: hash_state,
                        state,
                        do_perm,
                    }));
            });
    
        let compress_test_inputs: Vec<[BabyBear; sp1_recursion_core::poseidon2_wide::WIDTH]> = (0..NUM_COMPRESSES)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();
        compress_test_inputs
            .iter()
            .enumerate()
            .for_each(|(i, input)| {
                let mut result_array = permuter.permute(*input);
                if incorrect_trace {
                    result_array = core::array::from_fn(|_| BabyBear::rand(rng));
                }
                let prev_ts = BabyBear::from_canonical_usize(i);
                let input_ts = BabyBear::from_canonical_usize(i + 1);
                let output_ts = BabyBear::from_canonical_usize(i + 2);
    
                let dst = BabyBear::from_canonical_usize(i + 1);
                let left = dst + BabyBear::from_canonical_usize(sp1_recursion_core::poseidon2_wide::WIDTH / 2);
                let right = left + BabyBear::from_canonical_usize(sp1_recursion_core::poseidon2_wide::WIDTH / 2);
    
                let compress_event = Poseidon2CompressEvent {
                    clk: input_ts,
                    dst,
                    left,
                    right,
                    input: *input,
                    result_array,
                    input_records: dummy_memory_access_records(input.to_vec(), prev_ts, input_ts)
                        .try_into()
                        .unwrap(),
                    result_records: dummy_memory_access_records(
                        result_array.to_vec(),
                        input_ts,
                        output_ts,
                    )
                    .try_into()
                    .unwrap(),
                };
    
                input_exec.poseidon2_compress_events.push(compress_event);
            });
    
        input_exec
    }

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

        let _expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        // let input_exec = generate_poseidon2_execution_record(&vec![], &test_inputs);
        let input_exec = generate_test_execution_record(false);

        let _ = prove_poseidon2_babybear::<9>(input_exec);
    }

    // #[test]
    // #[should_panic]
    // fn prove_babybear_failure() {
    //     let rng = &mut rand::thread_rng();
    //     let test_inputs: Vec<[BabyBear; 16]> = (0..16)
    //         .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
    //         .collect_vec();

    //     let _bad_outputs: Vec<[BabyBear; 16]> = (0..16)
    //         .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
    //         .collect_vec();

    //     let _ = prove_poseidon2_babybear(test_inputs);
    // }
}