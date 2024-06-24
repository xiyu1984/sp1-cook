use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::goldilocks_field::GoldilocksField;

pub fn calc_poseidon() {
    let num_cases = sp1_zkvm::io::read::<usize>();
    for _ in 0..num_cases {
        let input = sp1_zkvm::io::read::<Vec<GoldilocksField>>();
        let output = PoseidonHash::hash_no_pad(&input);
        sp1_zkvm::io::commit(&output);
    }
}
