use tiny_keccak::{Hasher, Keccak};

pub fn calc_keccak256() {
    let num_cases = sp1_zkvm::io::read::<usize>();
    for _ in 0..num_cases {
        // let input = sp1_zkvm::io::read::<String>();
        let input = sp1_zkvm::io::read_vec();
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        sp1_zkvm::io::commit(&output);
    }
}

// use sp1_zkvm::syscalls::syscall_keccak_permute;

// pub fn sys_calc_keccak256() {
//     // let num_cases = sp1_zkvm::io::read::<usize>();
//     for _ in 0..2 {
//         let mut state = [1u64; 25];
//         syscall_keccak_permute(state.as_mut_ptr());
//         println!("{:?}", state);
//         // sp1_zkvm::io::commit(&state);
//     }
// }