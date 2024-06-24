use alloy_sol_types::{sol, SolType};

/// The public values encoded as a tuple that can be easily deserialized inside Solidity.
type PublicValuesTuple = sol! {
    tuple(uint32, uint32, uint32)
};

pub fn fibonacci() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    if n > 186 {
        panic!(
            "This fibonacci program doesn't support n > 186, as it would overflow a 32-bit integer."
        );
    }

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a + b;
        a = b;
        b = c;
    }

    // Encocde the public values of the program.
    let bytes = PublicValuesTuple::abi_encode(&(n, a, b));

    // Commit to the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);
}