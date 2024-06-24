//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

use fibonacci_program::cooks::keccak256::calc_keccak256;

// use fibonacci_program::cooks::fibonacci::fibonacci;
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // fibonacci();
    calc_keccak256();
}
