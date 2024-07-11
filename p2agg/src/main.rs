#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    fibonacci_program::cooks::verify_p2_proof::verify_plonky2_proof();
}
