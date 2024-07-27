#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let left = sp1_zkvm::io::read_vec();
    let right = sp1_zkvm::io::read_vec();

    assert_eq!(left, right, "not the same");
}
