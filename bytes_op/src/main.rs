#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let left = sp1_zkvm::io::read_vec();
    let right = sp1_zkvm::io::read_vec();

    const CHUNK_SIZE: usize = 32 * 20 * 96;

    assert_eq!(left.len(), right.len(), "not the same length");

    left.chunks(CHUNK_SIZE).zip(right.chunks(CHUNK_SIZE)).for_each(|(l_ck, r_ck)| {
        assert_eq!(l_ck, r_ck, "not the same value");
    });
}
