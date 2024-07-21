# SP1 Project Template

This is a template for creating an end-to-end [SP1](https://github.com/succinctlabs/sp1) project 
that can generate a proof of any RISC-V program and verify the proof onchain.

## Docs about SP1

- [Summary of the source code](https://trapdoortech.medium.com/zero-knowledge-proof-introduction-to-sp1-zkvm-source-code-d26f88f90ce4)

- [SP1 technical white paper](https://drive.google.com/file/d/1aTCELr2b2Kc1NS-wZ0YYLKdw1Y2HcLTr/view)

- SP1 resources
    - [use cases](https://blog.succinct.xyz/introducing-sp1/)

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://succinctlabs.github.io/sp1/getting-started/install.html)
- [Foundry](https://book.getfoundry.sh/getting-started/installation)

## Standard Proof Generation

> [!WARNING]
> You will need at least 16GB RAM to generate the default proof.

Generate the proof for your program using the standard prover.

```
cd script
RUST_LOG=info cargo run --bin prove --release
```

## EVM-Compatible Proof Generation & Verification

> [!WARNING]
> You will need at least 128GB RAM to generate the PLONK proof.

Generate the proof that is small enough to be verified on-chain and verifiable by the EVM. This command also generates a fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.

```sh
cd script
RUST_LOG=info cargo run --bin prove --release -- --evm
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_keccak256 --release -- --evm
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_poseidon_goldilocks --release -- --evm
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_ecdsa --release -- --evm
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_ecrecover --release -- --evm > ./zk-running.log 2>&1 &
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_hybrid --release -- --evm > ./zk-running.log 2>&1 &

SHARD_SIZE=4194304 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --bin prove_hybrid --release -- --evm
```

```sh
cd script
RUST_LOG=info cargo run --bin prove_recursive --release -- --evm > ./zk-running.log 2>&1 &

SP1_PROVER=network SP1_PRIVATE_KEY=... RUST_LOG=info cargo run --bin prove_recursive --release -- --evm --n 1 > ./zk-running.log 2>&1 &
```

```sh
cd script
SP1_PROVER=network SP1_PRIVATE_KEY=... RUST_LOG=info cargo run --bin prove_eip_712 --release -- --evm --n 32 > ./zk-running.log 2>&1 &
```

```sh
cd script
SP1_PROVER=network SP1_PRIVATE_KEY=... RUST_LOG=info cargo run --bin prove_p3_verify --release -- --exec exec --n 32 > ./zk-running.log 2>&1 &
```

### Unit Tests

```sh
RUST_LOG=info cargo test -r --lib -- utils::unit_tests

RUST_LOG=info cargo test -r --lib -- utils::fixtures::tests::test_ecrecover_fixture --exact --nocapture
```

```sh
RUST_LOG=info cargo test -r --lib -- utils::p2_proof
```

```sh
RUST_LOG=info cargo test -r --package base_sp1_p3 --lib -- utils::sp1_p3_poseidon2

RUST_LOG=info cargo test -r --package base_sp1_p3 --lib -- utils::sp1_p3_poseidon2::tests::prove_babybear_success --exact --nocapture

RUST_LOG=info cargo test -r --package base_sp1_p3 --lib -- utils::sp1_p3_poseidon2::tests::test_prove_verify --exact --nocapture
```

### Solidity Proof Verification

After generating the verify the proof with the SP1 EVM verifier.

```
cd ../contracts
forge test -v
```

## Note

- Different server makes elf different due to the different setup
