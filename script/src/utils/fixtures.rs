
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};

pub const FIXTURE_PATH: &str = "../contracts/src/fixtures/";
pub const PROOF_PATH: &str = "./proof-bin/";

//////////////////////////////////////////////////////////////////////
// trait
pub trait FixtureBuilder<'a>: Clone + Serialize + Deserialize<'a> {
    fn from_sp1_plonk_bn254_proof_vk(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> Self;
    fn from_sp1_plonk_bn254_proof_vk_hash(proof: &SP1ProofWithPublicValues, vk_hash: String) -> Self;

    fn save_to_local(&self, filename: &String);
    fn load_from_local(filename: &String) -> Self;
}

//////////////////////////////////////////////////////////////////////
// ec-recover
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SP1ProofFixture {
    vkey_hash: String,
    public_values: String,
    proof: String,
}

impl<'a> FixtureBuilder<'a> for SP1ProofFixture {
    fn from_sp1_plonk_bn254_proof_vk(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> Self {
        SP1ProofFixture {
            vkey_hash: vk.bytes32(),
            public_values: proof.public_values.raw(),
            proof: format!("0x{}", hex::encode(proof.bytes()))
        }
    }

    fn from_sp1_plonk_bn254_proof_vk_hash(proof: &SP1ProofWithPublicValues, vkey_hash: String) -> Self {
        SP1ProofFixture {
            vkey_hash,
            public_values: proof.public_values.raw(),
            proof: format!("0x{}", hex::encode(proof.bytes()))
        }
    }

    fn save_to_local(&self, filename: &String) {
        std::fs::create_dir_all(FIXTURE_PATH).expect("failed to create fixture path");
        std::fs::write(
            format!("{}{}", FIXTURE_PATH, filename),
            serde_json::to_string_pretty(self).unwrap(),
        )
        .expect("failed to write fixture");
    }

    fn load_from_local(filename: &String) -> Self {
        let fixture_buf = std::fs::read(format!("{}{}", FIXTURE_PATH, filename)).expect("load common fixture file error");
        let sp1_fixture: SP1ProofFixture = serde_json::from_slice(&fixture_buf).expect("deserilize fixture file error");
        sp1_fixture
    }
}

#[cfg(test)]
mod tests {

    use sp1_sdk::ProverClient;
    use tracing::info;
    use super::*;

    #[test]
    fn test_ecrecover_fixture() {
        sp1_sdk::utils::setup_logger();

        let ecr_bn254_proof = SP1ProofWithPublicValues::load("./proof-bin/ecrecover-ppis.bin").expect("load ecr-ppis error");
        // call circuit
        // Setup the prover client.
        let client = ProverClient::new();

        // Setup the program.
        const ECRECOVER_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");
        let (_pk, vk) = client.setup(ECRECOVER_ELF);
        info!("{}", vk.bytes32());
        client
            .verify(&ecr_bn254_proof, &vk)
            .expect("verification failed");

        let ecr_vk_hash = std::fs::read_to_string(format!("{}{}", PROOF_PATH, "ecrecover-vk-hash")).expect("load vk hash failed");
        info!("{}", ecr_vk_hash);

        let ecrecover_proof_fixture = SP1ProofFixture:: from_sp1_plonk_bn254_proof_vk_hash(&ecr_bn254_proof, ecr_vk_hash);

        ecrecover_proof_fixture.save_to_local(&"ecr-fixture.json".to_string());
    }
}
