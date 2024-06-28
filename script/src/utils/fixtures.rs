
use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, SP1PlonkBn254Proof, SP1VerifyingKey};

pub const FIXTURE_PATH: &str = "../contracts/src/fixtures/";
pub const PROOF_PATH: &str = "./proof-bin/";

//////////////////////////////////////////////////////////////////////
// trait
pub trait FixtureBuilder<'a>: Clone + Serialize + Deserialize<'a> {
    fn from_sp1_plonk_bn254_proof_vk(proof: &SP1PlonkBn254Proof, vk: &SP1VerifyingKey) -> Self;
    fn from_sp1_plonk_bn254_proof_vk_hash(proof: &SP1PlonkBn254Proof, vk_hash: String) -> Self;

    fn save_to_local(&self, filename: &String);
    fn load_from_local(filename: &String) -> Self;
}

//////////////////////////////////////////////////////////////////////
// ec-recover
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SP1EcRecoverProofFixture {
    vkey_hash: String,
    public_values: String,
    proof: String,
}

impl<'a> FixtureBuilder<'a> for SP1EcRecoverProofFixture {
    fn from_sp1_plonk_bn254_proof_vk(proof: &SP1PlonkBn254Proof, vk: &SP1VerifyingKey) -> Self {
        SP1EcRecoverProofFixture {
            vkey_hash: vk.bytes32().to_string(),
            public_values: proof.public_values.bytes().to_string(),
            proof: proof.bytes().to_string(),
        }
    }

    fn from_sp1_plonk_bn254_proof_vk_hash(proof: &SP1PlonkBn254Proof, vkey_hash: String) -> Self {
        SP1EcRecoverProofFixture {
            vkey_hash,
            public_values: proof.public_values.bytes().to_string(),
            proof: proof.bytes().to_string(),
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
        let fixture_buf = std::fs::read(format!("{}{}", FIXTURE_PATH, filename)).expect("load ec-recover fixture file error");
        let ecrecover_fixture: SP1EcRecoverProofFixture = serde_json::from_slice(&fixture_buf).expect("deserilize fixture file error");
        ecrecover_fixture
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

        let ecr_bn254_proof = SP1PlonkBn254Proof::load("./proof-bin/ecrecover-ppis.bin").expect("load ecr-ppis error");
        // call circuit
        // Setup the prover client.
        let client = ProverClient::new();

        // Setup the program.
        const ECRECOVER_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");
        let (_pk, vk) = client.setup(ECRECOVER_ELF);
        info!("{}", vk.bytes32());
        client
            .verify_plonk(&ecr_bn254_proof, &vk)
            .expect("verification failed");

        let ecr_vk_hash = std::fs::read_to_string(format!("{}{}", PROOF_PATH, "ecrecover-vk-hash")).expect("load vk hash failed");
        info!("{}", ecr_vk_hash);

        let ecrecover_proof_fixture = SP1EcRecoverProofFixture:: from_sp1_plonk_bn254_proof_vk_hash(&ecr_bn254_proof, ecr_vk_hash);

        ecrecover_proof_fixture.save_to_local(&"ecr-fixture.json".to_string());
    }
}
