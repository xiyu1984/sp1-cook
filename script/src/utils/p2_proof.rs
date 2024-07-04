use std::fs;
use anyhow::Result;

use plonky2::{hash::hash_types::RichField, plonk::{circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData}, config::GenericConfig, proof::ProofWithPublicInputs}, util::serialization::DefaultGateSerializer};
use plonky2_field::extension::Extendable;

const FRI_PROOF_DIR: &str = "./.p2-data";

// `CommonCircuitData` did not implemented the `serde::Deserialize`
pub fn load_p2_proof
<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
(hrr_proof_id: &str) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierOnlyCircuitData<C, D>, Vec<u8>)> 
{

    let vod_path = format!("{}/{}_vod", FRI_PROOF_DIR, hrr_proof_id);
    let ccd_path = format!("{}/{}_ccd", FRI_PROOF_DIR, hrr_proof_id);
    let ppis_path = format!("{}/{}_ppis.json", FRI_PROOF_DIR, hrr_proof_id);

    let vod = fs::read(vod_path).unwrap();
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(vod).unwrap();

    let gate_serializer = DefaultGateSerializer;
    let ccd = fs::read(ccd_path).unwrap();
    let common = CommonCircuitData::<F, D>::from_bytes(ccd.clone(), &gate_serializer).unwrap();

    let ppis = fs::read(ppis_path).unwrap();
    let ppis: ProofWithPublicInputs<F, C, D> = serde_json::from_slice(&ppis).unwrap();
    let vd = VerifierCircuitData {
        verifier_only,
        common,
    };
    vd.verify(ppis.clone()).unwrap();

    Ok((ppis, vd.verifier_only, ccd))
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;

    #[test]
    fn test_load_p2_proof() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let _ = load_p2_proof::<F, C, D>("8").unwrap();
    }
}
