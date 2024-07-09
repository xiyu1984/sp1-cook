use serde::{Deserialize, Serialize};
use zk_6358::utils6358::{deploy_tx::SignedDeployTx, mint_tx::SignedMintTx, transaction::SignedSpendTx};


///////////////////////////////////////////////////////////////
/// data structure
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum SP1SignedOmniverseTx {
    OmniDeployTx(SignedDeployTx),
    OmniMintTx(SignedMintTx),
    OmniSpendTx(SignedSpendTx),
    InvalidTx,
}