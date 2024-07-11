use serde::{Deserialize, Serialize};
use zk_6358::utils6358::{deploy_tx::SignedDeployTx, mint_tx::SignedMintTx, transaction::SignedSpendTx, type_utils::SIGN_BYTES, utxo::USER_ADDRESS_LEN};

pub const SP1_FULL_PK_LEN: usize = 1 + USER_ADDRESS_LEN * 2;

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

impl SP1SignedOmniverseTx {
    pub fn full_pk_be(&self) -> [u8; SP1_FULL_PK_LEN] {
        match self {
            SP1SignedOmniverseTx::OmniDeployTx(signed_deploy_tx) => {
                signed_deploy_tx.full_pk_be()
            },
            SP1SignedOmniverseTx::OmniMintTx(signed_mint_tx) => {
                signed_mint_tx.full_pk_be()
            },
            SP1SignedOmniverseTx::OmniSpendTx(signed_spend_tx) => {
                signed_spend_tx.full_pk_be()
            },
            _ => {
                panic!("invalid transaction")
            }
        }
    }

    pub fn get_sig_be(&self) -> [u8; SIGN_BYTES] {
        match self {
            SP1SignedOmniverseTx::OmniDeployTx(signed_deploy_tx) => {
                signed_deploy_tx.signature_be()
            },
            SP1SignedOmniverseTx::OmniMintTx(signed_mint_tx) => {
                signed_mint_tx.signature_be()
            },
            SP1SignedOmniverseTx::OmniSpendTx(signed_spend_tx) => {
                signed_spend_tx.signature_be()
            },
            _ => {
                panic!("invalid transaction")
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////
/// full pk traits
/// Note that all the addresses of the input UTXOs are proved to be the same in the `prove_tx_balance` function of the `plonky2 proof`
pub trait SP1ECCrypto {
    fn owner_as_x_be(&self) -> [u8; USER_ADDRESS_LEN];
    fn y_be(&self) -> [u8; USER_ADDRESS_LEN];
    
    fn full_pk_be(&self) -> [u8; SP1_FULL_PK_LEN] {
        let mut full_pk: [u8; SP1_FULL_PK_LEN] = [0; SP1_FULL_PK_LEN];
        full_pk[0] = 4;
        full_pk[1..1 + USER_ADDRESS_LEN].copy_from_slice(&self.owner_as_x_be());
        full_pk[1 + USER_ADDRESS_LEN..].copy_from_slice(&self.y_be());

        full_pk
    }

    fn signature_be(&self) -> [u8; SIGN_BYTES];
}

// Note the `notes` above
impl SP1ECCrypto for SignedDeployTx {
    fn owner_as_x_be(&self) -> [u8; USER_ADDRESS_LEN] {
        self.borrow_deploy_tx().gas_fee_tx.fee_inputs[0].address
    }

    fn y_be(&self) -> [u8; USER_ADDRESS_LEN] {
        // it's `be` in `sp1` actually
        self.pk_y_le
    }

    fn signature_be(&self) -> [u8; SIGN_BYTES] {
        // it's `be` in `sp1` actually
        self.signature_le
    }
}

// Note the `notes` above
impl SP1ECCrypto for SignedMintTx {
    fn owner_as_x_be(&self) -> [u8; USER_ADDRESS_LEN] {
        self.borrow_mint_tx().gas_fee_tx.fee_inputs[0].address
    }

    fn y_be(&self) -> [u8; USER_ADDRESS_LEN] {
        // it's `be` in `sp1` actually
        self.pk_y_le
    }

    fn signature_be(&self) -> [u8; SIGN_BYTES] {
        // it's `be` in `sp1` actually
        self.signature_le
    }
}

// Note the `notes` above
impl SP1ECCrypto for SignedSpendTx {
    fn owner_as_x_be(&self) -> [u8; USER_ADDRESS_LEN] {
        self.borrow_spend_tx().gas_fee_tx.fee_inputs[0].address
    }

    fn y_be(&self) -> [u8; USER_ADDRESS_LEN] {
        // it's `be` in `sp1` actually
        self.pk_y_le
    }

    fn signature_be(&self) -> [u8; SIGN_BYTES] {
        // it's `be` in `sp1` actually
        self.signature_le
    }
}