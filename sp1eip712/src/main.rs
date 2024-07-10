#![no_main]

use sp1_eip712_type::types::sp1_tx_types::SP1SignedOmniverseTx;
use sp1eip712::eip::traits::EIP712ForSignedOmniTx;
sp1_zkvm::entrypoint!(main);

fn main() {
    let num_cases = sp1_zkvm::io::read::<usize>();
    for _ in 0..num_cases {
        let omni_signed_tx = sp1_zkvm::io::read::<SP1SignedOmniverseTx>();
        let eip712_sgin_hash = omni_signed_tx.eip_712_signature_hash();
        let tx_hash = omni_signed_tx.txid_hash();

        sp1_zkvm::io::commit(&eip712_sgin_hash);
        sp1_zkvm::io::commit(&tx_hash);
    }
}
