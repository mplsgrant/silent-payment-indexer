use crate::{
    pubkey_extraction::{get_input_for_ssd, InputForSSDPubKey},
    InputData,
};
use bitcoin::{secp256k1::PublicKey, PrivateKey};
use std::collections::HashMap;

/// Select UTXOs which the sender controls, at least one of which must be an Inputs For Shared Secret Derivation (IFSSD)
///
/// BDK UTXO includes: OutPoint (txid, vout) and TxOut (value, scriptPubKey) + (internal/external & is_spent)
/// InputData inclues:
pub fn select_utxos<'a>(
    input_data: &'a [&'a InputData],
) -> impl Iterator<Item = InputForSSDPubKey> + 'a {
    // TODO return Item = &'a PublicKey
    input_data.iter().flat_map(|data| get_input_for_ssd(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test() {}
}
