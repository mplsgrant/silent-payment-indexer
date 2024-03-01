use crate::{pubkey_extraction::get_ifssd, InputData};
use bitcoin::{secp256k1::PublicKey, PrivateKey};
use std::collections::HashMap;

type InputDataPrivateKeyMap = HashMap<InputData, PrivateKey>;
type PublicKeyInputData = HashMap<PublicKey, InputData>;

/// Select UTXOs which the sender controls, at least one of which must be an Inputs For Shared Secret Derivation (IFSSD)
///
/// BDK UTXO includes: OutPoint (txid, vout) and TxOut (value, scriptPubKey) + (internal/external & is_spent)
/// InputData inclues:
pub fn select_utxos<'a>(input_data: &'a [&'a InputData]) -> impl Iterator<Item = PublicKey> + 'a {
    // TODO return Item = &'a PublicKey
    input_data.iter().flat_map(|data| get_ifssd(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::BIP352TestVectors;
    use std::{fs::File, io::Read};
    fn get_bip352_test_vectors() -> BIP352TestVectors {
        let path = format!(
            "{}/test/send_and_receive_test_vectors.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut file = File::open(path).unwrap();
        let mut json = String::new();
        file.read_to_string(&mut json).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn get_vectors() {
        let vectors = get_bip352_test_vectors();
        assert_eq!(vectors.test_vectors.len(), 24);
    }
}