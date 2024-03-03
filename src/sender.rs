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
    use crate::{pubkey_extraction::InputForSSDPubKey, test_data::BIP352TestVectors};
    use bitcoin::{
        key::{Parity, Secp256k1},
        ScriptBuf,
    };
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
    fn pubkeys_from_secret_match_pubkeys_from_get_input_for_sdd() {
        let secp = Secp256k1::new();
        let vectors = get_bip352_test_vectors();
        vectors.test_vectors.iter().for_each(|vector| {
            for sending_object in &vector.sending {
                sending_object.given.vin.iter().for_each(|vin| {
                    let prevout = ScriptBuf::from_hex(&vin.prevout.script_pubkey.hex).unwrap();
                    let input_data = InputData {
                        prevout: &prevout,
                        script_sig: vin.script_sig.as_deref(),
                        txinwitness: vin.txinwitness.as_ref(),
                    };
                    if let Some(pubkey_from_input_for_ssd) = get_input_for_ssd(&input_data) {
                        let pubkey_from_secret =
                            PublicKey::from_secret_key(&secp, &vin.private_key);
                        let pubkey_from_secret = if let InputForSSDPubKey::P2TR { pubkey: _ } =
                            pubkey_from_input_for_ssd
                        {
                            if pubkey_from_secret.x_only_public_key().1 == Parity::Odd {
                                PublicKey::from_secret_key(&secp, &vin.private_key.negate())
                            } else {
                                pubkey_from_secret
                            }
                        } else {
                            pubkey_from_secret
                        };
                        match pubkey_from_input_for_ssd {
                            InputForSSDPubKey::P2PKH { pubkey } => {
                                assert_eq!(pubkey_from_secret, pubkey);
                                Some(pubkey)
                            }
                            InputForSSDPubKey::P2SH { pubkey } => {
                                assert_eq!(pubkey_from_secret, pubkey);
                                Some(pubkey)
                            }
                            InputForSSDPubKey::P2WPKH { pubkey } => {
                                assert_eq!(pubkey_from_secret, pubkey);
                                Some(pubkey)
                            }
                            InputForSSDPubKey::P2TR { pubkey } => {
                                assert_eq!(pubkey_from_secret, pubkey);
                                Some(pubkey)
                            }
                            InputForSSDPubKey::P2TRWithH => None,
                        };
                    } else {
                        assert!([
                            "P2PKH and P2WPKH Uncompressed Keys are skipped",
                            "Skip invalid P2SH inputs"
                        ]
                        .contains(&vector.comment.as_str()));
                    }
                });
            }
        });
    }
}
