use crate::{
    pubkey_extraction::{get_ifssd, IFSSDPubKey},
    InputData,
};
use bitcoin::{secp256k1::PublicKey, PrivateKey};
use std::collections::HashMap;

/// Select UTXOs which the sender controls, at least one of which must be an Inputs For Shared Secret Derivation (IFSSD)
///
/// BDK UTXO includes: OutPoint (txid, vout) and TxOut (value, scriptPubKey) + (internal/external & is_spent)
/// InputData inclues:
pub fn select_utxos<'a>(input_data: &'a [&'a InputData]) -> impl Iterator<Item = IFSSDPubKey> + 'a {
    // TODO return Item = &'a PublicKey
    input_data.iter().flat_map(|data| get_ifssd(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pubkey_extraction::IFSSDPubKey, test_data::BIP352TestVectors};
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
    fn get_vectors() {
        let vectors = get_bip352_test_vectors();
        assert_eq!(vectors.test_vectors.len(), 24);
    }

    #[test]
    fn get_pubkeys_from_first_test_vector() {
        let secp = Secp256k1::new();
        let vectors = get_bip352_test_vectors();
        let maybe_public_keys = vectors
            .test_vectors
            .iter()
            .flat_map(|vector| {
                println!("{:?}", vector.comment);
                vector.sending.first()
            })
            .map(|sending_object| {
                sending_object.given.vin.iter().map(|vin| {
                    let prevout = ScriptBuf::from_hex(&vin.prevout.script_pubkey.hex).unwrap();
                    let input_data = InputData {
                        prevout: &prevout,
                        script_sig: vin.script_sig.as_deref(),
                        txinwitness: vin.txinwitness.as_ref(),
                    };
                    let frompriv_pubkey = PublicKey::from_secret_key(&secp, &vin.private_key);

                    let ifssd_pubkey = get_ifssd(&input_data).unwrap();
                    let frompriv_pubkey = if let IFSSDPubKey::P2TR { pubkey } = ifssd_pubkey {
                        if &frompriv_pubkey.x_only_public_key().1 == &Parity::Odd {
                            PublicKey::from_secret_key(&secp, &vin.private_key.negate())
                        } else {
                            frompriv_pubkey
                        }
                    } else {
                        frompriv_pubkey
                    };

                    assert_eq!(&frompriv_pubkey, ifssd_pubkey.pubkey());
                    ifssd_pubkey.pubkey().clone()
                })
            })
            .flatten()
            .collect::<Vec<PublicKey>>(); // TODO Fix test as it relates to NUMS
    }
}
