use crate::{InputData, NUMS_PUBKEY};
use bitcoin::key::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::taproot::ControlBlock;
use bitcoin::Witness;
use bitcoin::{
    hashes::{hash160, Hash},
    key::Parity,
    Script,
};

use crate::NUMS;

/// Inputs For Shared Secret Derivation (SSD) Type provides the input type for the `PublicKey`.
/// This allows us to perform actions such as negating private keys later on based on whether the
/// public key has a taproot type
#[derive(Debug)]
pub enum InputForSSDPubKey {
    P2PKH { pubkey: PublicKey },
    P2SH { pubkey: PublicKey },
    P2WPKH { pubkey: PublicKey },
    P2TR { pubkey: PublicKey },
    P2TRWithH,
}
impl InputForSSDPubKey {
    pub fn pubkey(&self) -> Option<&PublicKey> {
        match self {
            InputForSSDPubKey::P2PKH { pubkey } => Some(pubkey),
            InputForSSDPubKey::P2SH { pubkey } => Some(pubkey),
            InputForSSDPubKey::P2WPKH { pubkey } => Some(pubkey),
            InputForSSDPubKey::P2TR { pubkey } => Some(pubkey),
            InputForSSDPubKey::P2TRWithH => None,
        }
    }
}

/// Get Inputs For Shared Secret Derivation (SSD)
///
/// As per BIP 352: "While any UTXO with known output scripts can be used to fund the transaction,
/// the sender and receiver MUST use inputs from the following list when deriving the shared secret:
/// P2TR, P2WPKH, P2SH-P2WPKH, P2PKH". Also, "for all of the output types listed, only X-only and
/// compressed public keys are permitted."
pub fn get_input_for_ssd(input_data: &InputData) -> Option<InputForSSDPubKey> {
    if input_data.prevout.is_p2pkh() {
        return get_pubkey_from_p2pkh(input_data).map(|pubkey| InputForSSDPubKey::P2PKH { pubkey });
    }
    if input_data.prevout.is_p2sh() {
        return get_pubkey_from_p2sh_p2wpkh(input_data)
            .map(|pubkey| InputForSSDPubKey::P2SH { pubkey });
    }
    if input_data.prevout.is_p2wpkh() {
        return get_pubkey_from_p2wpkh(input_data)
            .map(|pubkey| InputForSSDPubKey::P2WPKH { pubkey });
    }
    if input_data.prevout.is_p2tr() {
        return if let Some(xonly_scenario) = get_pubkey_from_p2tr(input_data) {
            match xonly_scenario {
                XOnlyScenario::XOnly(xonly_pk) => {
                    // For Parity, see BIP 340: "Implicitly choosing the Y coordinate that is even"
                    let pubkey = PublicKey::from_x_only_public_key(xonly_pk, Parity::Even);
                    Some(InputForSSDPubKey::P2TR { pubkey })
                }
                XOnlyScenario::XOnlyWithH => Some(InputForSSDPubKey::P2TRWithH),
            }
        } else {
            None
        };
    }
    None
}

fn get_pubkey_from_p2pkh(vin: &InputData) -> Option<PublicKey> {
    let script_sig = if let Some(script_sig) = &vin.script_sig {
        script_sig
    } else {
        return None;
    };
    // skip the first 3 op_codes and grab the 20 byte hash from the scriptPubKey
    let script_pubkey_hash = &vin.prevout.as_bytes()[3..23];
    let maybe_pubkey = &script_sig.as_bytes()[script_sig.len() - 33..];
    let maybe_pubkey_hash = hash160::Hash::hash(maybe_pubkey);
    if &maybe_pubkey_hash[..] == script_pubkey_hash {
        Some(PublicKey::from_slice(maybe_pubkey).expect("maybe_pubkey IS a pubkey"))
    } else {
        script_sig
            .instruction_indices()
            .flatten()
            .flat_map(|(index, instruction)| {
                instruction.push_bytes().map(|bytes| {
                    // TODO: use instruction.push_bytes directly instead of slicing the bytes
                    Some(&script_sig.as_bytes()[index + 1..index + bytes.len() + 1])
                })
            })
            .flatten()
            .find_map(|maybe_pubkey| {
                let maybe_pubkey_hash = hash160::Hash::hash(maybe_pubkey);
                if &maybe_pubkey_hash[..] == script_pubkey_hash {
                    let maybe_pub_key = PublicKey::from_slice(maybe_pubkey);
                    Some(maybe_pub_key.expect("maybe_pubkey IS a pubkey"))
                } else {
                    None
                }
            })
    }
}

fn get_pubkey_from_p2sh_p2wpkh(vin: &InputData) -> Option<PublicKey> {
    let script_sig = if let Some(script_sig) = &vin.script_sig {
        script_sig
    } else {
        return None;
    };
    let txinwitness = if let Some(txinwitness) = &vin.txinwitness {
        txinwitness
    } else {
        return None;
    };
    let redeem_script = &script_sig.as_bytes()[1..];
    if Script::from_bytes(redeem_script).is_p2wpkh() {
        txinwitness
            .last()
            .filter(|maybe_pubkey| maybe_pubkey.len() == PUBLIC_KEY_SIZE)
            .and_then(|maybe_pubkey| PublicKey::from_slice(maybe_pubkey).ok())
    } else {
        None
    }
}

fn get_pubkey_from_p2wpkh(vin: &InputData) -> Option<PublicKey> {
    let txinwitness = if let Some(txinwitness) = &vin.txinwitness {
        txinwitness
    } else {
        return None;
    };
    txinwitness
        .last()
        .filter(|maybe_pubkey| maybe_pubkey.len() == PUBLIC_KEY_SIZE)
        .and_then(|maybe_pubkey| PublicKey::from_slice(maybe_pubkey).ok())
}

fn get_pubkey_from_p2tr(vin: &InputData) -> Option<XOnlyScenario> {
    let txinwitness = if let Some(txinwitness) = &vin.txinwitness {
        txinwitness
    } else {
        return None;
    };
    if txinwitness.len() == 1 {
        //  Keypath spend
        return if let Ok(xonly) = XOnlyPublicKey::from_slice(&vin.prevout.as_bytes()[2..]) {
            Some(XOnlyScenario::XOnly(xonly))
        } else {
            None
        };
    };
    println!("TXIN_WITNESS: {:?}", txinwitness);
    get_control_block_from_witness(txinwitness)
        .map(|control_block| control_block.internal_key)
        .and_then(|internal_key| {
            println!("INTERNAL_KEY: {:02x?}", internal_key);
            if internal_key == *NUMS_PUBKEY {
                println!("GOT NUMS!");
                Some(XOnlyScenario::XOnlyWithH)
            } else if let Ok(xonly) = XOnlyPublicKey::from_slice(&vin.prevout.as_bytes()[2..]) {
                Some(XOnlyScenario::XOnly(xonly))
            } else {
                None
            }
        })
}

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum XOnlyScenario {
    XOnly(XOnlyPublicKey),
    XOnlyWithH,
}

fn get_control_block_from_witness(witness: &Witness) -> Option<ControlBlock> {
    let length = witness.len();
    if length == 0 {
        return None;
    }
    let length_sans_annex = witness
        .last()
        .as_slice()
        .first()
        .map(|maybe_annex_byte| {
            if length >= 2 && maybe_annex_byte == &[0x50u8] {
                length - 1
            } else {
                length
            }
        })
        .unwrap_or(length);

    if length_sans_annex == 1 {
        return None;
    }
    if let Some(control_block_bytes) = witness.nth(length_sans_annex - 1) {
        ControlBlock::decode(control_block_bytes).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::BIP352TestVectors;
    use bitcoin::{
        consensus::deserialize,
        key::{Parity, Secp256k1},
        ScriptBuf, Witness,
    };
    use hex_conservative::test_hex_unwrap as hex;
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
    fn basic_get_pubkey_from_p2pkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L15
        let prevout =
            ScriptBuf::from_hex("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac").unwrap();
        let script_sig = ScriptBuf::from_hex("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5").unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: Some(&script_sig),
            txinwitness: None,
        };
        let pubkey = get_pubkey_from_p2pkh(&vin).unwrap();
        let pubkey_hash = bitcoin::PublicKey::new(pubkey).pubkey_hash().to_string();
        assert_eq!(pubkey_hash, "19c2f3ae0ca3b642bd3e49598b8da89f50c14161",);
        let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
        match pubkey_from_input {
            InputForSSDPubKey::P2PKH { pubkey } => {
                let pubkey_from_input = pubkey_from_input.pubkey();
                assert_eq!(pubkey, *pubkey_from_input.unwrap());
            }
            _ => panic!("was expecting p2pkh"),
        }
    }

    #[test]
    fn malleated_get_pubkey_from_p2pkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L2198
        // TODO: Verify that the malleation is swapping a compressed pubkey with an uncompressed one
        let prevout =
            ScriptBuf::from_hex("76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac").unwrap();
        let script_sig = ScriptBuf::from_hex("5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68").unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: Some(&script_sig),
            txinwitness: None,
        };
        let pubkey = get_pubkey_from_p2pkh(&vin).unwrap();
        let pubkey_hash = bitcoin::PublicKey::new(pubkey).pubkey_hash().to_string();
        assert_eq!(pubkey_hash, "c82c5ec473cbc6c86e5ef410e36f9495adcf9799",);
        let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
        match pubkey_from_input {
            InputForSSDPubKey::P2PKH { pubkey } => {
                let pubkey_from_input = pubkey_from_input.pubkey();
                assert_eq!(pubkey, *pubkey_from_input.unwrap());
            }
            _ => panic!("was expecting p2pkh"),
        }
    }

    #[test]
    fn basic_get_pubkey_from_p2sh_p2wpkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L2412
        let prevout =
            ScriptBuf::from_hex("a9148629db5007d5fcfbdbb466637af09daf9125969387").unwrap();
        let script_sig =
            ScriptBuf::from_hex("16001419c2f3ae0ca3b642bd3e49598b8da89f50c14161").unwrap();
        let witness = deserialize::<Witness>(&hex!("02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")).unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: Some(&script_sig),
            txinwitness: Some(&witness),
        };
        let pubkey = get_pubkey_from_p2sh_p2wpkh(&vin).unwrap();
        let pubkey_hash = bitcoin::PublicKey::new(pubkey).pubkey_hash().to_string();
        assert_eq!(pubkey_hash, "19c2f3ae0ca3b642bd3e49598b8da89f50c14161");
        let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
        match pubkey_from_input {
            InputForSSDPubKey::P2SH { pubkey } => {
                let pubkey_from_input = pubkey_from_input.pubkey();
                assert_eq!(pubkey, *pubkey_from_input.unwrap());
            }
            _ => panic!("was only expecting p2sh-p2wpkh"),
        }
    }
    #[test]
    fn basic_get_pubkey_from_p2wpkh() {
        // TODO got these values from they p2sh_p2wpkh test. Need to find (or make) known-good p2wpkh test data.
        let prevout = ScriptBuf::from_hex("00140423f731a07491364e8dce98b7c00bda63336950").unwrap();
        let witness = deserialize::<Witness>(&hex!("02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")).unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: None,
            txinwitness: Some(&witness),
        };
        let pubkey = get_pubkey_from_p2wpkh(&vin).unwrap();
        let pubkey_hash = bitcoin::PublicKey::new(pubkey).pubkey_hash();
        assert_eq!(
            pubkey_hash.to_string(),
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161"
        );
        let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
        match pubkey_from_input {
            InputForSSDPubKey::P2WPKH { pubkey } => {
                let pubkey_from_input = pubkey_from_input.pubkey();
                assert_eq!(pubkey, *pubkey_from_input.unwrap());
            }
            _ => panic!("was only expecting p2wpkh"),
        }
    }
    #[test]
    fn basic_size_1_get_pubkey_from_p2tr() {
        let prevout = ScriptBuf::from_hex(
            "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
        )
        .unwrap();
        let witness = deserialize::<Witness>(&hex!("0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b")).unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: None,
            txinwitness: Some(&witness),
        };
        let xonly_scenario = get_pubkey_from_p2tr(&vin).unwrap();
        match xonly_scenario {
            XOnlyScenario::XOnly(pubkey) => {
                assert_eq!(
                    pubkey.to_string(),
                    "5a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
                );
                let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
                let pubkey_from_input = pubkey_from_input.pubkey();
                assert_eq!(pubkey.public_key(Parity::Even), *pubkey_from_input.unwrap());
            }
            XOnlyScenario::XOnlyWithH => panic!("was not expecting H"),
        }
    }
    #[test]
    fn basic_size_4_get_pubkey_from_p2tr_with_h() {
        let witness = deserialize::<Witness>(&hex!("0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150")).unwrap();
        let prevout = ScriptBuf::from_hex(
            "5120da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85",
        )
        .unwrap();
        let vin = InputData {
            prevout: &prevout,
            script_sig: None,
            txinwitness: Some(&witness),
        };
        let xonly_scenario = get_pubkey_from_p2tr(&vin).unwrap();
        match xonly_scenario {
            XOnlyScenario::XOnly(_pubkey) => {
                // assert_eq!(
                //     pubkey.to_string(),
                //     "da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85"
                // );
                // let pubkey_from_input = get_input_for_ssd(&vin).unwrap();
                // let pubkey_from_input = pubkey_from_input.pubkey();
                // assert_eq!(pubkey.public_key(Parity::Even), *pubkey_from_input.unwrap());
                panic!("Was expecting H")
            }
            XOnlyScenario::XOnlyWithH => {}
        }
    }

    #[test]
    fn the_pubkeys_from_privkey_match_the_pubkeys_from_the_get_input_for_sdd_function() {
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
