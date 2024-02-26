// Copyright (C) 2024      Whittier Digital Technologies LLC
//
// This file is part of silent-payment-indexer.
//
// silent-payment-indexer is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// silent-payment-indexer is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Foobar. If not, see
// <https://www.gnu.org/licenses/>.

use bitcoin::{
    hashes::{hash160, Hash},
    PublicKey, Script, ScriptBuf, Witness,
};

/// "Nothing Up My Sleeves" number from BIP 341: 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
static NUMS: [u8; 32] = [
    80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90, 15, 40,
    236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192,
];

/// The test data file contains these "given" items
struct TestDataGiven {
    pub txid: String,
    pub vout: u32,
    pub script_sig: ScriptBuf,
    pub txinwitness: String,
    /// The _scriptPubKey_hex of the prevout
    pub prevout: ScriptBuf,
    pub private_key: String,
}

/// The data required to derive a pubkey from an input.
///
/// This differs from bip-0352's VinInfo because VinInfo contains data not strictly necessary for
/// retrieving the pubkey. VinInfo includes: "outpoint", "scriptSig", "txinwitness", "prevout", and
/// "private_key"
struct InputData {
    /// The _scriptPubKey_hex of the prevout
    pub prevout: ScriptBuf,
    pub script_sig: ScriptBuf,
    pub txinwitness: Witness,
}

fn get_pubkey_from_input(vin: InputData) {
    if vin.prevout.is_p2pkh() {
        get_pubkey_from_p2pkh(&vin);
    }
    if vin.prevout.is_p2sh() {
        get_pubkey_from_p2sh_p2wpkh(&vin);
    }
    if vin.prevout.is_p2wpkh() {
        get_pubkey_from_p2wpkh(&vin);
    }
}

fn get_pubkey_from_p2pkh(vin: &InputData) -> Option<PublicKey> {
    // skip the first 3 op_codes and grab the 20 byte hash from the scriptPubKey
    let script_pubkey_hash = &vin.prevout.as_bytes()[3..23];
    let maybe_pubkey = &vin.script_sig.as_bytes()[vin.script_sig.len() - 33..];
    let maybe_pubkey_hash = hash160::Hash::hash(maybe_pubkey);
    if &maybe_pubkey_hash[..] == script_pubkey_hash {
        Some(PublicKey::from_slice(maybe_pubkey).expect("maybe_pubkey IS a pubkey"))
    } else {
        vin.script_sig
            .instruction_indices()
            .flatten()
            .flat_map(|(index, instruction)| {
                instruction.push_bytes().map(|bytes| {
                    // TODO: use instruction.push_bytes directly instead of slicing the bytes
                    Some(&vin.script_sig.as_bytes()[index + 1..index + bytes.len() + 1])
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
    let redeem_script = &vin.script_sig.as_bytes()[1..];
    if Script::from_bytes(redeem_script).is_p2wpkh() {
        vin.txinwitness
            .last()
            .and_then(|maybe_pubkey| PublicKey::from_slice(maybe_pubkey).ok())
            .filter(|pub_key| pub_key.compressed)
    } else {
        None
    }
}

fn get_pubkey_from_p2wpkh(vin: &InputData) -> Option<PublicKey> {
    vin.txinwitness
        .last()
        .and_then(|maybe_pubkey| PublicKey::from_slice(maybe_pubkey).ok())
        .filter(|pub_key| pub_key.compressed)
}

fn get_pubkey_from_p2tr(vin: &InputData) -> Option<PublicKey> {
    // TODO Why does tapscript() give us Script when BIP 141 says that "Witness data is NOT script."
    let y = vin.txinwitness.len();
    println!("{y}");
    let z = vin
        .txinwitness
        .tapscript().map(|witness| witness.instruction_indices()).and_then(|instruction_indices| instruction_indices);
    println!("z: {z:?}");
    z.and_then(|witness| Some(println!("witness: {witness:?}")));


    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use hex_conservative::test_hex_unwrap as hex;

    #[test]
    fn simple_get_pubkey_from_p2pkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L15
        let vin = InputData {
            prevout: ScriptBuf::from_hex("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac").unwrap(), script_sig: ScriptBuf::from_hex("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5").unwrap(),
            txinwitness: Witness::new(), };
        let maybe_pubkey = get_pubkey_from_p2pkh(&vin);
        assert_eq!(
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161",
            maybe_pubkey.unwrap().pubkey_hash().to_string()
        );
    }

    #[test]
    fn malleated_get_pubkey_from_p2pkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L2198
        // TODO: Verify that the malleation is swapping a compressed pubkey with an uncompressed one
        let vin = InputData {
            prevout: ScriptBuf::from_hex("76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac").unwrap(), script_sig: ScriptBuf::from_hex("5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68").unwrap(), txinwitness: Witness::new() };
        let maybe_pubkey = get_pubkey_from_p2pkh(&vin);
        assert_eq!(
            "c82c5ec473cbc6c86e5ef410e36f9495adcf9799",
            maybe_pubkey.unwrap().pubkey_hash().to_string()
        );
    }

    #[test]
    fn simple_get_pubkey_from_p2sh_p2wpkh() {
        // https://github.com/bitcoin/bips/blob/73f1a52aafbc54a6ea2ce9a9e5edb20c24948b87/bip-0352/send_and_receive_test_vectors.json#L2412
        let vin = InputData {
            prevout: ScriptBuf::from_hex("a9148629db5007d5fcfbdbb466637af09daf9125969387").unwrap(),
            script_sig: ScriptBuf::from_hex("16001419c2f3ae0ca3b642bd3e49598b8da89f50c14161")
                .unwrap(),
            txinwitness: deserialize::<Witness>(&hex!("02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")).unwrap(),
        };
        let maybe_pubkey = get_pubkey_from_p2sh_p2wpkh(&vin);
        assert_eq!(
            maybe_pubkey.unwrap().pubkey_hash().to_string(),
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161"
        );
    }
    #[test]
    fn simple_get_pubkey_from_p2wpkh() {
        // TODO got these values from they p2sh_p2wpkh test. Need to find (or make) known-good p2wpkh test data.
        let vin = InputData {
            prevout: ScriptBuf::from_hex("00140423f731a07491364e8dce98b7c00bda63336950").unwrap(),
            script_sig: ScriptBuf::new(),

            txinwitness: deserialize::<Witness>(&hex!("02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")).unwrap(),
        };
        let maybe_pubkey = get_pubkey_from_p2wpkh(&vin);
        assert_eq!(
            maybe_pubkey.unwrap().pubkey_hash().to_string(),
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161"
        );
    }
    #[test]
    fn simple_get_pubkey_from_p2tr() {
        let vin = InputData {
            prevout: ScriptBuf::from_hex("51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5").unwrap(),
            script_sig: ScriptBuf::new(),

            txinwitness: deserialize::<Witness>(&hex!("0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150")).unwrap(),
        };
        let maybe_pubkey = get_pubkey_from_p2tr(&vin);
        assert_eq!(
            maybe_pubkey.unwrap().pubkey_hash().to_string(),
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161"
        );
    }

    #[test]
    fn arrive_at_nums() {
        let (nums, _, _) = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            .chars()
            .enumerate()
            .fold(
                (vec![], ' ', ' '),
                |(mut v, mut left, mut right), (i, ch)| {
                    if i % 2 == 0 {
                        left = ch;
                    } else {
                        right = ch;
                        let src = format!("{}{}", left, right);
                        v.push(u8::from_str_radix(&src, 16).unwrap());
                    }
                    (v, left, right)
                },
            );
        assert_eq!(NUMS, nums.as_slice());
    }
}
