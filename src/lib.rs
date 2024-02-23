use bitcoin::{
    hashes::{hash160, Hash},
    PublicKey, Script, ScriptBuf, TxIn,
};

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
}

fn get_pubkey_from_input(vin: InputData) {
    if vin.prevout.is_p2pkh() {
        get_pubkey_from_p2pkh(vin);
    }
}

fn get_pubkey_from_p2pkh(vin: InputData) -> Option<PublicKey> {
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
                if let Some(bytes) = instruction.push_bytes() {
                    // TODO: use instruction.push_bytes directly instead of slicing the bytes
                    Some(&vin.script_sig.as_bytes()[index + 1..index + bytes.len() + 1])
                } else {
                    None
                }
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_get_pubkey_from_p2pkh() {
        let vin = InputData {
            prevout: ScriptBuf::from_hex("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac").unwrap(), script_sig: ScriptBuf::from_hex("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5").unwrap() };
        let maybe_pubkey = get_pubkey_from_p2pkh(vin);
        assert_eq!(
            "19c2f3ae0ca3b642bd3e49598b8da89f50c14161",
            maybe_pubkey.unwrap().pubkey_hash().to_string()
        );
    }

    #[test]
    fn malleated_get_pubkey_from_p2pkh() {
        // TODO: Verify that the malleation is swapping a compressed pubkey with an uncompressed one
        let vin = InputData {
            prevout: ScriptBuf::from_hex("76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac").unwrap(), script_sig: ScriptBuf::from_hex("5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68").unwrap() };
        let maybe_pubkey = get_pubkey_from_p2pkh(vin);
        assert_eq!(
            "c82c5ec473cbc6c86e5ef410e36f9495adcf9799",
            maybe_pubkey.unwrap().pubkey_hash().to_string()
        );
    }
}
