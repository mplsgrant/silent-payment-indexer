use crate::{
    pubkey_extraction::{get_input_for_ssd, InputForSSDPubKey},
    tagged_hashes::{InputsHash, SmallestOutpoint},
    InputData, PublicKeySummation,
};

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

pub fn generate_input_hash(outpoint: SmallestOutpoint, input_summation: PublicKeySummation) {
    let input_hash = InputsHash::from_outpoint_and_input_summation(outpoint, &input_summation);
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        bech32::{self, Bech32},
        key::{Parity, Secp256k1},
        secp256k1::{PublicKey, Scalar, SecretKey},
        OutPoint, Script, ScriptBuf, XOnlyPublicKey,
    };
    use bitcoin_hashes::Hash;

    use super::*;
    use crate::test_data::{BIP352TestVectors, BIP352Vin, Recipient};

    use std::{collections::BTreeSet, fs::File, io::Read};

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
    fn a_test() {
        let secp = Secp256k1::new();
        let test_vectors = get_bip352_test_vectors();
        let sending = test_vectors
            .test_vectors
            .iter()
            .flat_map(|test| test.sending.iter())
            .map(|sending| {
                let (secret_keys, pubkeys, btree) = sending
                    .given
                    .vin
                    .iter()
                    .flat_map(|vin| {
                        let prevout = ScriptBuf::from_hex(&vin.prevout.script_pubkey.hex).unwrap();
                        let input_data = InputData {
                            prevout: &prevout,
                            script_sig: vin.script_sig.as_deref(),
                            txinwitness: vin.txinwitness.as_ref(),
                        };
                        get_input_for_ssd(&input_data).map(|input_for_ssd| (vin, input_for_ssd))
                    })
                    .filter(|(_vin, input_for_ssd)| {
                        !matches!(input_for_ssd, InputForSSDPubKey::P2TRWithH)
                    })
                    .map(|(vin, input_for_ssd)| {
                        (vin, input_for_ssd, OutPoint::new(vin.txid, vin.vout))
                    })
                    .fold(
                        (
                            Vec::<SecretKey>::new(),
                            Vec::<&PublicKey>::new(),
                            BTreeSet::<OutPoint>::new(),
                        ),
                        |(mut priv_keys, mut pubkeys, mut btree),
                         (vin, input_for_ssd, outpoint)| {
                            btree.insert(outpoint);
                            let (private_key, pubkey) = match input_for_ssd {
                                InputForSSDPubKey::P2PKH { pubkey } => (vin.private_key, pubkey),
                                InputForSSDPubKey::P2SH { pubkey } => (vin.private_key, pubkey),
                                InputForSSDPubKey::P2WPKH { pubkey } => (vin.private_key, pubkey),
                                InputForSSDPubKey::P2TR { pubkey } => {
                                    let pubkey_from_secret_key =
                                        PublicKey::from_secret_key(&secp, &vin.private_key);
                                    let secret_key_even_y =
                                        if pubkey_from_secret_key.x_only_public_key().1
                                            == Parity::Odd
                                        {
                                            vin.private_key.negate()
                                        } else {
                                            vin.private_key
                                        };
                                    (secret_key_even_y, pubkey)
                                }
                                InputForSSDPubKey::P2TRWithH => panic!("should not see H here"),
                            };

                            priv_keys.push(private_key);
                            pubkeys.push(&pubkey);
                            (priv_keys, pubkeys, btree)
                        },
                    );

                let maybe_smallest_outpoint = btree
                    .into_iter()
                    .next()
                    .and_then(|smallest_outpoint| SmallestOutpoint::new(&[smallest_outpoint]));

                // Let a = a1 + a2 + ... + an, where each ai has been negated if necessary
                let maybe_secret_key_summation =
                    secret_keys.split_first().map(|(first_sk, rest)| {
                        rest.iter().fold(first_sk, |summed_sk, sk| {
                            let scalar = &(*sk).into();
                            summed_sk.add_tweak(scalar).expect("secret keys do sum");
                            summed_sk
                        })
                    });

                let maybe_pubkey_summation = PublicKeySummation::new(pubkeys.as_slice());
                let maybe_input_hash = match (maybe_smallest_outpoint, maybe_pubkey_summation) {
                    (Some(smallest_outpoint), Some(pubkey_summation)) => {
                        Some(InputsHash::from_outpoint_and_input_summation(
                            smallest_outpoint,
                            &pubkey_summation,
                        ))
                    }
                    _ => None,
                };
                let recipients = test_vectors
                    .test_vectors
                    .iter()
                    .flat_map(|test| test.sending.iter())
                    .flat_map(|sending| sending.given.recipients.iter())
                    .map(|recipient| bech32::decode(&recipient.recipient.0).expect("recipient"))
                    .map(|(_, keys)| {
                        let b_scan = PublicKey::from_slice(&keys[0..33]).expect("b_scan key fits");
                        let b_m = PublicKey::from_slice(&keys[33..66]).expect("b_m key fits");
                        (b_scan, b_m)
                    })
                    .map(
                        |(b_scan, b_m)| match (maybe_input_hash, maybe_secret_key_summation) {
                            (Some(input_hash), Some(secret_key_summation)) => {
                                //  input_hash·a·Bscan
                                let input_hash_scalar =
                                    Scalar::from_be_bytes(input_hash.to_byte_array())
                                        .expect("input_hash converts to scalar");
                                let secret_key_summation_scalar =
                                    Scalar::from_be_bytes(secret_key_summation.secret_bytes())
                                        .expect("secret keys convert to scalar");
                                let input_hash_bscan = b_scan
                                    .mul_tweak(&secp, &input_hash_scalar)
                                    .expect("scalars multiply");
                                let ecdh_shared_secret = input_hash_bscan
                                    .mul_tweak(&secp, &secret_key_summation_scalar)
                                    .expect("secret scalars multiply");
                                Some(ecdh_shared_secret)
                            }
                            _ => None,
                        },
                    );
            })
            .for_each(drop);

        assert!(false)
    }
}
