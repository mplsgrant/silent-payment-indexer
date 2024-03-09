use crate::{
    pubkey_extraction::{get_input_for_ssd, InputForSSDPubKey},
    tagged_hashes::{InputsHash, SmallestOutpoint},
    InputData, PublicKeySummation,
};
use bitcoin::secp256k1::PublicKey;

type BScan = PublicKey;
type Bm = PublicKey;

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
    let input_hash = InputsHash::new(outpoint, &input_summation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tagged_hashes::SharedSecretHash,
        test_data::{BIP352TestVectors, BIP352Vin, Recipient},
    };
    use bech32::FromBase32;
    use bitcoin::{
        key::{Parity, Secp256k1},
        secp256k1::{PublicKey, Scalar, SecretKey},
        Amount, OutPoint, Script, ScriptBuf, XOnlyPublicKey,
    };
    use bitcoin_hashes::Hash;
    use hex_conservative::DisplayHex;
    use std::{
        collections::{BTreeSet, HashMap},
        fs::File,
        io::Read,
    };

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
        test_vectors
            .test_vectors
            .iter()
            .flat_map(|test| {
                println!("Comment: {}", test.comment);
                test.sending.iter()
            })
            .map(|sending| {
                let (secret_keys, pubkeys, outpoints) = sending
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
                            Vec::<PublicKey>::new(),
                            BTreeSet::<OutPoint>::new(),
                        ),
                        |(mut priv_keys, mut pubkeys, mut outpoints),
                         (vin, input_for_ssd, outpoint)| {
                            outpoints.insert(outpoint);
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
                            pubkeys.push(pubkey);
                            if let Some(pubkey) = input_for_ssd.pubkey() {
                                assert_eq!(private_key.public_key(&secp), *pubkey);
                            }
                            (priv_keys, pubkeys, outpoints)
                        },
                    );

                let maybe_smallest_outpoint = outpoints
                    .into_iter()
                    .next()
                    .and_then(|smallest_outpoint| SmallestOutpoint::new(&[smallest_outpoint]));

                // Let a = a1 + a2 + ... + an, where each ai has been negated if necessary
                let maybe_secret_key_summation =
                    secret_keys.split_first().map(|(first_sk, rest)| {
                        let mut first_sk = *first_sk;
                        if !rest.is_empty() {
                            for sk in rest {
                                let scalar = &(*sk).into();
                                first_sk = first_sk.add_tweak(scalar).expect("secret keys do sum");
                            }
                            first_sk
                        } else {
                            first_sk
                        }
                    });

                let pubkeys: Vec<&PublicKey> = pubkeys.iter().collect(); // TODO Can we push the referencing up?
                let maybe_pubkey_summation = PublicKeySummation::new(pubkeys.as_slice());
                let maybe_input_hash = match (maybe_smallest_outpoint, maybe_pubkey_summation) {
                    (Some(smallest_outpoint), Some(pubkey_summation)) => {
                        Some(InputsHash::new(smallest_outpoint, &pubkey_summation))
                    }
                    _ => None,
                };

                let outputs = sending
                    .given
                    .recipients
                    .iter()
                    .map(|recipient| {
                        // bech32 decoding in version 10 & 11 works differntly.
                        let (hrp, data, _var) =
                            bech32::decode(&recipient.recipient.0).expect("recipient");
                        let keys = Vec::<u8>::from_base32(&data[1..]).unwrap();
                        ((hrp, keys), recipient.recipient.1)
                    })
                    .map(|((_, keys), amount)| {
                        let b_scan = BScan::from_slice(&keys[0..33]).expect("b_scan key fits");
                        let b_m = Bm::from_slice(&keys[33..66]).expect("b_m key fits");
                        let amount = Amount::from_btc(amount).expect("amount parses");
                        (b_scan, b_m, amount)
                    })
                    .fold(
                        HashMap::<BScan, Vec<(Bm, Amount)>>::new(),
                        |mut grouping, (b_scan, b_m, amount)| {
                            println!("AAA");
                            grouping
                                .entry(b_scan)
                                .or_insert(vec![(b_m, amount)])
                                .push((b_m, amount));
                            println!("grouping: {:?}", grouping);
                            grouping
                        },
                    )
                    .iter()
                    // Sort for sole purpose of keeping the tests determininstic.
                    // .fold(
                    //     HashMap::<BScan, Vec<(Bm, Amount)>>::new(),
                    //     |mut grouping, (b_scan, b_m_and_amounts)| {
                    //         let mut b_m_and_amounts_sorted = b_m_and_amounts.clone();
                    //         b_m_and_amounts_sorted
                    //             .sort_by(|(_, a_amount), (_, b_amount)| a_amount.cmp(b_amount));
                    //         grouping.insert(*b_scan, b_m_and_amounts_sorted);
                    //         grouping
                    //     },
                    // )
                    // .iter()
                    .flat_map(|(b_scan, b_m_and_amounts)| {
                        match (maybe_input_hash, maybe_secret_key_summation) {
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
                                Some((ecdh_shared_secret, b_m_and_amounts))
                            }
                            _ => None,
                        }
                    })
                    .fold(
                        Vec::<(XOnlyPublicKey, Amount)>::new(),
                        |mut pubkeys_with_amounts, (ecdh_shared_secret, b_m_and_amounts)| {
                            let mut k = 0;
                            b_m_and_amounts
                                .iter()
                                .map(|(b_m, amount)| {
                                    let t_k = SharedSecretHash::new(&ecdh_shared_secret, k);
                                    let t_k = Scalar::from_be_bytes(t_k.to_byte_array())
                                        .expect("hashes convert to scalars");
                                    let p_km = b_m
                                        .add_exp_tweak(&secp, &t_k)
                                        .expect("public keys get tweaked cleanly");
                                    k += 1;
                                    let xonly_p_km = p_km.x_only_public_key();
                                    pubkeys_with_amounts.push((xonly_p_km.0, *amount));
                                })
                                .for_each(drop);
                            pubkeys_with_amounts
                        },
                    );

                sending
                    .expected
                    .outputs
                    .iter()
                    .map(|expected_outputs| {
                        (
                            expected_outputs.outputs.0,
                            Amount::from_btc(expected_outputs.outputs.1).unwrap(),
                        )
                    })
                    .zip(outputs.iter())
                    .map(|(given, produced)| {
                        println!("given: {} {}", given.0, given.1);
                        println!("prod : {} {}", produced.0, produced.1);
                        assert_eq!(&given, produced);
                    })
                    .for_each(drop);
            })
            .for_each(drop);
    }
}
