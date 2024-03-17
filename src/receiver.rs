use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use bech32::{
    primitives::decode::UncheckedHrpstring, Bech32, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp,
};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification, XOnlyPublicKey};
use bitcoin_hashes::Hash;
use hex_conservative::{Case, DisplayHex, FromHex};

use crate::{
    tagged_hashes::{InputsHash, SharedSecretHash},
    PublicKeySummation,
};

type MGHex = String;
type LabelHashHex = String;

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct SilentPaymentAddress {
    pub b_scan: PublicKey,
    pub b_spend: PublicKey,
}
impl SilentPaymentAddress {
    pub fn new(b_scan: &PublicKey, b_spend: &PublicKey) -> Self {
        Self {
            b_scan: *b_scan,
            b_spend: *b_spend,
        }
    }
    pub fn from_bech32(bech32: &str) -> Self {
        let unchecked =
            UncheckedHrpstring::new(bech32).expect("valid bech32 character encoded string");
        if unchecked.has_valid_checksum::<Bech32>() {
            panic!("expected a Bech32m string, not a Bech32 string")
        } else if unchecked.has_valid_checksum::<Bech32m>() {
            let mut checked = unchecked.remove_checksum::<Bech32m>();
            if checked.hrp() != Hrp::parse_unchecked("sp") {
                panic!("Expected an 'sp' human readable part (HRP)")
            }
            match checked.remove_witness_version() {
                Some(Fe32::Q) => {
                    let address_bytes = checked.byte_iter().collect::<Vec<u8>>();
                    let (b_scan, b_spend) = address_bytes.split_at(33);
                    let b_scan = PublicKey::from_slice(b_scan).expect("b_scan slice");
                    let b_spend = PublicKey::from_slice(b_spend).expect("b_spend slice");
                    SilentPaymentAddress::new(&b_scan, &b_spend)
                }
                _ => panic!("Wrong witness version"),
            }
        } else {
            panic!("Not a valid bech32m Silent Payment address")
        }
    }
    pub fn to_bech32(&self) -> String {
        self.b_scan
            .serialize()
            .iter()
            .chain(self.b_spend.serialize().iter())
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&Hrp::parse_unchecked("sp"))
            .with_witness_version(Fe32::Q)
            .chars()
            .collect()
    }
}
impl Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

#[allow(non_snake_case)]
fn scanning<C: Verification>(
    secp: &Secp256k1<C>,
    inputs_hash: &InputsHash,
    b_scan: &SecretKey,
    B_spend: &PublicKey,
    pubkey_summation: &PublicKeySummation,
    outputs_to_check: &mut HashSet<XOnlyPublicKey>,
    precomputed_labels: HashMap<MGHex, LabelHashHex>,
) -> Vec<(PublicKey, SecretKey)> {
    //  ecdh_shared_secret = input_hash·A_sum·b_scan
    let input_hash_scalar =
        Scalar::from_be_bytes(inputs_hash.to_byte_array()).expect("input_hash converts to scalar");
    let input_hash_bscan = b_scan
        .mul_tweak(&input_hash_scalar)
        .expect("scalars multiply");
    let input_hash_bscan =
        Scalar::from_be_bytes(input_hash_bscan.secret_bytes()).expect("secret key scalars");
    let ecdh_shared_secret = pubkey_summation
        .inner
        .mul_tweak(secp, &input_hash_bscan)
        .expect("scalars should tweak");
    let mut k = 0;
    let mut wallet = Vec::<(PublicKey, SecretKey)>::new();
    let mut output_to_remove = None::<XOnlyPublicKey>;
    let mut escape_hatch = 25;
    loop {
        let t_k = SharedSecretHash::new(&ecdh_shared_secret, k);
        let t_k = Scalar::from_be_bytes(t_k.to_byte_array()).expect("hash to scalar");
        let (P_k, parity) = B_spend
            .add_exp_tweak(secp, &t_k)
            .expect("scalar to tweak")
            .x_only_public_key();

        if let Some(pubkey) = output_to_remove {
            outputs_to_check.remove(&pubkey);
        }
        outputs_to_check
            .iter()
            .for_each(|x| println!("{}", x.serialize().as_hex()));
        for output in outputs_to_check.iter() {
            if &P_k == output {
                wallet.push((
                    P_k.public_key(parity),
                    SecretKey::from_slice(&t_k.to_be_bytes()).unwrap(),
                ));
                output_to_remove = Some(*output);
                k += 1;
                println!(
                    "output_to_remove: {}",
                    output_to_remove.unwrap().serialize().as_hex()
                );
                break;
            }
            if !precomputed_labels.is_empty() {
                // m_G_sub = output - P_k
                let m_G_sub = xonly_minus_xonly(secp, output, &P_k);
                let m_G_sub_key = m_G_sub.serialize().to_lower_hex_string();
                println!("subkey: {}", m_G_sub_key);
                if let Some(label) = precomputed_labels.get(&m_G_sub_key) {
                    let m_G_sub_scalar =
                        Scalar::from_be_bytes(m_G_sub.x_only_public_key().0.serialize())
                            .expect("scalar from x_only pubkey");
                    let P_km = P_k
                        .add_tweak(secp, &m_G_sub_scalar)
                        .expect("add scalar tweak");
                    let pub_key = P_km.0.public_key(P_km.1);
                    let priv_key_tweak = SecretKey::from_slice(&t_k.to_be_bytes())
                        .expect("scalar becomes secretkey")
                        .add_tweak(
                            &Scalar::from_be_bytes(
                                <[u8; 32]>::from_hex(label).expect("label fits in 32"),
                            )
                            .expect("label to scalar"),
                        )
                        .expect("scalar to tweak");
                    wallet.push((pub_key, priv_key_tweak));
                    output_to_remove = Some(*output);
                    println!(
                        "pub_key: {} \npriv_key_tweak: {}",
                        pub_key.serialize().as_hex(),
                        priv_key_tweak.display_secret()
                    );
                    k += 1;
                } else {
                    let m_G_sub = xonly_minus_xonly(secp, output, &P_k);
                    let m_g_sub_key = m_G_sub.serialize().to_hex_string(Case::Lower);
                    if let Some(label) = precomputed_labels.get(&m_g_sub_key) {
                        let m_g_sub_scalar =
                            Scalar::from_be_bytes(m_G_sub.x_only_public_key().0.serialize())
                                .expect("scalar from x_only pubkey");
                        let P_km = P_k
                            .add_tweak(secp, &m_g_sub_scalar)
                            .expect("add scalar tweak");
                        let pub_key = P_km.0.public_key(P_km.1);
                        let priv_key_tweak = SecretKey::from_slice(&t_k.to_be_bytes())
                            .expect("scalar becomes secretkey")
                            .add_tweak(
                                &Scalar::from_be_bytes(
                                    <[u8; 32]>::from_hex(label).expect("label fits in 32"),
                                )
                                .expect("label to scalar"),
                            )
                            .expect("scalar to tweak");
                        wallet.push((pub_key, priv_key_tweak));
                        output_to_remove = Some(*output);
                        k += 1;
                        break;
                    }
                };
            }
        }
        escape_hatch -= 1;
        if escape_hatch == 0 {
            // TODO remove
            break;
        }
    }
    wallet
}

fn public_key_minus_xonly<C: Verification>(
    secp: &Secp256k1<C>,
    left: &PublicKey,
    right: &XOnlyPublicKey,
) -> PublicKey {
    left.combine(&right.public_key(bitcoin::key::Parity::Even).negate(secp))
        .expect("combine with a negative")
}

fn xonly_minus_xonly<C: Verification>(
    secp: &Secp256k1<C>,
    left: &XOnlyPublicKey,
    right: &XOnlyPublicKey,
) -> PublicKey {
    left.public_key(bitcoin::key::Parity::Even)
        .combine(&right.public_key(bitcoin::key::Parity::Even).negate(secp))
        .expect("combine with a negative")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pubkey_extraction::get_input_for_ssd,
        tagged_hashes::{InputsHash, LabelTagHash, SmallestOutpoint},
        test_data::{BIP352TestVectors, ReceivingObject},
        InputData, PublicKeySummation,
    };
    use bitcoin::{
        key::{Keypair, Parity, Secp256k1},
        secp256k1::{schnorr::Signature, Message, PublicKey, Scalar, SecretKey},
        OutPoint, ScriptBuf, XOnlyPublicKey,
    };
    use bitcoin_hashes::{sha256, Hash};
    use hex_conservative::{Case, DisplayHex};

    use std::{
        collections::{BTreeSet, HashMap, HashSet},
        fs::File,
        io::Read,
        str::FromStr,
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

    #[allow(non_snake_case)]
    #[test]
    fn test_a() {
        let secp = Secp256k1::new();
        let test_vectors = get_bip352_test_vectors();
        let receiving_objects: Vec<(&ReceivingObject, &String)> = test_vectors
            .test_vectors
            .iter()
            .flat_map(|test_case| {
                test_case
                    .receiving
                    .iter()
                    .map(move |receiving_object| (receiving_object, &test_case.comment))
            })
            .collect();
        for (receiving, comment) in receiving_objects.iter() {
            println!("Receiving: {}", comment);
            let given = &receiving.given;
            let expected = &receiving.expected;
            let mut outputs_to_check: HashSet<XOnlyPublicKey> =
                given.outputs.iter().map(|output| output.output).collect();
            let (given_pubkeys, given_outpoints) = given
                .vin
                .iter()
                .flat_map(|vin| {
                    let prevout = ScriptBuf::from_hex(&vin.prevout.script_pubkey.hex).unwrap();
                    let input_data = InputData {
                        prevout: &prevout,
                        script_sig: vin.script_sig.as_deref(),
                        txinwitness: vin.txinwitness.as_ref(),
                    };
                    let out_point = OutPoint::new(vin.txid, vin.vout);
                    get_input_for_ssd(&input_data).map(|input_for_ssd| (out_point, input_for_ssd))
                })
                .fold(
                    (Vec::<PublicKey>::new(), BTreeSet::<OutPoint>::new()),
                    |(mut pubkeys, mut outpoint_set), (outpoint, input_for_ssd_pubkey)| {
                        if let Some(pubkey) = input_for_ssd_pubkey.pubkey() {
                            pubkeys.push(pubkey);
                        }
                        outpoint_set.insert(outpoint);
                        (pubkeys, outpoint_set)
                    },
                );
            let b_scan = &given.key_material.scan_priv_key;
            let b_spend = &given.key_material.spend_priv_key;
            let B_scan = b_scan.public_key(&secp);
            let B_spend = b_spend.public_key(&secp);
            let mut receiving_addresses = Vec::<SilentPaymentAddress>::new();
            let address = SilentPaymentAddress::new(&B_scan, &B_spend);
            receiving_addresses.push(address);
            for label in given.labels.iter() {
                let tagged_label = LabelTagHash::new(b_scan, *label);

                // METHOD 1: one idea is to take the label hash and convert to a scalar and tweak the public key with it.
                let scalar_tag = Scalar::from_be_bytes(tagged_label.to_byte_array())
                    .expect("labels are scalar-able");
                let B_m = B_spend
                    .add_exp_tweak(&secp, &scalar_tag)
                    .expect("pubkeys get tweaked by scalars");

                // METHOD 2: Another idea is to just convert the label hash into a public key via a secret key and combine that with B_spend
                let tagged_label_as_secret_key =
                    SecretKey::from_slice(tagged_label.as_byte_array())
                        .expect("tagged label hash becomes a secret key");
                let tagged_label_as_public_key = tagged_label_as_secret_key.public_key(&secp);
                let B_m_using_method_2 = B_spend
                    .combine(&tagged_label_as_public_key)
                    .expect("combine using method 2");
                assert_eq!(B_m, B_m_using_method_2);

                let address = SilentPaymentAddress::new(&B_scan, &B_m);
                receiving_addresses.push(address);
            }

            let created_addresses: BTreeSet<String> = receiving_addresses
                .iter()
                .map(|address| address.to_bech32())
                .collect();

            let expected_addresses: BTreeSet<String> = expected.addresses.iter().cloned().collect();
            assert!(!&created_addresses.is_empty());
            assert!(!&expected_addresses.is_empty());
            assert_eq!(created_addresses.difference(&expected_addresses).count(), 0);

            assert!(!given_pubkeys.is_empty());
            if !given_pubkeys.is_empty() {
                let pubkeys: Vec<&PublicKey> = given_pubkeys.iter().collect();
                let pubkey_summation = PublicKeySummation::new(&pubkeys).expect("pubkeys");
                let smallest_outpoint = SmallestOutpoint::new(&[*given_outpoints
                    .iter()
                    .next()
                    .expect("outpoint exists")])
                .expect("outpoint exists");
                let inputs_hash = InputsHash::new(smallest_outpoint, &pubkey_summation);

                let precomputed_labels: HashMap<MGHex, LabelHashHex> = given
                    .labels
                    .iter()
                    .map(|m| LabelTagHash::new(b_scan, *m))
                    .map(|label_hash| {
                        let label_hash_secret = SecretKey::from_slice(label_hash.as_byte_array())
                            .expect("label hash converts to scalar");
                        let m_g = PublicKey::from_secret_key(&secp, &label_hash_secret)
                            .serialize()
                            .to_lower_hex_string();
                        let label_hash = label_hash.as_byte_array().to_lower_hex_string();
                        (m_g, label_hash)
                    })
                    .fold(
                        HashMap::<MGHex, LabelHashHex>::new(),
                        |mut precomputed_labels, (m_g, label_hash)| {
                            precomputed_labels.insert(m_g, label_hash);
                            precomputed_labels
                        },
                    );

                let add_to_wallet = scanning(
                    &secp,
                    &inputs_hash,
                    b_scan,
                    &B_spend,
                    &pubkey_summation,
                    &mut outputs_to_check,
                    precomputed_labels,
                );

                let expected_pubkeys: Vec<XOnlyPublicKey> =
                    expected.outputs.iter().map(|exp| exp.pub_key).collect();
                let expected_priv_key_tweak: Vec<Scalar> = expected
                    .outputs
                    .iter()
                    .map(|exp| exp.priv_key_tweak)
                    .collect();
                let expected_sig: Vec<Signature> =
                    expected.outputs.iter().map(|exp| exp.signature).collect();
                // add_to_wallet.iter().for_each(|x| {
                //     println!("{} {}", x.0.serialize().as_hex(), x.1.display_secret())
                // });
                add_to_wallet
                    .iter()
                    .map(|output| {
                        let pubkey = output.0;
                        let private_key_tweak =
                            Scalar::from_be_bytes(output.1.secret_bytes()).unwrap();
                        let mut full_private_key = b_spend.add_tweak(&private_key_tweak).unwrap();
                        if full_private_key.public_key(&secp).x_only_public_key().1 == Parity::Odd {
                            full_private_key = full_private_key.negate();
                        }
                        let keypair = Keypair::from_secret_key(&secp, &full_private_key);
                        let msg = Message::from_hashed_data::<sha256::Hash>("message".as_bytes());
                        let aux_rand = sha256::Hash::hash("random auxiliary data".as_bytes());
                        let sig = &secp.sign_schnorr_with_aux_rand(
                            &msg,
                            &keypair,
                            aux_rand.as_byte_array(),
                        );
                        println!("msg: {}", msg);
                        println!("pubkey: {}", pubkey.x_only_public_key().0);
                        println!("full private: {}", full_private_key.display_secret());
                        println!("sig: {}", sig);
                        assert!(pubkey
                            .x_only_public_key()
                            .0
                            .verify(&secp, &msg, sig)
                            .is_ok());
                        (pubkey, private_key_tweak, *sig)
                    })
                    .map(|(pubkey, private_key_tweak, sig)| {
                        assert!(expected_pubkeys.contains(&pubkey.x_only_public_key().0));
                        assert!(expected_priv_key_tweak.contains(&private_key_tweak));
                        assert!(expected_sig.contains(&sig));
                    })
                    .for_each(drop);
            }
        }
    }
}
