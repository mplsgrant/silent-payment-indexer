use bitcoin::{
    secp256k1::{schnorr::Signature, SecretKey},
    Amount, ScriptBuf, Txid, Witness, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct BIP352TestVectors {
    pub test_vectors: Vec<BIP352Test>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Test {
    pub comment: String,
    pub sending: Vec<SendingObject>,
    pub receiving: Vec<ReceivingObject>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceivingObject {
    pub given: ReceivingGiven,
    pub expected: ReceivingExpected,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceivingGiven {
    pub vin: Vec<ReceivingVin>,
    pub outputs: Vec<ReceivingOutput>,
    pub key_material: KeyMaterial,
    pub labels: Vec<u32>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceivingVin {
    pub txid: Txid,
    pub vout: u32,
    #[serde(alias = "scriptSig")]
    #[serde(with = "empty_scriptsig_is_none")]
    pub script_sig: Option<ScriptBuf>,
    #[serde(with = "empty_witness_is_none")]
    pub txinwitness: Option<Witness>,
    pub prevout: Prevout,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct ReceivingOutput {
    pub output: XOnlyPublicKey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceivingExpected {
    pub addresses: Vec<String>,
    pub outputs: Vec<ReceivingExpectedOutputs>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceivingExpectedOutputs {
    pub pub_key: XOnlyPublicKey,
    pub priv_key_tweak: String,
    pub signature: Signature,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMaterial {
    pub spend_priv_key: SecretKey,
    pub scan_priv_key: SecretKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendingObject {
    pub given: SendingGiven,
    pub expected: SendingExpected,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendingGiven {
    pub vin: Vec<SendingVin>,
    pub recipients: Vec<Recipient>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendingExpected {
    pub outputs: Vec<SendingOutputs>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendingVin {
    pub txid: Txid,
    pub vout: u32,
    #[serde(alias = "scriptSig")]
    #[serde(with = "empty_scriptsig_is_none")]
    pub script_sig: Option<ScriptBuf>,
    #[serde(with = "empty_witness_is_none")]
    pub txinwitness: Option<Witness>,
    pub prevout: Prevout,
    pub private_key: SecretKey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct Recipient {
    pub recipient: (SPAddress, f64),
}

type SPAddress = String;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct SendingOutputs {
    pub outputs: Output,
}
type Output = (XOnlyPublicKey, f64);
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Prevout {
    #[serde(alias = "scriptPubKey")]
    pub script_pubkey: ScriptPubKey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScriptPubKey {
    pub hex: String,
}

mod empty_witness_is_none {
    use bitcoin::{consensus::Decodable, Witness};
    use hex_conservative::FromHex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Witness>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v = if let Some(v) = value {
            return v.serialize(serializer);
        } else {
            ""
        };
        serializer.serialize_str(v)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Witness>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This can be made generic: https://github.com/serde-rs/serde/issues/1425#issuecomment-462282398
        let opt = Option::<String>::deserialize(deserializer)?;
        let opt = opt.as_deref();
        match opt {
            None | Some("") => Ok(None),
            Some(s) => {
                let reader = Vec::from_hex(s).unwrap();
                let mut reader = reader.as_slice();
                let w =
                    Witness::consensus_decode(&mut reader).expect("witness deserialization issue");
                Ok(Some(w))
            }
        }
    }
}

mod empty_scriptsig_is_none {
    use bitcoin::ScriptBuf;
    use hex_conservative::FromHex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<ScriptBuf>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v = if let Some(v) = value {
            return v.serialize(serializer);
        } else {
            ""
        };
        serializer.serialize_str(v)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<ScriptBuf>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This can be made generic: https://github.com/serde-rs/serde/issues/1425#issuecomment-462282398
        let opt = Option::<String>::deserialize(deserializer)?;
        let opt = opt.as_deref();
        match opt {
            None | Some("") => Ok(None),
            Some(s) => {
                let reader = Vec::from_hex(s).unwrap();
                let reader = reader.as_slice();
                let w = ScriptBuf::from_hex(s).expect("script_sig deserialization issue");
                Ok(Some(w))
            }
        }
    }
}

mod priv_key_tweak_is_scalar {
    use bitcoin::secp256k1::Scalar;
    use hex_conservative::{DisplayHex, FromHex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", value.to_be_bytes().as_hex()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let scalar = String::deserialize(deserializer)?;
        let scalar = Vec::from_hex(&scalar).unwrap();
        let scalar = Scalar::from_be_bytes(scalar.try_into().unwrap()).unwrap();
        Ok(scalar)
    }
}

mod amount_parser {
    use bitcoin::Amount;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: Amount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(value.to_float_in(bitcoin::Denomination::Bitcoin))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This can be made generic: https://github.com/serde-rs/serde/issues/1425#issuecomment-462282398
        let btc = f64::deserialize(deserializer)?;
        Ok(Amount::from_btc(btc).expect("bitcoin amount parses"))
    }
}
