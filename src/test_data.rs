use bitcoin::{secp256k1::SecretKey, ScriptBuf, Txid, Witness};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct BIP352TestVectors {
    pub test_vectors: Vec<BIP352Test>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Test {
    pub comment: String,
    pub sending: Vec<BIP352SendingObject>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352SendingObject {
    pub given: BIP352Given,
    pub expected: BIP352Expected,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Given {
    pub vin: Vec<BIP352Vin>,
    pub recipients: Vec<Recipients>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Expected {
    pub outputs: Vec<Outputs>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Vin {
    pub txid: Txid,
    pub vout: usize,
    #[serde(alias = "scriptSig")]
    #[serde(with = "empty_scriptsig_is_none")]
    pub script_sig: Option<ScriptBuf>,
    #[serde(with = "empty_witness_is_none")]
    pub txinwitness: Option<Witness>,
    pub prevout: BIP352Prevout,
    pub private_key: SecretKey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct Recipients {
    pub recipients: (SPAddress, f32),
}
type SPAddress = String;
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct Outputs {
    pub outputs: Output,
}
type Output = (Txid, f32);
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352Prevout {
    #[serde(alias = "scriptPubKey")]
    pub script_pubkey: BIP352ScriptPubKey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BIP352ScriptPubKey {
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
                let mut reader = reader.as_slice();
                let w = ScriptBuf::from_hex(s).expect("script_sig deserialization issue");
                Ok(Some(w))
            }
        }
    }
}
