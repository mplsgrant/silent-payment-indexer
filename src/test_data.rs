use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct BIP352TestVectors {
    pub test_vectors: Vec<BIP352Test>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BIP352Test {
    pub comment: String,
    pub sending: Vec<BIP352SendingObject>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BIP352SendingObject {
    pub given: BIP352Given,
    pub expected: BIP352Expected,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BIP352Given {
    pub vin: Vec<Vin>,
    pub recipients: Vec<Recipients>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BIP352Expected {
    pub outputs: Vec<Outputs>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Vin {
    pub txid: String,
    pub vout: usize,
    #[serde(alias = "scriptSig")]
    pub script_sig: String,
    pub txinwitness: String,
    pub prevout: BIP352Prevout,
    pub private_key: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
struct Recipients {
    pub recipients: Item,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
struct Outputs {
    pub outputs: Item,
}
type Item = (String, f32);
#[derive(Serialize, Deserialize, Clone)]
struct BIP352Prevout {
    #[serde(alias = "scriptPubKey")]
    pub script_pubkey: BIP352ScriptPubKey,
}
#[derive(Serialize, Deserialize, Clone)]
struct BIP352ScriptPubKey {
    pub hex: String,
}
