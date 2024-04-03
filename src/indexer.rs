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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, str::FromStr};

    use bitcoin::{
        absolute::LockTime, bip32::{DerivationPath, Xpriv}, key::{rand, Keypair, Parity, Secp256k1}, psbt::Input, secp256k1::{PublicKey, SecretKey}, transaction::Version, Address, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness
    };
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use bitcoind::Conf;
    use hex_conservative::DisplayHex;
    use silentpayments::utils::receiving::{calculate_tweak_data, get_pubkey_from_input};

    const ALICE_XPRIV_STR: &str = "tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7";
    const BOB_XPRIV_STR: &str = "tprv8ZgxMBicQKsPe72C5c3cugP8b7AzEuNjP4NSC17Dkpqk5kaAmsL6FHwPsVxPpURVqbNwdLAbNqi8Cvdq6nycDwYdKHDjDRYcsMzfshimAUq";
    const BIP86_DERIVATION_PATH: &str = "m/86'/1'/0'/0";

    pub fn make_tr_address(maybe_sk: Option<&SecretKey>) -> Address {
        let secp = Secp256k1::new();
        let sk = if let Some(sk) = maybe_sk {
            *sk
        } else {
            let sk = SecretKey::new(&mut rand::thread_rng());
            println!("SK: {}", sk.display_secret());
            sk
        };
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let pubkey = match keypair.x_only_public_key() {
            (pubkey, Parity::Even) => pubkey,
            (_, Parity::Odd) => {
                let sk = sk.negate();
                let keypair = Keypair::from_secret_key(&secp, &sk);
                keypair.x_only_public_key().0
            }
        };
        Address::p2tr(&secp, pubkey, None, bitcoin::Network::Regtest)
    }

    pub fn get_txns_in_blocknum(block_num: u64, rpc: &Client) -> Vec<Transaction> {
        let block_hash = rpc.get_block_hash(block_num).expect("block hash");
        let block = rpc.get_block(&block_hash).expect("block");
        block.txdata
    }

    #[test]
    fn make_test_blocks() {
        let secp = Secp256k1::new();
        let base_deriv_path =
            DerivationPath::from_str(BIP86_DERIVATION_PATH).expect("bip86 deriv path");

        // Alice keys and addresses
        let alice_xpriv = Xpriv::from_str(ALICE_XPRIV_STR).expect("alice xpriv");
        let a_priv = alice_xpriv
            .derive_priv(&secp, &base_deriv_path.child(0.into()))
            .expect("a priv");
        let a_sk = a_priv.private_key;
        let a_address = make_tr_address(Some(&a_sk));

        // Bob keys and addresses
        let bob_xpriv = Xpriv::from_str(BOB_XPRIV_STR).expect("alice xpriv");
        let b_priv = bob_xpriv
            .derive_priv(&secp, &base_deriv_path.child(0.into()))
            .expect("a priv");
        let b_sk = b_priv.private_key;
        let b_address = make_tr_address(Some(&a_sk));

        // bitcoind setup
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        conf.args.push("-blockfilterindex=1");
        conf.network = "regtest";
        let exe = bitcoind::exe_path().expect("probably downloaded bitcoind");
        let bitcoind = bitcoind::BitcoinD::with_conf(exe, &conf).expect("new bitcoind");
        let rpc = &bitcoind.client;

        // get some funds into the system
        rpc.generate_to_address(103, &a_address).expect("bitcoind");

        // spend the funds
        let txns = get_txns_in_blocknum(1, rpc);
        txns.iter().for_each(|tx| println!("TX: {:?}", tx));
        let maybe_amt_script_pubkey = txns
            .first()
            .and_then(|coinbase_txn| {
                let outpoint = OutPoint {
                    txid: coinbase_txn.txid(),
                    vout: 0,
                };
                coinbase_txn.output.first().map(move |txout| {
                    println!("txout: {:?}", txout);
                    (&txout.value, &txout.script_pubkey, outpoint)
                })
            })
            // prepare a psbt
            .and_then(|(amount, script_pubkey, previous_output)| {
                let txin = TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                };
                let txout = TxOut {
                    value: Amount::from_btc(49.0).expect("amount"),
                    script_pubkey: b_address.script_pubkey(),
                };
                let tx = Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![txin],
                    output: vec![txout],
                };
                Psbt::from_unsigned_tx(tx).ok()
            }).and_then( |psbt| {

                let mut origins = BTreeMap::new();
                origins.insert(
                    input_pubkey,
                    (
                        vec![],
                        (
                            Fingerprint::from_str(input_utxo.master_fingerprint)?,
                            DerivationPath::from_str(input_utxo.derivation_path)?,
                        ),
                    ),
                );
                let input = Input {witness_utxo: todo!(), tap_key_origins: todo!()};
            })

        // search block for pubkeys in latest block
        let block_count = rpc.get_block_count().expect("block count");
        let block_hash = rpc.get_block_hash(block_count).expect("block hash");
        let block = rpc.get_block(&block_hash).expect("block");
        let pubkeys = block
            .txdata
            .iter()
            // skip the coinbase txn
            .skip(1)
            // The transaction contains at least one BIP341 taproot output
            .filter(|tx| tx.output.iter().any(|txout| txout.script_pubkey.is_p2tr()))
            // The transaction has at least one input from the Inputs For Shared Secret Derivation list
            .filter_map(|tx| {
                let input_pub_keys: Vec<PublicKey> = tx
                    .input
                    .iter()
                    .flat_map(|txin| {
                        let script_sig = &txin.script_sig.as_bytes();
                        let txinwitness = &txin.witness.to_vec();
                        let vout = txin.previous_output.vout as usize;
                        let txid = txin.previous_output.txid;
                        let maybe_pubkey_for_input_ssd = rpc
                            .get_raw_transaction(&txid, None)
                            .expect("prev txn")
                            .output
                            .get(vout)
                            .map(|txout| txout.script_pubkey.as_bytes())
                            .map(|script_pub_key| {
                                get_pubkey_from_input(script_sig, txinwitness, script_pub_key)
                            });
                        maybe_pubkey_for_input_ssd
                    })
                    .flatten()
                    .flatten()
                    .collect();

                let input_pub_keys: Vec<&PublicKey> = input_pub_keys.iter().collect();
                let outpoints_data: Vec<(String, u32)> = tx
                    .input
                    .iter()
                    .map(|txin| {
                        (
                            txin.previous_output.txid.to_string(),
                            txin.previous_output.vout,
                        )
                    })
                    .collect();

                calculate_tweak_data(input_pub_keys.as_slice(), outpoints_data.as_slice()).ok()
            });
        pubkeys.for_each(|x| println!("{x:?}"));
        assert!(false)
    }
}
