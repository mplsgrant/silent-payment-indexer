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
    use std::str::FromStr;

    use bitcoin::{
        key::{rand, Keypair, Parity, Secp256k1},
        secp256k1::{PublicKey, SecretKey},
        Address, Transaction,
    };
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use bitcoind::Conf;
    use silentpayments::utils::receiving::{calculate_tweak_data, get_pubkey_from_input};

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
    fn dothing() {
        let a_sk =
            SecretKey::from_str("ef1ec963c51a782667b62cf8adee6cabc70698000dfaa5bc8ff9e5766c8fc4d2")
                .expect("a_sk");
        let b_sk =
            SecretKey::from_str("d344a95bd10d8529cd8a8ecd35166853abe7891184bf28b93383681cba591d7b")
                .expect("b_sk");
        let a_address = make_tr_address(Some(&a_sk));
        let b_address = make_tr_address(Some(&b_sk));

        let mut conf = Conf::default();
        conf.args.push("-txindex"); // allows for get_raw_transaction_info
        conf.args.push("-blockfilterindex=1"); // allegedly makes the importdescriptors run faster
        conf.network = "regtest";
        let exe = bitcoind::exe_path().expect("probably downloaded bitcoind");
        let bitcoind = bitcoind::BitcoinD::with_conf(exe, &conf).expect("new bitcoind");
        let rpc = &bitcoind.client;

        rpc.generate_to_address(103, &a_address).expect("bitcoind");
        let txn = get_txns_in_blocknum(0, rpc)
            .first()
            .expect("initial coinbase txn");

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
