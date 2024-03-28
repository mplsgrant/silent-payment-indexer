#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::PublicKey;
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use silentpayments::utils::receiving::{calculate_tweak_data, get_pubkey_from_input};

    use super::*;

    #[test]
    fn dothing() {
        let rpc = Client::new(
            "127.0.0.1:38332",
            Auth::CookieFile("/home/dev/.bitcoin/signet/.cookie".into()),
        )
        .expect("a client");
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
