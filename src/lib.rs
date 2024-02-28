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

mod pubkey_extraction;
mod sender;
mod tagged_hashes;
mod test_data;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{ScriptBuf, Witness};

/// "Nothing Up My Sleeves" number from BIP 341: 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
static NUMS: [u8; 32] = [
    80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90, 15, 40,
    236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192,
];

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

struct PublicKeySummation {
    inner: PublicKey,
}
impl PublicKeySummation {
    fn new(keys: &[&PublicKey]) -> Option<Self> {
        PublicKey::combine_keys(keys)
            .ok()
            .map(|pubkey| Self { inner: pubkey })
    }
    fn public_key(&self) -> PublicKey {
        self.inner
    }
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
    pub txinwitness: Witness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrive_at_nums() {
        let (nums, _, _) = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            .chars()
            .enumerate()
            .fold(
                (vec![], ' ', ' '),
                |(mut v, mut left, mut right), (i, ch)| {
                    if i % 2 == 0 {
                        left = ch;
                    } else {
                        right = ch;
                        let src = format!("{}{}", left, right);
                        v.push(u8::from_str_radix(&src, 16).unwrap());
                    }
                    (v, left, right)
                },
            );
        assert_eq!(NUMS, nums.as_slice());
    }
}
