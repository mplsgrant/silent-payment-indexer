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

use std::collections::BTreeSet;

use bitcoin::{consensus::Encodable, OutPoint};
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};

use crate::PublicKeySummation;

/// Need to use the smallest outpoint when tagging input values
struct SmallestOutpoint {
    inner: OutPoint,
}
impl SmallestOutpoint {
    fn new(outpoints: &[OutPoint]) -> Option<Self> {
        let mut a = BTreeSet::new();
        for outpoint in outpoints {
            a.insert(outpoint);
        }
        a.into_iter().next().map(|z| Self { inner: *z })
    }
    fn outpoint(&self) -> OutPoint {
        self.inner
    }
}

sha256t_hash_newtype! {
    pub struct InputsTag = hash_str("BIP0352/Inputs");

    /// Hash of the sum of the input public keys concatenated with the lexicographically smallest
    /// outpoint
    #[hash_newtype(forward)]
    pub struct InputsHash(_);
}

impl InputsHash {
    /// outpoint is the lexicographically smallest, and input_summation is the contributing public keys
    fn from_outpoint_and_input_summation(
        outpoint: SmallestOutpoint,
        input_summation: &PublicKeySummation,
    ) -> InputsHash {
        let mut eng = InputsHash::engine();
        outpoint
            .outpoint()
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        eng.input(&input_summation.public_key().serialize());
        InputsHash::from_engine(eng)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;

    use super::*;

    #[test]
    fn smallest_outpoints() {
        let txid_1 = Txid::from_slice(&[
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1,
        ])
        .unwrap();
        let txid_2 = Txid::from_slice(&[
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2,
        ])
        .unwrap();

        let outpoint_1_0 = OutPoint {
            txid: txid_1,
            vout: 0,
        };
        let outpoint_1_1 = OutPoint {
            txid: txid_1,
            vout: 1,
        };
        let smallest_1_0 = SmallestOutpoint::new(&[outpoint_1_0, outpoint_1_1]).unwrap();
        assert_eq!(smallest_1_0.outpoint(), outpoint_1_0);
        let outpoint_2_0 = OutPoint {
            txid: txid_2,
            vout: 0,
        };
        let smallest_1_1 = SmallestOutpoint::new(&[outpoint_2_0, outpoint_1_1]).unwrap();
        assert_eq!(smallest_1_1.outpoint(), outpoint_1_1);
    }
}
