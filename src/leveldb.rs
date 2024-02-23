// Copyright (C) 2024      Whittier Digital Technologies LLC
//
// This file is part of silent-payement-indexer.
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

use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use std::path::Path;

struct SomeKey {
    pub key: Vec<u8>,
}
impl db_key::Key for SomeKey {
    fn from_u8(key: &[u8]) -> Self {
        SomeKey {
            key: Vec::from(key),
        }
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&self.key)
    }
}

fn try_leveldb() {
    let path = Path::new("/home/dev/.bitcoin/signet/blocks/index");
    let mut options = Options::new();
    let mut db = Database::<SomeKey>::open(path, options).unwrap();
    let read_options = ReadOptions::new();
    let some_key = SomeKey { key: vec![] };
    let something = db.get(read_options, some_key);
    println!("It finds nothing: {:?}", something);
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_try_leveldb() {
        try_leveldb()
    }
}
