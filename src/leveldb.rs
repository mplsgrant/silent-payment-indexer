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
