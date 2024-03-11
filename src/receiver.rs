#[cfg(test)]
mod tests {
    use crate::test_data::BIP352TestVectors;
    use std::{fs::File, io::Read};

    fn get_bip352_test_vectors() -> BIP352TestVectors {
        let path = format!(
            "{}/test/send_and_receive_test_vectors.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut file = File::open(path).unwrap();
        let mut json = String::new();
        file.read_to_string(&mut json).unwrap();
        serde_json::from_str(&json).unwrap()
    }
    fn test_a() {
        let test_vectors = get_bip352_test_vectors();
        //        for test_case in test_vectors.test_vectors.iter().map(|test_case| {println!("{}", test_case.comment); test_case.})
    }
}
