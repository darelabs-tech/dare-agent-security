//! Deterministic JSON canonicalization (key-sorted) + SHA-256.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::BenchmarkError;

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, BenchmarkError> {
    let sorted = sort_value(value);
    serde_json::to_vec(&sorted).map_err(|_| BenchmarkError::Serialization {
        kind: "canonical-json",
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes).as_slice())
}

pub fn digest_value(value: &Value) -> Result<String, BenchmarkError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), sort_value(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_digest() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(digest_value(&a).unwrap(), digest_value(&b).unwrap());
    }
}
