//! Cycle 006/007 compatible key-sorted JSON and SHA-256.
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::Result;

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&sort_value(value))?)
}

pub fn digest_value(value: &Value) -> Result<String> {
    let digest = Sha256::digest(canonical_json_bytes(value)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}
