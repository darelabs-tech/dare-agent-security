use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Result;

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&sort_value(value))?)
}

pub fn digest_value(value: &Value) -> Result<String> {
    let hash = Sha256::digest(canonical_json_bytes(value)?);
    Ok(format!("sha256:{hash:x}"))
}

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    digest_value(&serde_json::to_value(value)?)
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
