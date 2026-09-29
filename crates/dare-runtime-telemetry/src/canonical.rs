//! Canonical JSON digests: sorted keys, compact, `sha256:<hex>`.
use serde_json::Value;
use sha2::{Digest, Sha256};

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub fn canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

pub fn digest(value: &Value) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(canonical_string(value).as_bytes())
    )
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn key_order_and_whitespace_do_not_change_the_digest() {
        let a: Value = serde_json::from_str(r#"{"b": [1, {"d": 2, "c": 3}], "a": "x"}"#).unwrap();
        let b = json!({"a": "x", "b": [1, {"c": 3, "d": 2}]});
        assert_eq!(digest(&a), digest(&b));
        assert_eq!(canonical_string(&b), r#"{"a":"x","b":[1,{"c":3,"d":2}]}"#);
        assert_ne!(
            digest(&b),
            digest(&json!({"a": "y", "b": [1, {"c": 3, "d": 2}]}))
        );
    }
}
