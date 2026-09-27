//! Canonical bytes and digests.
//!
//! Values are serialized through `serde_json::Value`, whose map is a
//! `BTreeMap` in this workspace (no crate enables `preserve_order`), so object
//! keys are always sorted. Collections whose order carries no meaning are
//! sorted by their callers before digesting.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{MultiTurnError, Result};

/// Compact JSON bytes with sorted object keys.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| MultiTurnError::Serialization {
        kind: "canonical value",
    })?;
    serde_json::to_vec(&value).map_err(|_| MultiTurnError::Serialization {
        kind: "canonical bytes",
    })
}

/// `sha256:<hex>` over raw bytes.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// `sha256:<hex>` over a value's canonical bytes.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(digest_bytes(&canonical_bytes(value)?))
}

/// Whether `value` is a well-formed `sha256:` digest.
pub fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_the_digest() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).expect("json");
        let b: serde_json::Value =
            serde_json::from_str(r#"{"a":{"x":3,"y":2},"b":1}"#).expect("json");
        assert_eq!(digest(&a).expect("digest"), digest(&b).expect("digest"));
    }

    #[test]
    fn digests_are_well_formed_and_the_shape_check_is_strict() {
        let d = digest(&json!({"k": "v"})).expect("digest");
        assert!(is_digest(&d));
        for bad in ["sha256:", "sha1:00", &d.to_uppercase(), &format!("{d}0")] {
            assert!(!is_digest(bad), "`{bad}`");
        }
    }
}
