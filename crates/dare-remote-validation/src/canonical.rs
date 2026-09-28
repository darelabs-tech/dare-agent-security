//! Canonical bytes and digests.
//!
//! Values are serialized through `serde_json::Value`, whose map is a
//! `BTreeMap` in this workspace (no crate enables `preserve_order`), so object
//! keys are always sorted. The same construction as the Cycle 021 crate, so a
//! digest computed here and one computed by an engine agree.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{RemoteError, Result};

/// Compact JSON bytes with sorted object keys.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value =
        serde_json::to_value(value).map_err(|_| RemoteError::Serialization("canonical value"))?;
    serde_json::to_vec(&value).map_err(|_| RemoteError::Serialization("canonical bytes"))
}

/// `sha256:<hex>` over raw bytes.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// `sha256:<hex>` over a value's canonical bytes.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(digest_bytes(&canonical_bytes(value)?))
}

/// The first `n` hex characters of a digest, used for derived identifiers.
pub fn short_hex(bytes: &[u8], n: usize) -> String {
    let hex = format!("{:x}", Sha256::digest(bytes));
    hex[..n.min(hex.len())].to_owned()
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
        let a = json!({"b": 1, "a": {"y": 2, "x": 3}});
        let b = json!({"a": {"x": 3, "y": 2}, "b": 1});
        assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
    }

    #[test]
    fn digests_are_well_formed_and_the_shape_check_is_strict() {
        let d = digest_bytes(b"x");
        assert!(is_digest(&d));
        assert!(!is_digest(&d.to_uppercase()));
        assert!(!is_digest(&d[..70]));
        assert!(!is_digest(d.trim_start_matches("sha256:")));
        assert_eq!(short_hex(b"x", 16).len(), 16);
    }
}
