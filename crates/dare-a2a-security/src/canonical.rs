//! Canonical digests and safe identifiers.
//!
//! Two jobs. The first is turning a value into a digest that is stable across
//! runs and machines, so "the same message" means the same thing tomorrow.
//! The second is refusing identifiers that could deceive whoever reads them.
//!
//! The second matters more than it looks. Agent ids, skill names, tenant ids
//! and task ids come out of documents somebody else wrote, and they end up in
//! logs, in reports and next to each other in tables. An identifier carrying a
//! newline can forge a log line; one carrying a right-to-left override renders
//! as a different name than it compares as. Neither is a parsing problem — both
//! parse fine — and both are ways of making a reader believe something the data
//! does not say.
//!
//! For an authority-bearing identifier that is not cosmetic. Two tenant ids
//! that render identically and compare differently are two tenants an operator
//! believes are one.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{A2aSecurityError, Result};

/// Longest identifier this engine will accept.
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Digest a serializable value with a canonical key order.
///
/// Every model in this crate uses ordered collections for exactly this reason:
/// two captures that mean the same thing must digest the same, or a message
/// binding cannot be checked at all.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| A2aSecurityError::Serialization {
        kind: "canonical-digest",
    })?;
    Ok(digest_bytes(&bytes))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Whether a string is a well-formed `sha256:`-prefixed digest.
pub fn assert_digest_shape(value: &str, where_found: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(A2aSecurityError::invalid(format!(
            "{where_found} is not a sha256-prefixed digest"
        )));
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(A2aSecurityError::invalid(format!(
            "{where_found} is not a 64-character hexadecimal digest"
        )));
    }
    Ok(())
}

/// Recompute a value's digest and compare it against a pinned one.
pub fn verify_digest<T: Serialize>(value: &T, pinned: &str, where_found: &str) -> Result<()> {
    assert_digest_shape(pinned, where_found)?;
    let actual = digest(value)?;
    if actual != pinned {
        return Err(A2aSecurityError::BindingMismatch(format!(
            "{where_found} does not match its pinned digest"
        )));
    }
    Ok(())
}

/// Refuse an identifier that could deceive a reader or escape a directory.
///
/// The rules, and what each one is for:
///
/// - **empty** identifies nothing;
/// - **oversized** is a log-flooding surface;
/// - **control characters** forge log lines;
/// - **bidirectional and invisible characters** render differently from how
///   they compare, which for a tenant id means two tenants an operator believes
///   are one;
/// - **leading or trailing whitespace** is a duplicate-identity trap that costs
///   nothing to close;
/// - **path shapes** escape a directory;
/// - **URL shapes** belong in a reference field, where they are inert, and
///   never in an identity.
pub fn assert_safe_identifier(value: &str, where_found: &str) -> Result<()> {
    if value.is_empty() {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} is empty and identifies nothing"
        )));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} is longer than {MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} carries a control character, which could forge a log line"
        )));
    }
    if value.chars().any(is_bidi_or_invisible) {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} carries a bidirectional or invisible character, so it would render \
             differently from how it compares"
        )));
    }
    if value.trim() != value {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} has leading or trailing whitespace, which reads as one identifier \
             and compares as another"
        )));
    }
    if value.contains("..")
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(":\\")
    {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} is shaped like a path"
        )));
    }
    if value.contains("://") {
        return Err(A2aSecurityError::refusal(format!(
            "{where_found} is shaped like a URL; a location belongs in a reference field, \
             where it is inert, and never in an identity"
        )));
    }
    Ok(())
}

fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_stable_and_key_order_independent() {
        use std::collections::BTreeMap;
        let left: BTreeMap<&str, u8> = BTreeMap::from([("a", 1), ("b", 2)]);
        let right: BTreeMap<&str, u8> = BTreeMap::from([("b", 2), ("a", 1)]);
        assert_eq!(digest(&left).unwrap(), digest(&right).unwrap());
        assert_eq!(digest(&left).unwrap(), digest(&left).unwrap());
    }

    #[test]
    fn a_digest_shape_is_checked_before_it_is_trusted() {
        assert!(assert_digest_shape(&digest_bytes(b"x"), "a digest").is_ok());
        assert!(assert_digest_shape("sha256:short", "a digest").is_err());
        assert!(assert_digest_shape("deadbeef", "a digest").is_err());
        assert!(assert_digest_shape(&format!("sha256:{}", "z".repeat(64)), "a digest").is_err());
    }

    #[test]
    fn a_pinned_digest_that_does_not_match_is_a_binding_mismatch() {
        let value = serde_json::json!({ "task": "t-1" });
        assert!(verify_digest(&value, &digest(&value).unwrap(), "a task").is_ok());
        assert!(verify_digest(&value, &digest_bytes(b"other"), "a task").is_err());
    }

    #[test]
    fn a_control_character_is_refused_because_it_forges_a_log_line() {
        assert!(assert_safe_identifier("agent\nWARN: approved", "an agent id").is_err());
        assert!(assert_safe_identifier("agent\ttab", "an agent id").is_err());
    }

    #[test]
    fn a_bidi_override_is_refused_because_it_renders_as_another_identity() {
        // For a tenant id this is not cosmetic: two ids that render identically
        // and compare differently are two tenants an operator believes are one.
        assert!(assert_safe_identifier("tenant\u{202E}evil", "a tenant id").is_err());
        assert!(assert_safe_identifier("tenant\u{200B}hidden", "a tenant id").is_err());
    }

    #[test]
    fn whitespace_padding_is_refused_as_a_duplicate_identity_trap() {
        assert!(assert_safe_identifier(" planner", "an agent id").is_err());
        assert!(assert_safe_identifier("planner ", "an agent id").is_err());
    }

    #[test]
    fn a_path_or_url_shape_is_refused_in_an_identity() {
        for hostile in [
            "../../etc/passwd",
            "/absolute/agent",
            "C:\\agents\\planner",
            "https://peer.example/agent",
        ] {
            assert!(
                assert_safe_identifier(hostile, "an agent id").is_err(),
                "`{hostile}` was accepted as an identity"
            );
        }
    }

    #[test]
    fn ordinary_identifiers_stay_usable() {
        // The control. A rule that refused real identifiers would be turned off
        // by the first person who hit it.
        for ordinary in [
            "planner-agent",
            "urn:agent:planner",
            "tenant_42",
            "skill.summarize.v2",
            "task-9f3c1a",
            "did:example:123456",
        ] {
            assert_safe_identifier(ordinary, "an identifier")
                .unwrap_or_else(|error| panic!("`{ordinary}` was refused: {error}"));
        }
    }

    #[test]
    fn a_refusal_never_echoes_what_it_refused() {
        // An error log is a persistence surface. A message quoting a smuggled
        // value back would store the thing it declined to store.
        let hostile = "tenant\u{202E}not-a-real-secret";
        let error = assert_safe_identifier(hostile, "a tenant id").expect_err("refused");
        assert!(!error.to_string().contains("not-a-real-secret"));
    }
}
