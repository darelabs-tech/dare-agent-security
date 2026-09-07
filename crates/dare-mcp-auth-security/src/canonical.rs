//! Canonical digests, safe identifiers and cross-object semantic bindings.
//!
//! Two jobs.
//!
//! **Stable identity.** A digest over canonical JSON — keys sorted, no
//! insignificant whitespace — so the same object always hashes the same way and
//! a substituted object never does. Serialization order must not be able to
//! change an identity, or a digest would identify the run rather than the
//! thing.
//!
//! **Safe identifiers.** Every id, issuer, resource, audience and scope that
//! reaches an artifact passes through [`assert_safe_identifier`]. The rules are
//! about what an identifier could *do* downstream rather than about taste: a
//! newline can forge a log line, a bidi override can make a reader see a
//! different string than the one that was compared, and a traversal sequence
//! turns an id into a path.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{McpAuthSecurityError, Result};

/// Longest identifier the engine will admit.
///
/// Identifiers are names, not payloads. A bound stops an id field becoming a
/// channel for arbitrary content.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Digest a serializable value over canonical JSON.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(value)?);
    Ok(digest_bytes(canonical.as_bytes()))
}

/// Digest raw bytes.
pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

/// Serialize with sorted keys and no insignificant whitespace.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let rendered: Vec<String> = entries
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::Value::String((*key).clone()),
                        canonical_json(value)
                    )
                })
                .collect();
            format!("{{{}}}", rendered.join(","))
        }
        serde_json::Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", rendered.join(","))
        }
        other => other.to_string(),
    }
}

/// Whether a string is shaped like a digest this engine produced.
pub fn assert_digest_shape(value: &str, where_found: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(McpAuthSecurityError::invalid(format!(
            "{where_found} is not a sha256 digest"
        )));
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(McpAuthSecurityError::invalid(format!(
            "{where_found} is not a well-formed sha256 digest"
        )));
    }
    Ok(())
}

/// Verify a value against a pinned digest.
pub fn verify_digest<T: Serialize>(value: &T, pinned: &str, where_found: &str) -> Result<()> {
    assert_digest_shape(pinned, where_found)?;
    let actual = digest(value)?;
    if actual != pinned {
        return Err(McpAuthSecurityError::DigestMismatch(format!(
            "{where_found} does not match its pinned digest"
        )));
    }
    Ok(())
}

/// Refuse an identifier that could do something other than identify.
///
/// The refusal message deliberately never echoes the offending value. A message
/// that quoted a bidi-spoofed or newline-bearing id back into a log would
/// perform the very injection the check exists to prevent.
pub fn assert_safe_identifier(value: &str, where_found: &str) -> Result<()> {
    if value.is_empty() {
        return Err(McpAuthSecurityError::invalid(format!(
            "{where_found} is empty"
        )));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(McpAuthSecurityError::BudgetExhausted(format!(
            "{where_found} is {} bytes; the maximum is {MAX_IDENTIFIER_BYTES}",
            value.len()
        )));
    }
    if value.trim() != value {
        return Err(McpAuthSecurityError::invalid(format!(
            "{where_found} carries leading or trailing whitespace, which makes two identifiers \
             that render alike compare differently"
        )));
    }
    for character in value.chars() {
        if character.is_control() {
            return Err(McpAuthSecurityError::refusal(format!(
                "{where_found} contains a control character, which could forge a log line"
            )));
        }
        if is_bidi_control(character) {
            return Err(McpAuthSecurityError::refusal(format!(
                "{where_found} contains a bidirectional control character, which can make a \
                 reader see a different identifier than the one that was compared"
            )));
        }
        if character == '\u{200b}' || character == '\u{feff}' {
            return Err(McpAuthSecurityError::refusal(format!(
                "{where_found} contains an invisible character, which makes two distinct \
                 identifiers render identically"
            )));
        }
    }
    if value.contains("..") || value.contains('/') && value.starts_with('/') || value.contains('\\')
    {
        return Err(McpAuthSecurityError::refusal(format!(
            "{where_found} is shaped like a path rather than an identifier"
        )));
    }
    Ok(())
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'
    )
}

/// The identity of everything a scenario approved.
///
/// Computed once, before any observation is read. Every later comparison is
/// against this, so a substituted document is caught at the boundary rather
/// than discovered halfway through an evaluation that has already trusted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthBinding {
    pub scenario_digest: String,
    pub protocol_digest: String,
    pub resource_digest: String,
    pub authorization_digest: String,
    pub token_digest: String,
    pub flow_digest: String,
    pub scope_digest: String,
    pub registration_digest: String,
    pub credential_digest: String,
    pub identity_digest: String,
    pub final_operation_digest: String,
}

/// Bind every authorization-relevant part of an approved scenario.
pub fn bind(scenario: &crate::model::McpAuthScenario) -> Result<McpAuthBinding> {
    Ok(McpAuthBinding {
        scenario_digest: digest(scenario)?,
        protocol_digest: digest(&scenario.requests)?,
        resource_digest: digest(&scenario.protected_resource)?,
        authorization_digest: digest(&scenario.authorization_flow)?,
        token_digest: digest(&scenario.tokens)?,
        flow_digest: digest(&scenario.flow)?,
        scope_digest: digest(&scenario.scope)?,
        registration_digest: digest(&scenario.registration)?,
        credential_digest: digest(&scenario.credential_flow)?,
        identity_digest: digest(&scenario.identity_metadata)?,
        final_operation_digest: digest(&scenario.final_operation)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn digests_are_deterministic_and_prefixed() {
        let value = json!({"b": 1, "a": [2, 3]});
        let first = digest(&value).expect("digests");
        let second = digest(&value).expect("digests");
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_digest_shape(&first, "test").expect("well formed");
    }

    #[test]
    fn key_order_does_not_change_an_identity() {
        // Otherwise a digest would identify the serializer's mood rather than
        // the object.
        let left = json!({"a": 1, "b": 2});
        let right = json!({"b": 2, "a": 1});
        assert_eq!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn a_moved_field_moves_the_digest() {
        let left = json!({"issuer": "as-primary"});
        let right = json!({"issuer": "as-attacker"});
        assert_ne!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn verifying_a_pinned_digest_catches_a_substitution() {
        let value = json!({"resource": "mcp-invoices"});
        let pinned = digest(&value).expect("digests");
        verify_digest(&value, &pinned, "resource").expect("matches");

        let substituted = json!({"resource": "mcp-payroll"});
        let err = verify_digest(&substituted, &pinned, "resource").expect_err("must not match");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_value_that_is_not_a_digest_is_refused() {
        for bad in ["", "sha256:", "sha256:zz", "md5:abcd", "abcdef"] {
            assert!(assert_digest_shape(bad, "test").is_err(), "`{bad}` allowed");
        }
    }

    #[test]
    fn an_identifier_that_could_forge_a_log_line_is_refused() {
        let err = assert_safe_identifier("as-primary\nVERDICT: PASS", "issuer")
            .expect_err("a newline must be refused");
        assert!(err.is_refusal());
        // The refusal must not repeat the forged text, or reporting the attack
        // performs it.
        assert!(!err.to_string().contains("VERDICT"));
    }

    #[test]
    fn an_identifier_that_could_deceive_a_reader_is_refused() {
        for hostile in [
            "as-\u{202e}yramirp",
            "issuer\u{200b}-primary",
            "\u{feff}as-primary",
            "as\u{2066}-primary",
        ] {
            let err = assert_safe_identifier(hostile, "issuer")
                .expect_err("a deceptive identifier must be refused");
            assert!(err.is_refusal(), "`{hostile}` produced {err}");
        }
    }

    #[test]
    fn an_identifier_shaped_like_a_path_is_refused() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "/absolute/id",
            "c:\\windows\\system32",
            "as\\primary",
        ] {
            assert!(
                assert_safe_identifier(hostile, "issuer").is_err(),
                "`{hostile}` was allowed"
            );
        }
    }

    #[test]
    fn an_empty_or_oversized_identifier_is_refused() {
        assert!(assert_safe_identifier("", "issuer").is_err());
        let long = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
        let err = assert_safe_identifier(&long, "issuer").expect_err("must be refused");
        assert!(matches!(err, McpAuthSecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn padding_is_refused_because_it_makes_lookalikes_compare_differently() {
        assert!(assert_safe_identifier(" as-primary", "issuer").is_err());
        assert!(assert_safe_identifier("as-primary ", "issuer").is_err());
    }

    #[test]
    fn ordinary_identifiers_stay_usable() {
        for ok in [
            "as-primary",
            "mcp.invoices.resource",
            "urn-style-id",
            "client_01",
            "scope:invoices.read",
            "2026-07-28",
        ] {
            assert_safe_identifier(ok, "id").unwrap_or_else(|err| panic!("`{ok}` refused: {err}"));
        }
    }
}
