//! Redaction metadata and contract-level secret-safety checks.
//!
//! Heuristics are defense-in-depth. They are not a complete secret discovery
//! capability and must not be documented as such.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::EvidenceError;
use crate::model::SecurityEvidence;

/// How sensitive values were handled before serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedactionStrategy {
    /// Producer verified that no sensitive value required redaction.
    NoneRequired,
    /// Sensitive values were removed.
    Remove,
    /// Sensitive values were masked.
    Mask,
    /// Sensitive values were replaced with hashes.
    Hash,
    /// Sensitive values were replaced with tokens.
    Tokenize,
    /// More than one strategy was applied.
    Mixed,
}

/// Mandatory redaction declaration on every evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionMetadata {
    /// Whether any redaction transform was applied to this record.
    pub applied: bool,
    /// Strategy used (or `NONE_REQUIRED` when none was needed).
    pub strategy: RedactionStrategy,
    /// Field paths that were redacted. Empty when `NONE_REQUIRED`.
    #[serde(default)]
    pub fields: Vec<String>,
}

const HIGH_RISK_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "authorization",
];

/// Validate internal coherence of redaction metadata.
pub fn validate_redaction_metadata(meta: &RedactionMetadata) -> Result<(), EvidenceError> {
    match (meta.applied, meta.strategy, meta.fields.is_empty()) {
        (false, RedactionStrategy::NoneRequired, true) => Ok(()),
        (false, RedactionStrategy::NoneRequired, false) => Err(EvidenceError::redaction(
            "redaction.fields",
            "NONE_REQUIRED must not list redacted fields",
        )),
        (true, RedactionStrategy::NoneRequired, _) => Err(EvidenceError::redaction(
            "redaction.strategy",
            "NONE_REQUIRED means no redaction was required, not that redaction was skipped",
        )),
        (false, _, _) => Err(EvidenceError::redaction(
            "redaction.applied",
            "non-NONE_REQUIRED strategy requires applied=true",
        )),
        (true, _, true) => Err(EvidenceError::redaction(
            "redaction.fields",
            "applied redaction must name at least one field path",
        )),
        (true, _, false) => Ok(()),
    }
}

/// Scan supported generic maps for high-risk keys and secret-like values.
///
/// Rejected values are never copied into the returned error.
pub fn validate_secret_safety(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    if let Some(operation) = &evidence.operation {
        if let Some(attrs) = &operation.attributes {
            scan_map("operation.attributes", attrs)?;
        }
    }
    if let Some(ctx) = &evidence.authorization_context {
        if let Some(attrs) = &ctx.context_attributes {
            scan_map("authorization_context.context_attributes", attrs)?;
        }
    }
    if let Some(extensions) = &evidence.extensions {
        scan_map("extensions", extensions)?;
    }
    Ok(())
}

fn scan_map(location: &str, map: &BTreeMap<String, Value>) -> Result<(), EvidenceError> {
    for (key, value) in map {
        if is_high_risk_key(key) {
            return Err(EvidenceError::redaction(
                location,
                "high-risk key name is not permitted in generic maps",
            ));
        }
        match value {
            Value::String(raw) if looks_secret_like(raw) => {
                return Err(EvidenceError::redaction(
                    location,
                    "secret-like value is not permitted in generic maps",
                ));
            }
            Value::Object(nested) => {
                let nested_map = nested
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>();
                scan_map(location, &nested_map)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn normalize_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

fn is_high_risk_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    HIGH_RISK_KEYS
        .iter()
        .any(|needle| normalized == *needle || normalized.ends_with(needle))
}

fn looks_secret_like(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("bearer ")
        || (lower.contains("begin ") && lower.contains("private key"))
        || trimmed.starts_with("eyj")
        || trimmed.starts_with("eyJ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample_evidence;
    use crate::validation::validate;
    use serde_json::json;

    #[test]
    fn redaction_strategy_wire_tokens() {
        assert_eq!(
            serde_json::to_value(RedactionStrategy::NoneRequired).unwrap(),
            json!("NONE_REQUIRED")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::Remove).unwrap(),
            json!("REMOVE")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::Mask).unwrap(),
            json!("MASK")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::Hash).unwrap(),
            json!("HASH")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::Tokenize).unwrap(),
            json!("TOKENIZE")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::Mixed).unwrap(),
            json!("MIXED")
        );
    }

    #[test]
    fn redaction_strategy_rejects_unknown_values() {
        assert!(serde_json::from_str::<RedactionStrategy>("\"SKIPPED\"").is_err());
    }

    #[test]
    fn redaction_metadata_round_trips() {
        let meta = RedactionMetadata {
            applied: false,
            strategy: RedactionStrategy::NoneRequired,
            fields: Vec::new(),
        };
        let json = serde_json::to_value(&meta).unwrap();
        let back: RedactionMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn none_required_rejects_applied_true() {
        let mut evidence = sample_evidence();
        evidence.redaction.applied = true;
        let err = validate(&evidence).unwrap_err();
        assert!(matches!(err, EvidenceError::RedactionViolation { .. }));
    }

    fn assert_secret_blocked(mutate: impl FnOnce(&mut SecurityEvidence), marker: &str) {
        let mut evidence = sample_evidence();
        mutate(&mut evidence);
        let err = validate(&evidence).unwrap_err();
        let rendered = err.to_string();
        assert!(
            matches!(err, EvidenceError::RedactionViolation { .. }),
            "expected redaction violation, got {err}"
        );
        assert!(
            !rendered.contains(marker),
            "error leaked rejected material: {rendered}"
        );
    }

    #[test]
    fn bearer_like_token_value_is_rejected_without_echo() {
        const MARKER: &str = "Bearer SYNTHETIC.not-a-real-token";
        assert_secret_blocked(
            |evidence| {
                let mut map = BTreeMap::new();
                map.insert("note".to_owned(), json!(MARKER));
                evidence.operation.as_mut().unwrap().attributes = Some(map);
            },
            MARKER,
        );
    }

    #[test]
    fn password_field_is_rejected_without_echo() {
        const MARKER: &str = "synth-password-value-001";
        assert_secret_blocked(
            |evidence| {
                let mut map = BTreeMap::new();
                map.insert("password".to_owned(), json!(MARKER));
                evidence
                    .authorization_context
                    .as_mut()
                    .unwrap()
                    .context_attributes = Some(map);
            },
            MARKER,
        );
    }

    #[test]
    fn api_key_field_is_rejected_without_echo() {
        const MARKER: &str = "sk_synth_example_not_real";
        assert_secret_blocked(
            |evidence| {
                let mut map = BTreeMap::new();
                map.insert("api_key".to_owned(), json!(MARKER));
                evidence.operation.as_mut().unwrap().attributes = Some(map);
            },
            MARKER,
        );
    }

    #[test]
    fn private_key_field_is_rejected_without_echo() {
        const MARKER: &str = "-----BEGIN PRIVATE KEY-----SYNTH-----END PRIVATE KEY-----";
        assert_secret_blocked(
            |evidence| {
                let mut map = BTreeMap::new();
                map.insert("private_key".to_owned(), json!(MARKER));
                evidence.operation.as_mut().unwrap().attributes = Some(map);
            },
            MARKER,
        );
    }

    #[test]
    fn authorization_header_like_field_is_rejected_without_echo() {
        const MARKER: &str = "Bearer SYNTHETIC";
        assert_secret_blocked(
            |evidence| {
                let mut map = BTreeMap::new();
                map.insert("Authorization".to_owned(), json!(MARKER));
                evidence.operation.as_mut().unwrap().attributes = Some(map);
            },
            MARKER,
        );
    }

    #[test]
    fn safe_non_secret_metadata_is_accepted() {
        let mut evidence = sample_evidence();
        let mut map = BTreeMap::new();
        map.insert("locale".to_owned(), json!("en-US"));
        map.insert("lab".to_owned(), json!("synthetic-payment"));
        evidence.operation.as_mut().unwrap().attributes = Some(map);
        validate(&evidence).expect("safe metadata");
    }
}
