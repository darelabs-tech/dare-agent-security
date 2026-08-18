//! Semantic validation for evidence records.
//!
//! These checks are independent from JSON Schema and from serde. Unknown
//! schema majors fail closed.

use crate::comparison::validate_verdict_consistency;
use crate::error::EvidenceError;
use crate::model::{HashRef, SecurityEvidence};
use crate::redaction::{validate_redaction_metadata, validate_secret_safety};
use crate::verdict::Verdict;
use crate::version::SchemaVersion;

/// Supported evidence schema major version for this crate release.
pub const SUPPORTED_SCHEMA_MAJOR: u64 = 1;

/// Validate semantic invariants of a deserialized evidence record.
pub fn validate(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    validate_schema_version(evidence.schema.version)?;
    validate_identifiers(evidence)?;
    validate_timestamps(evidence)?;
    validate_hashes(evidence)?;
    validate_verdict_prerequisites(evidence)?;
    validate_verdict_consistency(evidence)?;
    validate_extensions(evidence)?;
    validate_redaction_metadata(&evidence.redaction)?;
    validate_secret_safety(evidence)?;
    Ok(())
}

fn validate_schema_version(version: SchemaVersion) -> Result<(), EvidenceError> {
    if version.major != SUPPORTED_SCHEMA_MAJOR {
        return Err(EvidenceError::UnsupportedSchemaVersion {
            found: Some(version),
            found_major: version.major,
            supported_major: SUPPORTED_SCHEMA_MAJOR,
        });
    }
    Ok(())
}

fn non_empty(label: &str, value: &str) -> Result<(), EvidenceError> {
    if value.trim().is_empty() {
        return Err(EvidenceError::semantic(
            label,
            "required identifier must be non-empty",
        ));
    }
    Ok(())
}

fn validate_identifiers(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    non_empty("schema.id", &evidence.schema.id)?;
    non_empty("id", &evidence.id)?;
    non_empty("vector.id", &evidence.vector.id)?;
    non_empty("vector.version", &evidence.vector.version)?;
    non_empty("target.type", &evidence.target.type_)?;
    non_empty("target.id", &evidence.target.id)?;
    if let Some(operation) = &evidence.operation {
        non_empty("operation.kind", &operation.kind)?;
        non_empty("operation.name", &operation.name)?;
    }
    Ok(())
}

fn validate_timestamps(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    let ts = &evidence.timestamps;
    if let Some(started) = ts.started_at {
        if started > ts.observed_at {
            return Err(EvidenceError::semantic(
                "timestamps",
                "started_at must be less than or equal to observed_at",
            ));
        }
    }
    if ts.observed_at > ts.recorded_at {
        return Err(EvidenceError::semantic(
            "timestamps",
            "observed_at must be less than or equal to recorded_at",
        ));
    }
    Ok(())
}

fn validate_hash(prefix: &str, hash: &HashRef) -> Result<(), EvidenceError> {
    let expected_len = match hash.algorithm.as_str() {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => {
            return Err(EvidenceError::semantic(
                prefix,
                "hash algorithm must be sha256, sha384, or sha512",
            ));
        }
    };
    if hash.value.len() != expected_len
        || !hash.value.bytes().all(|b| b.is_ascii_hexdigit())
        || hash.value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(EvidenceError::semantic(
            prefix,
            "hash digest must be lowercase hexadecimal with the length required by the algorithm",
        ));
    }
    Ok(())
}

fn validate_hashes(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    for (i, hash) in evidence.hashes.iter().enumerate() {
        validate_hash(&format!("hashes.{i}"), hash)?;
    }
    if let Some(operation) = &evidence.operation {
        if let Some(digest) = &operation.arguments_digest {
            validate_hash("operation.arguments_digest", digest)?;
        }
    }
    for (i, artifact) in evidence.artifacts.iter().enumerate() {
        if let Some(digest) = &artifact.digest {
            validate_hash(&format!("artifacts.{i}.digest"), digest)?;
        }
    }
    Ok(())
}

fn validate_verdict_prerequisites(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    match evidence.verdict {
        Verdict::Pass | Verdict::Fail => {
            if evidence.expected.decision.is_none() || evidence.observed.decision.is_none() {
                return Err(EvidenceError::VerdictConsistency {
                    reason: "PASS and FAIL require expected.decision and observed.decision".into(),
                });
            }
        }
        Verdict::Inconclusive => {
            let has_reason = evidence
                .expected
                .description
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
                || evidence
                    .observed
                    .description
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some();
            if !has_reason {
                return Err(EvidenceError::semantic(
                    "verdict.INCONCLUSIVE",
                    "INCONCLUSIVE requires an explicit description of insufficient evidence",
                ));
            }
        }
        Verdict::Error => match evidence.observed.description.as_deref().map(str::trim) {
            Some(text) if !text.is_empty() => {}
            _ => {
                return Err(EvidenceError::semantic(
                    "verdict.ERROR",
                    "ERROR requires observed.description with execution error context",
                ));
            }
        },
    }
    Ok(())
}

fn validate_extensions(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    let Some(extensions) = &evidence.extensions else {
        return Ok(());
    };
    for key in extensions.keys() {
        if !key.contains('.') {
            return Err(EvidenceError::semantic(
                "extensions",
                "extension keys must be namespaced with a '.'",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample_evidence;
    use crate::version::SchemaVersion;
    use time::macros::datetime;

    #[test]
    fn sample_v1_record_is_semantically_valid() {
        validate(&sample_evidence()).expect("sample");
    }

    #[test]
    fn accepts_compatible_1_x_versions() {
        let mut evidence = sample_evidence();
        evidence.schema.version = SchemaVersion::new(1, 4, 2);
        validate(&evidence).expect("1.x is compatible");
    }

    #[test]
    fn unsupported_major_fails_closed() {
        let mut evidence = sample_evidence();
        evidence.schema.version = SchemaVersion::new(2, 0, 0);
        let err = validate(&evidence).unwrap_err();
        match err {
            EvidenceError::UnsupportedSchemaVersion {
                found_major,
                supported_major,
                ..
            } => {
                assert_eq!(found_major, 2);
                assert_eq!(supported_major, 1);
            }
            other => panic!("unexpected {other}"),
        }
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn empty_semantic_ids_are_rejected() {
        let mut evidence = sample_evidence();
        evidence.vector.id = "   ".to_owned();
        let err = validate(&evidence).unwrap_err();
        match err {
            EvidenceError::SemanticValidation { invariant, .. } => {
                assert_eq!(invariant, "vector.id");
            }
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn invalid_timestamp_ordering_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.timestamps.observed_at = datetime!(2026-01-15 10:00:03 UTC);
        evidence.timestamps.recorded_at = datetime!(2026-01-15 10:00:02 UTC);
        assert!(matches!(
            validate(&evidence),
            Err(EvidenceError::SemanticValidation { .. })
        ));
    }

    #[test]
    fn incoherent_hash_metadata_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.hashes[0].value = "abcd".to_owned();
        assert!(matches!(
            validate(&evidence),
            Err(EvidenceError::SemanticValidation { .. })
        ));
    }

    #[test]
    fn error_without_context_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.verdict = Verdict::Error;
        evidence.observed.description = None;
        assert!(matches!(
            validate(&evidence),
            Err(EvidenceError::SemanticValidation { invariant, .. })
                if invariant == "verdict.ERROR"
        ));
    }

    #[test]
    fn typed_errors_are_displayable_without_payloads() {
        let err = EvidenceError::UnsupportedSchemaVersion {
            found: None,
            found_major: 9,
            supported_major: 1,
        };
        let text = err.to_string();
        assert!(text.contains("unsupported schema major version 9"));
        assert!(!text.contains('{'));
    }
}
