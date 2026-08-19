//! Semantic validation for vector execution results.

use crate::enforcement::validate_verdict_consistency;
use crate::error::IntegrityError;
use crate::result::{RedactionStrategy, VectorResult};
use crate::result_schema::{validate_result_instance, SUPPORTED_RESULT_SCHEMA_MAJOR};
use crate::secret_safety::validate_result_secret_safety;
use crate::version::SchemaVersion;

/// Validate a vector result structurally and semantically.
pub fn validate_result(result: &VectorResult) -> Result<(), IntegrityError> {
    let json = serde_json::to_value(result).map_err(|_| IntegrityError::Serialization {
        kind: "result-json".to_owned(),
    })?;
    validate_result_instance(&json)?;
    validate_result_schema_version(result.schema_version)?;
    validate_result_identifiers(result)?;
    validate_standards_present(result)?;
    validate_timestamps(result)?;
    validate_digests(result)?;
    validate_redaction(&result.redaction)?;
    validate_verdict_consistency(result.expected.enforcement, result.observed, result.verdict)?;
    validate_result_secret_safety(result)?;
    Ok(())
}

/// Parse JSON, validate structurally and semantically, and deserialize.
pub fn parse_and_validate_result(json: &str) -> Result<VectorResult, IntegrityError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| IntegrityError::Serialization {
            kind: "result-json".to_owned(),
        })?;
    validate_result_instance(&value)?;
    let result: VectorResult =
        serde_json::from_value(value).map_err(|_| IntegrityError::Serialization {
            kind: "result-model".to_owned(),
        })?;
    validate_result(&result)?;
    Ok(result)
}

fn validate_result_schema_version(version: SchemaVersion) -> Result<(), IntegrityError> {
    if version.major != SUPPORTED_RESULT_SCHEMA_MAJOR {
        return Err(IntegrityError::UnsupportedSchemaVersion {
            found: Some(version),
            found_major: version.major,
            supported_major: SUPPORTED_RESULT_SCHEMA_MAJOR,
        });
    }
    Ok(())
}

fn non_empty(label: &str, value: &str) -> Result<(), IntegrityError> {
    if value.trim().is_empty() {
        return Err(IntegrityError::semantic(
            label,
            "required identifier must be non-empty",
        ));
    }
    Ok(())
}

fn validate_result_identifiers(result: &VectorResult) -> Result<(), IntegrityError> {
    non_empty("vector_id", &result.vector_id)?;
    non_empty(
        "initial_decision.decision_id",
        &result.initial_decision.decision_id,
    )?;
    Ok(())
}

fn validate_standards_present(result: &VectorResult) -> Result<(), IntegrityError> {
    if result.standards.references.is_empty() {
        return Err(IntegrityError::semantic(
            "standards.references",
            "standards metadata must include at least one reference",
        ));
    }
    Ok(())
}

fn validate_timestamps(result: &VectorResult) -> Result<(), IntegrityError> {
    if result.started_at > result.finished_at {
        return Err(IntegrityError::semantic(
            "timestamps",
            "started_at must be less than or equal to finished_at",
        ));
    }
    Ok(())
}

fn validate_sha256(prefix: &str, digest: &str) -> Result<(), IntegrityError> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(IntegrityError::semantic(
            prefix,
            "digest must be 64 lowercase hexadecimal characters",
        ));
    }
    if digest.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(IntegrityError::semantic(
            prefix,
            "digest must use lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn validate_digests(result: &VectorResult) -> Result<(), IntegrityError> {
    validate_sha256("initial_binding.digest", &result.initial_binding.digest)?;
    validate_sha256("final_binding.digest", &result.final_binding.digest)?;
    validate_sha256(
        "initial_projection.mapping.digest",
        &result.initial_projection.mapping.digest,
    )?;
    if let Some(digest) = &result.sink_receipt.params_digest {
        validate_sha256("sink_receipt.params_digest", digest)?;
    }
    Ok(())
}

fn validate_redaction(redaction: &crate::result::RedactionMetadata) -> Result<(), IntegrityError> {
    match (
        redaction.applied,
        redaction.strategy,
        redaction.fields.is_empty(),
    ) {
        (false, RedactionStrategy::NoneRequired, true) => Ok(()),
        (false, RedactionStrategy::NoneRequired, false) => Err(IntegrityError::secret(
            "redaction.fields",
            "NONE_REQUIRED must not list redacted fields",
        )),
        (true, RedactionStrategy::NoneRequired, _) => Err(IntegrityError::secret(
            "redaction.strategy",
            "NONE_REQUIRED means no redaction was required",
        )),
        (false, _, _) => Err(IntegrityError::secret(
            "redaction.applied",
            "non-NONE_REQUIRED strategy requires applied=true",
        )),
        (true, _, true) => Err(IntegrityError::secret(
            "redaction.fields",
            "applied redaction must name at least one field path",
        )),
        (true, _, false) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{sample_vector_result_pass, sample_vector_result_stale_permit_fail};
    use crate::result::{IntegrityVerdict, ObservedEnforcement};
    use crate::vector::ExpectedEnforcement;
    use crate::version::SchemaVersion;

    #[test]
    fn sample_pass_result_is_semantically_valid() {
        validate_result(&sample_vector_result_pass()).expect("sample pass");
    }

    #[test]
    fn sample_stale_permit_fail_is_semantically_valid() {
        validate_result(&sample_vector_result_stale_permit_fail()).expect("sample fail");
    }

    #[test]
    fn unsupported_major_fails_closed() {
        let mut result = sample_vector_result_pass();
        result.schema_version = SchemaVersion::new(2, 0, 0);
        let err = validate_result(&result).unwrap_err();
        assert!(matches!(
            err,
            IntegrityError::UnsupportedSchemaVersion { found_major: 2, .. }
        ));
    }

    #[test]
    fn incoherent_verdict_rejected() {
        let mut result = sample_vector_result_pass();
        result.expected.enforcement = ExpectedEnforcement::ReevaluateOrRefuse;
        result.observed = ObservedEnforcement::ForwardedWithExistingPermit;
        result.verdict = IntegrityVerdict::Pass;
        assert!(matches!(
            validate_result(&result),
            Err(IntegrityError::VerdictConsistency { .. })
        ));
    }

    #[test]
    fn round_trip_json() {
        let original = sample_vector_result_pass();
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let parsed = parse_and_validate_result(&json).expect("parse");
        assert_eq!(parsed, original);
    }
}
