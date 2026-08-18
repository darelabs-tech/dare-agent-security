//! Local JSON Schema loader for the v1 evidence contract.
//!
//! The repository copy is normative. Validation never fetches the `$id` URL.

use serde_json::Value;

use crate::error::EvidenceError;

/// Canonical `$id` for evidence schema v1.
pub const EVIDENCE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/evidence.schema.json";

/// Embedded schema document. Kept in sync with `schemas/evidence/v1/evidence.schema.json`.
pub const EVIDENCE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/evidence/v1/evidence.schema.json");

/// Parse the committed v1 schema document.
pub fn evidence_schema_v1() -> Result<Value, EvidenceError> {
    serde_json::from_str(EVIDENCE_SCHEMA_V1_JSON).map_err(|_| EvidenceError::Serialization {
        kind: "schema-json".to_owned(),
    })
}

/// Path to the committed schema file relative to the crate manifest.
pub fn evidence_schema_v1_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/evidence/v1/evidence.schema.json")
}

/// Compile and validate `instance` against the local v1 schema.
///
/// Format assertions (including `date-time`) are enabled. No remote retrieval
/// is configured; `$id` is treated as an identifier only.
pub fn validate_instance(instance: &Value) -> Result<(), EvidenceError> {
    let schema = evidence_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| EvidenceError::StructuralValidation {
            path: "/".to_owned(),
            reason: compact_schema_error(&err.to_string()),
        })?;

    if validator.is_valid(instance) {
        return Ok(());
    }

    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(EvidenceError::StructuralValidation {
            path: err.instance_path().to_string(),
            reason: compact_schema_error(&err.to_string()),
        }),
        None => Err(EvidenceError::StructuralValidation {
            path: "/".to_owned(),
            reason: "instance failed schema validation".to_owned(),
        }),
    }
}

fn compact_schema_error(message: &str) -> String {
    const MAX: usize = 240;
    let cleaned: String = message.chars().take(MAX).collect();
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample_evidence;
    use serde_json::{json, Value};

    fn sample_json() -> Value {
        serde_json::to_value(sample_evidence()).expect("sample json")
    }

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(evidence_schema_v1_path()).expect("read schema");
        assert_eq!(
            disk.replace("\r\n", "\n"),
            EVIDENCE_SCHEMA_V1_JSON.replace("\r\n", "\n")
        );
    }

    #[test]
    fn schema_self_validates_as_object() {
        let schema = evidence_schema_v1().expect("parse schema");
        assert_eq!(schema["$id"], json!(EVIDENCE_SCHEMA_V1_ID));
        assert_eq!(schema["additionalProperties"], json!(false));
        jsonschema::options()
            .build(&schema)
            .expect("schema compiles locally");
    }

    #[test]
    fn minimal_valid_record_passes() {
        validate_instance(&sample_json()).expect("sample must pass schema");
    }

    #[test]
    fn missing_required_field_fails() {
        let mut value = sample_json();
        value.as_object_mut().unwrap().remove("vector");
        let err = validate_instance(&value).unwrap_err();
        match err {
            EvidenceError::StructuralValidation { .. } => {}
            other => panic!("expected structural error, got {other}"),
        }
    }

    #[test]
    fn invalid_verdict_enum_fails() {
        let mut value = sample_json();
        value["verdict"] = json!("MAYBE");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn malformed_digest_fails() {
        let mut value = sample_json();
        value["hashes"][0]["value"] = json!("not-hex");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn unknown_top_level_field_fails() {
        let mut value = sample_json();
        value
            .as_object_mut()
            .unwrap()
            .insert("customer_tenant".to_owned(), json!("acme"));
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn malformed_timestamp_fails() {
        let mut value = sample_json();
        value["timestamps"]["observed_at"] = json!("yesterday");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn schema_defines_no_credential_fields() {
        let raw = EVIDENCE_SCHEMA_V1_JSON.to_lowercase();
        for forbidden in ["password", "api_key", "private_key", "bearer", "secret"] {
            assert!(
                !raw.contains(forbidden),
                "schema document must not define {forbidden}"
            );
        }
    }
}
