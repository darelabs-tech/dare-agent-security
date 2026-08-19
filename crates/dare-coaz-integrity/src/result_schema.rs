//! Local JSON Schema loader for the v1 vector result contract.

use serde_json::Value;

use crate::error::IntegrityError;

/// Canonical `$id` for result schema v1.
pub const RESULT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/vectors/coaz-integrity/v1/result.schema.json";

/// Embedded schema document. Kept in sync with `schemas/vectors/coaz-integrity/v1/result.schema.json`.
pub const RESULT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/vectors/coaz-integrity/v1/result.schema.json");

/// Supported result contract major version for this crate release.
pub const SUPPORTED_RESULT_SCHEMA_MAJOR: u64 = 1;

pub fn result_schema_v1() -> Result<Value, IntegrityError> {
    serde_json::from_str(RESULT_SCHEMA_V1_JSON).map_err(|_| IntegrityError::Serialization {
        kind: "result-schema-json".to_owned(),
    })
}

pub fn result_schema_v1_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/vectors/coaz-integrity/v1/result.schema.json")
}

pub fn validate_result_instance(instance: &Value) -> Result<(), IntegrityError> {
    let schema = result_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|_| IntegrityError::StructuralValidation {
            path: "/".to_owned(),
            reason: "schema compilation failed".to_owned(),
        })?;

    if validator.is_valid(instance) {
        return Ok(());
    }

    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(IntegrityError::StructuralValidation {
            path: err.instance_path().to_string(),
            reason: "schema constraint failed".to_owned(),
        }),
        None => Err(IntegrityError::StructuralValidation {
            path: "/".to_owned(),
            reason: "instance failed schema validation".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::sample_vector_result_pass;
    use crate::vector_schema::assert_schema_defines_no_credential_property_names;
    use serde_json::{json, Value};

    fn sample_json() -> Value {
        serde_json::to_value(sample_vector_result_pass()).expect("sample json")
    }

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(result_schema_v1_path()).expect("read schema");
        assert_eq!(
            disk.replace("\r\n", "\n"),
            RESULT_SCHEMA_V1_JSON.replace("\r\n", "\n")
        );
    }

    #[test]
    fn schema_self_validates_as_object() {
        let schema = result_schema_v1().expect("parse schema");
        assert_eq!(schema["$id"], json!(RESULT_SCHEMA_V1_ID));
        assert_eq!(schema["additionalProperties"], json!(false));
        jsonschema::options()
            .build(&schema)
            .expect("schema compiles locally");
    }

    #[test]
    fn minimal_valid_result_passes() {
        validate_result_instance(&sample_json()).expect("sample must pass schema");
    }

    #[test]
    fn missing_required_field_fails() {
        let mut value = sample_json();
        value.as_object_mut().unwrap().remove("verdict");
        assert!(validate_result_instance(&value).is_err());
    }

    #[test]
    fn invalid_verdict_enum_fails() {
        let mut value = sample_json();
        value["verdict"] = json!("MAYBE");
        assert!(validate_result_instance(&value).is_err());
    }

    #[test]
    fn malformed_timestamp_fails() {
        let mut value = sample_json();
        value["finished_at"] = json!("yesterday");
        assert!(validate_result_instance(&value).is_err());
    }

    #[test]
    fn schema_defines_no_credential_fields() {
        let schema = result_schema_v1().expect("parse schema");
        assert_schema_defines_no_credential_property_names(&schema);
    }
}
