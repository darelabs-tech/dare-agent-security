//! Local JSON Schema loader for the v1 vector definition contract.

use serde_json::Value;

use crate::error::IntegrityError;

/// Canonical `$id` for vector schema v1.
pub const VECTOR_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/vectors/coaz-integrity/v1/vector.schema.json";

/// Embedded schema document. Kept in sync with `schemas/vectors/coaz-integrity/v1/vector.schema.json`.
pub const VECTOR_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/vectors/coaz-integrity/v1/vector.schema.json");

/// Supported vector contract major version for this crate release.
pub const SUPPORTED_VECTOR_SCHEMA_MAJOR: u64 = 1;

pub fn vector_schema_v1() -> Result<Value, IntegrityError> {
    serde_json::from_str(VECTOR_SCHEMA_V1_JSON).map_err(|_| IntegrityError::Serialization {
        kind: "vector-schema-json".to_owned(),
    })
}

pub fn vector_schema_v1_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/vectors/coaz-integrity/v1/vector.schema.json")
}

pub fn validate_vector_instance(instance: &Value) -> Result<(), IntegrityError> {
    let schema = vector_schema_v1()?;
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

pub fn assert_schema_defines_no_credential_property_names(schema: &Value) {
    let forbidden = [
        "password",
        "api_key",
        "private_key",
        "bearer",
        "access_token",
    ];
    let mut property_maps = Vec::new();
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        property_maps.push(("root", props));
    }
    if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
        for (def_name, def) in defs {
            if let Some(props) = def.get("properties").and_then(Value::as_object) {
                property_maps.push((def_name.as_str(), props));
            }
        }
    }
    for (scope, props) in property_maps {
        for key in props.keys() {
            let normalized = key.to_ascii_lowercase();
            for term in forbidden {
                assert!(
                    !normalized.contains(term),
                    "schema {scope} must not define property {key}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::sample_vector_definition;
    use serde_json::{json, Value};

    fn sample_json() -> Value {
        serde_json::to_value(sample_vector_definition()).expect("sample json")
    }

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(vector_schema_v1_path()).expect("read schema");
        assert_eq!(
            disk.replace("\r\n", "\n"),
            VECTOR_SCHEMA_V1_JSON.replace("\r\n", "\n")
        );
    }

    #[test]
    fn schema_self_validates_as_object() {
        let schema = vector_schema_v1().expect("parse schema");
        assert_eq!(schema["$id"], json!(VECTOR_SCHEMA_V1_ID));
        assert_eq!(schema["additionalProperties"], json!(false));
        jsonschema::options()
            .build(&schema)
            .expect("schema compiles locally");
    }

    #[test]
    fn minimal_valid_vector_passes() {
        validate_vector_instance(&sample_json()).expect("sample must pass schema");
    }

    #[test]
    fn missing_required_field_fails() {
        let mut value = sample_json();
        value.as_object_mut().unwrap().remove("vector_id");
        assert!(validate_vector_instance(&value).is_err());
    }

    #[test]
    fn invalid_expected_enforcement_fails() {
        let mut value = sample_json();
        value["expected"]["enforcement"] = json!("MAYBE");
        assert!(validate_vector_instance(&value).is_err());
    }

    #[test]
    fn secret_bearing_property_name_fails_schema() {
        let mut value = sample_json();
        value["trusted_context"]["claims"]["access_token"] = json!("SYNTHETIC.not-real");
        let err = validate_vector_instance(&value).expect_err("must fail");
        assert!(matches!(err, IntegrityError::StructuralValidation { .. }));
        assert!(!err.to_string().contains("SYNTHETIC"));
    }

    #[test]
    fn schema_defines_no_credential_fields() {
        let schema = vector_schema_v1().expect("parse schema");
        assert_schema_defines_no_credential_property_names(&schema);
    }
}
