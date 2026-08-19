//! Local JSON Schema loader for the v1 discovery inventory contract.
//!
//! The repository copy is normative. Validation never fetches the `$id` URL.

use serde_json::Value;

use crate::inventory_error::InventoryError;

/// Canonical schema identifier stored in inventory `schema.id`.
pub const INVENTORY_SCHEMA_ID: &str = "https://darelabs.tech/schemas/discovery";

/// Canonical `$id` for discovery inventory schema v1.
pub const INVENTORY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/discovery/v1/inventory.schema.json";

/// Embedded schema document. Kept in sync with `schemas/discovery/v1/inventory.schema.json`.
pub const INVENTORY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/discovery/v1/inventory.schema.json");

/// Parse the committed v1 schema document.
pub fn inventory_schema_v1() -> Result<Value, InventoryError> {
    serde_json::from_str(INVENTORY_SCHEMA_V1_JSON).map_err(|_| InventoryError::Serialization {
        kind: "schema-json".to_owned(),
    })
}

/// Path to the committed schema file relative to the crate manifest.
pub fn inventory_schema_v1_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/discovery/v1/inventory.schema.json")
}

/// Compile and validate `instance` against the local v1 schema.
///
/// Format assertions (including `date-time`) are enabled. No remote retrieval
/// is configured; `$id` is treated as an identifier only.
///
/// Error messages include JSON Pointer paths and reason codes only. Rejected
/// instance values are never copied into the error.
pub fn validate_instance(instance: &Value) -> Result<(), InventoryError> {
    let schema = inventory_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|_| InventoryError::StructuralValidation {
            path: "/".to_owned(),
            reason: "schema compilation failed".to_owned(),
        })?;

    if validator.is_valid(instance) {
        return Ok(());
    }

    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(InventoryError::StructuralValidation {
            path: err.instance_path().to_string(),
            reason: "schema constraint failed".to_owned(),
        }),
        None => Err(InventoryError::StructuralValidation {
            path: "/".to_owned(),
            reason: "instance failed schema validation".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::sample_complete_inventory;
    use serde_json::{json, Value};

    fn sample_json() -> Value {
        serde_json::to_value(sample_complete_inventory()).expect("sample json")
    }

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(inventory_schema_v1_path()).expect("read schema");
        assert_eq!(
            disk.replace("\r\n", "\n"),
            INVENTORY_SCHEMA_V1_JSON.replace("\r\n", "\n")
        );
    }

    #[test]
    fn schema_self_validates_as_object() {
        let schema = inventory_schema_v1().expect("parse schema");
        assert_eq!(schema["$id"], json!(INVENTORY_SCHEMA_V1_ID));
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
        value.as_object_mut().expect("object").remove("target");
        let err = validate_instance(&value).expect_err("must fail");
        match err {
            InventoryError::StructuralValidation { .. } => {}
            other => panic!("expected structural error, got {other}"),
        }
    }

    #[test]
    fn invalid_completeness_enum_fails() {
        let mut value = sample_json();
        value["completeness"] = json!("DONE");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn malformed_digest_fails() {
        let mut value = sample_json();
        value["hashes"][0]["digest"] = json!("not-hex");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn unknown_top_level_field_fails() {
        let mut value = sample_json();
        value
            .as_object_mut()
            .expect("object")
            .insert("customer_tenant".to_owned(), json!("acme"));
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn malformed_timestamp_fails() {
        let mut value = sample_json();
        value["generated_at"] = json!("yesterday");
        assert!(validate_instance(&value).is_err());
    }

    #[test]
    fn structural_errors_do_not_echo_instance_values() {
        let mut value = sample_json();
        const MARKER: &str = "Bearer SYNTHETIC.not-real";
        value["generated_at"] = json!(MARKER);
        let err = validate_instance(&value).expect_err("must fail");
        assert!(!err.to_string().contains(MARKER));
    }
}
