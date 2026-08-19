use std::fs;
use std::path::PathBuf;

use dare_mcp_discovery::{
    validate, validate_instance, Completeness, DiscoveryInventory, InventoryError,
    InventorySchemaVersion, WarningCode,
};
use serde_json::{json, Value};

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/discovery")
}

fn load_json(name: &str) -> Value {
    let path = examples_dir().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!("{} is not valid JSON: {err}", path.display());
    })
}

fn load_inventory(name: &str) -> DiscoveryInventory {
    serde_json::from_value(load_json(name)).expect("deserialize fixture")
}

#[test]
fn missing_target_identifier_fails() {
    let mut value = load_json("complete.json");
    value["target"]
        .as_object_mut()
        .expect("target")
        .remove("id");
    assert!(
        validate_instance(&value).is_err(),
        "schema must reject missing target.id"
    );
    assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
}

#[test]
fn empty_tool_name_fails_semantically() {
    let mut inventory = load_inventory("complete.json");
    inventory.tools[0].name = "   ".to_owned();
    let err = validate(&inventory).expect_err("must fail");
    match err {
        InventoryError::SemanticValidation { invariant, .. } => {
            assert!(invariant.contains("name"));
        }
        other => panic!("unexpected {other}"),
    }
}

#[test]
fn invalid_version_string_fails() {
    let mut value = load_json("complete.json");
    value["schema"]["version"] = json!("v1");
    assert!(validate_instance(&value).is_err());
    assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
}

#[test]
fn unsupported_major_version_fails_closed() {
    let mut inventory = load_inventory("complete.json");
    inventory.schema.version = InventorySchemaVersion::new(9, 0, 0);
    assert!(matches!(
        validate(&inventory),
        Err(InventoryError::UnsupportedSchemaVersion { found_major: 9, .. })
    ));
}

#[test]
fn incoherent_complete_with_limit_warning_fails() {
    let mut inventory = load_inventory("complete.json");
    assert_eq!(inventory.completeness, Completeness::Complete);
    inventory
        .warnings
        .push(dare_mcp_discovery::DiscoveryWarning {
            code: WarningCode::PaginationLimitReached,
            message: "page bound reached".to_owned(),
        });
    assert!(matches!(
        validate(&inventory),
        Err(InventoryError::SemanticValidation { invariant, .. }) if invariant == "completeness"
    ));
}

#[test]
fn malformed_digest_fails_structurally() {
    let mut value = load_json("complete.json");
    value["hashes"][0]["digest"] = json!("zzzz");
    assert!(validate_instance(&value).is_err());
}

#[test]
fn malformed_timestamp_fails_structurally() {
    let mut value = load_json("complete.json");
    value["generated_at"] = json!("yesterday");
    let err = validate_instance(&value).expect_err("must fail");
    assert!(!err.to_string().contains("yesterday"));
    assert!(serde_json::from_value::<DiscoveryInventory>(value.clone()).is_err());
}

#[test]
fn unknown_enum_fails() {
    let mut value = load_json("complete.json");
    value["transport"]["kind"] = json!("TCP");
    assert!(validate_instance(&value).is_err());
    assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
}

#[test]
fn unknown_top_level_field_fails() {
    let mut value = load_json("complete.json");
    value
        .as_object_mut()
        .expect("object")
        .insert("customer_tenant".to_owned(), json!("acme"));
    assert!(validate_instance(&value).is_err());
    assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
}

#[test]
fn forbidden_credential_field_names_fail_without_echo() {
    for field in [
        "password",
        "token",
        "authorization",
        "api_key",
        "private_key",
    ] {
        let mut value = load_json("complete.json");
        const MARKER: &str = "synth-secret-value-not-real";
        value
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), json!(MARKER));
        let schema_err = validate_instance(&value).expect_err("schema must reject {field}");
        assert!(
            !schema_err.to_string().contains(MARKER),
            "schema error echoed rejected secret"
        );
        let decode_err = serde_json::from_value::<DiscoveryInventory>(value)
            .expect_err("serde must reject {field}");
        assert!(
            !decode_err.to_string().contains(MARKER),
            "serde error echoed rejected secret"
        );
    }
}
