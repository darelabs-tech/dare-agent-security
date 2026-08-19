use std::fs;
use std::path::PathBuf;

use dare_mcp_discovery::{
    validate, validate_instance, Completeness, DiscoveryInventory, INVENTORY_SCHEMA_V1_JSON,
};
use serde_json::Value;

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

const FIXTURES: &[&str] = &["complete.json", "partial.json"];

#[test]
fn public_fixtures_round_trip() {
    for name in FIXTURES {
        let original = load_json(name);
        validate_instance(&original).expect("schema");
        let first: DiscoveryInventory = serde_json::from_value(original.clone()).expect("decode");
        validate(&first).expect("semantic");
        let encoded = serde_json::to_value(&first).expect("encode");
        validate_instance(&encoded).expect("re-schema");
        let second: DiscoveryInventory = serde_json::from_value(encoded).expect("re-decode");
        validate(&second).expect("re-semantic");
        assert_eq!(first, second, "{name} lost semantics on round-trip");
    }
}

#[test]
fn fixture_completeness_matches_file_names() {
    let complete: DiscoveryInventory =
        serde_json::from_value(load_json("complete.json")).expect("complete");
    let partial: DiscoveryInventory =
        serde_json::from_value(load_json("partial.json")).expect("partial");
    assert_eq!(complete.completeness, Completeness::Complete);
    assert_eq!(partial.completeness, Completeness::Partial);
    assert_eq!(complete.target.id, "synthetic-rental-mcp");
    assert_eq!(complete.protocol.revision, "2026-07-28");
    assert!(complete
        .tools
        .iter()
        .any(|tool| tool.name == "legacy.ambiguous"
            && tool
                .classification
                .as_ref()
                .is_some_and(|c| c.class == dare_mcp_discovery::OperationClass::Unknown)));
    assert!(!partial.warnings.is_empty());
}

#[test]
fn fixtures_are_synthetic() {
    for name in FIXTURES {
        let dumped = load_json(name).to_string().to_lowercase();
        for forbidden in ["nexora", "acme-prod", "password=", "bearer "] {
            assert!(
                !dumped.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
}

#[test]
fn schema_file_matches_embedded_copy() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/discovery/v1/inventory.schema.json");
    let disk = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    assert_eq!(
        disk.replace("\r\n", "\n"),
        INVENTORY_SCHEMA_V1_JSON.replace("\r\n", "\n")
    );
}
