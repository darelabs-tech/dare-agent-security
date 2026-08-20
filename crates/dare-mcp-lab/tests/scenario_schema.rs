//! Cycle 005 task-002: scenario manifest schema acceptance tests.

use dare_mcp_lab::{
    assert_safety_policy, load_scenario_file, parse_scenario, sample_scenario_passive_boundary,
    validate_scenario, validate_scenario_instance, ScenarioManifest, SCENARIO_SCHEMA_V1_ID,
};
use serde_json::{json, Value};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sample_json() -> Value {
    serde_json::to_value(sample_scenario_passive_boundary()).expect("sample json")
}

#[test]
fn valid_manifest_passes_schema_and_semantics() {
    let sample = sample_scenario_passive_boundary();
    validate_scenario(&sample).expect("valid");
    let path = repo_root().join("labs/scenarios/MCP-LAB-001/scenario.json");
    let loaded = load_scenario_file(&path).expect("load fixture");
    assert_eq!(loaded.id, "MCP-LAB-001");
    assert_eq!(loaded.schema.id, SCENARIO_SCHEMA_V1_ID);
}

#[test]
fn missing_required_field_fails() {
    let mut value = sample_json();
    value.as_object_mut().unwrap().remove("family");
    assert!(validate_scenario_instance(&value).is_err());
}

#[test]
fn unknown_verdict_fails() {
    let mut value = sample_json();
    value["variants"]["secure"]["expected"]["verdict"] = json!("MAYBE");
    assert!(validate_scenario_instance(&value).is_err());
}

#[test]
fn invalid_standards_status_fails() {
    let mut value = sample_json();
    value["standards"][0]["status"] = json!("GUESS");
    assert!(validate_scenario_instance(&value).is_err());
}

#[test]
fn external_network_declaration_is_refused() {
    let mut sample = sample_scenario_passive_boundary();
    sample.safety.external_network = true;
    let err = assert_safety_policy(&sample).expect_err("must refuse");
    assert!(err.to_string().contains("external_network"));
    let value = serde_json::to_value(&sample).unwrap();
    // Schema allows the boolean; semantic safety policy refuses it.
    assert!(validate_scenario_instance(&value).is_ok());
    assert!(validate_scenario(&sample).is_err());
}

#[test]
fn real_credentials_declaration_is_refused() {
    let mut sample = sample_scenario_passive_boundary();
    sample.safety.real_credentials = true;
    assert!(parse_scenario(&serde_json::to_string(&sample).unwrap()).is_err());
}

#[test]
fn typed_round_trip_preserves_verdict_vocabulary() {
    let raw = serde_json::to_string_pretty(&sample_scenario_passive_boundary()).unwrap();
    let parsed: ScenarioManifest = parse_scenario(&raw).unwrap();
    assert_eq!(
        parsed.variants.secure.expected.verdict,
        dare_security_evidence::Verdict::Pass
    );
    assert_eq!(
        parsed.variants.vulnerable.expected.verdict,
        dare_security_evidence::Verdict::Fail
    );
}
