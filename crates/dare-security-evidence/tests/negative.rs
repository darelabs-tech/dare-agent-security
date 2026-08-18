mod common;

use dare_security_evidence::{validate, validate_instance, EvidenceError, SecurityEvidence};
use serde_json::json;
use time::Duration;

#[test]
fn unsupported_major_version_fails_closed() {
    let mut evidence = common::load_evidence("pass.json");
    evidence.schema.version = dare_security_evidence::SchemaVersion::new(9, 0, 0);
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::UnsupportedSchemaVersion { found_major: 9, .. })
    ));
}

#[test]
fn missing_vector_identifier_fails() {
    let mut value = common::load_json("pass.json");
    value["vector"].as_object_mut().unwrap().remove("id");
    assert!(
        validate_instance(&value).is_err(),
        "schema must reject missing vector.id"
    );
}

#[test]
fn contradictory_pass_fails_for_consistency() {
    let mut evidence = common::load_evidence("fail.json");
    evidence.verdict = dare_security_evidence::Verdict::Pass;
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::VerdictConsistency { .. })
    ));
}

#[test]
fn error_without_context_fails_semantically() {
    let mut evidence = common::load_evidence("error.json");
    evidence.observed.description = None;
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::SemanticValidation { invariant, .. }) if invariant == "verdict.ERROR"
    ));
}

#[test]
fn invalid_timestamp_ordering_fails() {
    let mut evidence = common::load_evidence("pass.json");
    evidence.timestamps.recorded_at = evidence.timestamps.observed_at - Duration::seconds(5);
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::SemanticValidation { invariant, .. }) if invariant == "timestamps"
    ));
}

#[test]
fn raw_authorization_content_is_rejected_without_echo() {
    let mut evidence = common::load_evidence("pass.json");
    let mut map = std::collections::BTreeMap::new();
    const MARKER: &str = "Bearer SYNTHETIC.not-real";
    map.insert("Authorization".to_owned(), json!(MARKER));
    evidence.operation.as_mut().unwrap().attributes = Some(map);
    let err = validate(&evidence).unwrap_err();
    assert!(matches!(err, EvidenceError::RedactionViolation { .. }));
    assert!(!err.to_string().contains(MARKER));
}

#[test]
fn invalid_verdict_enum_fails_structurally() {
    let mut value = common::load_json("pass.json");
    value["verdict"] = json!("SUCCESS");
    assert!(validate_instance(&value).is_err());
    assert!(serde_json::from_value::<SecurityEvidence>(value).is_err());
}

#[test]
fn malformed_digest_fails_structurally() {
    let mut value = common::load_json("pass.json");
    value["hashes"][0]["value"] = json!("zzzz");
    assert!(validate_instance(&value).is_err());
}

#[test]
fn forbidden_unknown_top_level_field_fails() {
    let mut value = common::load_json("pass.json");
    value
        .as_object_mut()
        .unwrap()
        .insert("customer_tenant".to_owned(), json!("acme"));
    assert!(validate_instance(&value).is_err());
}
