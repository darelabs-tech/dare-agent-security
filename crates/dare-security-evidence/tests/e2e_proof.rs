//! End-to-end Cycle 001 proof. Adds no product capability.

mod common;

use dare_security_evidence::{
    apply_derived_verdict, validate, validate_instance, ComparisonResult, Decision, EvidenceError,
    ExactOutcomeComparator, OutcomeComparator, SchemaVersion, Verdict,
};
use serde_json::json;

#[test]
fn e2e_synthetic_vector_to_round_trip() {
    let mut evidence = common::load_evidence("fail.json");
    evidence.verdict = Verdict::Pass;
    apply_derived_verdict(&mut evidence);
    assert_eq!(evidence.verdict, Verdict::Fail);

    validate(&evidence).expect("semantic");
    let encoded = serde_json::to_value(&evidence).expect("serialize");
    validate_instance(&encoded).expect("schema offline");
    let decoded = serde_json::from_value(encoded).expect("deserialize");
    validate(&decoded).expect("semantic again");
    assert_eq!(evidence, decoded);
}

#[test]
fn e2e_v1_validates() {
    common::assert_fixture("pass.json", Verdict::Pass);
}

#[test]
fn e2e_unknown_major_fails_closed() {
    let mut evidence = common::load_evidence("pass.json");
    evidence.schema.version = SchemaVersion::new(2, 0, 0);
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::UnsupportedSchemaVersion { found_major: 2, .. })
    ));
}

#[test]
fn e2e_contradictory_verdict_rejected() {
    let mut evidence = common::load_evidence("fail.json");
    evidence.verdict = Verdict::Pass;
    assert!(matches!(
        validate(&evidence),
        Err(EvidenceError::VerdictConsistency { .. })
    ));
}

#[test]
fn e2e_secret_material_rejected() {
    let mut evidence = common::load_evidence("pass.json");
    let mut map = std::collections::BTreeMap::new();
    const MARKER: &str = "sk_synth_example_not_real";
    map.insert("api_key".to_owned(), json!(MARKER));
    evidence.operation.as_mut().unwrap().attributes = Some(map);
    let err = validate(&evidence).unwrap_err();
    assert!(matches!(err, EvidenceError::RedactionViolation { .. }));
    assert!(!err.to_string().contains(MARKER));
}

#[test]
fn e2e_verdict_fixtures_keep_semantics() {
    let pass = common::load_evidence("pass.json");
    let fail = common::load_evidence("fail.json");
    let inconclusive = common::load_evidence("inconclusive.json");
    let error = common::load_evidence("error.json");

    let cmp = ExactOutcomeComparator;
    assert_eq!(
        cmp.compare(&pass.expected, &pass.observed),
        ComparisonResult::Match
    );
    assert_eq!(
        cmp.compare(&fail.expected, &fail.observed),
        ComparisonResult::Mismatch
    );
    assert_eq!(inconclusive.verdict, Verdict::Inconclusive);
    assert_ne!(inconclusive.verdict, Verdict::Pass);
    assert_eq!(error.verdict, Verdict::Error);
    assert_ne!(error.verdict, Verdict::Pass);
    assert_ne!(error.verdict, Verdict::Fail);
    assert!(error.observed.description.is_some());
}

#[test]
fn e2e_no_mcp_types_in_public_api_surface() {
    let pass = common::load_evidence("pass.json");
    let encoded = serde_json::to_string(&pass).unwrap().to_lowercase();
    for token in ["authzen", "coaz", "mcp-tool", "jsonrpc"] {
        assert!(
            !encoded.contains(token),
            "generic fixture must not require {token}"
        );
    }
    let _ = Decision::Deny;
}

#[test]
fn e2e_ci_workflow_matches_local_gates() {
    let ci = std::fs::read_to_string(common::repo_root().join(".github/workflows/ci.yml"))
        .expect("ci workflow");
    for gate in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
    ] {
        assert!(ci.contains(gate), "CI missing gate: {gate}");
    }
}

#[test]
fn e2e_schema_and_docs_exist() {
    assert!(common::repo_file_exists(
        "schemas/evidence/v1/evidence.schema.json"
    ));
    assert!(common::repo_file_exists(
        "crates/dare-security-evidence/README.md"
    ));
    assert!(common::repo_file_exists("examples/evidence/pass.json"));
}
