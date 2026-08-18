mod common;

use dare_security_evidence::{validate, validate_instance, SecurityEvidence, Verdict};
use serde_json::Value;

const FIXTURES: &[&str] = &["pass.json", "fail.json", "inconclusive.json", "error.json"];

#[test]
fn public_fixtures_round_trip() {
    for name in FIXTURES {
        let original = common::load_json(name);
        validate_instance(&original).expect("schema");
        let first: SecurityEvidence = serde_json::from_value(original.clone()).expect("decode");
        validate(&first).expect("semantic");
        let encoded = serde_json::to_value(&first).expect("encode");
        validate_instance(&encoded).expect("re-schema");
        let second: SecurityEvidence = serde_json::from_value(encoded).expect("re-decode");
        validate(&second).expect("re-semantic");
        assert_eq!(first, second, "{name} lost semantics on round-trip");
    }
}

#[test]
fn fixture_verdicts_match_file_names() {
    assert_eq!(common::load_evidence("pass.json").verdict, Verdict::Pass);
    assert_eq!(common::load_evidence("fail.json").verdict, Verdict::Fail);
    assert_eq!(
        common::load_evidence("inconclusive.json").verdict,
        Verdict::Inconclusive
    );
    assert_eq!(common::load_evidence("error.json").verdict, Verdict::Error);
}

#[test]
fn fixtures_are_synthetic() {
    for name in FIXTURES {
        let dumped = common::load_json(name).to_string().to_lowercase();
        for forbidden in ["nexora", "customer", "acme-prod", "password=", "bearer "] {
            assert!(
                !dumped.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
}

#[test]
fn round_trip_json_value_pipeline() {
    let json: Value = common::load_json("fail.json");
    let evidence: SecurityEvidence = serde_json::from_value(json).unwrap();
    let again = serde_json::to_vec(&evidence).unwrap();
    let decoded: SecurityEvidence = serde_json::from_slice(&again).unwrap();
    assert_eq!(decoded.verdict, Verdict::Fail);
}
