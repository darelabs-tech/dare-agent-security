//! Cycle 001 evidence bridge: vector results emit valid, round-trippable records.

use std::fs;
use std::path::PathBuf;

use dare_coaz_integrity::{
    emit_integrity_evidence, execute_builtin_vector, parse_and_validate_result,
    sample_vector_result_harness_error, sample_vector_result_inconclusive,
    sample_vector_result_pass, sample_vector_result_stale_permit_fail, EmitOptions,
    EvidenceBridgeError, RunOptions, EXTENSION_KEY,
};
use dare_security_evidence::{SecurityEvidence, Verdict};
use serde_json::Value;
use time::macros::datetime;

const CANARY_URL_USER: &str = "canaryUser_7f3a";
const CANARY_URL_PASS: &str = "canaryPass_7f3a";
const CANARY_BEARER: &str = "canaryBearer_7f3a";

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/coaz-integrity")
}

fn evidence_examples_dir() -> PathBuf {
    examples_dir().join("evidence")
}

fn load_result_fixture(relative: &str) -> dare_coaz_integrity::VectorResult {
    let path = examples_dir().join(relative);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    parse_and_validate_result(&raw).unwrap_or_else(|err| {
        panic!("{relative} is not a valid result JSON: {err}");
    })
}

fn emit_options_for(
    result: &dare_coaz_integrity::VectorResult,
    artifact_path: &str,
) -> EmitOptions {
    EmitOptions::deterministic_for_result(result).with_result_artifact_path(artifact_path)
}

fn assert_valid_round_trip(evidence: &SecurityEvidence) {
    dare_security_evidence::validate(evidence).expect("semantic validate");
    let json = serde_json::to_value(evidence).expect("serialize");
    dare_security_evidence::validate_instance(&json).expect("schema validate_instance");
    let decoded: SecurityEvidence = serde_json::from_value(json.clone()).expect("deserialize");
    dare_security_evidence::validate(&decoded).expect("round-trip semantic");
    let json2 = serde_json::to_value(&decoded).expect("serialize again");
    assert_eq!(json, json2);
    assert_eq!(
        json["schema"]["id"],
        Value::String("https://darelabs.tech/schemas/evidence".to_owned())
    );
    assert_eq!(json["schema"]["version"], Value::String("1.0.0".to_owned()));
    let extensions = json["extensions"].as_object().expect("extensions object");
    assert!(
        extensions.keys().all(|key| key.contains('.')),
        "extension keys must be namespaced: {extensions:?}"
    );
    assert!(extensions.contains_key(EXTENSION_KEY));
    assert!(json["hashes"][0]["value"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())));
}

fn assert_no_canary(label: &str, value: &Value) {
    let rendered = value.to_string();
    for canary in [CANARY_URL_USER, CANARY_URL_PASS, CANARY_BEARER] {
        assert!(
            !rendered.contains(canary),
            "{label} leaked canary `{canary}`: {rendered}"
        );
    }
}

#[test]
fn pass_fixture_emits_valid_pass_evidence() {
    let result = load_result_fixture("secure/result-pass-v1.json");
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/secure/result-pass-v1.json",
        ),
    )
    .expect("emit");
    assert_eq!(evidence.vector.id, "COAZ-INTEGRITY-001");
    assert_eq!(evidence.verdict, Verdict::Pass);
    assert_valid_round_trip(&evidence);
}

#[test]
fn fail_fixture_emits_valid_fail_evidence() {
    let result = load_result_fixture("vulnerable/result-stale-permit-fail-v1.json");
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json",
        ),
    )
    .expect("emit");
    assert_eq!(evidence.vector.id, "COAZ-INTEGRITY-003");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert!(evidence.severity.is_some());
    assert_valid_round_trip(&evidence);
}

#[test]
fn inconclusive_sample_emits_valid_inconclusive_evidence() {
    let result = sample_vector_result_inconclusive();
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/evidence/inconclusive-source.json",
        ),
    )
    .expect("emit");
    assert_eq!(evidence.verdict, Verdict::Inconclusive);
    assert_valid_round_trip(&evidence);
}

#[test]
fn error_sample_emits_valid_error_evidence() {
    let result = sample_vector_result_harness_error();
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/evidence/error-source.json",
        ),
    )
    .expect("emit");
    assert_eq!(evidence.verdict, Verdict::Error);
    assert_valid_round_trip(&evidence);
}

#[test]
fn builtin_vector_execution_emits_pass_evidence() {
    let result = execute_builtin_vector("COAZ-INTEGRITY-001", &RunOptions::default()).expect("run");
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json",
        ),
    )
    .expect("emit");
    assert_eq!(evidence.verdict, Verdict::Pass);
    assert_valid_round_trip(&evidence);
}

#[test]
fn stale_permit_sample_maps_to_fail_not_pass() {
    let result = sample_vector_result_stale_permit_fail();
    let evidence =
        emit_integrity_evidence(&result, &EmitOptions::deterministic_for_result(&result))
            .expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
}

#[test]
fn pass_sample_matches_checked_in_example_fixture() {
    let result = sample_vector_result_pass();
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/secure/result-pass-v1.json",
        ),
    )
    .expect("emit");
    let fixture_path = evidence_examples_dir().join("pass.json");
    let fixture_raw = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "missing checked-in fixture {}: {err}",
            fixture_path.display()
        );
    });
    let fixture: SecurityEvidence =
        serde_json::from_str(&fixture_raw).expect("fixture deserialize");
    assert_eq!(evidence.verdict, fixture.verdict);
    assert_eq!(evidence.vector.id, fixture.vector.id);
    assert_valid_round_trip(&fixture);
}

#[test]
fn fail_sample_matches_checked_in_example_fixture() {
    let result = sample_vector_result_stale_permit_fail();
    let evidence = emit_integrity_evidence(
        &result,
        &emit_options_for(
            &result,
            "examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json",
        ),
    )
    .expect("emit");
    let fixture_path = evidence_examples_dir().join("fail.json");
    let fixture: SecurityEvidence =
        serde_json::from_str(&fs::read_to_string(&fixture_path).expect("read fail fixture"))
            .expect("fixture deserialize");
    assert_eq!(evidence.verdict, fixture.verdict);
    assert_eq!(evidence.vector.id, fixture.vector.id);
    assert_valid_round_trip(&fixture);
}

#[test]
fn redaction_fail_does_not_copy_raw_credentials() {
    let mut result = sample_vector_result_stale_permit_fail();
    let canary_url = format!("https://{CANARY_URL_USER}:{CANARY_URL_PASS}@mcp.example.test/mcp");
    result.initial_operation.params["name"] = Value::String(format!(
        "rental.quote Authorization: Bearer {CANARY_BEARER}"
    ));
    result.mutation.detail = Some(canary_url.clone());
    result.redaction.applied = true;
    result.redaction.strategy = dare_coaz_integrity::RedactionStrategy::Mask;
    result.redaction.fields = vec!["mutation.detail".to_owned()];

    let evidence =
        emit_integrity_evidence(&result, &EmitOptions::deterministic_for_result(&result))
            .expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
    let json = serde_json::to_value(&evidence).expect("json");
    assert_no_canary("fail evidence", &json);
}

#[test]
fn invalid_timestamps_are_rejected() {
    let result = sample_vector_result_pass();
    let options = EmitOptions {
        result_artifact_path: None,
        recorded_at: datetime!(2026-08-19 11:00:00 UTC),
    };
    let err = emit_integrity_evidence(&result, &options).expect_err("timestamps");
    assert_eq!(err, EvidenceBridgeError::InvalidTimestamps);
}

#[test]
fn coaz_details_stay_in_namespaced_extensions() {
    let result = sample_vector_result_pass();
    let evidence =
        emit_integrity_evidence(&result, &EmitOptions::deterministic_for_result(&result))
            .expect("emit");
    let json = serde_json::to_value(&evidence).expect("json");
    let top = json.as_object().expect("object");
    assert!(!top.contains_key("coaz"));
    assert!(!top.contains_key("reference_mode"));
    assert!(json["extensions"][EXTENSION_KEY]["reference_mode"].is_string());
    assert_eq!(
        json["extensions"][EXTENSION_KEY]["vector_id"],
        Value::String("COAZ-INTEGRITY-001".to_owned())
    );
}

#[test]
fn evidence_crate_domain_is_untouched_by_this_module() {
    let manifest = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dare-security-evidence/Cargo.toml"
    ));
    assert!(!manifest.contains("dare-coaz-integrity"));
}
