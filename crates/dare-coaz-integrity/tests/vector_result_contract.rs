//! Contract tests for vector/result portable contracts.

use dare_coaz_integrity::{
    parse_and_validate_result, parse_and_validate_vector, sample_vector_definition,
    sample_vector_result_pass, sample_vector_result_stale_permit_fail, validate_result,
    validate_vector, ExpectedEnforcement, IntegrityError, IntegrityVerdict, ObservedEnforcement,
    SchemaVersion,
};
use dare_coaz_integrity::{validate_result_instance, validate_vector_instance};

#[test]
fn secure_fixture_vector_round_trips_offline() {
    let vector = sample_vector_definition();
    validate_vector(&vector).expect("semantic validation");
    let json = serde_json::to_string_pretty(&vector).expect("serialize");
    std::fs::write(
        "../../examples/coaz-integrity/secure/vector-minimal-v1.json",
        &json,
    )
    .expect("write fixture");
    let value: serde_json::Value = serde_json::from_str(&json).expect("json");
    validate_vector_instance(&value).expect("schema validation");
    let parsed = parse_and_validate_vector(&json).expect("parse");
    assert_eq!(parsed, vector);
}

#[test]
fn secure_fixture_result_pass_round_trips_offline() {
    let result = sample_vector_result_pass();
    validate_result(&result).expect("semantic validation");
    let json = serde_json::to_string_pretty(&result).expect("serialize");
    std::fs::write(
        "../../examples/coaz-integrity/secure/result-pass-v1.json",
        &json,
    )
    .expect("write fixture");
    let value: serde_json::Value = serde_json::from_str(&json).expect("json");
    validate_result_instance(&value).expect("schema validation");
    let parsed = parse_and_validate_result(&json).expect("parse");
    assert_eq!(parsed, result);
}

#[test]
fn vulnerable_fixture_result_fail_round_trips_offline() {
    let result = sample_vector_result_stale_permit_fail();
    validate_result(&result).expect("semantic validation");
    let json = serde_json::to_string_pretty(&result).expect("serialize");
    std::fs::write(
        "../../examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json",
        &json,
    )
    .expect("write fixture");
    let parsed = parse_and_validate_result(&json).expect("parse");
    assert_eq!(parsed.verdict, IntegrityVerdict::Fail);
    assert_eq!(
        parsed.observed,
        ObservedEnforcement::ForwardedWithStalePermit
    );
}

#[test]
fn invalid_schema_major_rejected_for_vector_and_result() {
    let mut vector = sample_vector_definition();
    vector.schema_version = SchemaVersion::new(2, 0, 0);
    assert!(matches!(
        validate_vector(&vector),
        Err(IntegrityError::UnsupportedSchemaVersion { found_major: 2, .. })
    ));

    let mut result = sample_vector_result_pass();
    result.schema_version = SchemaVersion::new(2, 0, 0);
    assert!(matches!(
        validate_result(&result),
        Err(IntegrityError::UnsupportedSchemaVersion { found_major: 2, .. })
    ));
}

#[test]
fn missing_vector_id_rejected() {
    let mut value = serde_json::to_value(sample_vector_definition()).expect("json");
    value.as_object_mut().unwrap().remove("vector_id");
    assert!(validate_vector_instance(&value).is_err());
}

#[test]
fn missing_standards_rejected() {
    let mut vector = sample_vector_definition();
    vector.standards.references.clear();
    assert!(validate_vector(&vector).is_err());
}

#[test]
fn missing_expected_state_rejected() {
    let mut value = serde_json::to_value(sample_vector_definition()).expect("json");
    value.as_object_mut().unwrap().remove("expected");
    assert!(validate_vector_instance(&value).is_err());
}

#[test]
fn incoherent_verdict_rejected() {
    let mut result = sample_vector_result_pass();
    result.expected.enforcement = ExpectedEnforcement::ReevaluateOrRefuse;
    result.observed = ObservedEnforcement::ForwardedWithStalePermit;
    result.verdict = IntegrityVerdict::Pass;
    assert!(matches!(
        validate_result(&result),
        Err(IntegrityError::VerdictConsistency { .. })
    ));
}

#[test]
fn secret_bearing_field_rejected() {
    let mut vector = sample_vector_definition();
    vector.trusted_context.claims["access_token"] = serde_json::json!("SYNTHETIC.not-real");
    let err = validate_vector(&vector).expect_err("must reject");
    assert!(matches!(
        err,
        IntegrityError::SecretSafety { .. } | IntegrityError::StructuralValidation { .. }
    ));
    assert!(!err.to_string().contains("SYNTHETIC"));
}
