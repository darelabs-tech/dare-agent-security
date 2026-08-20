use std::path::PathBuf;

use dare_adversarial::{
    budget_enforce::BudgetState, canonical::digest, load_bundle, parse_bundle,
    policy::authorize_step, reclassify::reclassify, AdversarialError, ControlledRunner, PathStatus,
    ResultStatus, RoeDocument, ValidationMode,
};
use serde_json::Value;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/adversarial/confused-deputy.json")
}

fn bundle() -> dare_adversarial::ValidationBundle {
    load_bundle(&fixture_path()).expect("fixture")
}

fn authorized_bundle() -> dare_adversarial::ValidationBundle {
    let mut bundle = bundle();
    bundle.plan.mode = ValidationMode::AuthorizedDynamic;
    bundle.vector.mode = ValidationMode::AuthorizedDynamic;
    bundle.plan.vector_digest = digest(&bundle.vector).expect("vector digest");
    let roe = RoeDocument {
        schema_version: "1.0.0".to_owned(),
        id: "ROE-TEST-001".to_owned(),
        target_id: bundle.plan.target_id.clone(),
        environment: bundle.plan.environment.clone(),
        allowed_capabilities: vec!["customer.lookup".to_owned()],
        allowed_identities: vec!["test-identity".to_owned()],
        allowed_categories: vec!["IDENTITY".to_owned()],
        allowed_data_classes: vec!["SYNTHETIC".to_owned()],
        prohibited_operations: vec!["delete".to_owned()],
        not_before: "2020-01-01T00:00:00Z".to_owned(),
        not_after: "2099-01-01T00:00:00Z".to_owned(),
        allow_state_changes: false,
        allow_external_egress: false,
        local_only: true,
        approved_by: "security-test".to_owned(),
    };
    bundle.plan.roe_id = Some(roe.id.clone());
    bundle.plan.roe_digest = Some(digest(&roe).expect("roe digest"));
    bundle.roe = Some(roe);
    bundle
}

#[test]
fn dynamic_without_roe_is_a_safety_refusal() {
    let mut bundle = authorized_bundle();
    bundle.roe = None;
    let error = ControlledRunner::new(ValidationMode::AuthorizedDynamic)
        .run(&bundle)
        .expect_err("missing ROE");
    assert!(matches!(error, AdversarialError::SafetyRefusal(_)));
}

#[test]
fn valid_local_only_roe_allows_authorized_synthetic_execution() {
    let result = ControlledRunner::new(ValidationMode::AuthorizedDynamic)
        .run(&authorized_bundle())
        .expect("authorized local run");
    assert_eq!(result.status, ResultStatus::Completed);
}

#[test]
fn roe_tampering_is_detected_by_digest() {
    let mut bundle = authorized_bundle();
    bundle.roe.as_mut().expect("roe").environment = "production".to_owned();
    let error = ControlledRunner::new(ValidationMode::AuthorizedDynamic)
        .run(&bundle)
        .expect_err("tampered ROE");
    assert!(matches!(error, AdversarialError::SafetyRefusal(_)));
}

#[test]
fn vector_digest_substitution_is_denied() {
    let mut bundle = bundle();
    bundle.plan.vector_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    assert!(ControlledRunner::new(ValidationMode::LocalSynthetic)
        .run(&bundle)
        .is_err());
}

#[test]
fn code_like_argument_fields_are_rejected() {
    let value: Value =
        serde_json::from_slice(&std::fs::read(fixture_path()).expect("fixture")).expect("json");
    let mut hostile = value;
    hostile["vector"]["steps"][0]["arguments"]["shell"] = Value::String("echo no".to_owned());
    let error = parse_bundle(hostile).expect_err("code field");
    assert!(matches!(error, AdversarialError::SafetyRefusal(_)));
}

#[test]
fn target_substitution_triggers_kill_switch() {
    let mut bundle = bundle();
    bundle.vector.steps[0].target_id = Some("other-target".to_owned());
    bundle.plan.vector_digest = digest(&bundle.vector).expect("digest");
    let result = ControlledRunner::new(ValidationMode::LocalSynthetic)
        .run(&bundle)
        .expect("kill result");
    assert_eq!(result.status, ResultStatus::Killed);
    assert_eq!(result.operations, 0);
}

#[test]
fn retry_amplification_and_budget_bypass_stop_without_expansion() {
    let mut bundle = bundle();
    bundle.vector.steps[0].retries = 1;
    bundle.plan.vector_digest = digest(&bundle.vector).expect("digest");
    let result = ControlledRunner::new(ValidationMode::LocalSynthetic)
        .run(&bundle)
        .expect("budget stop");
    assert_eq!(result.status, ResultStatus::Stopped);
    assert_eq!(result.operations, 0);
}

#[test]
fn secret_and_egress_are_kill_triggers() {
    for mutate in [0, 1] {
        let mut bundle = bundle();
        if mutate == 0 {
            bundle.vector.steps[0].arguments["token"] = Value::String("synthetic".to_owned());
        } else {
            bundle.vector.steps[0].external_egress_bytes = 1;
        }
        bundle.plan.vector_digest = digest(&bundle.vector).expect("digest");
        let result = ControlledRunner::new(ValidationMode::LocalSynthetic)
            .run(&bundle)
            .expect("kill");
        assert_eq!(result.status, ResultStatus::Killed);
        assert_eq!(result.operations, 0);
    }
}

#[test]
fn unapproved_extra_step_is_denied() {
    let bundle = bundle();
    let state = BudgetState::default();
    let error = authorize_step(
        bundle.vector.steps.len(),
        &bundle.vector.steps[0],
        &bundle.plan,
        &bundle.vector,
        &bundle.budget,
        &state,
        None,
    )
    .expect_err("extra step");
    assert!(matches!(error, AdversarialError::SafetyRefusal(_)));
}

#[test]
fn canonical_digest_is_key_order_stable() {
    let a = serde_json::json!({"b": 2, "a": {"y": 2, "x": 1}});
    let b = serde_json::json!({"a": {"x": 1, "y": 2}, "b": 2});
    assert_eq!(digest(&a).expect("a"), digest(&b).expect("b"));
}

#[test]
fn reclassification_creates_a_new_revision_without_mutating_parent() {
    let bundle = bundle();
    let result = ControlledRunner::new(ValidationMode::LocalSynthetic)
        .run(&bundle)
        .expect("result");
    let parent = bundle.plan.attack_path_digest.clone();
    let revision = reclassify(
        &bundle.plan.attack_path_id,
        &parent,
        PathStatus::Inferred,
        &result,
    )
    .expect("revision");
    assert_eq!(revision.previous_digest, parent);
    assert_ne!(revision.new_digest, revision.previous_digest);
    assert_eq!(bundle.plan.attack_path_digest, parent);
}
