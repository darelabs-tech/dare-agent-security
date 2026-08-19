//! End-to-end integrity proof tests (Cycle 003 task-011).
//!
//! Captures deterministic execution traces that prove:
//! - vulnerable reference PEP forwards stale permits for mutation vectors 002–005 (FAIL);
//! - secure reference PEP re-evaluates or refuses the same vectors (PASS);
//! - semantic control vectors 006–007 preserve binding equality;
//! - negative security: no canary leakage, fail-closed validation, harness errors never forward.

use dare_coaz_integrity::{
    bindings_equal, emit_integrity_evidence, enforce_reference_pep, execute_vector,
    load_builtin_vector, parse_and_validate_vector, validate_result, AuthorizationBinding,
    AuthorizationDecider, AuthorizationDecision, AuthorizationProjection, Decision, EmitOptions,
    IntegrityVerdict, MutationKind, ObservedEnforcement, PepEnforcementRequest,
    ReferencePepGateway, ReferencePepMode, RunError, RunOptions, SyntheticExecutionSink,
    VectorDefinition,
};
use serde_json::Value;

const MUTATION_VECTOR_IDS: &[&str] = &[
    "COAZ-INTEGRITY-002",
    "COAZ-INTEGRITY-003",
    "COAZ-INTEGRITY-004",
    "COAZ-INTEGRITY-005",
];

const CONTROL_VECTOR_IDS: &[(&str, MutationKind)] = &[
    ("COAZ-INTEGRITY-006", MutationKind::JsonReorderOnly),
    ("COAZ-INTEGRITY-007", MutationKind::UnmappedField),
];

const CANARY_URL_USER: &str = "canaryUser_7f3a";
const CANARY_URL_PASS: &str = "canaryPass_7f3a";
const CANARY_BEARER: &str = "canaryBearer_7f3a";
const CANARY_APIKEY: &str = "canaryApiKey_7f3a";

const SECURE_OBSERVATIONS: &[ObservedEnforcement] = &[
    ObservedEnforcement::RefusedAfterBindingChange,
    ObservedEnforcement::DeniedAfterReevaluation,
    ObservedEnforcement::ForwardedAfterReevaluation,
];

fn assert_no_canary_text(label: &str, text: &str) {
    for canary in [
        CANARY_URL_USER,
        CANARY_URL_PASS,
        CANARY_BEARER,
        CANARY_APIKEY,
    ] {
        assert!(!text.contains(canary), "{label} leaked canary `{canary}`");
    }
}

fn assert_no_canary_json(label: &str, value: &Value) {
    assert_no_canary_text(label, &value.to_string());
}

fn assert_vulnerable_stale_permit_proof(
    result: &dare_coaz_integrity::VectorResult,
    vector_id: &str,
) {
    validate_result(result).expect("result contract");
    assert_eq!(
        result.initial_decision.decision,
        Decision::Permit,
        "{vector_id} requires initial PERMIT"
    );
    assert!(
        !bindings_equal(&result.initial_binding, &result.final_binding),
        "{vector_id} must change binding before sink"
    );
    assert!(
        result.sink_receipt.forwarded,
        "{vector_id} vulnerable mode must forward for stale-permit proof"
    );
    assert_eq!(
        result.observed,
        ObservedEnforcement::ForwardedWithStalePermit,
        "{vector_id} must observe stale permit forwarding"
    );
    assert_eq!(
        result.initial_decision.bound_to, result.initial_binding,
        "{vector_id} stale permit must reuse initial binding material"
    );
    assert_ne!(
        result.initial_decision.bound_to.digest, result.final_binding.digest,
        "{vector_id} final binding must differ from permit binding"
    );
    assert_eq!(
        result.verdict,
        IntegrityVerdict::Fail,
        "{vector_id} stale permit must FAIL"
    );
}

fn assert_secure_mutation_proof(result: &dare_coaz_integrity::VectorResult, vector_id: &str) {
    validate_result(result).expect("result contract");
    assert!(
        !bindings_equal(&result.initial_binding, &result.final_binding),
        "{vector_id} secure proof assumes binding change"
    );
    assert!(
        SECURE_OBSERVATIONS.contains(&result.observed),
        "{vector_id} observed {:?} not in secure set",
        result.observed
    );
    assert_ne!(
        result.observed,
        ObservedEnforcement::ForwardedWithStalePermit,
        "{vector_id} secure mode must not forward stale permit"
    );
    match result.observed {
        ObservedEnforcement::ForwardedAfterReevaluation => {
            assert!(
                result.sink_receipt.forwarded,
                "{vector_id} forwarded after reevaluation must reach sink"
            );
            assert!(result.enforcement_trace.reevaluated);
            assert_ne!(
                result.initial_decision.bound_to.digest, result.final_binding.digest,
                "{vector_id} reevaluation must not reuse stale permit binding"
            );
        }
        ObservedEnforcement::DeniedAfterReevaluation
        | ObservedEnforcement::RefusedAfterBindingChange => {
            assert!(
                !result.sink_receipt.forwarded,
                "{vector_id} deny/refuse must not reach sink"
            );
        }
        other => panic!("{vector_id} unexpected secure observation: {other:?}"),
    }
    assert_eq!(result.verdict, IntegrityVerdict::Pass);
}

#[test]
fn vulnerable_mode_proves_stale_permit_fail_for_mutation_vectors() {
    for vector_id in MUTATION_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options =
            RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::VulnerableReuse);
        let result = execute_vector(&vector, &options).expect("execute");
        assert_vulnerable_stale_permit_proof(&result, vector_id);
    }
}

#[test]
fn secure_reevaluate_mode_proves_invariant_for_mutation_vectors() {
    for vector_id in MUTATION_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options = RunOptions::from_vector(&vector);
        assert_eq!(options.reference_mode, ReferencePepMode::SecureReevaluate);
        let result = execute_vector(&vector, &options).expect("execute");
        assert_secure_mutation_proof(&result, vector_id);
    }
}

#[test]
fn secure_refuse_mode_blocks_binding_mismatch_without_sink_forward() {
    for vector_id in MUTATION_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options =
            RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::SecureRefuse);
        let result = execute_vector(&vector, &options).expect("execute");
        assert!(
            !bindings_equal(&result.initial_binding, &result.final_binding),
            "{vector_id} refuse proof assumes binding change"
        );
        assert_eq!(
            result.observed,
            ObservedEnforcement::RefusedAfterBindingChange
        );
        assert!(!result.sink_receipt.forwarded);
        assert_eq!(result.verdict, IntegrityVerdict::Pass);
    }
}

#[test]
fn control_vectors_prove_semantic_binding_equality() {
    for (vector_id, kind) in CONTROL_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        assert_eq!(vector.mutation.kind, *kind);
        let result = execute_vector(&vector, &RunOptions::from_vector(&vector)).expect("execute");
        assert_eq!(result.initial_binding, result.final_binding);
        assert!(!result.enforcement_trace.binding_changed);
        assert_eq!(result.verdict, IntegrityVerdict::Pass);
    }
}

#[test]
fn built_in_traces_contain_no_canary_secrets() {
    for vector_id in MUTATION_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let result = execute_vector(&vector, &RunOptions::from_vector(&vector)).expect("execute");
        let result_json = serde_json::to_value(&result).expect("serialize result");
        assert_no_canary_json(&format!("{vector_id} result"), &result_json);

        let evidence = emit_integrity_evidence(
            &result,
            &EmitOptions::deterministic_for_result(&result)
                .with_result_artifact_path(format!("proof/{vector_id}.result.json")),
        )
        .expect("emit evidence");
        let evidence_json = serde_json::to_value(&evidence).expect("serialize evidence");
        assert_no_canary_json(&format!("{vector_id} evidence"), &evidence_json);
    }
}

#[test]
fn redacted_evidence_strips_planted_canary_credentials() {
    use dare_coaz_integrity::{sample_vector_result_stale_permit_fail, RedactionStrategy};

    let mut result = sample_vector_result_stale_permit_fail();
    result.mutation.detail = Some(format!(
        "daily_rate 50 -> 5000 Authorization: Bearer {CANARY_BEARER} api_key={CANARY_APIKEY}"
    ));
    result.redaction.applied = true;
    result.redaction.strategy = RedactionStrategy::Mask;
    result.redaction.fields = vec!["mutation.detail".to_owned()];

    let evidence = emit_integrity_evidence(
        &result,
        &EmitOptions::deterministic_for_result(&result)
            .with_result_artifact_path("proof/stale-permit.result.json"),
    )
    .expect("emit evidence");
    let evidence_json = serde_json::to_value(&evidence).expect("serialize evidence");
    assert_no_canary_json("redacted evidence", &evidence_json);
}

#[test]
fn vulnerable_gateway_refuses_non_synthetic_targets() {
    let err = ReferencePepGateway::new(ReferencePepMode::VulnerableReuse, false)
        .validate_mode()
        .expect_err("must refuse non-synthetic vulnerable mode");
    assert!(err.to_string().contains("synthetic"));
}

#[test]
fn malformed_vector_json_fails_closed_before_execution() {
    let valid = load_builtin_vector("COAZ-INTEGRITY-001").expect("load");
    let mut value = serde_json::to_value(valid).expect("json");
    value["vector_id"] = Value::String(String::new());
    let malformed = value.to_string();
    let err = parse_and_validate_vector(&malformed).expect_err("empty vector_id must fail");
    assert!(!err.to_string().contains(CANARY_BEARER));
    assert!(parse_and_validate_vector("{ not-json").is_err());
}

#[test]
fn projector_error_does_not_reach_sink_in_secure_refuse_mode() {
    let mut vector = load_builtin_vector("COAZ-INTEGRITY-003").expect("load");
    vector.projector_fixture.id = "missing-projector-fixture".to_owned();
    let options =
        RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::SecureRefuse);
    let err = execute_vector(&vector, &options).expect_err("projection must fail");
    assert!(matches!(err, RunError::Projection(_)));
}

#[test]
fn pdp_error_does_not_reach_sink_in_secure_refuse_mode() {
    let mut vector = load_builtin_vector("COAZ-INTEGRITY-003").expect("load");
    vector.pdp_fixture.id = "missing-pdp-fixture".to_owned();
    let options =
        RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::SecureRefuse);
    let err = execute_vector(&vector, &options).expect_err("pdp must fail");
    assert!(matches!(err, RunError::Pdp(_)));
}

#[test]
fn binding_mismatch_does_not_reach_sink_in_secure_refuse_mode() {
    let vector = load_builtin_vector("COAZ-INTEGRITY-003").expect("load");
    let options =
        RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::SecureRefuse);
    let result = execute_vector(&vector, &options).expect("execute");
    assert!(
        !bindings_equal(&result.initial_binding, &result.final_binding),
        "fixture must change binding"
    );
    assert!(!result.sink_receipt.forwarded);
    assert_eq!(
        result.observed,
        ObservedEnforcement::RefusedAfterBindingChange
    );
}

#[test]
fn pdp_harness_error_does_not_forward_through_pep_in_secure_refuse_mode() {
    struct DenyDecider;

    impl AuthorizationDecider for DenyDecider {
        fn decide(
            &self,
            _projection: &AuthorizationProjection,
            binding: &AuthorizationBinding,
        ) -> AuthorizationDecision {
            AuthorizationDecision {
                decision_id: "decision-harness-deny".to_owned(),
                decision: Decision::Deny,
                bound_to: binding.clone(),
            }
        }
    }

    let vector = load_builtin_vector("COAZ-INTEGRITY-003").expect("load");
    let secure_options =
        RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::SecureRefuse);
    let baseline = execute_vector(&vector, &secure_options).expect("baseline refuse run");
    assert!(!baseline.sink_receipt.forwarded);

    let mut sink = SyntheticExecutionSink::new();
    let gateway = ReferencePepGateway::new(ReferencePepMode::SecureRefuse, true);
    let outcome = enforce_reference_pep(PepEnforcementRequest {
        gateway: &gateway,
        initial_decision: &baseline.initial_decision,
        initial_binding: &baseline.initial_binding,
        final_binding: &baseline.final_binding,
        final_operation: &baseline.final_operation,
        final_projection: &baseline.final_projection,
        decider: &DenyDecider,
        sink: &mut sink,
    })
    .expect("pep enforcement");

    assert_eq!(
        outcome.observed,
        ObservedEnforcement::RefusedAfterBindingChange
    );
    assert!(
        sink.is_empty(),
        "secure refuse must not forward on binding mismatch"
    );
}

fn corrupt_vector(base_id: &str, mutate: impl FnOnce(&mut VectorDefinition)) -> VectorDefinition {
    let mut vector = load_builtin_vector(base_id).expect("load");
    mutate(&mut vector);
    vector
}

#[test]
fn initial_decision_not_permit_never_forwards() {
    let vector = corrupt_vector("COAZ-INTEGRITY-001", |v| {
        v.initial_operation.params["arguments"]["daily_rate"] = Value::from(5000);
    });
    let err = execute_vector(&vector, &RunOptions::from_vector(&vector)).expect_err("must deny");
    assert!(matches!(err, RunError::InitialDecisionNotPermit));
}
