//! Integration tests for built-in COAZ-INTEGRITY-001..007 vector fixtures.

use dare_coaz_integrity::{
    bindings_equal, execute_builtin_vector, execute_vector, load_all_builtin_vectors,
    load_builtin_vector, result_deterministic_signature, validate_result, validate_vector,
    Decision, IntegrityVerdict, MutationKind, ObservedEnforcement, ReferencePepMode, RunOptions,
    BUILTIN_VECTOR_IDS,
};

#[test]
fn all_builtin_vectors_load_and_validate() {
    let vectors = load_all_builtin_vectors().expect("load all vectors");
    assert_eq!(vectors.len(), BUILTIN_VECTOR_IDS.len());
    for vector in &vectors {
        validate_vector(vector).expect("semantic validation");
        assert!(BUILTIN_VECTOR_IDS.contains(&vector.vector_id.as_str()));
    }
}

#[test]
fn secure_mode_all_vectors_pass() {
    for vector_id in BUILTIN_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options = RunOptions::from_vector(&vector);
        assert_eq!(options.reference_mode, ReferencePepMode::SecureReevaluate);

        let result = execute_vector(&vector, &options).expect("execute");
        validate_result(&result).expect("result contract");

        assert_eq!(
            result.initial_decision.decision,
            Decision::Permit,
            "{vector_id} requires initial PERMIT"
        );
        assert_eq!(
            result.verdict,
            IntegrityVerdict::Pass,
            "{vector_id} secure mode must PASS"
        );
        assert_ne!(
            result.observed,
            ObservedEnforcement::ForwardedWithStalePermit,
            "{vector_id} secure mode must not forward stale permit"
        );
    }
}

#[test]
fn vulnerable_mode_mutation_vectors_fail_stale_permit() {
    for vector_id in &[
        "COAZ-INTEGRITY-002",
        "COAZ-INTEGRITY-003",
        "COAZ-INTEGRITY-004",
        "COAZ-INTEGRITY-005",
    ] {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options =
            RunOptions::from_vector(&vector).with_reference_mode(ReferencePepMode::VulnerableReuse);

        let result = execute_vector(&vector, &options).expect("execute");
        validate_result(&result).expect("result contract");

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
            "{vector_id} vulnerable mode must forward for proof"
        );
        assert_eq!(
            result.observed,
            ObservedEnforcement::ForwardedWithStalePermit,
            "{vector_id} must observe stale permit forwarding"
        );
        assert_eq!(
            result.verdict,
            IntegrityVerdict::Fail,
            "{vector_id} vulnerable stale permit must FAIL"
        );
    }
}

#[test]
fn control_vectors_preserve_binding_under_mutation() {
    for (vector_id, kind) in [
        ("COAZ-INTEGRITY-006", MutationKind::JsonReorderOnly),
        ("COAZ-INTEGRITY-007", MutationKind::UnmappedField),
    ] {
        let vector = load_builtin_vector(vector_id).expect("load");
        assert_eq!(vector.mutation.kind, kind);

        let result = execute_vector(&vector, &RunOptions::from_vector(&vector)).expect("execute");
        assert_eq!(result.initial_binding, result.final_binding);
        assert!(!result.enforcement_trace.binding_changed);
        assert_eq!(result.verdict, IntegrityVerdict::Pass);
    }
}

#[test]
fn mapped_argument_vector_003_changes_daily_rate() {
    let vector = load_builtin_vector("COAZ-INTEGRITY-003").expect("load");
    assert_eq!(vector.mutation.kind, MutationKind::MappedArgument);
    assert_eq!(
        vector.mutation.detail.as_deref(),
        Some("daily_rate 50 -> 5000")
    );

    let result = execute_vector(&vector, &RunOptions::from_vector(&vector)).expect("execute");
    assert_eq!(
        result.final_operation.params["arguments"]["daily_rate"],
        5000
    );
    assert_ne!(result.initial_binding.digest, result.final_binding.digest);
}

#[test]
fn execution_is_deterministic_across_repeated_runs() {
    for vector_id in BUILTIN_VECTOR_IDS {
        let vector = load_builtin_vector(vector_id).expect("load");
        let options = RunOptions::from_vector(&vector);

        let first = execute_vector(&vector, &options).expect("first run");
        let second = execute_vector(&vector, &options).expect("second run");

        assert_eq!(
            result_deterministic_signature(&first),
            result_deterministic_signature(&second),
            "{vector_id} deterministic signature must match"
        );
    }
}

#[test]
fn execute_builtin_vector_entrypoint_matches_execute_vector() {
    let vector_id = "COAZ-INTEGRITY-001";
    let vector = load_builtin_vector(vector_id).expect("load");
    let options = RunOptions::default();

    let direct = execute_vector(&vector, &options).expect("direct");
    let via_id = execute_builtin_vector(vector_id, &options).expect("via id");
    assert_eq!(
        result_deterministic_signature(&direct),
        result_deterministic_signature(&via_id)
    );
}
