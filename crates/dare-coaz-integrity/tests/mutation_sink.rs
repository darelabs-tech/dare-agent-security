//! Integration tests for controlled mutation stage and synthetic execution sink.

use dare_coaz_integrity::{
    apply_mutation, binding_from_projection, bindings_equal, enforce_reference_pep,
    projector_for_fixture, AuthorizationBinding, AuthorizationDecider, AuthorizationDecision,
    AuthorizationProjection, Decision, DeterministicMutator, EnforcementOutcome, ExecutionSink,
    IntegrityMutation, MutationKind, OperationMutator, PepEnforcementRequest, PepError,
    ReferencePepGateway, ReferencePepMode, SyntheticExecutionSink, TrustedAuthorizationContext,
};
use dare_coaz_integrity::{compute_authorization_binding, BindingMaterialV1};
use serde_json::json;

struct RentalPolicyDecider;

impl AuthorizationDecider for RentalPolicyDecider {
    fn decide(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> AuthorizationDecision {
        let tool_name = projection
            .authzen_request
            .get("resource")
            .and_then(|resource| resource.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let daily_rate = projection
            .mapped_inputs
            .get("daily_rate")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);

        let decision = if tool_name.ends_with("_internal") || daily_rate > 1000 {
            Decision::Deny
        } else {
            Decision::Permit
        };

        AuthorizationDecision {
            decision_id: format!("decision-{}", &binding.digest[..8]),
            decision,
            bound_to: binding.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pep(
    mode: ReferencePepMode,
    synthetic_only: bool,
    initial_decision: &AuthorizationDecision,
    initial_binding: &AuthorizationBinding,
    final_binding: &AuthorizationBinding,
    final_operation: &dare_coaz_integrity::McpOperation,
    final_projection: &AuthorizationProjection,
    sink: &mut SyntheticExecutionSink,
) -> Result<EnforcementOutcome, PepError> {
    enforce_reference_pep(PepEnforcementRequest {
        gateway: &ReferencePepGateway::new(mode, synthetic_only),
        initial_decision,
        initial_binding,
        final_binding,
        final_operation,
        final_projection,
        decider: &RentalPolicyDecider,
        sink,
    })
}

fn baseline_operation() -> dare_coaz_integrity::McpOperation {
    dare_coaz_integrity::McpOperation {
        method: "tools/call".to_owned(),
        params: json!({
            "name": "rental.quote",
            "arguments": {
                "customer_id": "cust-synthetic-001",
                "vehicle_id": "vehicle-synthetic-001",
                "daily_rate": 50,
                "days": 3
            }
        }),
    }
}

fn baseline_trusted() -> TrustedAuthorizationContext {
    TrustedAuthorizationContext {
        subject_id: "subject-synthetic-001".to_owned(),
        agent_id: Some("agent-synthetic-001".to_owned()),
        claims: json!({ "role": "standard" }),
    }
}

fn rental_projector() -> Box<dyn dare_coaz_integrity::AuthorizationProjector> {
    projector_for_fixture("declared-rental-quote").expect("projector")
}

fn project_and_bind(
    projector: &dyn dare_coaz_integrity::AuthorizationProjector,
    operation: &dare_coaz_integrity::McpOperation,
    trusted: &TrustedAuthorizationContext,
) -> (AuthorizationProjection, AuthorizationBinding) {
    let projection = projector.project(operation, trusted).expect("projection");
    let binding = binding_from_projection(operation, &projection).expect("binding");
    (projection, binding)
}

#[test]
fn each_mutation_changes_only_intended_fixture_fields() {
    let operation = baseline_operation();
    let trusted = baseline_trusted();
    let cases = [
        (
            MutationKind::None,
            vec![] as Vec<&str>,
            false,
            false,
            false,
            false,
        ),
        (
            MutationKind::ToolName,
            vec!["params.name"],
            true,
            false,
            false,
            false,
        ),
        (
            MutationKind::MappedArgument,
            vec!["params.arguments.daily_rate"],
            false,
            true,
            false,
            false,
        ),
        (
            MutationKind::Method,
            vec!["method"],
            false,
            false,
            true,
            false,
        ),
        (
            MutationKind::MappedTrustedContext,
            vec!["trusted.agent_id"],
            false,
            false,
            false,
            true,
        ),
        (
            MutationKind::JsonReorderOnly,
            vec!["params.key_order", "params.arguments.key_order"],
            false,
            false,
            false,
            false,
        ),
        (
            MutationKind::UnmappedField,
            vec!["params.arguments.internal_notes"],
            false,
            false,
            false,
            false,
        ),
    ];

    for (kind, expected_fields, name_changed, rate_changed, method_changed, agent_changed) in cases
    {
        let result = apply_mutation(
            &operation,
            &trusted,
            &IntegrityMutation { kind, detail: None },
        )
        .expect("mutation");

        let name_delta = result.operation.params["name"] != operation.params["name"];
        let rate_delta = result.operation.params["arguments"]["daily_rate"]
            != operation.params["arguments"]["daily_rate"];
        let method_delta = result.operation.method != operation.method;
        let agent_delta = result.trusted.agent_id != trusted.agent_id;

        assert_eq!(name_delta, name_changed, "{kind:?} tool name delta");
        assert_eq!(rate_delta, rate_changed, "{kind:?} daily_rate delta");
        assert_eq!(method_delta, method_changed, "{kind:?} method delta");
        assert_eq!(agent_delta, agent_changed, "{kind:?} agent delta");

        let changed = dare_coaz_integrity::changed_operation_fields(kind);
        let trusted_changed = dare_coaz_integrity::changed_trusted_fields(kind);
        let mut labels = changed
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        labels.extend(trusted_changed.iter().map(|value| (*value).to_owned()));
        assert_eq!(labels, expected_fields, "{kind:?} changed field metadata");
    }
}

#[test]
fn sink_trace_is_repeatable_across_runs() {
    let mut sink_a = SyntheticExecutionSink::new();
    let mut sink_b = SyntheticExecutionSink::new();
    let operation = baseline_operation();
    let auth = dare_coaz_integrity::SinkAuthorizationContext {
        decision_id: "decision-synthetic-001".to_owned(),
        binding: AuthorizationBinding {
            algorithm: "coaz-binding-v1".to_owned(),
            digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        },
    };

    let left = sink_a.forward(&operation, &auth).expect("left");
    let right = sink_b.forward(&operation, &auth).expect("right");
    assert_eq!(left.receipt.params_digest, right.receipt.params_digest);
    assert_eq!(left.receipt.operation_name, "rental.quote");
    assert_eq!(left.receipt.sequence, Some(1));
}

#[test]
fn secure_reevaluate_denies_changed_mapped_argument() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let initial_operation = baseline_operation();
    let (initial_projection, initial_binding) =
        project_and_bind(projector.as_ref(), &initial_operation, &trusted);

    let mutated = DeterministicMutator
        .mutate(
            &initial_operation,
            &trusted,
            &IntegrityMutation {
                kind: MutationKind::MappedArgument,
                detail: Some("daily_rate 50 -> 5000".to_owned()),
            },
        )
        .expect("mutation");
    let (final_projection, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);

    assert!(!bindings_equal(&initial_binding, &final_binding));

    let initial_decision = RentalPolicyDecider.decide(&initial_projection, &initial_binding);
    let mut sink = SyntheticExecutionSink::new();
    let outcome = run_pep(
        ReferencePepMode::SecureReevaluate,
        true,
        &initial_decision,
        &initial_binding,
        &final_binding,
        &mutated.operation,
        &final_projection,
        &mut sink,
    )
    .expect("secure reevaluate");

    assert_eq!(
        outcome.observed,
        dare_coaz_integrity::ObservedEnforcement::DeniedAfterReevaluation
    );
    assert!(sink.is_empty());
    assert!(outcome.trace.reevaluated);
    assert!(outcome.trace.binding_changed);
}

#[test]
fn secure_refuse_blocks_binding_mismatch_without_sink_forward() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let initial_operation = baseline_operation();
    let (initial_projection, initial_binding) =
        project_and_bind(projector.as_ref(), &initial_operation, &trusted);

    let mutated = apply_mutation(
        &initial_operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::MappedArgument,
            detail: Some("daily_rate 50 -> 5000".to_owned()),
        },
    )
    .expect("mapped argument mutation");
    let (final_projection, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);

    assert!(!bindings_equal(&initial_binding, &final_binding));
    let _ = final_projection;

    let initial_decision = RentalPolicyDecider.decide(&initial_projection, &initial_binding);
    let mut sink = SyntheticExecutionSink::new();
    let outcome = run_pep(
        ReferencePepMode::SecureRefuse,
        true,
        &initial_decision,
        &initial_binding,
        &final_binding,
        &mutated.operation,
        &final_projection,
        &mut sink,
    )
    .expect("secure refuse");

    assert_eq!(
        outcome.observed,
        dare_coaz_integrity::ObservedEnforcement::RefusedAfterBindingChange
    );
    assert!(sink.is_empty());
}

#[test]
fn vulnerable_mode_forwards_with_stale_binding_for_proof() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let initial_operation = baseline_operation();
    let (initial_projection, initial_binding) =
        project_and_bind(projector.as_ref(), &initial_operation, &trusted);

    let mutated = apply_mutation(
        &initial_operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::MappedArgument,
            detail: Some("daily_rate 50 -> 5000".to_owned()),
        },
    )
    .expect("mapped argument mutation");
    let (final_projection, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);

    assert!(!bindings_equal(&initial_binding, &final_binding));

    let initial_decision = RentalPolicyDecider.decide(&initial_projection, &initial_binding);
    let mut sink = SyntheticExecutionSink::new();
    let outcome = run_pep(
        ReferencePepMode::VulnerableReuse,
        true,
        &initial_decision,
        &initial_binding,
        &final_binding,
        &mutated.operation,
        &final_projection,
        &mut sink,
    )
    .expect("vulnerable reuse");

    assert_eq!(
        outcome.observed,
        dare_coaz_integrity::ObservedEnforcement::ForwardedWithStalePermit
    );
    let record = sink.records().first().expect("sink record");
    assert!(record.receipt.forwarded);
    assert_eq!(
        record.authorization.binding.digest, initial_binding.digest,
        "stale permit must reuse initial binding"
    );
    assert_eq!(
        record.authorization.decision_id, initial_decision.decision_id,
        "stale permit must reuse initial decision id"
    );
}

#[test]
fn vulnerable_reuse_rejects_non_synthetic_targets() {
    let gateway = ReferencePepGateway::new(ReferencePepMode::VulnerableReuse, false);
    let err = gateway.validate_mode().expect_err("must reject");
    assert!(err.to_string().contains("synthetic_only"));
}

#[test]
fn json_reorder_mutation_preserves_binding_material() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (_, initial_binding) = project_and_bind(projector.as_ref(), &operation, &trusted);

    let mutated = apply_mutation(
        &operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::JsonReorderOnly,
            detail: None,
        },
    )
    .expect("json reorder");
    let (_, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);

    assert_eq!(
        mutated.applied.kind,
        MutationKind::JsonReorderOnly,
        "json reorder mutation must be explicit"
    );
    assert_eq!(initial_binding, final_binding);
}

#[test]
fn unmapped_field_mutation_preserves_binding_material() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (_, initial_binding) = project_and_bind(projector.as_ref(), &operation, &trusted);

    let mutated = apply_mutation(
        &operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::UnmappedField,
            detail: None,
        },
    )
    .expect("unmapped field");
    assert!(mutated.operation.params["arguments"]
        .get("internal_notes")
        .is_some());
    let (_, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);
    assert_eq!(initial_binding, final_binding);
}

#[test]
fn binding_truth_table_matches_mutation_stage() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (_, initial_binding) = project_and_bind(projector.as_ref(), &operation, &trusted);

    let expect_change = |kind: MutationKind, expected: bool| {
        let mutated = apply_mutation(
            &operation,
            &trusted,
            &IntegrityMutation { kind, detail: None },
        )
        .expect("mutation");
        let (_, final_binding) =
            project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);
        assert_eq!(
            initial_binding != final_binding,
            expected,
            "{kind:?} binding change expectation"
        );
    };

    expect_change(MutationKind::None, false);
    expect_change(MutationKind::MappedArgument, true);
    expect_change(MutationKind::MappedTrustedContext, true);
    expect_change(MutationKind::JsonReorderOnly, false);
    expect_change(MutationKind::UnmappedField, false);
}

#[test]
fn tool_name_mutation_changes_binding_material() {
    let projector = projector_for_fixture("default-tools-call").expect("default projector");
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (_, initial_binding) = project_and_bind(projector.as_ref(), &operation, &trusted);

    let mutated = apply_mutation(
        &operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::ToolName,
            detail: None,
        },
    )
    .expect("tool name mutation");
    let (_, final_binding) =
        project_and_bind(projector.as_ref(), &mutated.operation, &mutated.trusted);

    assert_ne!(initial_binding, final_binding);
}

#[test]
fn method_mutation_changes_binding_material() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (initial_projection, initial_binding) =
        project_and_bind(projector.as_ref(), &operation, &trusted);

    let mutated = apply_mutation(
        &operation,
        &trusted,
        &IntegrityMutation {
            kind: MutationKind::Method,
            detail: None,
        },
    )
    .expect("method mutation");

    let mut material = BindingMaterialV1::from_projection(
        operation.method.as_str(),
        Some("rental.quote"),
        &initial_projection,
    )
    .expect("material");
    material.method = mutated.operation.method.clone();
    let final_binding = compute_authorization_binding(&material);

    assert_ne!(initial_binding, final_binding);
    assert_ne!(initial_binding.digest, final_binding.digest);
}

#[test]
fn secure_reevaluate_forwards_unchanged_binding_with_existing_permit() {
    let projector = rental_projector();
    let trusted = baseline_trusted();
    let operation = baseline_operation();
    let (initial_projection, initial_binding) =
        project_and_bind(projector.as_ref(), &operation, &trusted);
    let initial_decision = RentalPolicyDecider.decide(&initial_projection, &initial_binding);

    let mut sink = SyntheticExecutionSink::new();
    let outcome = run_pep(
        ReferencePepMode::SecureReevaluate,
        true,
        &initial_decision,
        &initial_binding,
        &initial_binding,
        &operation,
        &initial_projection,
        &mut sink,
    )
    .expect("unchanged binding");

    assert_eq!(
        outcome.observed,
        dare_coaz_integrity::ObservedEnforcement::ForwardedWithExistingPermit
    );
    assert_eq!(sink.records().len(), 1);
}

#[test]
fn binding_from_projection_matches_material_digest() {
    let projector = rental_projector();
    let operation = baseline_operation();
    let trusted = baseline_trusted();
    let projection = projector.project(&operation, &trusted).expect("projection");
    let binding = binding_from_projection(&operation, &projection).expect("binding");
    let material = BindingMaterialV1::from_projection(
        operation.method.as_str(),
        Some("rental.quote"),
        &projection,
    )
    .expect("material");
    assert_eq!(binding, compute_authorization_binding(&material));
}
