//! Deterministic PDP and bound decision contract tests (task-006).

use dare_coaz_integrity::{
    bind_decision, bindings_equal, compute_authorization_binding, pdp_for_fixture,
    BindingMaterialV1, BoundDecision, Decision, DecisionProvider, ProjectionError,
    RentalQuoteProjector, SyntheticRentalPolicyV1,
};
use dare_coaz_integrity::{AuthorizationProjector, McpOperation, TrustedAuthorizationContext};
use serde_json::json;

fn sample_operation(daily_rate: i64) -> McpOperation {
    McpOperation {
        method: "tools/call".to_owned(),
        params: json!({
            "name": "rental.quote",
            "arguments": {
                "customer_id": "cust-synthetic-001",
                "vehicle_id": "vehicle-synthetic-001",
                "daily_rate": daily_rate,
                "days": 3
            }
        }),
    }
}

fn sample_trusted_context() -> TrustedAuthorizationContext {
    TrustedAuthorizationContext {
        subject_id: "subject-synthetic-001".to_owned(),
        agent_id: Some("agent-synthetic-001".to_owned()),
        claims: json!({ "role": "standard" }),
    }
}

fn project_and_bind(
    daily_rate: i64,
) -> Result<
    (
        dare_coaz_integrity::AuthorizationProjection,
        dare_coaz_integrity::AuthorizationBinding,
    ),
    ProjectionError,
> {
    let projection =
        RentalQuoteProjector.project(&sample_operation(daily_rate), &sample_trusted_context())?;
    let material =
        BindingMaterialV1::from_projection("tools/call", Some("rental.quote"), &projection)
            .map_err(|_| ProjectionError::Canonicalization)?;
    Ok((projection, compute_authorization_binding(&material)))
}

fn evaluate_rate(daily_rate: i64) -> BoundDecision {
    let (projection, binding) = project_and_bind(daily_rate).expect("projection");
    SyntheticRentalPolicyV1
        .evaluate(&projection, &binding)
        .expect("decision")
}

#[test]
fn same_projection_yields_same_decision() {
    let first = evaluate_rate(50);
    let second = evaluate_rate(50);

    assert_eq!(first, second);
    assert_eq!(first.decision, Decision::Permit);
    assert_eq!(first.decision_id, second.decision_id);
}

#[test]
fn changed_mapped_projection_can_change_decision() {
    let permit = evaluate_rate(50);
    let deny = evaluate_rate(5000);

    assert_eq!(permit.decision, Decision::Permit);
    assert_eq!(deny.decision, Decision::Deny);
    assert_ne!(permit.decision_id, deny.decision_id);
    assert_ne!(permit.binding_digest(), deny.binding_digest());
}

#[test]
fn decision_records_evaluated_binding() {
    let (projection, binding) = project_and_bind(50).expect("projection");
    let decision = SyntheticRentalPolicyV1
        .evaluate(&projection, &binding)
        .expect("decision");

    assert!(decision.is_bound_to(&binding));
    assert_eq!(decision.binding_digest(), binding.digest);
    assert_eq!(decision.binding, binding);
}

#[test]
fn secure_path_does_not_reuse_decision_for_different_binding() {
    let binding_a = project_and_bind(50).expect("binding a").1;
    let binding_b = project_and_bind(5000).expect("binding b").1;
    assert!(!bindings_equal(&binding_a, &binding_b));

    let decision_a = bind_decision(
        SyntheticRentalPolicyV1::FIXTURE_ID,
        Decision::Permit,
        binding_a.clone(),
    );
    let decision_b = bind_decision(
        SyntheticRentalPolicyV1::FIXTURE_ID,
        Decision::Deny,
        binding_b.clone(),
    );

    assert_ne!(decision_a.decision_id, decision_b.decision_id);
    assert!(decision_a.is_bound_to(&binding_a));
    assert!(decision_b.is_bound_to(&binding_b));
    assert!(!decision_a.is_bound_to(&binding_b));
    assert!(!decision_b.is_bound_to(&binding_a));
}

#[test]
fn rental_quote_internal_denies_standard_synthetic_subject() {
    let operation = McpOperation {
        method: "tools/call".to_owned(),
        params: json!({
            "name": "rental.quote_internal",
            "arguments": {
                "customer_id": "cust-synthetic-001",
                "vehicle_id": "vehicle-synthetic-001",
                "daily_rate": 50,
                "days": 3
            }
        }),
    };

    let projection = RentalQuoteProjector
        .project(&operation, &sample_trusted_context())
        .expect_err("internal quote requires rental.quote tool");
    assert!(matches!(
        projection,
        ProjectionError::InvalidOperation { .. }
    ));

    let mut internal_projection = RentalQuoteProjector
        .project(&sample_operation(50), &sample_trusted_context())
        .expect("quote projection");
    internal_projection.authzen_request["resource"]["id"] = json!("rental.quote_internal");

    let material = BindingMaterialV1::from_projection(
        "tools/call",
        Some("rental.quote_internal"),
        &internal_projection,
    )
    .expect("material");
    let binding = compute_authorization_binding(&material);

    let decision = SyntheticRentalPolicyV1
        .evaluate(&internal_projection, &binding)
        .expect("decision");

    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.is_bound_to(&binding));
}

#[test]
fn pdp_registry_resolves_reference_fixture() {
    let pdp = pdp_for_fixture("synthetic-rental-policy-v1").expect("fixture");
    assert_eq!(pdp.fixture_id(), SyntheticRentalPolicyV1::FIXTURE_ID);
}
