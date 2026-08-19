use dare_coaz_integrity::{
    projector_for_fixture, AuthorizationProjector, DefaultToolsCallProjector, McpOperation,
    ProjectionError, RentalQuoteProjector, TrustedAuthorizationContext,
};
use serde_json::json;

fn sample_operation() -> McpOperation {
    McpOperation {
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

fn sample_trusted_context() -> TrustedAuthorizationContext {
    TrustedAuthorizationContext {
        subject_id: "subject-synthetic-001".to_owned(),
        agent_id: Some("agent-synthetic-001".to_owned()),
        claims: json!({ "role": "standard" }),
    }
}

#[test]
fn default_projection_fixture_matches_expected_shape() {
    let projection = DefaultToolsCallProjector
        .project(&sample_operation(), &sample_trusted_context())
        .expect("default projection");

    assert_eq!(projection.mapping.kind, "default");
    assert_eq!(projection.mapping.id, "default-tools-call");
    assert_eq!(projection.mapped_inputs["days"], json!(3));
    assert_eq!(projection.mapped_inputs["daily_rate"], json!(50));
    assert_eq!(
        projection.trusted_inputs["subject_id"],
        json!("subject-synthetic-001")
    );
    assert_eq!(
        projection.authzen_request["resource"]["id"],
        json!("rental.quote")
    );
    assert!(!projection
        .authzen_request
        .as_object()
        .unwrap()
        .contains_key("context"));
}

#[test]
fn declared_projection_fixture_maps_only_binding_relevant_arguments() {
    let projection = RentalQuoteProjector
        .project(&sample_operation(), &sample_trusted_context())
        .expect("declared projection");

    assert_eq!(projection.mapping.kind, "declared");
    assert_eq!(projection.mapping.id, "declared-rental-quote");
    assert_eq!(projection.mapped_inputs["daily_rate"], json!(50));
    assert_eq!(
        projection.mapped_inputs["customer_id"],
        json!("cust-synthetic-001")
    );
    assert!(!projection
        .mapped_inputs
        .as_object()
        .unwrap()
        .contains_key("days"));
    assert_eq!(
        projection.authzen_request["context"]["daily_rate"],
        json!(50)
    );
    assert_eq!(
        projection.authzen_request["context"]["agent_id"],
        json!("agent-synthetic-001")
    );
}

#[test]
fn missing_mapped_value_returns_deterministic_error() {
    let mut operation = sample_operation();
    operation.params["arguments"]
        .as_object_mut()
        .unwrap()
        .remove("daily_rate");

    let err = RentalQuoteProjector
        .project(&operation, &sample_trusted_context())
        .expect_err("missing daily_rate must fail");

    assert_eq!(
        err,
        ProjectionError::MissingMappedValue {
            field: "daily_rate".to_owned()
        }
    );
    assert_eq!(err.to_string(), "missing required mapped value: daily_rate");
    assert!(!err.to_string().contains("cust-synthetic"));
}

#[test]
fn trust_context_projection_preserves_trusted_provenance() {
    let projection = RentalQuoteProjector
        .project(&sample_operation(), &sample_trusted_context())
        .expect("projection");

    assert_eq!(
        projection.trusted_inputs["subject_id"],
        json!("subject-synthetic-001")
    );
    assert_eq!(
        projection.trusted_inputs["agent_id"],
        json!("agent-synthetic-001")
    );
    assert!(!projection
        .trusted_inputs
        .as_object()
        .unwrap()
        .contains_key("claims"));
    assert!(!projection
        .mapped_inputs
        .as_object()
        .unwrap()
        .contains_key("agent_id"));
}

#[test]
fn repeated_projection_is_deterministic() {
    let operation = sample_operation();
    let trusted = sample_trusted_context();

    let first = DefaultToolsCallProjector
        .project(&operation, &trusted)
        .expect("first projection");
    let second = DefaultToolsCallProjector
        .project(&operation, &trusted)
        .expect("second projection");

    assert_eq!(first, second);
    assert_eq!(first.mapping.digest, second.mapping.digest);

    let declared_first = RentalQuoteProjector
        .project(&operation, &trusted)
        .expect("declared first");
    let declared_second = RentalQuoteProjector
        .project(&operation, &trusted)
        .expect("declared second");
    assert_eq!(declared_first, declared_second);
}

#[test]
fn daily_rate_change_changes_declared_mapped_inputs() {
    let mut changed = sample_operation();
    changed.params["arguments"]["daily_rate"] = json!(5000);

    let baseline = RentalQuoteProjector
        .project(&sample_operation(), &sample_trusted_context())
        .expect("baseline");
    let mutated = RentalQuoteProjector
        .project(&changed, &sample_trusted_context())
        .expect("mutated");

    assert_ne!(baseline.mapped_inputs, mutated.mapped_inputs);
    assert_ne!(baseline.authzen_request, mutated.authzen_request);
}

#[test]
fn projector_registry_resolves_reference_fixtures() {
    let default = projector_for_fixture("default-tools-call").expect("default fixture");
    assert_eq!(default.fixture_id(), "default-tools-call");

    let declared = projector_for_fixture("declared-rental-quote").expect("declared fixture");
    assert_eq!(declared.fixture_id(), "declared-rental-quote");
}

#[test]
fn projection_artifacts_do_not_contain_credential_fields() {
    let mut trusted = sample_trusted_context();
    trusted.claims = json!({ "access_token": "SYNTHETIC.not-real" });

    let projection = DefaultToolsCallProjector
        .project(&sample_operation(), &trusted)
        .expect("projection");

    let serialized = serde_json::to_string(&projection).expect("serialize projection");
    assert!(!serialized.contains("access_token"));
    assert!(!serialized.contains("SYNTHETIC.not-real"));
}
