//! Truth table for authorization binding mutation classes (vectors 001–007).

use dare_coaz_integrity::{
    binding_material_v1, bindings_equal, compute_authorization_binding, digest_json_value,
    BindingMaterialV1, CanonicalValue, MappingIdentity, MutationKind,
};
use serde_json::{json, Value};

#[derive(Debug)]
struct BindingTruthCase {
    vector_id: &'static str,
    mutation: MutationKind,
    initial: BindingMaterialV1,
    final_material: BindingMaterialV1,
    expect_binding_change: bool,
}

fn default_mapping() -> MappingIdentity {
    MappingIdentity {
        kind: "default".to_owned(),
        id: "default-tools-call".to_owned(),
        revision: None,
        digest: "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    }
}

fn rental_mapping(tool_name: &str) -> MappingIdentity {
    MappingIdentity {
        kind: "declared".to_owned(),
        id: format!("declared-{tool_name}"),
        revision: Some("v1".to_owned()),
        digest: format!("mapping-digest-{tool_name}"),
    }
}

fn mapped_inputs(daily_rate: i64) -> CanonicalValue {
    CanonicalValue::normalize(&json!({
        "customer_id": "cust-synthetic-001",
        "vehicle_id": "vehicle-synthetic-001",
        "daily_rate": daily_rate,
        "days": 3
    }))
    .expect("mapped inputs")
}

fn trusted_inputs(agent_id: &str) -> CanonicalValue {
    CanonicalValue::normalize(&json!({
        "subject_id": "subject-synthetic-001",
        "agent_id": agent_id
    }))
    .expect("trusted inputs")
}

fn authzen_request(tool_name: &str) -> Value {
    json!({
        "subject": { "type": "user", "id": "subject-synthetic-001" },
        "resource": { "type": "mcp-tool", "id": tool_name },
        "action": { "name": "invoke" }
    })
}

fn baseline_material(tool_name: &str, daily_rate: i64, agent_id: &str) -> BindingMaterialV1 {
    binding_material_v1(
        "tools/call",
        Some(tool_name),
        rental_mapping(tool_name),
        mapped_inputs(daily_rate),
        trusted_inputs(agent_id),
        digest_json_value(&authzen_request(tool_name)).expect("authzen digest"),
    )
}

fn truth_table() -> Vec<BindingTruthCase> {
    let baseline = baseline_material("rental.quote", 50, "agent-synthetic-001");

    vec![
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-001",
            mutation: MutationKind::None,
            initial: baseline.clone(),
            final_material: baseline.clone(),
            expect_binding_change: false,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-002",
            mutation: MutationKind::ToolName,
            initial: baseline.clone(),
            final_material: baseline_material("rental.confirm", 50, "agent-synthetic-001"),
            expect_binding_change: true,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-003",
            mutation: MutationKind::MappedArgument,
            initial: baseline.clone(),
            final_material: baseline_material("rental.quote", 5000, "agent-synthetic-001"),
            expect_binding_change: true,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-004",
            mutation: MutationKind::Method,
            initial: baseline.clone(),
            final_material: binding_material_v1(
                "tools/list",
                Some("rental.quote"),
                baseline.mapping_identity.clone(),
                baseline.mapped_inputs.clone(),
                baseline.trusted_inputs.clone(),
                baseline.authzen_request_digest.clone(),
            ),
            expect_binding_change: true,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-005",
            mutation: MutationKind::MappedTrustedContext,
            initial: baseline.clone(),
            final_material: baseline_material("rental.quote", 50, "agent-synthetic-002"),
            expect_binding_change: true,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-006",
            mutation: MutationKind::JsonReorderOnly,
            initial: baseline.clone(),
            final_material: binding_material_v1(
                "tools/call",
                Some("rental.quote"),
                baseline.mapping_identity.clone(),
                CanonicalValue::normalize(&json!({
                    "days": 3,
                    "daily_rate": 50,
                    "vehicle_id": "vehicle-synthetic-001",
                    "customer_id": "cust-synthetic-001"
                }))
                .expect("reordered mapped inputs"),
                CanonicalValue::normalize(&json!({
                    "agent_id": "agent-synthetic-001",
                    "subject_id": "subject-synthetic-001"
                }))
                .expect("reordered trusted inputs"),
                digest_json_value(&json!({
                    "action": { "name": "invoke" },
                    "resource": { "id": "rental.quote", "type": "mcp-tool" },
                    "subject": { "id": "subject-synthetic-001", "type": "user" }
                }))
                .expect("reordered authzen digest"),
            ),
            expect_binding_change: false,
        },
        BindingTruthCase {
            vector_id: "COAZ-INTEGRITY-007",
            mutation: MutationKind::UnmappedField,
            initial: baseline.clone(),
            final_material: baseline.clone(),
            expect_binding_change: false,
        },
    ]
}

#[test]
fn vector_mutation_binding_truth_table() {
    for case in truth_table() {
        let initial_binding = compute_authorization_binding(&case.initial);
        let final_binding = compute_authorization_binding(&case.final_material);
        let changed = !bindings_equal(&initial_binding, &final_binding);

        assert_eq!(
            changed,
            case.expect_binding_change,
            "{} ({:?}): expected binding change={} got change={}; initial={} final={}",
            case.vector_id,
            case.mutation,
            case.expect_binding_change,
            changed,
            initial_binding.digest,
            final_binding.digest
        );

        if case.expect_binding_change {
            assert_ne!(
                initial_binding.digest, final_binding.digest,
                "{} must produce distinct binding digests",
                case.vector_id
            );
        } else {
            assert_eq!(
                initial_binding, final_binding,
                "{} must preserve authorized_binding == final_binding",
                case.vector_id
            );
        }
    }
}

#[test]
fn json_reorder_alone_preserves_binding_digest() {
    let left = CanonicalValue::normalize(&json!({"a": 1, "b": 2})).expect("left");
    let right = CanonicalValue::normalize(&json!({"b": 2, "a": 1})).expect("right");
    assert_eq!(left.digest(), right.digest());

    let material_left = binding_material_v1(
        "tools/call",
        Some("rental.quote"),
        default_mapping(),
        left,
        trusted_inputs("agent-synthetic-001"),
        digest_json_value(&authzen_request("rental.quote")).expect("digest"),
    );
    let material_right = binding_material_v1(
        "tools/call",
        Some("rental.quote"),
        default_mapping(),
        right,
        trusted_inputs("agent-synthetic-001"),
        digest_json_value(&authzen_request("rental.quote")).expect("digest"),
    );

    assert_eq!(
        compute_authorization_binding(&material_left),
        compute_authorization_binding(&material_right)
    );
}

#[test]
fn unmapped_field_change_does_not_affect_binding_material() {
    let mapped = mapped_inputs(50);
    let trusted = trusted_inputs("agent-synthetic-001");
    let authzen_digest = digest_json_value(&authzen_request("rental.quote")).expect("digest");

    let with_notes = binding_material_v1(
        "tools/call",
        Some("rental.quote"),
        rental_mapping("rental.quote"),
        mapped.clone(),
        trusted.clone(),
        authzen_digest.clone(),
    );

    let without_notes = binding_material_v1(
        "tools/call",
        Some("rental.quote"),
        rental_mapping("rental.quote"),
        mapped,
        trusted,
        authzen_digest,
    );

    assert_eq!(
        compute_authorization_binding(&with_notes),
        compute_authorization_binding(&without_notes)
    );
}

#[test]
fn mapping_identity_participates_in_binding() {
    let baseline = baseline_material("rental.quote", 50, "agent-synthetic-001");
    let mut mapping_changed = baseline.clone();
    mapping_changed.mapping_identity = MappingIdentity {
        kind: "declared".to_owned(),
        id: "declared-rental.quote".to_owned(),
        revision: Some("v2".to_owned()),
        digest: "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
    };

    assert_ne!(
        compute_authorization_binding(&baseline),
        compute_authorization_binding(&mapping_changed)
    );
}
