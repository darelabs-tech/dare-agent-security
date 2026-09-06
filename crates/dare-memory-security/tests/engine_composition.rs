//! Cycle 013 and Cycle 015 composition, exercised through the public API only.
//!
//! The in-crate tests check the mapping functions directly. These check the
//! property an operator actually depends on: that Cycle 016 can be added to a
//! workspace that already runs prompt-injection and identity engines without
//! any of the three changing what the other two mean.

use dare_memory_security::compat::{
    acting_principal_originates_authority, assert_ceiling_agrees_with_injection_model,
    assert_identity_agreement, composed_boundary_properties, injection_invariant_names,
    injection_source_for, injection_trust_level, memory_principal_from_identity,
    persistence_preserves_attacker_control,
};
use dare_memory_security::{
    MemoryContext, MemoryInvariantType, MemoryPrincipal, MemoryProperty, PrincipalKind, SourceKind,
    TrustClass, TrustLevel,
};

use dare_identity_security::principal::PrincipalSet;

fn identity_set() -> PrincipalSet {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1",
        "set_id": "set-composition",
        "principals": [
            {"id": "user-7", "kind": "HUMAN", "tenant_id": "tenant-a"},
            {"id": "svc-1", "kind": "SERVICE", "tenant_id": "tenant-a"}
        ],
        "bindings": {
            "initiating_principal_id": "user-7",
            "effective_principal_id": "user-7"
        }
    }))
    .expect("fixture decodes")
}

fn memory_context() -> MemoryContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1",
        "context_id": "context-composition",
        "principals": [
            {
                "principal_id": "user-7",
                "kind": "HUMAN",
                "tenant_id": "tenant-a",
                "namespaces": ["ns-support"]
            },
            {
                "principal_id": "svc-1",
                "kind": "SERVICE",
                "tenant_id": "tenant-a",
                "namespaces": ["ns-support"]
            }
        ],
        "acting_principal_id": "user-7",
        "tenant_id": "tenant-a",
        "namespace_id": "ns-support"
    }))
    .expect("fixture decodes")
}

#[test]
fn the_three_engines_describe_the_same_principals_identically() {
    let set = identity_set();
    let context = memory_context();
    context
        .validate()
        .expect("the memory context is well formed");
    assert_identity_agreement(&set, &context).expect("no reinterpretation");
}

#[test]
fn a_service_principal_does_not_become_an_authority_by_owning_memory() {
    // Cycle 015 says a SERVICE principal never originates authority. Owning or
    // writing memory is not a route around that, and Cycle 016 borrows the
    // answer rather than forming its own.
    let mut context = memory_context();
    context.acting_principal_id = "svc-1".to_owned();
    assert!(!acting_principal_originates_authority(&context).expect("declared"));

    context.acting_principal_id = "user-7".to_owned();
    assert!(acting_principal_originates_authority(&context).expect("declared"));
}

#[test]
fn a_memory_store_cannot_relabel_an_identity_the_identity_engine_already_fixed() {
    let mut context = memory_context();
    context.principals[1].kind = PrincipalKind::Human;

    let err = assert_identity_agreement(&identity_set(), &context)
        .expect_err("the disagreement must stop the run");
    assert!(err.is_refusal());
    assert!(err.to_string().contains("svc-1"));
}

#[test]
fn persistence_never_discharges_the_injection_boundary() {
    // For every source that entered through a Cycle 013 channel, the composed
    // view names that channel's property first and the memory property second.
    // Persisting adds a boundary; it removes none.
    for source in SourceKind::all() {
        let composed = composed_boundary_properties(source);
        assert!(
            composed.contains(&MemoryProperty::WriteTrustBoundary.as_str()),
            "{source:?} lost its memory write boundary"
        );

        match injection_source_for(source) {
            Some(channel) => {
                assert_eq!(composed.len(), 2, "{source:?}");
                assert_eq!(composed[0], channel.boundary_property());
            }
            None => assert_eq!(composed.len(), 1, "{source:?}"),
        }
    }
}

#[test]
fn no_content_channel_gains_policy_authority_by_being_written() {
    for source in SourceKind::all() {
        assert_ceiling_agrees_with_injection_model(source).expect("the two models agree");

        if persistence_preserves_attacker_control(source) {
            assert_ne!(
                source.default_trust_ceiling(),
                TrustClass::TrustedPolicy,
                "{source:?} would be policy-authoritative straight out of an untrusted channel"
            );
        }
    }
}

#[test]
fn the_two_engines_name_disjoint_invariants() {
    let injection = injection_invariant_names();
    let memory: Vec<&str> = MemoryInvariantType::all()
        .iter()
        .map(|invariant| invariant.as_str())
        .collect();

    for name in &memory {
        assert!(
            !injection.contains(name),
            "`{name}` is claimed by both engines"
        );
    }
    assert_eq!(memory.len(), 12);
    assert_eq!(injection.len(), 6);
}

#[test]
fn trust_level_tokens_are_shared_across_the_two_crates() {
    for level in TrustLevel::all() {
        assert_eq!(level.as_str(), injection_trust_level(level).as_str());
    }
}

#[test]
fn an_identity_principal_carries_its_tenant_across_or_is_refused() {
    let set = identity_set();

    let converted: MemoryPrincipal =
        memory_principal_from_identity(&set.principals[1], vec!["ns-support".to_owned()])
            .expect("converts");
    assert_eq!(converted.kind, PrincipalKind::Service);
    assert_eq!(converted.tenant_id, "tenant-a");

    let mut tenantless = set.principals[1].clone();
    tenantless.tenant_id = None;
    let err = memory_principal_from_identity(&tenantless, vec!["ns-support".to_owned()])
        .expect_err("a tenant may not be invented");
    assert!(err.is_refusal());
}
