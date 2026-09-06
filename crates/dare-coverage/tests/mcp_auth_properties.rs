//! Cycle 018 `MCP.AUTH.*` properties, predicates and applicability semantics.
//!
//! The ten new properties are additive to the **v1 MCP registry**, not the v2
//! Agentic one. That placement is the whole reason this cycle needs no
//! exclusion rule to keep the Agentic risk-family count at ten: nothing was
//! added to the registry that carries families, so nothing could have created
//! an eleventh.
//!
//! The subtler contract this suite exists to pin is applicability. A predicate
//! that is false can mean two completely different things, and conflating them
//! is the failure mode acceptance criterion 8 was written for:
//!
//! - the target does not have the surface at all — a stdio-only server has no
//!   HTTP authorization surface — and `NOT_APPLICABLE` is honest;
//! - the target *has* the auth surface and the control or its evidence is
//!   missing — no Protected Resource Metadata, no token claims, no PKCE
//!   context — which is a **gap**.
//!
//! Reporting the second as `NOT_APPLICABLE` would let a server missing its
//! authorization metadata score identically to one that was never in scope, and
//! would shrink the denominator by exactly the properties most worth asking
//! about. Those resolve to `NOT_TESTED` instead.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_registry, builtin_profile, builtin_registry, mcp_auth_security_provenance,
    AssessmentFacts, CoverageStatus, PropertyRegistry, TransportKind,
};

/// The ten properties approved for Cycle 018, in approved order.
const MCP_AUTH_PROPERTIES: [&str; 10] = [
    "MCP.AUTH.PROTOCOL_BINDING",
    "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
    "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
    "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
    "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
    "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
    "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
    "MCP.AUTH.CREDENTIAL_SEPARATION",
    "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY",
    "MCP.AUTH.FINAL_OPERATION_BINDING",
];

/// The ten v1 properties that predate this cycle.
const PRE_EXISTING: [&str; 10] = [
    "MCP.DISCOVERY.PASSIVE_BOUNDARY",
    "MCP.DISCOVERY.EXPLICIT_TARGET",
    "MCP.AUTHZ.PER_OPERATION",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT",
    "MCP.EVIDENCE.REDACTION",
    "MCP.IDENTITY.CONFUSED_DEPUTY",
    "MCP.DISCOVERY.STREAMABLE_HTTP",
    "MCP.AUTHZ.DYNAMIC_VALIDATION",
];

/// Predicates that describe the shape of the target. False means the question
/// genuinely does not apply.
const TARGET_SHAPE_PREDICATES: [&str; 4] = [
    "mcp_current_protocol_present",
    "mcp_http_transport_present",
    "mcp_auth_flow_present",
    "mcp_identity_metadata_present",
];

/// Predicates that describe an auth control or an evidence channel. False means
/// a gap, never an exemption.
const CONTROL_EVIDENCE_PREDICATES: [&str; 7] = [
    "protected_resource_metadata_present",
    "authorization_server_metadata_present",
    "token_claims_present",
    "pkce_context_present",
    "scope_challenge_present",
    "client_registration_present",
    "credential_forwarding_present",
];

fn registry() -> PropertyRegistry {
    builtin_registry().expect("v1 registry loads")
}

/// A target that has every Cycle 018 surface and every control.
fn full_auth_target() -> AssessmentFacts {
    AssessmentFacts {
        tools_count: 2,
        resources_count: 0,
        prompts_count: 0,
        transport: TransportKind::Http,
        authorization_present: true,
        dynamic_authorization_allowed: true,
        execution_integrity_supported: true,
        confused_deputy_supported: true,
        agent_present: true,
        memory_present: false,
        rag_present: false,
        multi_agent_present: false,
        code_execution_present: false,
        human_approval_present: false,
        delegated_identity_present: false,
        external_components_present: false,
        stateful_agent_present: false,
        runtime_dynamic_allowed: false,
        user_prompt_present: false,
        untrusted_external_content_present: false,
        tool_metadata_present: false,
        tool_output_present: false,
        tool_chaining_present: false,
        principal_context_present: false,
        authorization_decision_present: false,
        tenant_context_present: false,
        resource_owner_context_present: false,
        memory_provenance_present: false,
        memory_recall_present: false,
        memory_lifecycle_present: false,
        memory_namespace_present: false,
        retrieval_trace_present: false,
        retrieval_policy_present: false,
        document_acl_present: false,
        retrieval_provenance_present: false,
        retrieval_tenant_context_present: false,
        mcp_current_protocol_present: true,
        mcp_http_transport_present: true,
        mcp_auth_flow_present: true,
        mcp_identity_metadata_present: true,
        protected_resource_metadata_present: true,
        authorization_server_metadata_present: true,
        token_claims_present: true,
        pkce_context_present: true,
        scope_challenge_present: true,
        client_registration_present: true,
        credential_forwarding_present: true,
        out_of_scope_property_ids: Vec::new(),
    }
}

/// Set one named predicate false on an otherwise complete target.
fn without(predicate: &str) -> AssessmentFacts {
    let mut facts = full_auth_target();
    match predicate {
        "mcp_current_protocol_present" => facts.mcp_current_protocol_present = false,
        "mcp_http_transport_present" => facts.mcp_http_transport_present = false,
        "mcp_auth_flow_present" => facts.mcp_auth_flow_present = false,
        "mcp_identity_metadata_present" => facts.mcp_identity_metadata_present = false,
        "protected_resource_metadata_present" => facts.protected_resource_metadata_present = false,
        "authorization_server_metadata_present" => {
            facts.authorization_server_metadata_present = false
        }
        "token_claims_present" => facts.token_claims_present = false,
        "pkce_context_present" => facts.pkce_context_present = false,
        "scope_challenge_present" => facts.scope_challenge_present = false,
        "client_registration_present" => facts.client_registration_present = false,
        "credential_forwarding_present" => facts.credential_forwarding_present = false,
        other => panic!("unknown predicate {other}"),
    }
    facts
}

/// The first Cycle 018 property whose applicability names this predicate.
fn property_requiring(predicate: &str) -> String {
    let registry = registry();
    registry
        .properties
        .iter()
        .find(|property| {
            MCP_AUTH_PROPERTIES.contains(&property.id.as_str())
                && property
                    .applicability
                    .predicates
                    .iter()
                    .any(|declared| declared.as_str() == predicate)
        })
        .map(|property| property.id.clone())
        .unwrap_or_else(|| panic!("no Cycle 018 property requires {predicate}"))
}

#[test]
fn the_ten_approved_properties_exist_and_no_others_were_added() {
    let registry = registry();
    let present: BTreeSet<&str> = registry
        .properties
        .iter()
        .filter(|property| {
            property.id.starts_with("MCP.AUTH.")
                || property.id == "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY"
        })
        .map(|property| property.id.as_str())
        .collect();
    let approved: BTreeSet<&str> = MCP_AUTH_PROPERTIES.into_iter().collect();
    assert_eq!(present, approved);
}

#[test]
fn every_property_that_predates_this_cycle_is_unchanged() {
    // Identity, not count. A rename silently stops matching every assessment
    // already filed against the old id, and a count never detects one.
    let registry = registry();
    for id in PRE_EXISTING {
        assert!(registry.get(id).is_some(), "{id} disappeared from v1");
    }
    assert_eq!(registry.properties.len(), 20);
}

#[test]
fn the_new_properties_did_not_enter_the_mcp_baseline_profile() {
    // `mcp-security-baseline` is the denominator of every coverage percentage
    // already filed against it. Ten properties in, ten properties out.
    let profile = builtin_profile().expect("mcp profile");
    assert_eq!(profile.properties.len(), 10);
    for entry in &profile.properties {
        assert!(
            !MCP_AUTH_PROPERTIES.contains(&entry.id.as_str()),
            "{} leaked into the MCP baseline",
            entry.id
        );
    }
}

#[test]
fn the_agentic_registry_and_its_family_count_are_untouched() {
    // Cycle 018 adds to v1. The v2 registry carries the risk families, so
    // adding nothing to it is what keeps the count at ten — there is no
    // exclusion rule doing the work, and there is nothing to exclude.
    let agentic = agentic_registry().expect("v2 registry");
    assert_eq!(agentic.properties.len(), 40);
    let families: std::collections::HashSet<_> = agentic
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10);

    for property in &agentic.properties {
        assert!(
            !MCP_AUTH_PROPERTIES.contains(&property.id.as_str()),
            "{} does not belong in the Agentic registry",
            property.id
        );
    }
}

#[test]
fn no_new_property_carries_an_agentic_risk_family() {
    let registry = registry();
    for id in MCP_AUTH_PROPERTIES {
        let property = registry.get(id).expect("present");
        assert!(
            property.risk_family.is_none(),
            "{id} claims an Agentic risk family"
        );
    }
}

#[test]
fn a_target_without_the_surface_is_not_applicable() {
    // The honest half of the applicability contract.
    let registry = registry();
    for predicate in TARGET_SHAPE_PREDICATES {
        let id = property_requiring(predicate);
        let property = registry.get(&id).expect("present");
        let decision = dare_coverage::evaluate_applicability(property, &without(predicate))
            .expect("evaluates");
        assert_eq!(
            decision.status,
            CoverageStatus::NotApplicable,
            "{predicate} absent should be NOT_APPLICABLE for {id}: {}",
            decision.rationale
        );
    }
}

#[test]
fn a_missing_auth_control_is_a_gap_and_never_not_applicable() {
    // The half that acceptance criterion 8 is about, and the one that would
    // otherwise flatter a target. Every one of these targets *has* the auth
    // surface; what is missing is the control or the evidence for it.
    let registry = registry();
    for predicate in CONTROL_EVIDENCE_PREDICATES {
        let id = property_requiring(predicate);
        let property = registry.get(&id).expect("present");
        let decision = dare_coverage::evaluate_applicability(property, &without(predicate))
            .expect("evaluates");

        assert_ne!(
            decision.status,
            CoverageStatus::NotApplicable,
            "{predicate} absent was relabeled NOT_APPLICABLE for {id}, which hides a gap"
        );
        assert_eq!(
            decision.status,
            CoverageStatus::NotTested,
            "{predicate} absent should be NOT_TESTED for {id}: {}",
            decision.rationale
        );
        assert!(
            decision.rationale.contains("gap"),
            "the rationale should say why: {}",
            decision.rationale
        );
    }
}

#[test]
fn a_complete_target_makes_every_new_property_applicable() {
    // The mirror of the two tests above. If nothing were ever applicable, the
    // NOT_APPLICABLE and NOT_TESTED assertions would pass vacuously.
    let registry = registry();
    let facts = full_auth_target();
    for id in MCP_AUTH_PROPERTIES {
        let property = registry.get(id).expect("present");
        let decision = dare_coverage::evaluate_applicability(property, &facts).expect("evaluates");
        assert_eq!(
            decision.status,
            CoverageStatus::Applicable,
            "{id} was not applicable to a complete target: {}",
            decision.rationale
        );
    }
}

#[test]
fn every_new_property_declares_at_least_one_target_shape_predicate() {
    // Without one, a property would be evaluated against a target that has no
    // MCP auth surface at all, and would report a gap where there is genuinely
    // nothing to assess.
    let registry = registry();
    for id in MCP_AUTH_PROPERTIES {
        let property = registry.get(id).expect("present");
        assert!(
            property
                .applicability
                .predicates
                .iter()
                .any(|predicate| TARGET_SHAPE_PREDICATES.contains(&predicate.as_str())),
            "{id} declares no target-shape predicate"
        );
    }
}

#[test]
fn an_unknown_predicate_fails_closed() {
    // The registry schema is a closed enum. A predicate nobody defined must
    // stop the load rather than be ignored, because an ignored predicate makes
    // a property applicable to targets it was never meant for.
    let hostile = serde_json::json!({
        "schema": { "id": "https://darelabs.tech/schemas/coverage/v1/registry.json",
                    "version": "1.0.0" },
        "properties": [{
            "id": "MCP.AUTH.PROTOCOL_BINDING",
            "title": "t",
            "category": "AUTHENTICATION",
            "description": "d",
            "applicability": { "predicates": ["mcp_quantum_readiness_present"] },
            "supported_modes": ["static"],
            "evidence": { "required_for_confirmed_verdict": true },
            "standards": [{ "source": "MCP", "reference": "r", "status": "NORMATIVE" }]
        }]
    });
    assert!(dare_coverage::load_registry(&hostile.to_string()).is_err());
}

#[test]
fn every_new_property_is_mapped_in_the_standards_manifest() {
    // A property with no recorded provenance would appear in a report with no
    // way for a reader to learn where it came from or what status it carries.
    let provenance = mcp_auth_security_provenance().expect("provenance valid");
    for id in MCP_AUTH_PROPERTIES {
        assert!(
            provenance
                .property_mappings
                .iter()
                .any(|mapping| mapping.property_id == id),
            "{id} has no standards mapping"
        );
    }
}

#[test]
fn the_open_proposal_property_records_its_status_honestly() {
    // Final-operation binding is the one property whose upstream reference is
    // an open discussion rather than a specification. Recording it as anything
    // firmer would manufacture a requirement, and the implementation does not
    // depend on the proposal being accepted.
    let registry = registry();
    let property = registry
        .get("MCP.AUTH.FINAL_OPERATION_BINDING")
        .expect("present");
    assert_eq!(property.standards[0].status.as_str(), "OPEN_PROPOSAL");

    let provenance = mcp_auth_security_provenance().expect("provenance valid");
    let mapping = provenance
        .property_mappings
        .iter()
        .find(|mapping| mapping.property_id == "MCP.AUTH.FINAL_OPERATION_BINDING")
        .expect("mapped");
    assert_eq!(mapping.status, "OPEN_PROPOSAL");
    assert_eq!(mapping.relation, "COMPOSES_WITH");
}
