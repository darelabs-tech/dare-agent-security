//! Cycle 015 identity-security properties and predicates.
//!
//! The registry grew by four properties and four predicates. These tests exist
//! to prove that is *all* that happened: the two pre-existing
//! `AGENT.IDENTITY.*` properties are unchanged field by field, nothing was
//! renamed or reordered, no earlier profile moved, and every new predicate
//! fails closed when unknown.

use std::collections::{BTreeSet, HashSet};

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, builtin_registry, evaluate_applicability,
    prompt_injection_profile, tool_security_profile, AssessmentFacts, CoverageStatus, Predicate,
    PropertyCategory, RiskFamily, TransportKind,
};

/// Facts with every Cycle 015 predicate independently controllable.
#[allow(clippy::fn_params_excessive_bools)]
fn facts(
    principal: bool,
    decision: bool,
    tenant: bool,
    owner: bool,
    delegated: bool,
) -> AssessmentFacts {
    AssessmentFacts {
        tools_count: 2,
        resources_count: 1,
        prompts_count: 1,
        transport: TransportKind::Stdio,
        authorization_present: true,
        dynamic_authorization_allowed: false,
        execution_integrity_supported: true,
        confused_deputy_supported: true,
        agent_present: true,
        memory_present: false,
        rag_present: false,
        multi_agent_present: false,
        code_execution_present: false,
        human_approval_present: false,
        delegated_identity_present: delegated,
        external_components_present: false,
        stateful_agent_present: false,
        runtime_dynamic_allowed: false,
        user_prompt_present: true,
        untrusted_external_content_present: true,
        tool_metadata_present: true,
        tool_output_present: true,
        tool_chaining_present: true,
        principal_context_present: principal,
        authorization_decision_present: decision,
        tenant_context_present: tenant,
        resource_owner_context_present: owner,
        out_of_scope_property_ids: Vec::new(),
    }
}

const PRINCIPAL_BINDING: &str = "AGENT.IDENTITY.PRINCIPAL_BINDING";
const DELEGATION_SCOPE: &str = "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY";
const TENANT_RESOURCE: &str = "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY";
const AUTHORIZATION_BINDING: &str = "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING";
const DELEGATION_INTEGRITY: &str = "AGENT.IDENTITY.DELEGATION_INTEGRITY";
const PRIVILEGE_AMPLIFICATION: &str = "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION";

#[test]
fn the_registry_grew_by_exactly_four_properties() {
    let registry = agentic_registry().expect("agentic registry");
    assert_eq!(
        registry.properties.len(),
        30,
        "26 before Cycle 015; four appended, none removed"
    );

    let identity: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .filter(|id| id.starts_with("AGENT.IDENTITY."))
        .collect();
    assert_eq!(
        identity,
        [
            DELEGATION_INTEGRITY,
            PRIVILEGE_AMPLIFICATION,
            PRINCIPAL_BINDING,
            DELEGATION_SCOPE,
            TENANT_RESOURCE,
            AUTHORIZATION_BINDING,
        ],
        "the two pre-existing ids must keep their position; the four new ones append after them"
    );
}

#[test]
fn the_two_pre_existing_properties_are_unchanged_field_by_field() {
    // Criteria 4 and 5 are about these exact objects, so this compares every
    // field rather than checking that the ids still exist.
    let registry = agentic_registry().expect("agentic registry");

    let delegation = registry.require(DELEGATION_INTEGRITY).expect("present");
    assert_eq!(delegation.title, "Delegated identity integrity");
    assert_eq!(delegation.category, PropertyCategory::Delegation);
    assert_eq!(
        delegation.description,
        "Delegated authority must remain bound to the original principal, purpose and permitted \
         scope."
    );
    assert_eq!(
        delegation.applicability.predicates,
        vec![Predicate::AgentPresent, Predicate::DelegatedIdentityPresent]
    );

    let privilege = registry.require(PRIVILEGE_AMPLIFICATION).expect("present");
    assert_eq!(privilege.title, "Privilege amplification prevention");
    assert_eq!(privilege.category, PropertyCategory::Privilege);
    assert_eq!(
        privilege.description,
        "Agent-mediated execution must not gain privileges beyond the authorized principal or \
         explicitly delegated authority."
    );
    assert_eq!(
        privilege.applicability.predicates,
        vec![Predicate::AgentPresent, Predicate::AuthorizationPresent]
    );
}

#[test]
fn every_new_property_belongs_to_the_identity_risk_family() {
    let registry = agentic_registry().expect("agentic registry");
    for id in [
        PRINCIPAL_BINDING,
        DELEGATION_SCOPE,
        TENANT_RESOURCE,
        AUTHORIZATION_BINDING,
    ] {
        let property = registry.require(id).expect("property is registered");
        assert_eq!(
            property.risk_family,
            Some(RiskFamily::IdentityPrivilegeAbuse),
            "{id} must map to the approved risk family"
        );
        assert!(!property.description.trim().is_empty(), "{id}");
        assert!(
            property
                .standards
                .iter()
                .any(|standard| standard.reference.contains("ASI03")),
            "{id} must carry its ASI03 attribution"
        );
    }
}

#[test]
fn the_new_properties_use_the_categories_the_design_named() {
    let registry = agentic_registry().expect("agentic registry");
    let category = |id: &str| registry.require(id).expect("present").category;
    assert_eq!(
        category(PRINCIPAL_BINDING),
        PropertyCategory::PrincipalBinding
    );
    assert_eq!(category(DELEGATION_SCOPE), PropertyCategory::Delegation);
    assert_eq!(category(TENANT_RESOURCE), PropertyCategory::TenantIsolation);
    assert_eq!(
        category(AUTHORIZATION_BINDING),
        PropertyCategory::AuthorizationIntegrity
    );
}

#[test]
fn each_new_predicate_drives_the_applicability_of_its_own_property() {
    let registry = agentic_registry().expect("agentic registry");

    // Present: the property is eligible.
    let all_present = facts(true, true, true, true, true);
    for id in [
        PRINCIPAL_BINDING,
        DELEGATION_SCOPE,
        TENANT_RESOURCE,
        AUTHORIZATION_BINDING,
    ] {
        let property = registry.require(id).expect("present");
        let decision = evaluate_applicability(property, &all_present).expect("evaluates");
        assert_ne!(
            decision.status,
            CoverageStatus::NotApplicable,
            "{id} should be eligible when its shape is present"
        );
    }

    // Absent: the property is NOT_APPLICABLE rather than silently passing.
    let none_present = facts(false, false, false, false, false);
    for id in [
        PRINCIPAL_BINDING,
        DELEGATION_SCOPE,
        TENANT_RESOURCE,
        AUTHORIZATION_BINDING,
    ] {
        let property = registry.require(id).expect("present");
        let decision = evaluate_applicability(property, &none_present).expect("evaluates");
        assert_eq!(
            decision.status,
            CoverageStatus::NotApplicable,
            "{id} must be NOT_APPLICABLE when its shape is absent"
        );
    }
}

#[test]
fn a_partially_present_shape_still_yields_not_applicable() {
    // TENANT_RESOURCE needs both tenant and owner context. Having one is not
    // having the shape, and must not make the property eligible.
    let registry = agentic_registry().expect("agentic registry");
    let property = registry.require(TENANT_RESOURCE).expect("present");

    assert_eq!(
        evaluate_applicability(property, &facts(true, true, true, false, true))
            .expect("evaluates")
            .status,
        CoverageStatus::NotApplicable,
        "tenant context without owner context is not the target shape"
    );
    assert_eq!(
        evaluate_applicability(property, &facts(true, true, false, true, true))
            .expect("evaluates")
            .status,
        CoverageStatus::NotApplicable,
        "owner context without tenant context is not the target shape"
    );
}

#[test]
fn the_new_predicates_serialize_stably_and_are_target_shape() {
    for (predicate, token) in [
        (
            Predicate::PrincipalContextPresent,
            "principal_context_present",
        ),
        (
            Predicate::AuthorizationDecisionPresent,
            "authorization_decision_present",
        ),
        (Predicate::TenantContextPresent, "tenant_context_present"),
        (
            Predicate::ResourceOwnerContextPresent,
            "resource_owner_context_present",
        ),
    ] {
        assert_eq!(predicate.as_str(), token);
        assert_eq!(
            serde_json::to_value(predicate).expect("serializes"),
            serde_json::json!(token)
        );
        // Target-shape predicates yield NOT_APPLICABLE when false, rather than
        // BLOCKED. These describe what the target *is*, not what ROE allows.
        assert!(predicate.is_target_shape(), "{token}");
    }
}

#[test]
fn an_unknown_predicate_still_fails_closed() {
    let raw = r#"{
        "id": "AGENT.IDENTITY.INVENTED",
        "title": "invented",
        "risk_family": "IDENTITY_PRIVILEGE_ABUSE",
        "category": "PRINCIPAL_BINDING",
        "description": "invented",
        "applicability": {"predicates": ["identity_telepathy_present"]},
        "supported_modes": ["static"],
        "evidence": {"required_for_confirmed_verdict": true, "accepted_classes": ["POLICY"]},
        "standards": [],
        "maturity": "EXPERIMENTAL"
    }"#;
    let value: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    assert!(
        dare_coverage::validate_property_instance(&value).is_err(),
        "an unknown predicate must be refused, never treated as satisfied"
    );
}

#[test]
fn an_unknown_category_still_fails_closed() {
    let raw = r#"{
        "id": "AGENT.IDENTITY.INVENTED",
        "title": "invented",
        "risk_family": "IDENTITY_PRIVILEGE_ABUSE",
        "category": "TELEPATHY",
        "description": "invented",
        "applicability": {"predicates": ["agent_present"]},
        "supported_modes": ["static"],
        "evidence": {"required_for_confirmed_verdict": true, "accepted_classes": ["POLICY"]},
        "standards": [],
        "maturity": "EXPERIMENTAL"
    }"#;
    let value: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    assert!(dare_coverage::validate_property_instance(&value).is_err());
}

#[test]
fn no_earlier_profile_picked_up_one_of_the_four_new_properties() {
    // Denominators are per-profile. An earlier profile silently gaining one of
    // these would grow its denominator without approval.
    let added: BTreeSet<&str> = BTreeSet::from([
        PRINCIPAL_BINDING,
        DELEGATION_SCOPE,
        TENANT_RESOURCE,
        AUTHORIZATION_BINDING,
    ]);
    for profile in [
        builtin_profile().expect("mcp"),
        agentic_profile().expect("agentic"),
        prompt_injection_profile().expect("prompt-injection"),
        tool_security_profile().expect("tool-security"),
    ] {
        for entry in &profile.properties {
            assert!(
                !added.contains(entry.id.as_str()),
                "{} unexpectedly selects {}",
                profile.id,
                entry.id
            );
        }
    }
}

#[test]
fn earlier_profiles_keep_their_exact_property_counts() {
    assert_eq!(builtin_profile().expect("mcp").properties.len(), 10);
    assert_eq!(agentic_profile().expect("agentic").properties.len(), 10);
    assert_eq!(
        prompt_injection_profile()
            .expect("prompt-injection")
            .properties
            .len(),
        3
    );
    assert_eq!(
        tool_security_profile()
            .expect("tool-security")
            .properties
            .len(),
        6
    );
}

#[test]
fn the_v1_registry_did_not_move() {
    // Cycle 015 touches the v2 registry only. The MCP baseline reads v1.
    let v1 = builtin_registry().expect("v1 registry");
    assert_eq!(v1.properties.len(), 10);
    assert!(
        !v1.properties
            .iter()
            .any(|property| property.id.starts_with("AGENT.IDENTITY.")),
        "no AGENT.IDENTITY.* property belongs in the v1 registry"
    );
}

#[test]
fn every_registry_property_id_is_unique() {
    let registry = agentic_registry().expect("agentic registry");
    let mut seen = HashSet::new();
    for property in &registry.properties {
        assert!(
            seen.insert(property.id.as_str()),
            "duplicate property id {}",
            property.id
        );
    }
    assert_eq!(seen.len(), 30);
}

#[test]
fn no_identity_property_declares_an_executable_or_credential_field() {
    // A property is declarative data. A field that could carry a token or a
    // callback has no business in the registry.
    let raw: serde_json::Value =
        serde_json::from_str(dare_coverage::AGENTIC_REGISTRY_JSON).expect("registry parses");
    let identity: Vec<&serde_json::Value> = raw["properties"]
        .as_array()
        .expect("properties")
        .iter()
        .filter(|property| {
            property["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("AGENT.IDENTITY.")
        })
        .collect();
    assert_eq!(identity.len(), 6);

    for property in identity {
        let encoded = serde_json::to_string(property).expect("serializes");
        for forbidden in [
            "\"shell\"",
            "\"eval\"",
            "\"callback\"",
            "\"command\"",
            "\"token\"",
            "\"bearer\"",
            "\"api_key\"",
            "\"client_secret\"",
            "\"private_key\"",
            "\"url\"",
            "\"endpoint\"",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "{} declares {forbidden}",
                property["id"]
            );
        }
    }
}
