//! Cycle 013 — additive prompt-injection property/predicate regressions.
//!
//! Proves the two new AGENT.GOAL boundary properties and their closed predicates
//! were added without mutating any Cycle 012 entry, and that unknown predicates
//! and unknown properties still fail closed.

use std::collections::HashSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, builtin_registry, evaluate_applicability,
    load_registry, registry_for_profile, run_assessment, validate_agentic_assets, validate_profile,
    validate_prompt_injection_standards, validate_property_instance_v2, AssessmentFacts,
    CoveragePolicy, CoverageStatus, Predicate, PropertyCategory, RiskFamily, TransportKind,
    AGENTIC_REGISTRY_JSON, EXTERNAL_CONTENT_BOUNDARY_PROPERTY, INSTRUCTION_INTEGRITY_PROPERTY,
    USER_INPUT_BOUNDARY_PROPERTY,
};
use serde_json::{json, Value};

fn facts(user_prompt: bool, external_content: bool) -> AssessmentFacts {
    AssessmentFacts {
        tools_count: 1,
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
        delegated_identity_present: false,
        external_components_present: false,
        stateful_agent_present: false,
        runtime_dynamic_allowed: false,
        user_prompt_present: user_prompt,
        untrusted_external_content_present: external_content,
        tool_metadata_present: true,
        tool_output_present: true,
        tool_chaining_present: true,
        principal_context_present: true,
        authorization_decision_present: true,
        tenant_context_present: true,
        resource_owner_context_present: true,
        out_of_scope_property_ids: Vec::new(),
    }
}

#[test]
fn both_boundary_properties_exist_in_the_agentic_registry() {
    let registry = agentic_registry().expect("registry");
    for id in [
        USER_INPUT_BOUNDARY_PROPERTY,
        EXTERNAL_CONTENT_BOUNDARY_PROPERTY,
    ] {
        let property = registry.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(property.risk_family, Some(RiskFamily::AgentGoalHijacking));
        assert_eq!(property.category, PropertyCategory::GoalIntegrity);
        assert!(property.evidence.required_for_confirmed_verdict);
        assert!(!property.standards.is_empty());
    }
}

#[test]
fn cycle012_instruction_integrity_property_is_unchanged() {
    let registry = agentic_registry().expect("registry");
    let property = registry
        .get(INSTRUCTION_INTEGRITY_PROPERTY)
        .expect("parent property");

    // Exact Cycle 012 definition, frozen in BASELINE.md section 7.
    assert_eq!(property.title, "Agent instruction and goal integrity");
    assert_eq!(property.risk_family, Some(RiskFamily::AgentGoalHijacking));
    assert_eq!(property.category, PropertyCategory::GoalIntegrity);
    assert_eq!(
        property.applicability.predicates,
        vec![Predicate::AgentPresent]
    );
    assert_eq!(property.standards.len(), 1);
    assert_eq!(property.standards[0].source, "OWASP_AGENTIC_TOP10_2026");
    assert_eq!(
        property.standards[0].reference,
        "ASI01 Agent Goal Hijacking"
    );
}

#[test]
fn registry_growth_is_purely_additive() {
    let registry = agentic_registry().expect("registry");
    // Grows additively with each cycle; Cycle 014 appended four AGENT.TOOL.* properties.
    // Additive growth only: Cycle 015 appended four properties and renamed none.
    assert_eq!(registry.properties.len(), 30);

    // Every Cycle 012 id is still present and unique.
    let ids: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate property id introduced");

    for id in [
        "AGENT.GOAL.INSTRUCTION_INTEGRITY",
        "AGENT.GOAL.TRUST_BOUNDARY",
        "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
        "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY",
        "AGENT.IDENTITY.DELEGATION_INTEGRITY",
        "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION",
        "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
        "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT",
        "AGENT.CODE_EXECUTION.BOUNDARY",
        "AGENT.CODE_EXECUTION.EGRESS_BOUNDARY",
        "AGENT.MEMORY.CONTEXT_INTEGRITY",
        "AGENT.MEMORY.TENANT_BOUNDARY",
        "AGENT.A2A.MESSAGE_AUTHENTICITY",
        "AGENT.A2A.AUTHORITY_PROPAGATION",
        "AGENT.FAILURE.RETRY_AMPLIFICATION",
        "AGENT.FAILURE.DUPLICATE_ACTION_BOUNDARY",
        "AGENT.HUMAN_APPROVAL.INTENT_BINDING",
        "AGENT.HUMAN_APPROVAL.RISK_DISCLOSURE",
        "AGENT.ROGUE.CAPABILITY_DRIFT",
        "AGENT.ROGUE.POLICY_BYPASS",
    ] {
        assert!(registry.get(id).is_some(), "Cycle 012 id {id} disappeared");
    }

    // Still exactly ten risk families; no family was invented or dropped.
    let families: HashSet<RiskFamily> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10);

    // Provenance validation still passes with the larger registry.
    validate_agentic_assets().expect("agentic assets still valid");
    validate_prompt_injection_standards().expect("prompt-injection provenance valid");
}

#[test]
fn legacy_profiles_keep_their_exact_property_sets() {
    let agentic = agentic_profile().expect("agentic profile");
    assert_eq!(agentic.id, "agentic-security-baseline-2026");
    assert_eq!(
        agentic.properties.len(),
        10,
        "Cycle 012 baseline denominator must not change"
    );
    assert!(
        !agentic
            .properties
            .iter()
            .any(|entry| entry.id == USER_INPUT_BOUNDARY_PROPERTY
                || entry.id == EXTERNAL_CONTENT_BOUNDARY_PROPERTY),
        "new properties must not be injected into the Cycle 012 baseline"
    );
    validate_profile(&agentic, &agentic_registry().unwrap()).expect("agentic profile valid");

    let mcp = builtin_profile().expect("mcp profile");
    let mcp_registry = builtin_registry().expect("mcp registry");
    assert_eq!(mcp.id, "mcp-security-baseline");
    assert_eq!(mcp_registry.properties.len(), 10);
    validate_profile(&mcp, &mcp_registry).expect("mcp profile valid");
    assert_eq!(registry_for_profile(&mcp).unwrap().properties.len(), 10);
}

#[test]
fn agentic_baseline_coverage_report_shape_is_unchanged() {
    let profile = agentic_profile().expect("profile");
    let registry = registry_for_profile(&profile).expect("registry");
    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, true),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");
    assert_eq!(report.properties.len(), 10);
}

#[test]
fn user_prompt_predicate_drives_applicability() {
    let registry = agentic_registry().expect("registry");
    let property = registry
        .require(USER_INPUT_BOUNDARY_PROPERTY)
        .expect("property");

    assert_eq!(
        evaluate_applicability(property, &facts(true, false))
            .unwrap()
            .status,
        CoverageStatus::Applicable
    );
    assert_eq!(
        evaluate_applicability(property, &facts(false, true))
            .unwrap()
            .status,
        CoverageStatus::NotApplicable
    );
}

#[test]
fn external_content_predicate_yields_not_applicable_not_pass() {
    let registry = agentic_registry().expect("registry");
    let property = registry
        .require(EXTERNAL_CONTENT_BOUNDARY_PROPERTY)
        .expect("property");

    assert_eq!(
        evaluate_applicability(property, &facts(true, true))
            .unwrap()
            .status,
        CoverageStatus::Applicable
    );

    // A target with no external-content ingestion path is NOT_APPLICABLE.
    // It is never silently promoted to a passing/secure state.
    let decision = evaluate_applicability(property, &facts(true, false)).unwrap();
    assert_eq!(decision.status, CoverageStatus::NotApplicable);
    assert_ne!(decision.status, CoverageStatus::Applicable);
}

#[test]
fn new_predicates_are_target_shape_and_serialize_stably() {
    assert!(Predicate::UserPromptPresent.is_target_shape());
    assert!(Predicate::UntrustedExternalContentPresent.is_target_shape());
    assert_eq!(Predicate::UserPromptPresent.as_str(), "user_prompt_present");
    assert_eq!(
        Predicate::UntrustedExternalContentPresent.as_str(),
        "untrusted_external_content_present"
    );
    assert_eq!(
        serde_json::to_value(Predicate::UserPromptPresent).unwrap(),
        json!("user_prompt_present")
    );
    assert_eq!(
        serde_json::to_value(Predicate::UntrustedExternalContentPresent).unwrap(),
        json!("untrusted_external_content_present")
    );
}

#[test]
fn unknown_predicate_still_fails_closed() {
    assert!(serde_json::from_str::<Predicate>("\"prompt_injection_present\"").is_err());
    assert!(serde_json::from_str::<Predicate>("\"user_prompt_present_\"").is_err());
    assert!(serde_json::from_str::<Predicate>("\"USER_PROMPT_PRESENT\"").is_err());

    let mut property: Value = serde_json::from_str(AGENTIC_REGISTRY_JSON).unwrap();
    property["properties"][2]["applicability"]["predicates"] = json!(["shell_present"]);
    assert!(validate_property_instance_v2(&property["properties"][2]).is_err());
}

#[test]
fn duplicate_boundary_property_id_fails_closed() {
    let mut value: Value = serde_json::from_str(AGENTIC_REGISTRY_JSON).unwrap();
    let clone = value["properties"][2].clone();
    value["properties"].as_array_mut().unwrap().push(clone);
    let raw = serde_json::to_string(&value).unwrap();
    assert!(
        load_registry(&raw).is_err(),
        "duplicate property id must fail closed"
    );
}

#[test]
fn boundary_properties_declare_no_executable_or_credential_fields() {
    let value: Value = serde_json::from_str(AGENTIC_REGISTRY_JSON).unwrap();
    let raw = serde_json::to_string(&value).unwrap();
    for forbidden in [
        "\"shell\"",
        "\"eval\"",
        "\"script\"",
        "\"callback\"",
        "\"command\"",
        "\"api_key\"",
        "\"token\"",
        "\"url\"",
    ] {
        assert!(
            !raw.contains(forbidden),
            "registry must not contain {forbidden}"
        );
    }
}
