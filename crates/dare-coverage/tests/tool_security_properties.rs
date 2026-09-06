//! Cycle 014 — additive Tool Security property/predicate regressions.
//!
//! Proves the four new `AGENT.TOOL.*` properties and their closed predicates
//! were added without mutating any pre-existing entry, and that unknown
//! predicates and duplicate ids still fail closed.

use std::collections::HashSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, builtin_registry, evaluate_applicability,
    load_registry, prompt_injection_profile, registry_for_profile, run_assessment,
    validate_agentic_assets, validate_profile, validate_property_instance_v2,
    validate_tool_security_standards, AssessmentFacts, CoveragePolicy, CoverageStatus, Predicate,
    PropertyCategory, RiskFamily, TransportKind, AGENTIC_REGISTRY_JSON,
    TOOL_ARGUMENT_INTEGRITY_PROPERTY, TOOL_AUTHORIZATION_BOUNDARY_PROPERTY,
    TOOL_CHAIN_BOUNDARY_PROPERTY, TOOL_METADATA_TRUST_BOUNDARY_PROPERTY,
    TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY, TOOL_SELECTION_INTENT_BINDING_PROPERTY,
};
use serde_json::{json, Value};

/// Facts with every tool-shape predicate independently controllable.
#[allow(clippy::fn_params_excessive_bools)]
fn facts(tools: bool, metadata: bool, output: bool, chaining: bool) -> AssessmentFacts {
    AssessmentFacts {
        tools_count: u32::from(tools),
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
        user_prompt_present: true,
        untrusted_external_content_present: true,
        tool_metadata_present: metadata,
        tool_output_present: output,
        tool_chaining_present: chaining,
        principal_context_present: false,
        authorization_decision_present: false,
        tenant_context_present: false,
        resource_owner_context_present: false,
        out_of_scope_property_ids: Vec::new(),
    }
}

#[test]
fn all_four_specialized_properties_exist_with_the_approved_taxonomy() {
    let registry = agentic_registry().expect("registry");
    for id in [
        TOOL_METADATA_TRUST_BOUNDARY_PROPERTY,
        TOOL_SELECTION_INTENT_BINDING_PROPERTY,
        TOOL_ARGUMENT_INTEGRITY_PROPERTY,
        TOOL_CHAIN_BOUNDARY_PROPERTY,
    ] {
        let property = registry.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(
            property.risk_family,
            Some(RiskFamily::ToolMisuseExploitation),
            "{id}"
        );
        assert_eq!(property.category, PropertyCategory::ToolSecurity, "{id}");
        assert!(property.evidence.required_for_confirmed_verdict, "{id}");
        assert!(!property.standards.is_empty(), "{id}");
        assert_eq!(property.standards[0].source, "OWASP_AGENTIC_TOP10_2026");
        assert_eq!(
            property.standards[0].reference,
            "ASI02 Tool Misuse and Exploitation"
        );
    }
}

#[test]
fn the_two_cycle_012_tool_properties_are_unchanged() {
    let registry = agentic_registry().expect("registry");

    // Exact Cycle 012 definitions, frozen in BASELINE.md section 8.
    let authorization = registry
        .get(TOOL_AUTHORIZATION_BOUNDARY_PROPERTY)
        .expect("authorization boundary");
    assert_eq!(authorization.title, "Tool authorization boundary");
    assert_eq!(
        authorization.risk_family,
        Some(RiskFamily::ToolMisuseExploitation)
    );
    assert_eq!(authorization.category, PropertyCategory::ToolSecurity);
    assert_eq!(
        authorization.applicability.predicates,
        vec![Predicate::AgentPresent, Predicate::ToolsPresent]
    );
    assert_eq!(authorization.standards.len(), 1);

    let output = registry
        .get(TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY)
        .expect("output trust boundary");
    assert_eq!(output.title, "Tool output trust boundary");
    assert_eq!(output.risk_family, Some(RiskFamily::ToolMisuseExploitation));
    assert_eq!(output.category, PropertyCategory::ToolSecurity);
    assert_eq!(
        output.applicability.predicates,
        vec![Predicate::AgentPresent, Predicate::ToolsPresent]
    );
    assert_eq!(output.standards.len(), 1);
}

#[test]
fn registry_growth_is_purely_additive() {
    let registry = agentic_registry().expect("registry");
    // Additive growth only: Cycle 015 appended four properties and renamed none.
    assert_eq!(registry.properties.len(), 30);

    let ids: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate property id introduced");

    // Every id present at the Cycle 013 baseline is still present.
    for id in [
        "AGENT.GOAL.INSTRUCTION_INTEGRITY",
        "AGENT.GOAL.TRUST_BOUNDARY",
        "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
        "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
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
        assert!(
            registry.get(id).is_some(),
            "pre-existing id {id} disappeared"
        );
    }

    // Still exactly ten risk families.
    let families: HashSet<RiskFamily> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10);

    validate_agentic_assets().expect("agentic assets still valid");
    validate_tool_security_standards().expect("tool-security provenance valid");
}

#[test]
fn every_existing_profile_keeps_its_exact_property_set() {
    let mcp = builtin_profile().expect("mcp profile");
    assert_eq!(mcp.properties.len(), 10);
    assert_eq!(builtin_registry().unwrap().properties.len(), 10);
    validate_profile(&mcp, &builtin_registry().unwrap()).expect("mcp valid");

    let agentic = agentic_profile().expect("agentic profile");
    assert_eq!(agentic.properties.len(), 10);
    validate_profile(&agentic, &agentic_registry().unwrap()).expect("agentic valid");

    let prompt_injection = prompt_injection_profile().expect("prompt-injection profile");
    assert_eq!(prompt_injection.properties.len(), 3);
    validate_profile(&prompt_injection, &agentic_registry().unwrap()).expect("pi valid");

    // None of the new Cycle 014 properties leaked into an existing profile.
    for profile in [&mcp, &agentic, &prompt_injection] {
        assert!(
            !profile
                .properties
                .iter()
                .any(|entry| entry.id.starts_with("AGENT.TOOL.")
                    && entry.id != TOOL_AUTHORIZATION_BOUNDARY_PROPERTY
                    && entry.id != TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY),
            "a Cycle 014 property leaked into profile {}",
            profile.id
        );
    }
}

#[test]
fn existing_profile_report_shapes_are_unchanged() {
    for (profile, expected) in [
        (builtin_profile().unwrap(), 10usize),
        (agentic_profile().unwrap(), 10),
        (prompt_injection_profile().unwrap(), 3),
    ] {
        let registry = registry_for_profile(&profile).expect("registry");
        let report = run_assessment(
            &profile,
            &registry,
            &facts(true, true, true, true),
            &[],
            CoveragePolicy::default(),
        )
        .expect("report");
        assert_eq!(report.properties.len(), expected, "{}", profile.id);
    }
}

#[test]
fn tool_metadata_predicate_drives_applicability() {
    let registry = agentic_registry().expect("registry");
    let property = registry
        .require(TOOL_METADATA_TRUST_BOUNDARY_PROPERTY)
        .expect("property");

    assert_eq!(
        evaluate_applicability(property, &facts(true, true, true, true))
            .unwrap()
            .status,
        CoverageStatus::Applicable
    );
    // No tool metadata surface: NOT_APPLICABLE, never a pass.
    let decision = evaluate_applicability(property, &facts(true, false, true, true)).unwrap();
    assert_eq!(decision.status, CoverageStatus::NotApplicable);
    assert_ne!(decision.status, CoverageStatus::Applicable);
}

#[test]
fn tool_chaining_predicate_drives_applicability() {
    let registry = agentic_registry().expect("registry");
    let property = registry
        .require(TOOL_CHAIN_BOUNDARY_PROPERTY)
        .expect("property");

    assert_eq!(
        evaluate_applicability(property, &facts(true, true, true, true))
            .unwrap()
            .status,
        CoverageStatus::Applicable
    );
    assert_eq!(
        evaluate_applicability(property, &facts(true, true, true, false))
            .unwrap()
            .status,
        CoverageStatus::NotApplicable
    );
}

#[test]
fn selection_and_argument_properties_need_only_a_tool_surface() {
    let registry = agentic_registry().expect("registry");
    for id in [
        TOOL_SELECTION_INTENT_BINDING_PROPERTY,
        TOOL_ARGUMENT_INTEGRITY_PROPERTY,
    ] {
        let property = registry.require(id).expect("property");
        assert_eq!(
            evaluate_applicability(property, &facts(true, false, false, false))
                .unwrap()
                .status,
            CoverageStatus::Applicable,
            "{id}"
        );
        // No tools at all: NOT_APPLICABLE.
        assert_eq!(
            evaluate_applicability(property, &facts(false, false, false, false))
                .unwrap()
                .status,
            CoverageStatus::NotApplicable,
            "{id}"
        );
    }
}

#[test]
fn new_predicates_are_target_shape_and_serialize_stably() {
    for (predicate, token) in [
        (Predicate::ToolMetadataPresent, "tool_metadata_present"),
        (Predicate::ToolOutputPresent, "tool_output_present"),
        (Predicate::ToolChainingPresent, "tool_chaining_present"),
    ] {
        assert!(predicate.is_target_shape(), "{token} must be target shape");
        assert_eq!(predicate.as_str(), token);
        assert_eq!(serde_json::to_value(predicate).unwrap(), json!(token));
        assert_eq!(
            serde_json::from_value::<Predicate>(json!(token)).unwrap(),
            predicate
        );
    }
}

#[test]
fn unknown_predicate_still_fails_closed() {
    for token in [
        "\"tool_present\"",
        "\"TOOL_METADATA_PRESENT\"",
        "\"tool_execution_allowed\"",
        "\"live_mcp_present\"",
    ] {
        assert!(
            serde_json::from_str::<Predicate>(token).is_err(),
            "{token} must not decode"
        );
    }

    let mut property: Value = serde_json::from_str(AGENTIC_REGISTRY_JSON).unwrap();
    property["properties"][2]["applicability"]["predicates"] = json!(["exec_tool"]);
    assert!(validate_property_instance_v2(&property["properties"][2]).is_err());
}

#[test]
fn duplicate_tool_property_id_fails_closed() {
    let mut value: Value = serde_json::from_str(AGENTIC_REGISTRY_JSON).unwrap();
    let clone = value["properties"][4].clone();
    value["properties"].as_array_mut().unwrap().push(clone);
    let raw = serde_json::to_string(&value).unwrap();
    assert!(
        load_registry(&raw).is_err(),
        "duplicate property id must fail closed"
    );
}

#[test]
fn tool_properties_declare_no_executable_or_credential_field() {
    let raw = AGENTIC_REGISTRY_JSON;
    for forbidden in [
        "\"shell\"",
        "\"eval\"",
        "\"script\"",
        "\"callback\"",
        "\"command\"",
        "\"exec\"",
        "\"api_key\"",
        "\"token\"",
        "\"url\"",
        "\"endpoint\"",
    ] {
        assert!(
            !raw.contains(forbidden),
            "registry must not contain the key {forbidden}"
        );
    }
}
