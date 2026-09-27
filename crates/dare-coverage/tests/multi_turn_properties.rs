//! Cycle 021 multi-turn properties in the v2 agentic registry.
//!
//! Additive, inside existing families (DESIGN §13 Q1): no `AGENT.MULTI_TURN.*`
//! namespace, no existing entry changed, every new property gated by the
//! already-existing `stateful_agent_present` predicate.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_registry, builtin_registry, evaluate_applicability, AssessmentFacts, CoverageStatus,
    Predicate, RiskFamily,
};

/// (id, risk family, category) exactly as Blueprint §5.2 froze them.
const ADDED: [(&str, RiskFamily, &str); 7] = [
    (
        "AGENT.GOAL.REFUSAL_PERSISTENCE",
        RiskFamily::AgentGoalHijacking,
        "GOAL_INTEGRITY",
    ),
    (
        "AGENT.GOAL.CUMULATIVE_INTENT_BOUNDARY",
        RiskFamily::AgentGoalHijacking,
        "GOAL_INTEGRITY",
    ),
    (
        "AGENT.GOAL.DELAYED_INSTRUCTION_BOUNDARY",
        RiskFamily::AgentGoalHijacking,
        "GOAL_INTEGRITY",
    ),
    (
        "AGENT.GOAL.OBJECTIVE_STABILITY",
        RiskFamily::AgentGoalHijacking,
        "GOAL_INTEGRITY",
    ),
    (
        "AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY",
        RiskFamily::IdentityPrivilegeAbuse,
        "PRINCIPAL_BINDING",
    ),
    (
        "AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY",
        RiskFamily::HumanAgentTrustExploitation,
        "HUMAN_OVERSIGHT",
    ),
    (
        "AGENT.MEMORY.CONVERSATION_ISOLATION",
        RiskFamily::MemoryContextPoisoning,
        "MEMORY_CONTEXT",
    ),
];

/// The registry size measured at the Cycle 021 baseline (`BASELINE.md`).
const BASELINE_PROPERTY_COUNT: usize = 58;

fn raw_registry() -> serde_json::Value {
    serde_json::from_str(dare_coverage::AGENTIC_REGISTRY_JSON).expect("registry parses")
}

#[test]
fn exactly_the_seven_approved_properties_were_added() {
    let registry = agentic_registry().expect("registry loads");
    assert_eq!(
        registry.properties.len(),
        BASELINE_PROPERTY_COUNT + ADDED.len()
    );
    let ids: BTreeSet<&str> = registry.properties.iter().map(|p| p.id.as_str()).collect();
    for (id, _, _) in ADDED {
        assert!(ids.contains(id), "{id} is missing");
    }
    // Appended after every pre-existing entry, so no earlier position moved.
    let tail: Vec<&str> = registry.properties[BASELINE_PROPERTY_COUNT..]
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(tail, ADDED.map(|(id, _, _)| id));
}

#[test]
fn each_property_carries_its_family_category_and_reference() {
    let raw = raw_registry();
    let registry = agentic_registry().expect("registry loads");
    for (id, family, category) in ADDED {
        let property = registry.get(id).expect("present");
        assert_eq!(property.risk_family, Some(family), "{id}");
        let entry = raw["properties"]
            .as_array()
            .expect("array")
            .iter()
            .find(|p| p["id"] == id)
            .expect("entry");
        assert_eq!(entry["category"], category, "{id}");
        let reference = entry["standards"][0]["reference"]
            .as_str()
            .expect("reference");
        let asi = reference.split(' ').next().expect("asi id");
        let existing = raw["properties"]
            .as_array()
            .expect("array")
            .iter()
            .take(BASELINE_PROPERTY_COUNT)
            .filter_map(|p| p["standards"][0]["reference"].as_str())
            .find(|r| r.starts_with(asi))
            .expect("a pre-existing entry uses this ASI reference");
        assert_eq!(
            reference, existing,
            "{id} must reuse the registry's exact reference string"
        );
    }
}

#[test]
fn no_multi_turn_namespace_was_introduced() {
    let registry = agentic_registry().expect("registry loads");
    assert!(!registry
        .properties
        .iter()
        .any(|p| p.id.contains("MULTI_TURN")));
}

#[test]
fn every_new_property_is_gated_by_the_existing_stateful_agent_predicate() {
    let registry = agentic_registry().expect("registry loads");
    for (id, _, _) in ADDED {
        let predicates = &registry.get(id).expect("present").applicability.predicates;
        assert_eq!(
            predicates,
            &vec![Predicate::AgentPresent, Predicate::StatefulAgentPresent],
            "{id}"
        );
    }
}

#[test]
fn a_stateful_agent_makes_them_applicable_and_a_stateless_one_does_not() {
    let registry = agentic_registry().expect("registry loads");
    let stateful = AssessmentFacts {
        agent_present: true,
        stateful_agent_present: true,
        ..Default::default()
    };
    let stateless = AssessmentFacts {
        agent_present: true,
        ..Default::default()
    };
    for (id, _, _) in ADDED {
        let property = registry.get(id).expect("present");
        assert_eq!(
            evaluate_applicability(property, &stateful)
                .expect("decides")
                .status,
            CoverageStatus::Applicable,
            "{id}"
        );
        assert_eq!(
            evaluate_applicability(property, &stateless)
                .expect("decides")
                .status,
            CoverageStatus::NotApplicable,
            "{id}"
        );
    }
}

#[test]
fn the_v1_registry_gained_nothing() {
    let v1 = builtin_registry().expect("v1 loads");
    assert!(v1.properties.iter().all(|p| p.id.starts_with("MCP.")));
}

#[test]
fn every_new_property_is_mapped_in_the_cycle_021_standards_record() {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "../../../standards/multi-turn-security/2026/provenance.json"
    ))
    .expect("provenance parses");
    let mapped: BTreeSet<&str> = raw["property_mappings"]
        .as_array()
        .expect("mappings")
        .iter()
        .filter_map(|m| m["property_id"].as_str())
        .collect();
    assert_eq!(mapped, ADDED.iter().map(|(id, _, _)| *id).collect());
}
