//! Cycle 025 `runtime-telemetry-baseline-2026` profile (Design Q5, task-020).
//!
//! The profile is additive: it resolves by name, selects exactly the nine
//! properties the runtime rules judge, and moves no earlier denominator.

use dare_coverage::{
    agentic_registry, evaluate_applicability, resolve_profile, runtime_telemetry_profile,
    AssessmentFacts, CoverageStatus, Predicate, RequirementLevel,
};

/// The nine properties, in rule order (B-1 … T-2), with their levels.
const APPROVED: [(&str, RequirementLevel); 9] = [
    (
        "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.HUMAN_APPROVAL.INTENT_BINDING",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.IDENTITY.PRINCIPAL_BINDING",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.MEMORY.TENANT_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.CODE_EXECUTION.EGRESS_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.FAILURE.RETRY_AMPLIFICATION",
        RequirementLevel::Required,
    ),
    (
        "AGENT.TELEMETRY.CONFIDENTIALITY",
        RequirementLevel::Required,
    ),
    ("AGENT.TELEMETRY.COMPLETENESS", RequirementLevel::Required),
];

/// The eleven profiles that existed before Cycle 025.
const EARLIER: [(&str, usize); 11] = [
    ("mcp-security-baseline", 10),
    ("agentic-security-baseline-2026", 10),
    ("prompt-injection-baseline-2026", 3),
    ("tool-security-baseline-2026", 6),
    ("identity-security-baseline-2026", 6),
    ("memory-security-baseline-2026", 6),
    ("rag-security-baseline-2026", 6),
    ("mcp-auth-hardening-2026", 10),
    ("agentic-supply-chain-security-2026", 10),
    ("agentic-a2a-security-2026", 12),
    ("multi-turn-security-baseline-2026", 7),
];

#[test]
fn the_profile_matches_the_approval_exactly() {
    let profile = runtime_telemetry_profile().expect("loads");
    assert_eq!(profile.id, "runtime-telemetry-baseline-2026");
    let selected: Vec<(&str, RequirementLevel)> = profile
        .properties
        .iter()
        .map(|p| (p.id.as_str(), p.requirement))
        .collect();
    assert_eq!(selected, APPROVED);
    assert_eq!(
        resolve_profile("runtime-telemetry-baseline-2026").expect("resolves"),
        profile
    );
}

#[test]
fn every_selected_property_is_registered() {
    let registry = agentic_registry().expect("registry");
    for (id, _) in APPROVED {
        assert!(registry.get(id).is_some(), "{id}");
    }
}

#[test]
fn required_means_every_traced_agent_has_the_surface() {
    // REQUIRED exactly when the registry gates the property only on an agent
    // and a runtime trace; anything else may legitimately be absent.
    let registry = agentic_registry().expect("registry");
    for (id, level) in APPROVED {
        let only_trace = registry
            .get(id)
            .expect("registered")
            .applicability
            .predicates
            .iter()
            .all(|p| matches!(p, Predicate::AgentPresent | Predicate::RuntimeTracePresent));
        assert_eq!(level == RequirementLevel::Required, only_trace, "{id}");
    }
}

#[test]
fn a_traced_agent_makes_every_required_property_applicable() {
    let registry = agentic_registry().expect("registry");
    let facts = AssessmentFacts {
        agent_present: true,
        runtime_trace_present: true,
        ..Default::default()
    };
    for (id, level) in APPROVED {
        if level == RequirementLevel::Required {
            let property = registry.get(id).expect("registered");
            assert_eq!(
                evaluate_applicability(property, &facts)
                    .expect("decides")
                    .status,
                CoverageStatus::Applicable,
                "{id}"
            );
        }
    }
}

#[test]
fn no_earlier_profile_denominator_moved() {
    // Literals: comparing a profile against itself would pass whatever moved.
    for (name, count) in EARLIER {
        assert_eq!(
            resolve_profile(name).expect("resolves").properties.len(),
            count,
            "the {name} denominator moved"
        );
    }
    assert_eq!(
        runtime_telemetry_profile().expect("loads").properties.len(),
        9
    );
}

#[test]
fn no_earlier_profile_selects_a_cycle_025_property() {
    for (name, _) in EARLIER {
        let profile = resolve_profile(name).expect("resolves");
        assert!(
            !profile
                .properties
                .iter()
                .any(|p| p.id.starts_with("AGENT.TELEMETRY.")),
            "{name} selects a telemetry property"
        );
    }
}
