//! The Cycle 021 `multi-turn-security-baseline-2026` profile.
//!
//! The profile is additive: every earlier profile keeps its denominator, and
//! the identity and memory profiles keep selecting exactly their own six
//! properties even though Cycle 021 added one property to each of those
//! families (Product Owner decision, 2026-09-27).

use dare_coverage::{
    agentic_registry, identity_security_profile, memory_security_profile,
    multi_turn_security_profile, registry_for_profile, resolve_profile, validate_profile,
    RequirementLevel,
};

const PROFILE_ID: &str = "multi-turn-security-baseline-2026";

const APPROVED: [(&str, RequirementLevel); 7] = [
    ("AGENT.GOAL.REFUSAL_PERSISTENCE", RequirementLevel::Required),
    (
        "AGENT.GOAL.CUMULATIVE_INTENT_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.GOAL.DELAYED_INSTRUCTION_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY",
        RequirementLevel::Conditional,
    ),
    ("AGENT.GOAL.OBJECTIVE_STABILITY", RequirementLevel::Required),
    (
        "AGENT.MEMORY.CONVERSATION_ISOLATION",
        RequirementLevel::Conditional,
    ),
];

#[test]
fn the_profile_matches_the_approval_exactly() {
    let profile = multi_turn_security_profile().expect("loads");
    assert_eq!(profile.id, PROFILE_ID);
    let got: Vec<(&str, RequirementLevel)> = profile
        .properties
        .iter()
        .map(|p| (p.id.as_str(), p.requirement))
        .collect();
    assert_eq!(got, APPROVED);
}

#[test]
fn the_profile_validates_and_every_property_exists_in_the_v2_registry() {
    let profile = multi_turn_security_profile().expect("loads");
    let registry = registry_for_profile(&profile).expect("a registry");
    validate_profile(&profile, &registry).expect("validates");
    let v2 = agentic_registry().expect("v2");
    for (id, _) in APPROVED {
        assert!(v2.get(id).is_some(), "{id}");
    }
}

#[test]
fn the_profile_resolves_by_name() {
    assert_eq!(
        resolve_profile(PROFILE_ID)
            .expect("resolves")
            .properties
            .len(),
        7
    );
}

#[test]
fn no_earlier_profile_denominator_moved() {
    // Literals, as in the Cycle 020 test: comparing a profile against itself
    // would pass no matter what moved.
    const DENOMINATORS: [(&str, usize); 10] = [
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
    ];
    for (name, count) in DENOMINATORS {
        assert_eq!(
            resolve_profile(name).expect("resolves").properties.len(),
            count,
            "the {name} denominator moved"
        );
    }
}

#[test]
fn the_identity_and_memory_profiles_do_not_select_the_cycle_021_additions() {
    let identity = identity_security_profile().expect("identity");
    assert!(!identity
        .properties
        .iter()
        .any(|p| p.id == "AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY"));
    let memory = memory_security_profile().expect("memory");
    assert!(!memory
        .properties
        .iter()
        .any(|p| p.id == "AGENT.MEMORY.CONVERSATION_ISOLATION"));
}

#[test]
fn no_earlier_profile_selects_any_cycle_021_property() {
    for name in [
        "mcp-security-baseline",
        "agentic-security-baseline-2026",
        "prompt-injection-baseline-2026",
        "tool-security-baseline-2026",
        "identity-security-baseline-2026",
        "memory-security-baseline-2026",
        "rag-security-baseline-2026",
        "mcp-auth-hardening-2026",
        "agentic-supply-chain-security-2026",
        "agentic-a2a-security-2026",
    ] {
        let profile = resolve_profile(name).expect("resolves");
        for (id, _) in APPROVED {
            assert!(
                !profile.properties.iter().any(|p| p.id == id),
                "{name} selects {id}"
            );
        }
    }
}
