//! Cycle 020 `agentic-a2a-security-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects the two A2A properties
//! earlier cycles created and the ten this cycle added to the **v2** agentic
//! registry, and touches nothing that was there before.
//!
//! These tests pin both halves — that the profile matches the approval exactly,
//! and that no earlier profile, property or denominator moved because of it.
//!
//! The second half is the one that would fail quietly. A coverage percentage is
//! a fraction whose denominator is a profile's property count. If adding this
//! profile changed an earlier one, every assessment already filed against that
//! earlier profile would silently mean something different from what it meant
//! when it was produced — and nothing about the number would look wrong.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_a2a_profile, agentic_profile, agentic_registry, agentic_supply_chain_profile,
    builtin_registry, profile_digest_sha256, registry_for_profile, resolve_profile,
    validate_profile, AssessmentProfile, RequirementLevel,
};

const PROFILE_ID: &str = "agentic-a2a-security-2026";

/// The twelve properties and requirement levels approved for Cycle 020, in order.
const APPROVED: [(&str, RequirementLevel); 12] = [
    (
        "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.A2A.PEER_IDENTITY_BINDING",
        RequirementLevel::Required,
    ),
    ("AGENT.A2A.MESSAGE_AUTHENTICITY", RequirementLevel::Required),
    ("AGENT.A2A.SKILL_AUTHORIZATION", RequirementLevel::Required),
    (
        "AGENT.A2A.AUTHORITY_PROPAGATION",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
        RequirementLevel::Conditional,
    ),
    ("AGENT.A2A.TENANT_BOUNDARY", RequirementLevel::Required),
    (
        "AGENT.A2A.DATA_SCOPE_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    ("AGENT.A2A.REPLAY_BOUNDARY", RequirementLevel::Conditional),
    (
        "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
        RequirementLevel::Conditional,
    ),
];

/// The two properties this cycle inherits rather than creates.
const INHERITED: [&str; 2] = [
    "AGENT.A2A.MESSAGE_AUTHENTICITY",
    "AGENT.A2A.AUTHORITY_PROPAGATION",
];

fn profile() -> AssessmentProfile {
    agentic_a2a_profile().expect("the Cycle 020 profile loads")
}

#[test]
fn the_profile_matches_the_approval_exactly() {
    let profile = profile();
    assert_eq!(profile.id, PROFILE_ID);

    let actual: Vec<(&str, RequirementLevel)> = profile
        .properties
        .iter()
        .map(|property| (property.id.as_str(), property.requirement))
        .collect();
    let approved: Vec<(&str, RequirementLevel)> = APPROVED.to_vec();
    assert_eq!(
        actual, approved,
        "the profile no longer matches what was approved"
    );
}

#[test]
fn the_profile_validates_against_the_v1_profile_schema() {
    let profile = profile();
    let registry = registry_for_profile(&profile).expect("a registry");
    validate_profile(&profile, &registry).expect("the profile validates");
}

#[test]
fn every_property_the_profile_names_exists_in_the_v2_registry() {
    // A profile naming a property no registry defines would compute a coverage
    // percentage over a denominator that includes something nothing can ever
    // satisfy.
    let registry = agentic_registry().expect("the v2 registry");
    let known: BTreeSet<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    for (id, _) in APPROVED {
        assert!(known.contains(id), "{id} is not in the v2 registry");
    }
}

#[test]
fn the_profile_selects_no_property_outside_the_a2a_namespace() {
    // There is deliberately no top-level `A2A.*` namespace, and this profile
    // does not reach into another cycle's properties to inflate its own
    // coverage.
    for (id, _) in APPROVED {
        assert!(
            id.starts_with("AGENT.A2A."),
            "{id} is outside the approved namespace"
        );
    }
}

#[test]
fn the_two_inherited_properties_keep_their_public_identifiers() {
    // These two predate this cycle. Renaming either would break every
    // assessment already filed against them, and the rename would look like a
    // tidy-up in a diff.
    let profile = profile();
    let selected: BTreeSet<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    for id in INHERITED {
        assert!(selected.contains(id), "{id} was dropped or renamed");
    }
}

#[test]
fn the_requirement_split_follows_the_predicate_that_gates_each_property() {
    // The split is not editorial. A property gated on a *target shape* is
    // CONDITIONAL, because a deployment that configures no callback genuinely
    // has no callback boundary. A property gated on an *evidence or control*
    // predicate is REQUIRED, because its absence is a gap in any deployment
    // that speaks A2A at all — and a gap that quietly became NOT_APPLICABLE
    // would let a target improve its coverage by collecting less evidence.
    let registry = agentic_registry().expect("the v2 registry");
    let profile = profile();

    for property in &profile.properties {
        let entry = registry
            .properties
            .iter()
            .find(|candidate| candidate.id == property.id)
            .expect("a registry entry");

        let rendered = serde_json::to_value(entry).expect("serializes");
        let predicates: Vec<String> = rendered["applicability"]["predicates"]
            .as_array()
            .expect("predicates")
            .iter()
            .map(|value| value.as_str().expect("a predicate").to_owned())
            .collect();

        // Everything past the two universal predicates decides the level.
        let extra: Vec<&str> = predicates
            .iter()
            .map(String::as_str)
            .filter(|predicate| !matches!(*predicate, "agent_present" | "multi_agent_present"))
            .collect();

        const SHAPES: [&str; 5] = [
            "a2a_exchange_present",
            "agent_card_present",
            "a2a_extension_present",
            "push_notification_config_present",
            "delegated_identity_present",
        ];

        let gated_on_a_shape = extra.iter().any(|predicate| SHAPES.contains(predicate));
        let expected = if extra.is_empty() || !gated_on_a_shape {
            RequirementLevel::Required
        } else {
            RequirementLevel::Conditional
        };
        assert_eq!(
            property.requirement, expected,
            "{} is gated on {extra:?} and is marked {:?}",
            property.id, property.requirement
        );
    }
}

#[test]
fn the_profile_resolves_by_name() {
    let resolved = resolve_profile(PROFILE_ID).expect("resolves by name");
    assert_eq!(resolved.id, PROFILE_ID);
    assert_eq!(
        profile_digest_sha256(&resolved).expect("a digest"),
        profile_digest_sha256(&profile()).expect("a digest")
    );
}

#[test]
fn no_earlier_profile_denominator_moved() {
    // The quiet failure this whole file exists for. Every one of these numbers
    // is the denominator of a coverage percentage somebody has already filed.
    // If adding a profile changed one, every earlier assessment would silently
    // mean something different and nothing about the number would look wrong.
    //
    // The counts are literals rather than reads of the same accessor. Comparing
    // a profile against itself would pass no matter what moved.
    const DENOMINATORS: [(&str, usize); 9] = [
        ("mcp-security-baseline", 10),
        ("agentic-security-baseline-2026", 10),
        ("prompt-injection-baseline-2026", 3),
        ("tool-security-baseline-2026", 6),
        ("identity-security-baseline-2026", 6),
        ("memory-security-baseline-2026", 6),
        ("rag-security-baseline-2026", 6),
        ("mcp-auth-hardening-2026", 10),
        ("agentic-supply-chain-security-2026", 10),
    ];

    for (name, count) in DENOMINATORS {
        let resolved = resolve_profile(name).expect("resolves");
        assert_eq!(
            resolved.properties.len(),
            count,
            "the {name} denominator moved"
        );
    }
}

#[test]
fn this_cycles_ten_new_properties_reached_no_earlier_profile() {
    // `AGENT.A2A.MESSAGE_AUTHENTICITY` has been in the Cycle 012 baseline since
    // that cycle, and inheriting it is the point — this cycle adds properties
    // around it rather than replacing it. What must not happen is one of the
    // ten *new* properties appearing in a profile that predates them, which
    // would change that profile's denominator without changing its file.
    const ADDED: [&str; 10] = [
        "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY",
        "AGENT.A2A.PEER_IDENTITY_BINDING",
        "AGENT.A2A.SKILL_AUTHORIZATION",
        "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
        "AGENT.A2A.TENANT_BOUNDARY",
        "AGENT.A2A.DATA_SCOPE_BOUNDARY",
        "AGENT.A2A.REPLAY_BOUNDARY",
        "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY",
        "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
        "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
    ];

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
    ] {
        let resolved = resolve_profile(name).expect("resolves");
        for property in &resolved.properties {
            assert!(
                !ADDED.contains(&property.id.as_str()),
                "{name} acquired {}, which this cycle created",
                property.id
            );
        }
    }

    // And the one inherited property is still exactly where it was.
    let baseline = agentic_profile().expect("loads");
    let a2a: Vec<&str> = baseline
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .filter(|id| id.starts_with("AGENT.A2A."))
        .collect();
    assert_eq!(a2a, ["AGENT.A2A.MESSAGE_AUTHENTICITY"]);
}

#[test]
fn the_cycle_019_profile_is_untouched_and_still_selects_ten_properties() {
    // Named separately from the sweep above because it is the profile most
    // likely to be edited by mistake: it is the previous cycle's, it lives in
    // the same directory, and its properties read similarly.
    let supply_chain = agentic_supply_chain_profile().expect("loads");
    assert_eq!(supply_chain.properties.len(), 10);
    assert_eq!(supply_chain.id, "agentic-supply-chain-security-2026");
}

#[test]
fn the_v1_registry_gained_nothing_from_this_cycle() {
    // A2A properties belong to the v2 agentic registry. One reaching v1 would
    // change what an MCP-only assessment is measured against.
    let v1 = builtin_registry().expect("the v1 registry");
    assert!(
        !v1.properties
            .iter()
            .any(|property| property.id.starts_with("AGENT.A2A.")),
        "an A2A property reached the v1 MCP registry"
    );
}
