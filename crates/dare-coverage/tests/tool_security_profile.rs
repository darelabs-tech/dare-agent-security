//! Cycle 014 `tool-security-baseline-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects six properties that
//! already exist in the v2 registry. These tests pin both halves of that claim
//! — that the new profile matches the approval exactly, and that no earlier
//! profile or denominator moved because of it.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, profile_digest_sha256,
    prompt_injection_profile, resolve_profile, tool_security_profile, validate_profile,
    PropertyRegistry, RequirementLevel,
};

const PROFILE_ID: &str = "tool-security-baseline-2026";

/// The six properties and requirement levels approved for Cycle 014.
const APPROVED: [(&str, RequirementLevel); 6] = [
    (
        "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.TOOL.METADATA_TRUST_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.TOOL.SELECTION_INTENT_BINDING",
        RequirementLevel::Required,
    ),
    ("AGENT.TOOL.ARGUMENT_INTEGRITY", RequirementLevel::Required),
    ("AGENT.TOOL.CHAIN_BOUNDARY", RequirementLevel::Conditional),
];

/// The v2 registry, which is where every `AGENT.TOOL.*` property lives.
fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

#[test]
fn the_profile_matches_the_approved_requirement_levels_exactly() {
    let profile = tool_security_profile().expect("profile loads");
    assert_eq!(profile.id, PROFILE_ID);
    assert_eq!(profile.version, "1.0.0");
    assert_eq!(
        profile.properties.len(),
        APPROVED.len(),
        "the profile must select exactly the approved properties"
    );

    for (index, (id, requirement)) in APPROVED.iter().enumerate() {
        let entry = &profile.properties[index];
        assert_eq!(&entry.id, id, "property {index} is out of approved order");
        assert_eq!(
            entry.requirement, *requirement,
            "{id} has the wrong requirement level"
        );
    }
}

#[test]
fn every_selected_property_already_exists_in_the_v2_registry() {
    // Additive means selecting, never inventing.
    let registry = registry();
    let profile = tool_security_profile().expect("profile loads");
    validate_profile(&profile, &registry).expect("every property resolves");

    for (id, _) in APPROVED {
        let property = registry.require(id).expect("property is registered");
        assert_eq!(property.id, id);
    }
}

#[test]
fn the_profile_resolves_by_name_and_only_by_its_own_name() {
    let by_name = resolve_profile(PROFILE_ID).expect("resolves by name");
    assert_eq!(by_name, tool_security_profile().expect("profile loads"));
    assert!(resolve_profile("tool-security").is_err());
    assert!(resolve_profile("tool-security-baseline").is_err());
    assert!(resolve_profile("tool-security-baseline-2027").is_err());
}

#[test]
fn the_earlier_profiles_are_regression_identical() {
    // The exact assertion that matters: adding a profile must not move an
    // existing one. Digests, not eyeballs.
    let mcp = builtin_profile().expect("mcp profile");
    assert_eq!(mcp.id, "mcp-security-baseline");
    assert_eq!(mcp.properties.len(), 10);

    let agentic = agentic_profile().expect("agentic profile");
    assert_eq!(agentic.id, "agentic-security-baseline-2026");
    assert_eq!(agentic.properties.len(), 10);

    let prompt_injection = prompt_injection_profile().expect("prompt-injection profile");
    assert_eq!(prompt_injection.id, "prompt-injection-baseline-2026");
    assert_eq!(prompt_injection.properties.len(), 3);

    // And each still resolves to itself, byte for byte.
    for profile in [&mcp, &agentic, &prompt_injection] {
        let resolved = resolve_profile(&profile.id).expect("resolves");
        assert_eq!(
            profile_digest_sha256(&resolved).expect("digest"),
            profile_digest_sha256(profile).expect("digest"),
            "{} changed",
            profile.id
        );
    }
}

#[test]
fn no_earlier_profile_picked_up_one_of_the_four_new_properties() {
    // Denominators are per-profile. Cycle 012's agentic profile already selects
    // AUTHORIZATION_BOUNDARY, and that is left exactly as it was; what must not
    // happen is an earlier profile silently gaining one of the four properties
    // Cycle 014 added, which would grow its denominator without approval.
    let added_by_cycle_014: BTreeSet<&str> = BTreeSet::from([
        "AGENT.TOOL.METADATA_TRUST_BOUNDARY",
        "AGENT.TOOL.SELECTION_INTENT_BINDING",
        "AGENT.TOOL.ARGUMENT_INTEGRITY",
        "AGENT.TOOL.CHAIN_BOUNDARY",
    ]);
    for profile in [
        builtin_profile().expect("mcp"),
        agentic_profile().expect("agentic"),
        prompt_injection_profile().expect("prompt-injection"),
    ] {
        for entry in &profile.properties {
            assert!(
                !added_by_cycle_014.contains(entry.id.as_str()),
                "{} unexpectedly selects {}",
                profile.id,
                entry.id
            );
        }
    }
}

#[test]
fn the_agentic_profile_keeps_its_own_requirement_level_for_the_shared_property() {
    // AUTHORIZATION_BOUNDARY appears in two profiles at two levels, which is
    // exactly how per-profile requirements are meant to work. Neither profile
    // may quietly adopt the other's level.
    let agentic = agentic_profile().expect("agentic profile");
    let shared = agentic
        .properties
        .iter()
        .find(|entry| entry.id == "AGENT.TOOL.AUTHORIZATION_BOUNDARY")
        .expect("the agentic profile still selects it");
    assert_eq!(shared.requirement, RequirementLevel::Conditional);

    let tool_security = tool_security_profile().expect("profile loads");
    let same = tool_security
        .properties
        .iter()
        .find(|entry| entry.id == "AGENT.TOOL.AUTHORIZATION_BOUNDARY")
        .expect("selected here too");
    assert_eq!(same.requirement, RequirementLevel::Required);
}

#[test]
fn the_registry_gained_four_properties_and_renamed_none() {
    // Cycle 012 already shipped AUTHORIZATION_BOUNDARY and
    // OUTPUT_TRUST_BOUNDARY; Cycle 014 added four more and renamed nothing.
    let registry = registry();
    let tool_properties: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .filter(|id| id.starts_with("AGENT.TOOL."))
        .collect();
    assert_eq!(
        tool_properties,
        [
            "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
            "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY",
            "AGENT.TOOL.METADATA_TRUST_BOUNDARY",
            "AGENT.TOOL.SELECTION_INTENT_BINDING",
            "AGENT.TOOL.ARGUMENT_INTEGRITY",
            "AGENT.TOOL.CHAIN_BOUNDARY",
        ],
        "pre-existing property ids must never be renamed or reordered away"
    );
}

#[test]
fn the_profile_digest_is_stable() {
    let first = tool_security_profile().expect("profile loads");
    let second = tool_security_profile().expect("profile loads");
    assert_eq!(
        profile_digest_sha256(&first).expect("digest"),
        profile_digest_sha256(&second).expect("digest")
    );
}

#[test]
fn a_profile_naming_an_unregistered_property_is_refused() {
    // Fail closed: a profile cannot bring its own property into existence.
    let raw = r#"{
        "schema": {
            "id": "https://darelabs.tech/schemas/coverage/v1/profile.schema.json",
            "version": "1.0.0"
        },
        "id": "tool-security-invented",
        "version": "1.0.0",
        "title": "invented",
        "properties": [{"id": "AGENT.TOOL.TELEPATHY_BOUNDARY", "requirement": "REQUIRED"}]
    }"#;
    let profile = dare_coverage::load_profile(raw).expect("document is well-formed");
    assert!(validate_profile(&profile, &registry()).is_err());
}
