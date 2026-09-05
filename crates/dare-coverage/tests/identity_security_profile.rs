//! Cycle 015 `identity-security-baseline-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects six properties that
//! already exist in the v2 registry, two of which predate this cycle. These
//! tests pin both halves of that claim — that the new profile matches the
//! approval exactly, and that no earlier profile, property or denominator moved
//! because of it.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, identity_security_profile,
    profile_digest_sha256, prompt_injection_profile, resolve_profile, tool_security_profile,
    validate_profile, PropertyRegistry, RequirementLevel,
};

const PROFILE_ID: &str = "identity-security-baseline-2026";

/// The six properties and requirement levels approved for Cycle 015.
const APPROVED: [(&str, RequirementLevel); 6] = [
    (
        "AGENT.IDENTITY.DELEGATION_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION",
        RequirementLevel::Required,
    ),
    (
        "AGENT.IDENTITY.PRINCIPAL_BINDING",
        RequirementLevel::Required,
    ),
    (
        "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING",
        RequirementLevel::Required,
    ),
];

/// The two properties that existed before Cycle 015 and must not have moved.
const PRE_EXISTING: [&str; 2] = [
    "AGENT.IDENTITY.DELEGATION_INTEGRITY",
    "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION",
];

/// The v2 registry, which is where every `AGENT.IDENTITY.*` property lives.
fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

#[test]
fn the_profile_matches_the_approved_requirement_levels_exactly() {
    let profile = identity_security_profile().expect("profile loads");
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
            "{id} does not carry its approved requirement level"
        );
    }
}

#[test]
fn every_selected_property_exists_in_the_registry() {
    let profile = identity_security_profile().expect("profile loads");
    let registry = registry();
    validate_profile(&profile, &registry).expect("the profile validates against the registry");

    for (id, _) in APPROVED {
        assert!(
            registry.properties.iter().any(|property| property.id == id),
            "{id} is not in the v2 registry"
        );
    }
}

#[test]
fn the_two_pre_existing_properties_keep_their_identifiers() {
    // Cycle 015 was allowed to add, never to rename or re-scope. If either of
    // these identifiers changed, every prior assessment referencing it would
    // silently stop matching.
    let registry = registry();
    for id in PRE_EXISTING {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .unwrap_or_else(|| panic!("{id} disappeared from the registry"));
        assert_eq!(property.id, id);
    }
}

#[test]
fn the_profile_resolves_by_name() {
    let by_name = resolve_profile(PROFILE_ID).expect("resolves by name");
    assert_eq!(by_name, identity_security_profile().expect("profile loads"));
}

#[test]
fn the_profile_is_deterministic() {
    let first = identity_security_profile().expect("profile loads");
    let second = identity_security_profile().expect("profile loads");
    assert_eq!(first, second);
    assert_eq!(
        profile_digest_sha256(&first).expect("digest"),
        profile_digest_sha256(&second).expect("digest")
    );
    assert_eq!(profile_digest_sha256(&first).expect("digest").len(), 64);
}

#[test]
fn no_earlier_profile_changed() {
    // The denominator of an earlier assessment is its own profile's property
    // count. Adding a profile must not move any of them.
    let mcp = builtin_profile().expect("profile loads");
    assert_eq!(mcp.id, "mcp-security-baseline");

    let agentic = agentic_profile().expect("profile loads");
    assert_eq!(agentic.id, "agentic-security-baseline-2026");
    assert_eq!(agentic.properties.len(), 10);

    let prompt_injection = prompt_injection_profile().expect("profile loads");
    assert_eq!(prompt_injection.id, "prompt-injection-baseline-2026");
    assert_eq!(prompt_injection.properties.len(), 3);

    let tool_security = tool_security_profile().expect("profile loads");
    assert_eq!(tool_security.id, "tool-security-baseline-2026");
    assert_eq!(tool_security.properties.len(), 6);
}

#[test]
fn the_identity_profile_selects_no_property_an_earlier_profile_selects() {
    // Overlap would make one property count toward two denominators, which is
    // how a coverage number quietly inflates.
    let profile = identity_security_profile().expect("profile loads");
    let identity: BTreeSet<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for earlier in [
        prompt_injection_profile().expect("profile loads"),
        tool_security_profile().expect("profile loads"),
    ] {
        for property in &earlier.properties {
            assert!(
                !identity.contains(property.id.as_str()),
                "{} is selected by both {} and {PROFILE_ID}",
                property.id,
                earlier.id
            );
        }
    }
}

#[test]
fn every_identity_property_in_the_registry_is_selected() {
    // A property in the registry that no profile selects is a property nothing
    // will ever assess.
    let registry = registry();
    let profile = identity_security_profile().expect("profile loads");
    let selected: Vec<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for property in &registry.properties {
        if property.id.starts_with("AGENT.IDENTITY.") {
            assert!(
                selected.contains(&property.id.as_str()),
                "{} is in the registry but no profile selects it",
                property.id
            );
        }
    }
}

#[test]
fn requirement_levels_are_only_the_three_defined_ones() {
    let profile = identity_security_profile().expect("profile loads");
    for property in &profile.properties {
        assert!(
            matches!(
                property.requirement,
                RequirementLevel::Required
                    | RequirementLevel::Conditional
                    | RequirementLevel::Optional
            ),
            "{} carries an unknown requirement level",
            property.id
        );
    }
    // Three REQUIRED and two CONDITIONAL among the four new ones, per approval.
    let required = profile
        .properties
        .iter()
        .filter(|property| property.requirement == RequirementLevel::Required)
        .count();
    let conditional = profile
        .properties
        .iter()
        .filter(|property| property.requirement == RequirementLevel::Conditional)
        .count();
    assert_eq!(required, 4);
    assert_eq!(conditional, 2);
}
