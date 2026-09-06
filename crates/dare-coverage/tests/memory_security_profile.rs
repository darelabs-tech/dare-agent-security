//! Cycle 016 `memory-security-baseline-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects six properties that
//! already exist in the v2 registry, two of which predate this cycle. These
//! tests pin both halves of that claim — that the new profile matches the
//! approval exactly, and that no earlier profile, property or denominator moved
//! because of it.
//!
//! The second half matters more than it looks. A coverage percentage is a
//! fraction whose denominator is a profile's property count. If adding this
//! profile changed an earlier one, every assessment already filed against that
//! earlier profile would silently mean something different from what it meant
//! when it was produced.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, identity_security_profile,
    memory_security_profile, profile_digest_sha256, prompt_injection_profile, resolve_profile,
    tool_security_profile, validate_profile, PropertyCategory, PropertyRegistry, RequirementLevel,
    RiskFamily,
};

const PROFILE_ID: &str = "memory-security-baseline-2026";

/// The six properties and requirement levels approved for Cycle 016.
const APPROVED: [(&str, RequirementLevel); 6] = [
    ("AGENT.MEMORY.CONTEXT_INTEGRITY", RequirementLevel::Required),
    ("AGENT.MEMORY.TENANT_BOUNDARY", RequirementLevel::Required),
    (
        "AGENT.MEMORY.PROVENANCE_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.MEMORY.WRITE_TRUST_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.MEMORY.LIFECYCLE_VALIDITY",
        RequirementLevel::Conditional,
    ),
];

/// The two properties that existed before Cycle 016 and must not have moved.
const PRE_EXISTING: [&str; 2] = [
    "AGENT.MEMORY.CONTEXT_INTEGRITY",
    "AGENT.MEMORY.TENANT_BOUNDARY",
];

/// The applicability predicates the two pre-existing properties carried before
/// this cycle, pinned field by field.
const PRE_EXISTING_PREDICATES: [(&str, &[&str]); 2] = [
    (
        "AGENT.MEMORY.CONTEXT_INTEGRITY",
        &["agent_present", "memory_present"],
    ),
    (
        "AGENT.MEMORY.TENANT_BOUNDARY",
        &["agent_present", "memory_present", "authorization_present"],
    ),
];

/// The v2 registry, which is where every `AGENT.MEMORY.*` property lives.
fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

#[test]
fn the_profile_matches_the_approved_requirement_levels_exactly() {
    let profile = memory_security_profile().expect("profile loads");
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
    let profile = memory_security_profile().expect("profile loads");
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
fn the_two_pre_existing_properties_keep_their_identifiers_and_applicability() {
    // Cycle 016 was allowed to add, never to rename or re-scope. A changed
    // identifier would silently stop matching every prior assessment; a changed
    // predicate would change which targets the property applies to, which moves
    // a denominator without touching a profile.
    let registry = registry();
    for id in PRE_EXISTING {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .unwrap_or_else(|| panic!("{id} disappeared from the registry"));
        assert_eq!(property.id, id);
    }

    for (id, expected) in PRE_EXISTING_PREDICATES {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .expect("declared");
        let actual: Vec<&str> = property
            .applicability
            .predicates
            .iter()
            .map(|predicate| predicate.as_str())
            .collect();
        assert_eq!(actual, expected, "{id} changed its applicability");
    }
}

#[test]
fn the_profile_resolves_by_name() {
    let by_name = resolve_profile(PROFILE_ID).expect("resolves by name");
    assert_eq!(by_name, memory_security_profile().expect("profile loads"));
}

#[test]
fn the_profile_is_deterministic() {
    let first = memory_security_profile().expect("profile loads");
    let second = memory_security_profile().expect("profile loads");
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

    let identity_security = identity_security_profile().expect("profile loads");
    assert_eq!(identity_security.id, "identity-security-baseline-2026");
    assert_eq!(identity_security.properties.len(), 6);
}

#[test]
fn the_memory_profile_selects_no_property_an_earlier_profile_selects() {
    // Overlap would make one property count toward two denominators, which is
    // how a coverage number quietly inflates.
    let profile = memory_security_profile().expect("profile loads");
    let memory: BTreeSet<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for earlier in [
        prompt_injection_profile().expect("profile loads"),
        tool_security_profile().expect("profile loads"),
        identity_security_profile().expect("profile loads"),
    ] {
        for property in &earlier.properties {
            assert!(
                !memory.contains(property.id.as_str()),
                "{} is selected by both {} and {PROFILE_ID}",
                property.id,
                earlier.id
            );
        }
    }
}

#[test]
fn every_memory_property_in_the_registry_is_selected() {
    // A property in the registry that no profile selects is a property nothing
    // will ever assess — present in the catalogue and absent from every run.
    let registry = registry();
    let profile = memory_security_profile().expect("profile loads");
    let selected: Vec<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for property in &registry.properties {
        if property.id.starts_with("AGENT.MEMORY.") {
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
    let profile = memory_security_profile().expect("profile loads");
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

#[test]
fn the_conditional_properties_are_the_ones_a_target_may_have_nothing_to_answer() {
    // Recall and lifecycle are CONDITIONAL because a target that never recalls
    // memory, or never expires it, has no answer to give there. Marking them
    // REQUIRED would turn "not applicable" into a gap, and a target that
    // honestly declared no recall would score worse than one with no memory at
    // all.
    let profile = memory_security_profile().expect("profile loads");
    let conditional: BTreeSet<&str> = profile
        .properties
        .iter()
        .filter(|property| property.requirement == RequirementLevel::Conditional)
        .map(|property| property.id.as_str())
        .collect();

    assert_eq!(
        conditional,
        BTreeSet::from([
            "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY",
            "AGENT.MEMORY.LIFECYCLE_VALIDITY",
        ])
    );
}

#[test]
fn the_four_new_properties_carry_the_predicates_this_cycle_added() {
    // Each new property is applicable only where the fact it needs is present.
    // A property applicable everywhere would report a gap on every target that
    // simply has no recall, no namespace or no lifecycle to speak of.
    let registry = registry();
    for (id, predicate) in [
        (
            "AGENT.MEMORY.PROVENANCE_INTEGRITY",
            "memory_provenance_present",
        ),
        (
            "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY",
            "memory_recall_present",
        ),
        (
            "AGENT.MEMORY.LIFECYCLE_VALIDITY",
            "memory_lifecycle_present",
        ),
    ] {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        assert!(
            property
                .applicability
                .predicates
                .iter()
                .any(|declared| declared.as_str() == predicate),
            "{id} does not require {predicate}"
        );
    }
}

#[test]
fn every_memory_property_belongs_to_the_same_risk_family_and_category() {
    // The six report as one surface. A property that drifted into another
    // family would be counted under a risk the operator was not looking at.
    let registry = registry();
    let memory: Vec<_> = registry
        .properties
        .iter()
        .filter(|property| property.id.starts_with("AGENT.MEMORY."))
        .collect();

    assert_eq!(memory.len(), 6);
    for property in memory {
        assert_eq!(
            property.risk_family,
            Some(RiskFamily::MemoryContextPoisoning),
            "{} drifted out of the memory risk family",
            property.id
        );
        assert_eq!(property.category, PropertyCategory::MemoryContext);
    }
}
