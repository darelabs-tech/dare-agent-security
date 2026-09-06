//! Cycle 017 `rag-security-baseline-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects six properties that this
//! cycle added to the v2 registry, and touches nothing that was there before.
//! These tests pin both halves of that claim — that the new profile matches the
//! approval exactly, and that no earlier profile, property, predicate or risk
//! family moved because of it.
//!
//! The second half is the one that would fail quietly. A coverage percentage is
//! a fraction whose denominator is a profile's property count. If adding this
//! profile changed an earlier one, every assessment already filed against that
//! earlier profile would silently mean something different from what it meant
//! when it was produced — and nothing about the number would look wrong.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, identity_security_profile,
    memory_security_profile, profile_digest_sha256, prompt_injection_profile, rag_security_profile,
    resolve_profile, tool_security_profile, validate_profile, AssessmentProfile, PropertyCategory,
    PropertyRegistry, RequirementLevel,
};

const PROFILE_ID: &str = "rag-security-baseline-2026";

/// The six properties and requirement levels approved for Cycle 017, in order.
const APPROVED: [(&str, RequirementLevel); 6] = [
    (
        "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
        RequirementLevel::Required,
    ),
    ("AGENT.RAG.PROVENANCE_INTEGRITY", RequirementLevel::Required),
    (
        "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
        RequirementLevel::Conditional,
    ),
    ("AGENT.RAG.RESULT_SET_INTEGRITY", RequirementLevel::Required),
    (
        "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
        RequirementLevel::Conditional,
    ),
];

fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

fn rag() -> AssessmentProfile {
    rag_security_profile().expect("profile loads")
}

#[test]
fn the_profile_matches_the_approved_requirement_levels_exactly() {
    let profile = rag();
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
    let profile = rag();
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
fn the_profile_resolves_by_name() {
    assert_eq!(
        resolve_profile(PROFILE_ID).expect("resolves by name"),
        rag()
    );
}

#[test]
fn the_profile_is_deterministic() {
    let first = rag();
    let second = rag();
    assert_eq!(first, second);
    assert_eq!(
        profile_digest_sha256(&first).expect("digest"),
        profile_digest_sha256(&second).expect("digest")
    );
    assert_eq!(profile_digest_sha256(&first).expect("digest").len(), 64);
}

#[test]
fn no_earlier_profile_changed() {
    // Each earlier profile's property count is the denominator of every
    // assessment ever filed against it. Adding a profile must not move one.
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

    let memory_security = memory_security_profile().expect("profile loads");
    assert_eq!(memory_security.id, "memory-security-baseline-2026");
    assert_eq!(memory_security.properties.len(), 6);
}

#[test]
fn the_rag_profile_selects_no_property_an_earlier_profile_selects() {
    // Overlap would make one property count toward two denominators, which is
    // how a coverage number quietly inflates without anyone editing a number.
    let profile = rag();
    let selected: BTreeSet<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for earlier in [
        builtin_profile().expect("profile loads"),
        agentic_profile().expect("profile loads"),
        prompt_injection_profile().expect("profile loads"),
        tool_security_profile().expect("profile loads"),
        identity_security_profile().expect("profile loads"),
        memory_security_profile().expect("profile loads"),
    ] {
        for property in &earlier.properties {
            assert!(
                !selected.contains(property.id.as_str()),
                "{} is selected by both {} and {PROFILE_ID}",
                property.id,
                earlier.id
            );
        }
    }
}

#[test]
fn every_rag_property_in_the_registry_is_selected() {
    // A property in the registry that no profile selects is a property nothing
    // will ever assess: present in the catalogue, absent from every run, and
    // indistinguishable in a report from one that was assessed and held.
    let registry = registry();
    let profile = rag();
    let selected: Vec<&str> = profile
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for property in &registry.properties {
        if property.id.starts_with("AGENT.RAG.") {
            assert!(
                selected.contains(&property.id.as_str()),
                "{} is in the registry but no profile selects it",
                property.id
            );
        }
    }
}

#[test]
fn the_conditional_properties_are_the_ones_a_target_may_have_nothing_to_answer() {
    // Trust promotion is CONDITIONAL because a corpus holding nothing untrusted
    // has no promotion to answer for. Protected nondisclosure is CONDITIONAL
    // because a policy designating no protected document or class has nothing
    // to withhold. Marking either REQUIRED would turn "not applicable" into a
    // gap, and a target that honestly declares neither would score worse than
    // one that declares less about itself.
    let profile = rag();
    let conditional: BTreeSet<&str> = profile
        .properties
        .iter()
        .filter(|property| property.requirement == RequirementLevel::Conditional)
        .map(|property| property.id.as_str())
        .collect();

    assert_eq!(
        conditional,
        BTreeSet::from([
            "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
            "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
        ])
    );

    let required = profile
        .properties
        .iter()
        .filter(|property| property.requirement == RequirementLevel::Required)
        .count();
    assert_eq!(required, 4);
}

#[test]
fn requirement_levels_are_only_the_three_defined_ones() {
    for property in &rag().properties {
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
}

#[test]
fn every_rag_property_reports_under_the_retrieval_category_and_no_risk_family() {
    // The six report as one surface. A property that drifted into another
    // category would be counted under a heading the operator was not reading.
    //
    // The absent risk family is deliberate, and is the taxonomy boundary this
    // cycle was told to hold: retrieval is not an eleventh Agentic risk family,
    // and LLM09 is not one either. The properties exist, they are assessed, and
    // they report under RETRIEVAL — without inventing a family or claiming
    // equivalence with an ASI category.
    let registry = registry();
    let rag: Vec<_> = registry
        .properties
        .iter()
        .filter(|property| property.id.starts_with("AGENT.RAG."))
        .collect();

    assert_eq!(rag.len(), 6);
    for property in rag {
        assert_eq!(
            property.category,
            PropertyCategory::Retrieval,
            "{} drifted out of the retrieval category",
            property.id
        );
        assert_eq!(
            property.risk_family, None,
            "{} claims a risk family; retrieval is not an Agentic risk family",
            property.id
        );
    }
}

#[test]
fn the_agentic_risk_families_still_number_exactly_ten() {
    // The count Cycle 012 fixed, re-checked from the profile side. Six new
    // properties were added and none of them created an eleventh family.
    let registry = registry();
    let families: std::collections::HashSet<_> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10, "the Agentic risk family count moved");
}
