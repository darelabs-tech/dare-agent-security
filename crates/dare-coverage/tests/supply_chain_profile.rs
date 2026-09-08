//! Cycle 019 `agentic-supply-chain-security-2026` profile and coverage
//! integration.
//!
//! The profile is additive by construction: it selects the two supply-chain
//! properties Cycle 012 created and the eight this cycle added to the **v2**
//! agentic registry, and touches nothing that was there before.
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
    agentic_profile, agentic_registry, agentic_supply_chain_profile, builtin_profile,
    builtin_registry, identity_security_profile, mcp_auth_hardening_profile,
    memory_security_profile, profile_digest_sha256, prompt_injection_profile, rag_security_profile,
    registry_for_profile, resolve_profile, tool_security_profile, validate_profile,
    AssessmentProfile, RequirementLevel,
};

const PROFILE_ID: &str = "agentic-supply-chain-security-2026";

/// The ten properties and requirement levels approved for Cycle 019, in order.
const APPROVED: [(&str, RequirementLevel); 10] = [
    (
        "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
        RequirementLevel::Required,
    ),
    (
        "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
        RequirementLevel::Required,
    ),
    (
        "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
        RequirementLevel::Conditional,
    ),
    (
        "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
        RequirementLevel::Required,
    ),
];

fn profile() -> AssessmentProfile {
    agentic_supply_chain_profile().expect("the profile loads")
}

#[test]
fn the_profile_is_exactly_what_the_approval_authorized() {
    let profile = profile();
    assert_eq!(profile.id, PROFILE_ID);
    assert_eq!(profile.properties.len(), APPROVED.len());

    for (entry, (id, requirement)) in profile.properties.iter().zip(APPROVED) {
        assert_eq!(entry.id, id);
        assert_eq!(entry.requirement, requirement, "{id}");
    }
    validate_profile(&profile, &agentic_registry().expect("the registry loads"))
        .expect("the profile validates");
}

#[test]
fn the_profile_resolves_by_name_and_by_path() {
    // An operator naming the profile and a CI job pointing at the file must get
    // the same denominator, or the same run would report two coverage numbers.
    let by_name = resolve_profile(PROFILE_ID).expect("resolves by name");
    let by_path = resolve_profile(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../profiles/agentic-supply-chain-security-2026.json"
    ))
    .expect("resolves by path");
    assert_eq!(
        profile_digest_sha256(&by_name).expect("digests"),
        profile_digest_sha256(&by_path).expect("digests")
    );
}

#[test]
fn every_selected_property_exists_in_the_agentic_registry() {
    // A profile naming a property no registry defines would produce a
    // denominator larger than anything that could ever be assessed, so coverage
    // would be permanently short by exactly the missing entries.
    let registry = agentic_registry().expect("the registry loads");
    let known: BTreeSet<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    for (id, _) in APPROVED {
        assert!(known.contains(id), "{id} is not in the agentic registry");
    }
}

#[test]
fn the_profile_routes_to_the_agentic_registry_and_not_the_mcp_one() {
    // Every property is an `AGENT.` one, and resolving against the v1 MCP
    // registry would leave all ten unresolvable.
    let registry = registry_for_profile(&profile()).expect("routes");
    let agentic = agentic_registry().expect("the registry loads");
    assert_eq!(registry.properties.len(), agentic.properties.len());
}

#[test]
fn the_split_between_required_and_conditional_is_deliberate() {
    // Identity, integrity, source trust and completeness apply wherever a bill
    // of materials exists at all. The other six apply where their evidence
    // class exists: a system with no model has no model lineage to preserve,
    // and marking lineage REQUIRED would report a finding against every
    // deployment that runs no model.
    let profile = profile();
    let required: BTreeSet<&str> = profile
        .properties
        .iter()
        .filter(|entry| entry.requirement == RequirementLevel::Required)
        .map(|entry| entry.id.as_str())
        .collect();

    assert_eq!(required.len(), 5);
    for always_applicable in [
        "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
        "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
        "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
        "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
        "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
    ] {
        assert!(required.contains(always_applicable), "{always_applicable}");
    }

    for class_gated in [
        "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
        "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
        "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT",
        "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
        "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
    ] {
        assert!(
            !required.contains(class_gated),
            "{class_gated} would fire against deployments it does not apply to"
        );
    }
}

#[test]
fn no_earlier_profile_moved() {
    // AC-71/AC-72. The denominators every earlier assessment was measured
    // against, pinned by count. A profile that grew or shrank would change what
    // a filed coverage percentage means, and the percentage itself would look
    // exactly as it always had.
    //
    // The counts differ between profiles because the cycles that produced them
    // selected different numbers of properties. What matters is that each one
    // is the number it was when assessments were filed against it.
    for (profile, expected) in [
        (builtin_profile().expect("loads"), 10),
        (agentic_profile().expect("loads"), 10),
        (prompt_injection_profile().expect("loads"), 3),
        (tool_security_profile().expect("loads"), 6),
        (identity_security_profile().expect("loads"), 6),
        (memory_security_profile().expect("loads"), 6),
        (rag_security_profile().expect("loads"), 6),
        (mcp_auth_hardening_profile().expect("loads"), 10),
    ] {
        assert_eq!(
            profile.properties.len(),
            expected,
            "the `{}` denominator moved",
            profile.id
        );
    }
}

#[test]
fn the_agentic_baseline_still_selects_what_it_always_selected() {
    // The closest neighbour, and the one this cycle could most easily have
    // edited: it already carries `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`.
    // Adding the seven new properties to it would have been the natural way to
    // make them visible, and would have changed a baseline eight cycles of
    // assessments were filed against.
    let baseline = agentic_profile().expect("loads");
    let selected: BTreeSet<&str> = baseline
        .properties
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();

    assert!(selected.contains("AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE"));
    for added in [
        "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
        "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
        "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
        "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
        "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
        "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
        "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
        "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
    ] {
        assert!(
            !selected.contains(added),
            "{added} was added to the agentic baseline, changing its denominator"
        );
    }
}

#[test]
fn the_mcp_registry_is_untouched_by_a_supply_chain_property() {
    // The two registries are separate on purpose. A supply-chain property in
    // the v1 MCP registry would appear in every MCP assessment's denominator.
    let registry = builtin_registry().expect("loads");
    for property in &registry.properties {
        assert!(
            !property.id.starts_with("AGENT.SUPPLY_CHAIN."),
            "{} reached the MCP registry",
            property.id
        );
    }
}

#[test]
fn the_profile_digest_is_stable() {
    // The digest is what a report cites to say which denominator produced a
    // number. If it moved between runs, two reports of the same assessment
    // would disagree about what they measured.
    assert_eq!(
        profile_digest_sha256(&profile()).expect("digests"),
        profile_digest_sha256(&profile()).expect("digests")
    );
}
