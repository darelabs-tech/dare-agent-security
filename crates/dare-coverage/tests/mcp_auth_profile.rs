//! Cycle 018 `mcp-auth-hardening-2026` profile and coverage integration.
//!
//! The profile is additive by construction: it selects ten properties this
//! cycle added to the **v1** MCP registry, and touches nothing that was there
//! before. These tests pin both halves of that claim — that the profile matches
//! the approval exactly, and that no earlier profile, property or denominator
//! moved because of it.
//!
//! The second half is the one that would fail quietly. A coverage percentage is
//! a fraction whose denominator is a profile's property count. If adding this
//! profile changed an earlier one, every assessment already filed against that
//! earlier profile would silently mean something different from what it meant
//! when it was produced — and nothing about the number would look wrong.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, builtin_registry,
    identity_security_profile, mcp_auth_hardening_profile, memory_security_profile,
    profile_digest_sha256, prompt_injection_profile, rag_security_profile, resolve_profile,
    tool_security_profile, validate_profile, AssessmentFacts, AssessmentProfile, CoverageStatus,
    PropertyRegistry, RequirementLevel,
};

const PROFILE_ID: &str = "mcp-auth-hardening-2026";

/// The ten properties and requirement levels approved for Cycle 018, in order.
const APPROVED: [(&str, RequirementLevel); 10] = [
    ("MCP.AUTH.PROTOCOL_BINDING", RequirementLevel::Required),
    (
        "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
        RequirementLevel::Required,
    ),
    ("MCP.AUTH.CREDENTIAL_SEPARATION", RequirementLevel::Required),
    (
        "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY",
        RequirementLevel::Required,
    ),
    (
        "MCP.AUTH.FINAL_OPERATION_BINDING",
        RequirementLevel::Required,
    ),
];

fn registry() -> PropertyRegistry {
    builtin_registry().expect("v1 registry loads")
}

fn auth() -> AssessmentProfile {
    mcp_auth_hardening_profile().expect("profile loads")
}

/// Every property this cycle added, by the identifier the registry uses.
fn cycle_018_properties(registry: &PropertyRegistry) -> BTreeSet<&str> {
    registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .filter(|id| {
            id.starts_with("MCP.AUTH.") || *id == "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY"
        })
        .collect()
}

#[test]
fn the_profile_matches_the_approved_requirement_levels_exactly() {
    let profile = auth();
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
fn every_selected_property_exists_in_the_v1_registry() {
    let profile = auth();
    let registry = registry();
    validate_profile(&profile, &registry).expect("the profile validates against the registry");

    for (id, _) in APPROVED {
        assert!(
            registry.properties.iter().any(|property| property.id == id),
            "{id} is not in the v1 registry"
        );
    }
}

#[test]
fn the_profile_selects_from_v1_and_not_from_the_agentic_registry() {
    // The placement is the point. These are MCP protocol and OAuth surfaces,
    // not agent behaviours; selecting them from v2 would have created an
    // eleventh Agentic risk family or forced an exclusion rule to hide one.
    let agentic = agentic_registry().expect("v2 registry loads");
    for (id, _) in APPROVED {
        assert!(
            !agentic.properties.iter().any(|property| property.id == id),
            "{id} leaked into the v2 Agentic registry"
        );
    }
}

#[test]
fn the_profile_resolves_by_name() {
    assert_eq!(
        resolve_profile(PROFILE_ID).expect("resolves by name"),
        auth()
    );
}

#[test]
fn the_profile_is_deterministic() {
    let first = auth();
    let second = auth();
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
    assert_eq!(mcp.properties.len(), 10);

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

    let rag_security = rag_security_profile().expect("profile loads");
    assert_eq!(rag_security.id, "rag-security-baseline-2026");
    assert_eq!(rag_security.properties.len(), 6);
}

#[test]
fn the_earlier_v1_profile_keeps_every_requirement_level_it_had() {
    // The count alone would not catch a requirement level moving from OPTIONAL
    // to REQUIRED, which changes what a gap means without changing the
    // denominator at all.
    let approved: [(&str, RequirementLevel); 10] = [
        ("MCP.DISCOVERY.PASSIVE_BOUNDARY", RequirementLevel::Required),
        ("MCP.DISCOVERY.EXPLICIT_TARGET", RequirementLevel::Required),
        ("MCP.AUTHZ.PER_OPERATION", RequirementLevel::Required),
        (
            "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
            RequirementLevel::Required,
        ),
        (
            "MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS",
            RequirementLevel::Conditional,
        ),
        (
            "MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT",
            RequirementLevel::Conditional,
        ),
        ("MCP.EVIDENCE.REDACTION", RequirementLevel::Optional),
        ("MCP.IDENTITY.CONFUSED_DEPUTY", RequirementLevel::Optional),
        ("MCP.DISCOVERY.STREAMABLE_HTTP", RequirementLevel::Optional),
        (
            "MCP.AUTHZ.DYNAMIC_VALIDATION",
            RequirementLevel::Conditional,
        ),
    ];

    let mcp = builtin_profile().expect("profile loads");
    for (index, (id, requirement)) in approved.iter().enumerate() {
        assert_eq!(&mcp.properties[index].id, id);
        assert_eq!(
            mcp.properties[index].requirement, *requirement,
            "{id} changed requirement level"
        );
    }
}

#[test]
fn the_auth_profile_selects_no_property_an_earlier_profile_selects() {
    // Overlap would make one property count toward two denominators, which is
    // how a coverage number quietly inflates without anyone editing a number.
    let selected: BTreeSet<&str> = APPROVED.iter().map(|(id, _)| *id).collect();

    for earlier in [
        builtin_profile().expect("profile loads"),
        agentic_profile().expect("profile loads"),
        prompt_injection_profile().expect("profile loads"),
        tool_security_profile().expect("profile loads"),
        identity_security_profile().expect("profile loads"),
        memory_security_profile().expect("profile loads"),
        rag_security_profile().expect("profile loads"),
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
fn every_cycle_018_property_in_the_registry_is_selected() {
    // A property in the registry that no profile selects is a property nothing
    // will ever assess: present in the catalogue, absent from every run, and
    // indistinguishable in a report from one that was assessed and held.
    let registry = registry();
    let selected: BTreeSet<&str> = APPROVED.iter().map(|(id, _)| *id).collect();
    assert_eq!(cycle_018_properties(&registry), selected);
}

#[test]
fn nothing_in_this_profile_is_conditional_or_optional() {
    // Unlike the profiles before it, this one has no CONDITIONAL entry, and
    // that is the requirement level AC-08 leaves available rather than an
    // oversight.
    //
    // Only REQUIRED properties feed the required-coverage ratio. Seven of these
    // ten are gated on an auth control/evidence predicate, so a missing control
    // reports NOT_TESTED — a gap. Marking one CONDITIONAL would leave that gap
    // printed in the report and counting toward nothing, which is the same
    // evasion AC-08 forbids, reached through a different door.
    //
    // The honest "nothing to answer for" case is handled one layer down and
    // more precisely: a target on a legacy revision, without HTTP transport or
    // without an authorization flow fails a *target-shape* predicate, and the
    // property is NOT_APPLICABLE and out of the denominator entirely.
    let profile = auth();
    assert_eq!(
        profile
            .properties
            .iter()
            .filter(|property| property.requirement == RequirementLevel::Required)
            .count(),
        10
    );
    for property in &profile.properties {
        assert_eq!(
            property.requirement,
            RequirementLevel::Required,
            "{} would report a gap that counts toward nothing",
            property.id
        );
    }
}

#[test]
fn requirement_levels_are_only_the_three_defined_ones() {
    for property in &auth().properties {
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
fn the_agentic_risk_families_still_number_exactly_ten() {
    // The count Cycle 012 fixed, re-checked from the profile side. Ten
    // properties were added to v1 and none of them created a family in v2.
    let agentic = agentic_registry().expect("v2 registry loads");
    let families: std::collections::HashSet<_> = agentic
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10, "the Agentic risk family count moved");
}

/// Facts for a target that presents every Cycle 018 surface.
fn facts(overrides: serde_json::Value) -> AssessmentFacts {
    let mut value = serde_json::json!({
        "tools_count": 1,
        "resources_count": 0,
        "prompts_count": 0,
        "transport": "http",
        "authorization_present": true,
        "dynamic_authorization_allowed": false,
        "execution_integrity_supported": true,
        "confused_deputy_supported": true,
        "mcp_current_protocol_present": true,
        "mcp_http_transport_present": true,
        "mcp_auth_flow_present": true,
        "mcp_identity_metadata_present": true,
        "protected_resource_metadata_present": true,
        "authorization_server_metadata_present": true,
        "token_claims_present": true,
        "pkce_context_present": true,
        "scope_challenge_present": true,
        "client_registration_present": true,
        "credential_forwarding_present": true
    });
    for (key, replacement) in overrides.as_object().expect("an object") {
        value[key] = replacement.clone();
    }
    serde_json::from_value(value).expect("facts decode")
}

#[test]
fn the_denominator_of_this_profile_is_its_own_property_count() {
    // Cycle 006 coverage semantics, unchanged: a profile's denominator is the
    // properties it selects. Adding a profile adds a denominator rather than
    // widening an existing one.
    let plan = dare_coverage::build_assessment_plan(&auth(), &registry(), &facts(json_empty()))
        .expect("plan builds");
    assert_eq!(plan.profile_id, PROFILE_ID);
    assert_eq!(plan.properties.len(), 10);
    assert!(plan
        .properties
        .iter()
        .all(|property| property.coverage_status == CoverageStatus::Applicable));
}

#[test]
fn a_missing_auth_control_is_not_tested_rather_than_not_applicable() {
    // AC-08, checked through the profile. The target runs an authorization
    // flow; the PKCE binding simply was not observed. That is a gap in what was
    // assessed, not a statement that PKCE does not apply here — and the two
    // read very differently in a report, because NOT_APPLICABLE leaves the
    // denominator while NOT_TESTED lowers the ratio.
    let plan = dare_coverage::build_assessment_plan(
        &auth(),
        &registry(),
        &facts(serde_json::json!({ "pkce_context_present": false })),
    )
    .expect("plan builds");

    assert_eq!(plan.properties.len(), 10, "the denominator moved");
    let pkce = plan
        .properties
        .iter()
        .find(|property| property.property_id == "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY")
        .expect("selected");
    assert_eq!(pkce.coverage_status, CoverageStatus::NotTested);
    assert!(
        !pkce.rationale.trim().is_empty(),
        "a gap with no rationale is indistinguishable from one nobody looked at"
    );

    assert_eq!(
        plan.properties
            .iter()
            .filter(|property| property.coverage_status == CoverageStatus::Applicable)
            .count(),
        9
    );
}

#[test]
fn every_auth_control_predicate_reports_a_gap_when_its_evidence_is_absent() {
    // The same check across all seven control-gated properties, so the one
    // above cannot be true by accident of which property was picked.
    for (fact, property_id) in [
        (
            "protected_resource_metadata_present",
            "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
        ),
        (
            "authorization_server_metadata_present",
            "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
        ),
        (
            "token_claims_present",
            "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
        ),
        (
            "pkce_context_present",
            "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
        ),
        (
            "scope_challenge_present",
            "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
        ),
        (
            "client_registration_present",
            "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
        ),
        (
            "credential_forwarding_present",
            "MCP.AUTH.CREDENTIAL_SEPARATION",
        ),
    ] {
        let plan = dare_coverage::build_assessment_plan(
            &auth(),
            &registry(),
            &facts(serde_json::json!({ fact: false })),
        )
        .expect("plan builds");
        let property = plan
            .properties
            .iter()
            .find(|property| property.property_id == property_id)
            .expect("selected");
        assert_eq!(
            property.coverage_status,
            CoverageStatus::NotTested,
            "{property_id} relabelled a missing control as something other than a gap"
        );
    }
}

#[test]
fn a_target_on_a_legacy_revision_reports_every_auth_property_not_applicable() {
    // The modern MCP authorization surface does not exist on the older
    // revision. Reporting these properties as gaps there would be reporting a
    // target for not having a control the revision never defined.
    let plan = dare_coverage::build_assessment_plan(
        &auth(),
        &registry(),
        &facts(serde_json::json!({ "mcp_current_protocol_present": false })),
    )
    .expect("plan builds");

    assert_eq!(plan.properties.len(), 10);
    for property in &plan.properties {
        assert_eq!(
            property.coverage_status,
            CoverageStatus::NotApplicable,
            "{} still claims to apply without the current revision",
            property.property_id
        );
    }
}

fn json_empty() -> serde_json::Value {
    serde_json::json!({})
}
