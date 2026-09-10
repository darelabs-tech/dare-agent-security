//! Cycle 020 A2A registry properties, predicates and applicability semantics.
//!
//! Two claims are pinned here, and they fail in opposite directions.
//!
//! The first is that the change is **additive**: ten properties were added to
//! the v2 agentic registry and nothing that was already there moved. The two
//! pre-existing `AGENT.A2A.*` properties are the ones at risk, because they are
//! the obvious place to "improve" while implementing the cycle that uses them.
//!
//! The second is that an absent A2A **control** is a gap rather than an
//! exemption. A deployment that speaks A2A and records no authentication
//! evidence must not score the same as one that speaks no A2A at all — the
//! first has a hole, the second has no surface, and collapsing them would let a
//! target improve its coverage by collecting less.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_registry, builtin_registry, evaluate_applicability, AssessmentFacts, CoverageStatus,
    Predicate, PropertyDefinition, PropertyRegistry,
};

/// The two properties Cycle 012 created. Their ids, predicates and registry
/// entries are frozen.
const INHERITED: [&str; 2] = [
    "AGENT.A2A.MESSAGE_AUTHENTICITY",
    "AGENT.A2A.AUTHORITY_PROPAGATION",
];

/// The ten the approval authorized, and no others.
const ADDED: [&str; 10] = [
    "AGENT.A2A.PEER_IDENTITY_BINDING",
    "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY",
    "AGENT.A2A.SKILL_AUTHORIZATION",
    "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
    "AGENT.A2A.TENANT_BOUNDARY",
    "AGENT.A2A.DATA_SCOPE_BOUNDARY",
    "AGENT.A2A.REPLAY_BOUNDARY",
    "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY",
    "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
    "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
];

/// The eleven predicates Cycle 020 adds.
const NEW_PREDICATES: [&str; 11] = [
    "a2a_exchange_present",
    "agent_card_present",
    "a2a_extension_present",
    "push_notification_config_present",
    "peer_authentication_evidence_present",
    "skill_authorization_policy_present",
    "task_context_binding_present",
    "a2a_tenant_policy_present",
    "data_scope_policy_present",
    "replay_policy_present",
    "protocol_policy_present",
];

/// The four that describe what the target *is*.
const TARGET_SHAPE: [&str; 4] = [
    "a2a_exchange_present",
    "agent_card_present",
    "a2a_extension_present",
    "push_notification_config_present",
];

fn registry() -> PropertyRegistry {
    agentic_registry().expect("the agentic registry loads")
}

fn a2a(registry: &PropertyRegistry) -> Vec<&PropertyDefinition> {
    registry
        .properties
        .iter()
        .filter(|property| property.id.starts_with("AGENT.A2A."))
        .collect()
}

/// A target that has every A2A surface and every piece of A2A evidence.
fn full_target() -> AssessmentFacts {
    AssessmentFacts {
        agent_present: true,
        multi_agent_present: true,
        delegated_identity_present: true,
        a2a_exchange_present: true,
        agent_card_present: true,
        a2a_extension_present: true,
        push_notification_config_present: true,
        peer_authentication_evidence_present: true,
        skill_authorization_policy_present: true,
        task_context_binding_present: true,
        a2a_tenant_policy_present: true,
        data_scope_policy_present: true,
        replay_policy_present: true,
        protocol_policy_present: true,
        ..Default::default()
    }
}

fn without(predicate: &str) -> AssessmentFacts {
    let mut facts = full_target();
    match predicate {
        "a2a_exchange_present" => facts.a2a_exchange_present = false,
        "agent_card_present" => facts.agent_card_present = false,
        "a2a_extension_present" => facts.a2a_extension_present = false,
        "push_notification_config_present" => facts.push_notification_config_present = false,
        "peer_authentication_evidence_present" => {
            facts.peer_authentication_evidence_present = false
        }
        "skill_authorization_policy_present" => facts.skill_authorization_policy_present = false,
        "task_context_binding_present" => facts.task_context_binding_present = false,
        "a2a_tenant_policy_present" => facts.a2a_tenant_policy_present = false,
        "data_scope_policy_present" => facts.data_scope_policy_present = false,
        "replay_policy_present" => facts.replay_policy_present = false,
        "protocol_policy_present" => facts.protocol_policy_present = false,
        other => panic!("unknown predicate {other}"),
    }
    facts
}

fn status_of(property: &PropertyDefinition, facts: &AssessmentFacts) -> CoverageStatus {
    evaluate_applicability(property, facts)
        .expect("applicability decides")
        .status
}

#[test]
fn exactly_the_ten_approved_properties_were_added() {
    let registry = registry();
    let ids: BTreeSet<&str> = a2a(&registry)
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    assert_eq!(ids.len(), INHERITED.len() + ADDED.len());
    for inherited in INHERITED {
        assert!(ids.contains(inherited), "{inherited} is missing");
    }
    for added in ADDED {
        assert!(ids.contains(added), "{added} is missing");
    }
}

#[test]
fn the_two_inherited_properties_are_unchanged() {
    // The obvious place to "improve" while implementing the cycle that uses
    // them. Their predicate sets are frozen: changing one would change what
    // every assessment already filed against it meant.
    let registry = registry();
    let properties = a2a(&registry);

    let authenticity = properties
        .iter()
        .find(|property| property.id == "AGENT.A2A.MESSAGE_AUTHENTICITY")
        .expect("the inherited authenticity property");
    let predicates: Vec<&str> = authenticity
        .applicability
        .predicates
        .iter()
        .map(|predicate| predicate.as_str())
        .collect();
    assert_eq!(predicates, vec!["agent_present", "multi_agent_present"]);

    let authority = properties
        .iter()
        .find(|property| property.id == "AGENT.A2A.AUTHORITY_PROPAGATION")
        .expect("the inherited authority property");
    let predicates: Vec<&str> = authority
        .applicability
        .predicates
        .iter()
        .map(|predicate| predicate.as_str())
        .collect();
    assert_eq!(
        predicates,
        vec![
            "agent_present",
            "multi_agent_present",
            "delegated_identity_present"
        ]
    );
}

#[test]
fn no_parallel_a2a_namespace_was_introduced() {
    // A top-level `A2A.*` would give a reader two places to look for one risk,
    // and nothing would ever fail to tell them which was authoritative.
    for registry in [
        registry(),
        builtin_registry().expect("the MCP registry loads"),
    ] {
        for property in &registry.properties {
            assert!(
                !property.id.starts_with("A2A."),
                "{} left the AGENT.A2A namespace",
                property.id
            );
        }
    }
}

#[test]
fn every_new_property_carries_the_existing_risk_family() {
    let registry = registry();
    for property in a2a(&registry) {
        assert_eq!(
            serde_json::to_value(property.risk_family).expect("serializes"),
            serde_json::json!("INSECURE_INTER_AGENT_COMMUNICATION"),
            "{} changed family",
            property.id
        );
    }
}

#[test]
fn the_agentic_risk_family_count_is_still_exactly_ten() {
    // Cycle 012 froze ten families. Cycle 020 adds properties to one of them
    // and creates none.
    let registry = registry();
    let families: BTreeSet<String> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .map(|family| {
            serde_json::to_value(family)
                .expect("serializes")
                .as_str()
                .expect("a string")
                .to_owned()
        })
        .collect();
    assert_eq!(families.len(), 10, "{families:?}");
    assert!(families.contains("INSECURE_INTER_AGENT_COMMUNICATION"));
}

#[test]
fn the_agentic_baseline_profile_keeps_its_a2a_selection_and_level() {
    // The baseline already selects `AGENT.A2A.MESSAGE_AUTHENTICITY`. Adding the
    // ten new properties to it would have been the natural way to make them
    // visible, and would have changed a denominator eight cycles of assessments
    // were filed against.
    let profile = dare_coverage::agentic_profile().expect("the baseline profile loads");
    let selected: BTreeSet<&str> = profile
        .properties
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();

    assert!(selected.contains("AGENT.A2A.MESSAGE_AUTHENTICITY"));
    assert_eq!(profile.properties.len(), 10);
    for added in ADDED {
        assert!(
            !selected.contains(added),
            "{added} was added to the agentic baseline, changing its denominator"
        );
    }
}

#[test]
fn the_eleven_new_predicates_exist_and_are_registry_reachable() {
    let registry = registry();
    let used: BTreeSet<&str> = a2a(&registry)
        .iter()
        .flat_map(|property| property.applicability.predicates.iter())
        .map(|predicate| predicate.as_str())
        .collect();

    for predicate in NEW_PREDICATES {
        assert!(
            used.contains(predicate),
            "{predicate} is declared but no property gates on it"
        );
    }
}

#[test]
fn an_unknown_predicate_fails_closed() {
    assert!(serde_json::from_str::<Predicate>("\"a2a_probably_fine\"").is_err());
}

#[test]
fn a_target_with_no_a2a_surface_is_not_applicable() {
    // The honest exemption. A system that exchanges no A2A messages has no
    // message binding to answer for, and a system that configures no push
    // notification has no callback boundary.
    let registry = registry();
    let properties = a2a(&registry);

    for (predicate, property_id) in [
        ("a2a_exchange_present", "AGENT.A2A.MESSAGE_CONTEXT_BINDING"),
        ("agent_card_present", "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY"),
        (
            "a2a_extension_present",
            "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
        ),
        (
            "push_notification_config_present",
            "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
        ),
    ] {
        let property = properties
            .iter()
            .find(|property| property.id == property_id)
            .unwrap_or_else(|| panic!("{property_id} is missing"));
        assert_eq!(
            status_of(property, &without(predicate)),
            CoverageStatus::NotApplicable,
            "{property_id} without {predicate}"
        );
    }
}

#[test]
fn a_missing_a2a_control_is_a_gap_and_never_not_applicable() {
    // The load-bearing assertion of this file. A deployment that speaks A2A and
    // records no authentication evidence must not score the same as one that
    // speaks no A2A at all.
    let registry = registry();
    let properties = a2a(&registry);

    for (predicate, property_id) in [
        (
            "peer_authentication_evidence_present",
            "AGENT.A2A.PEER_IDENTITY_BINDING",
        ),
        (
            "skill_authorization_policy_present",
            "AGENT.A2A.SKILL_AUTHORIZATION",
        ),
        (
            "task_context_binding_present",
            "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
        ),
        ("a2a_tenant_policy_present", "AGENT.A2A.TENANT_BOUNDARY"),
        ("data_scope_policy_present", "AGENT.A2A.DATA_SCOPE_BOUNDARY"),
        ("replay_policy_present", "AGENT.A2A.REPLAY_BOUNDARY"),
        (
            "protocol_policy_present",
            "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY",
        ),
    ] {
        let property = properties
            .iter()
            .find(|property| property.id == property_id)
            .unwrap_or_else(|| panic!("{property_id} is missing"));
        assert_eq!(
            status_of(property, &without(predicate)),
            CoverageStatus::NotTested,
            "{property_id} reported an exemption for the missing control {predicate}"
        );
    }
}

#[test]
fn the_evidence_and_shape_classifications_do_not_overlap() {
    // A predicate that was both would decide its own meaning depending on which
    // branch ran first, and the branch order is an implementation detail.
    for name in NEW_PREDICATES {
        let predicate: Predicate =
            serde_json::from_str(&format!("\"{name}\"")).expect("the predicate decodes");
        let shape = predicate.is_target_shape();
        let evidence = predicate.is_a2a_evidence();
        assert!(
            shape != evidence,
            "{name} is classified as both a shape and an evidence channel"
        );
        assert_eq!(
            shape,
            TARGET_SHAPE.contains(&name),
            "{name} is on the wrong side of the shape/evidence split"
        );
    }
}

#[test]
fn a_complete_target_makes_every_a2a_property_applicable() {
    // The control. If a fully-equipped target still reported gaps, the
    // predicates would be unsatisfiable and every assertion above would pass
    // for the wrong reason.
    let registry = registry();
    let facts = full_target();
    for property in a2a(&registry) {
        assert_eq!(
            status_of(property, &facts),
            CoverageStatus::Applicable,
            "{} is unsatisfiable",
            property.id
        );
    }
}

#[test]
fn every_a2a_property_is_mapped_in_the_standards_record() {
    let record = dare_coverage::a2a_provenance().expect("the standards record validates");
    let mapped: BTreeSet<&str> = record
        .property_mappings
        .iter()
        .map(|mapping| mapping.property_id.as_str())
        .collect();

    let registry = registry();
    for property in a2a(&registry) {
        assert!(
            mapped.contains(property.id.as_str()),
            "{} has no standards mapping",
            property.id
        );
    }
}

#[test]
fn the_registry_records_the_risk_taxonomy_rather_than_the_protocol() {
    // The registry cites OWASP because that is the taxonomy the property is
    // an instance of. A2A 1.0.0 supplies evidence shapes, and recording it here
    // as well would give two sources of truth that must agree — the mistake
    // Cycle 019 corrected by keeping interchange formats in the provenance
    // record only.
    let registry = registry();
    for property in a2a(&registry) {
        for standard in &property.standards {
            assert_eq!(
                standard.source, "OWASP_AGENTIC_TOP10_2026",
                "{} cites {} in the registry",
                property.id, standard.source
            );
        }
    }
}
