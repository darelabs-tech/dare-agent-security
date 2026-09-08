//! Cycle 019's eight additive supply-chain properties, and the nine predicates
//! that decide when they apply.
//!
//! Two things are being held at once here, and they pull in opposite
//! directions.
//!
//! **Additive means additive.** Two supply-chain properties already existed,
//! `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` and `…CAPABILITY_DRIFT`, both from
//! Cycle 012 and both under the `AGENTIC_SUPPLY_CHAIN` risk family. One of them
//! is selected by the agentic baseline profile at `CONDITIONAL`. Changing
//! either identifier, either family, or that requirement level would alter what
//! every assessment already filed against the baseline means, without moving
//! any denominator and without anything looking wrong.
//!
//! **The family count must not move.** Cycle 017 added six `AGENT.RAG.*`
//! properties to this same registry carrying *no* risk family, because
//! retrieval is not an Agentic risk family. Cycle 019 is the opposite case: its
//! family already exists, so its properties carry it, and the count must still
//! read ten afterwards. Both directions are asserted, because a property that
//! forgot its family and a property that invented one fail differently.

use std::collections::{BTreeSet, HashSet};

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_registry, evaluate_applicability,
    supply_chain_provenance, AssessmentFacts, CoverageStatus, Predicate, PropertyCategory,
    PropertyDefinition, PropertyRegistry, RequirementLevel, RiskFamily,
};

/// The two properties Cycle 012 created and Cycle 019 reuses unchanged.
const INHERITED: [&str; 2] = [
    "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
    "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT",
];

/// The eight the approval authorized, and no others.
const ADDED: [&str; 8] = [
    "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
    "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
    "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
    "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
    "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
    "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
];

/// The nine predicates Cycle 019 adds. `agent_present` and
/// `external_components_present` are reused from Cycle 012.
const NEW_PREDICATES: [&str; 9] = [
    "supply_chain_bom_present",
    "component_digest_present",
    "source_trust_policy_present",
    "provenance_present",
    "attestation_present",
    "dependency_graph_present",
    "model_component_present",
    "dataset_component_present",
    "declared_observed_components_present",
];

/// Predicates that describe the target's *shape*. Their absence is genuinely
/// "nothing to answer for".
const TARGET_SHAPE: [&str; 2] = ["model_component_present", "dataset_component_present"];

fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

fn supply_chain(registry: &PropertyRegistry) -> Vec<&PropertyDefinition> {
    registry
        .properties
        .iter()
        .filter(|property| property.id.starts_with("AGENT.SUPPLY_CHAIN."))
        .collect()
}

/// Facts for a target that presents every supply-chain surface.
fn full_target() -> AssessmentFacts {
    AssessmentFacts {
        tools_count: 1,
        agent_present: true,
        external_components_present: true,
        supply_chain_bom_present: true,
        component_digest_present: true,
        source_trust_policy_present: true,
        provenance_present: true,
        attestation_present: true,
        dependency_graph_present: true,
        model_component_present: true,
        dataset_component_present: true,
        declared_observed_components_present: true,
        ..Default::default()
    }
}

fn without(predicate: &str) -> AssessmentFacts {
    let mut facts = full_target();
    match predicate {
        "supply_chain_bom_present" => facts.supply_chain_bom_present = false,
        "component_digest_present" => facts.component_digest_present = false,
        "source_trust_policy_present" => facts.source_trust_policy_present = false,
        "provenance_present" => facts.provenance_present = false,
        "attestation_present" => facts.attestation_present = false,
        "dependency_graph_present" => facts.dependency_graph_present = false,
        "model_component_present" => facts.model_component_present = false,
        "dataset_component_present" => facts.dataset_component_present = false,
        "declared_observed_components_present" => {
            facts.declared_observed_components_present = false
        }
        "agent_present" => facts.agent_present = false,
        "external_components_present" => facts.external_components_present = false,
        other => panic!("unknown predicate {other}"),
    }
    facts
}

fn status_of(property: &PropertyDefinition, facts: &AssessmentFacts) -> CoverageStatus {
    evaluate_applicability(property, facts)
        .expect("applicability decides")
        .status
}

// --------------------------------------------------------------- additivity

#[test]
fn exactly_the_eight_approved_properties_were_added() {
    let registry = registry();
    let present: BTreeSet<&str> = supply_chain(&registry)
        .iter()
        .map(|property| property.id.as_str())
        .collect();

    let expected: BTreeSet<&str> = INHERITED.iter().chain(ADDED.iter()).copied().collect();
    assert_eq!(
        present, expected,
        "the supply-chain namespace is not exactly the ten approved properties"
    );
}

#[test]
fn the_two_inherited_properties_are_unchanged() {
    // Not just present — unchanged. Cycle 012 gave both the same two
    // predicates, and a cycle that quietly added a third would narrow when they
    // apply without anyone editing a requirement level.
    let registry = registry();
    for id in INHERITED {
        let property = registry
            .properties
            .iter()
            .find(|candidate| candidate.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));

        assert_eq!(property.risk_family, Some(RiskFamily::AgenticSupplyChain));
        assert_eq!(property.category, PropertyCategory::SupplyChain);

        let predicates: BTreeSet<&str> = property
            .applicability
            .predicates
            .iter()
            .map(|predicate| predicate.as_str())
            .collect();
        assert_eq!(
            predicates,
            BTreeSet::from(["agent_present", "external_components_present"]),
            "{id} no longer applies where it used to"
        );
    }
}

#[test]
fn no_parallel_supply_namespace_was_introduced() {
    // AC-06. `AGENT.SUPPLY.*` alongside `AGENT.SUPPLY_CHAIN.*` would be two
    // namespaces for one subject, and a reader would have to know which is
    // which to know what a report covered.
    for registry in [registry(), builtin_registry().expect("v1 registry")] {
        for property in &registry.properties {
            assert!(
                !property.id.starts_with("AGENT.SUPPLY."),
                "{} opens a parallel namespace",
                property.id
            );
        }
    }
}

#[test]
fn every_new_property_carries_the_existing_risk_family() {
    let registry = registry();
    for id in ADDED {
        let property = registry
            .properties
            .iter()
            .find(|candidate| candidate.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        assert_eq!(
            property.risk_family,
            Some(RiskFamily::AgenticSupplyChain),
            "{id} does not report under the family that already exists"
        );
        assert_eq!(property.category, PropertyCategory::SupplyChain);
    }
}

#[test]
fn the_agentic_risk_family_count_is_still_exactly_ten() {
    // Both directions. A property that forgot its family and a property that
    // invented one fail differently, and only one of them changes this number.
    let registry = registry();
    let families: HashSet<RiskFamily> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10, "the Agentic risk family count moved");
    assert!(families.contains(&RiskFamily::AgenticSupplyChain));
}

#[test]
fn the_agentic_baseline_profile_keeps_its_supply_chain_selection_and_level() {
    // AC-71. The count alone would not catch CONDITIONAL becoming REQUIRED,
    // which changes what a gap means for every assessment already filed against
    // this profile without moving its denominator.
    let profile = agentic_profile().expect("profile loads");
    assert_eq!(profile.properties.len(), 10);

    let entry = profile
        .properties
        .iter()
        .find(|entry| entry.id == "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE")
        .expect("the baseline still selects component provenance");
    assert_eq!(entry.requirement, RequirementLevel::Conditional);

    // And the eight new properties did not silently join the baseline profile.
    for id in ADDED {
        assert!(
            !profile.properties.iter().any(|entry| entry.id == id),
            "{id} entered the agentic baseline profile without an approval"
        );
    }
}

// ------------------------------------------------------------- applicability

#[test]
fn the_nine_new_predicates_exist_and_are_split_between_registry_and_engine() {
    // Seven gate a registry property's applicability. Two do not, and the
    // reason is worth stating rather than leaving as an off-by-two.
    //
    // `provenance_present` would naturally gate
    // `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` — but that property is Cycle
    // 012's, and its two predicates are frozen. Adding a third would narrow
    // when it applies, which is a change to what every assessment already filed
    // against it means. So provenance participates in evaluation rather than in
    // applicability.
    //
    // `declared_observed_components_present` is the same shape: it decides
    // whether the declared/observed comparison can be made at all, which the
    // evaluator asks, not the registry.
    const REGISTRY_GATED: [&str; 7] = [
        "supply_chain_bom_present",
        "component_digest_present",
        "source_trust_policy_present",
        "attestation_present",
        "dependency_graph_present",
        "model_component_present",
        "dataset_component_present",
    ];
    const ENGINE_ONLY: [&str; 2] = ["provenance_present", "declared_observed_components_present"];

    let known: HashSet<&str> = NEW_PREDICATES.into_iter().collect();
    let mut found = HashSet::new();
    for property in supply_chain(&registry()) {
        for predicate in &property.applicability.predicates {
            if known.contains(predicate.as_str()) {
                found.insert(predicate.as_str());
            }
        }
    }

    assert_eq!(
        found,
        REGISTRY_GATED.into_iter().collect::<HashSet<_>>(),
        "the registry-gated predicate set changed"
    );
    for predicate in ENGINE_ONLY {
        assert!(
            !found.contains(predicate),
            "{predicate} started gating a registry property; if that is intended it changes              when an inherited property applies"
        );
    }
    // And every one of the nine parses, so none is a string nothing can read.
    for predicate in NEW_PREDICATES {
        serde_json::from_value::<Predicate>(serde_json::Value::String(predicate.to_owned()))
            .unwrap_or_else(|_| panic!("{predicate} is not a known predicate"));
    }
}

#[test]
fn an_unknown_predicate_fails_closed() {
    // A predicate the registry does not know must not be treated as satisfied.
    let hostile = serde_json::json!({
        "id": "AGENT.SUPPLY_CHAIN.MADE_UP",
        "title": "t",
        "risk_family": "AGENTIC_SUPPLY_CHAIN",
        "category": "SUPPLY_CHAIN",
        "description": "d",
        "applicability": { "predicates": ["supply_chain_vibes_present"] },
        "supported_modes": ["static"],
        "evidence": { "required_for_confirmed_verdict": true },
        "standards": [],
        "maturity": "EXPERIMENTAL"
    });
    assert!(serde_json::from_value::<PropertyDefinition>(hostile).is_err());
}

#[test]
fn a_target_with_no_agent_or_no_external_components_is_not_applicable() {
    // Target shape, inherited from Cycle 012. A system with no external
    // components genuinely has no supply chain to answer for.
    let registry = registry();
    for predicate in ["agent_present", "external_components_present"] {
        let facts = without(predicate);
        for property in supply_chain(&registry) {
            assert_eq!(
                status_of(property, &facts),
                CoverageStatus::NotApplicable,
                "{} should not apply without {predicate}",
                property.id
            );
        }
    }
}

#[test]
fn a_target_with_no_model_or_dataset_is_not_applicable_for_that_property_only() {
    // The two genuinely shape-shaped predicates this cycle adds. A system with
    // no model has no model lineage to answer for — and that must not spill
    // over onto the other nine properties.
    let registry = registry();

    let facts = without("model_component_present");
    let lineage = registry
        .properties
        .iter()
        .find(|p| p.id == "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE")
        .expect("present");
    assert_eq!(status_of(lineage, &facts), CoverageStatus::NotApplicable);
    let identity = registry
        .properties
        .iter()
        .find(|p| p.id == "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY")
        .expect("present");
    assert_eq!(status_of(identity, &facts), CoverageStatus::Applicable);

    let facts = without("dataset_component_present");
    let dataset = registry
        .properties
        .iter()
        .find(|p| p.id == "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE")
        .expect("present");
    assert_eq!(status_of(dataset, &facts), CoverageStatus::NotApplicable);
    assert_eq!(status_of(identity, &facts), CoverageStatus::Applicable);
}

#[test]
fn a_missing_supply_chain_control_is_a_gap_and_never_not_applicable() {
    // AC-14, and the reason this cycle inherits Cycle 018's split rather than
    // inventing one. A target that ships external components but publishes no
    // bill of materials, records no digest, or declares no approved-source
    // policy has a **gap**. Reporting NOT_APPLICABLE there would let a target
    // score better for supplying less evidence about itself.
    let registry = registry();
    let evidence = [
        (
            "supply_chain_bom_present",
            "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
        ),
        (
            "component_digest_present",
            "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
        ),
        (
            "source_trust_policy_present",
            "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
        ),
        (
            "attestation_present",
            "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
        ),
        (
            "dependency_graph_present",
            "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
        ),
    ];

    for (predicate, property_id) in evidence {
        let facts = without(predicate);
        let property = registry
            .properties
            .iter()
            .find(|candidate| candidate.id == property_id)
            .unwrap_or_else(|| panic!("{property_id} is missing"));
        let decision = evaluate_applicability(property, &facts).expect("decides");
        assert_eq!(
            decision.status,
            CoverageStatus::NotTested,
            "{property_id} relabelled a missing control as something other than a gap"
        );
        assert!(
            !decision.rationale.trim().is_empty(),
            "a gap with no rationale is indistinguishable from one nobody looked at"
        );
    }
}

#[test]
fn the_evidence_and_shape_classifications_do_not_overlap() {
    // A predicate that were both would decide arbitrarily which branch ran, and
    // the two branches produce opposite answers.
    for predicate in NEW_PREDICATES {
        let parsed: Predicate =
            serde_json::from_value(serde_json::Value::String(predicate.to_owned()))
                .unwrap_or_else(|_| panic!("{predicate} does not parse"));
        let shape = parsed.is_target_shape();
        let evidence = parsed.is_supply_chain_evidence();
        assert!(
            shape != evidence,
            "{predicate} is classified as both shape and evidence, or as neither"
        );
        assert_eq!(
            shape,
            TARGET_SHAPE.contains(&predicate),
            "{predicate} is classified against what the design says it is"
        );
    }
}

#[test]
fn a_complete_target_makes_every_supply_chain_property_applicable() {
    // The other half of the gap tests. Tightening applicability is only correct
    // if a target that supplies everything is still assessed.
    let registry = registry();
    let facts = full_target();
    for property in supply_chain(&registry) {
        assert_eq!(
            status_of(property, &facts),
            CoverageStatus::Applicable,
            "{} is not applicable to a target that presents every surface",
            property.id
        );
    }
}

// ------------------------------------------------------------------ mapping

#[test]
fn every_supply_chain_property_is_mapped_in_the_standards_record() {
    // A property in the registry that the provenance record does not mention
    // would report under a taxonomy nobody wrote down.
    let record = supply_chain_provenance().expect("provenance validates");
    let mapped: HashSet<&str> = record
        .property_mappings
        .iter()
        .map(|mapping| mapping.property_id.as_str())
        .collect();

    for property in supply_chain(&registry()) {
        assert!(
            mapped.contains(property.id.as_str()),
            "{} is in the registry and absent from the standards record",
            property.id
        );
    }
    assert_eq!(mapped.len(), 10);
}

#[test]
fn the_registry_records_taxonomy_provenance_rather_than_interchange_formats() {
    // The registry's `standards` field is checked against the *Agentic*
    // provenance manifest, whose sources are risk taxonomies. CycloneDX, SPDX,
    // SLSA and in-toto are interchange and semantic references, and they are
    // recorded in the Cycle 019 provenance record instead — one subject, one
    // place, rather than two that must agree.
    for property in supply_chain(&registry()) {
        for standard in &property.standards {
            assert_eq!(
                standard.source, "OWASP_AGENTIC_TOP10_2026",
                "{} cites {} in the registry rather than in the cycle record",
                property.id, standard.source
            );
        }
    }

    let record = supply_chain_provenance().expect("provenance validates");
    let sources: HashSet<&str> = record
        .property_mappings
        .iter()
        .map(|mapping| mapping.standard.as_str())
        .collect();
    for expected in [
        "CYCLONEDX_1_7",
        "SPDX_3_0_1",
        "IN_TOTO_ATTESTATION_1_2",
        "SLSA_1_2",
    ] {
        assert!(sources.contains(expected), "{expected} is mapped nowhere");
    }
}
