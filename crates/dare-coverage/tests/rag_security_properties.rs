//! Cycle 017 `AGENT.RAG.*` properties and their place in the taxonomy.
//!
//! The six retrieval properties are additive to the v2 registry. What makes
//! them unusual is that they carry **no Agentic risk family**, and this suite
//! exists to prove that is a deliberate, checked decision rather than an
//! omission.
//!
//! The reasoning, asserted rather than asserted-about:
//!
//! - LLM09:2026 belongs to the OWASP Top 10 for LLM Applications. The Agentic
//!   Top 10 is a different document with different identifiers.
//! - Folding six retrieval properties into an existing Agentic family would
//!   move that family's property count and file retrieval findings under a risk
//!   an operator was not looking at.
//! - Adding an eleventh family would inflate a published taxonomy with
//!   something OWASP did not put in it.
//!
//! So the family stays absent, the family view skips these properties entirely,
//! and the Agentic count stays at ten.

use std::collections::BTreeSet;

use dare_coverage::{
    agentic_registry, rag_security_provenance, AssessmentFacts, PropertyCategory, PropertyRegistry,
    RiskFamily, TransportKind,
};

/// The six properties approved for Cycle 017, in approved order.
const RAG_PROPERTIES: [&str; 6] = [
    "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
    "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
    "AGENT.RAG.PROVENANCE_INTEGRITY",
    "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
    "AGENT.RAG.RESULT_SET_INTEGRITY",
    "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
];

/// The five predicates Cycle 017 added.
const RAG_PREDICATES: [&str; 5] = [
    "retrieval_trace_present",
    "retrieval_policy_present",
    "document_acl_present",
    "retrieval_provenance_present",
    "retrieval_tenant_context_present",
];

fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

#[test]
fn the_six_approved_properties_exist_and_no_others_were_added() {
    let registry = registry();
    let present: BTreeSet<&str> = registry
        .properties
        .iter()
        .filter(|property| property.id.starts_with("AGENT.RAG."))
        .map(|property| property.id.as_str())
        .collect();

    assert_eq!(present, BTreeSet::from(RAG_PROPERTIES));
}

#[test]
fn no_rag_property_carries_an_agentic_risk_family() {
    // The central taxonomy decision of this cycle. If one of these ever gained
    // a family, its findings would start being counted under a risk it does not
    // belong to.
    let registry = registry();
    for id in RAG_PROPERTIES {
        let property = registry.get(id).unwrap_or_else(|| panic!("{id} missing"));
        assert!(
            property.risk_family.is_none(),
            "{id} declares risk family {:?}; LLM09 is not an Agentic risk family",
            property.risk_family
        );
    }
}

#[test]
fn the_agentic_family_count_is_still_exactly_ten() {
    let registry = registry();
    let families: std::collections::HashSet<RiskFamily> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(
        families.len(),
        10,
        "the Agentic taxonomy must stay at ten families"
    );
}

#[test]
fn every_non_rag_agent_property_still_requires_a_family() {
    // The relaxation is scoped to one namespace. Any other AGENT.* property
    // without a family would still be rejected by the loader, and none exists.
    let registry = registry();
    for property in &registry.properties {
        if !property.id.starts_with("AGENT.") || property.id.starts_with("AGENT.RAG.") {
            continue;
        }
        assert!(
            property.risk_family.is_some(),
            "{} lost its risk family",
            property.id
        );
    }
}

#[test]
fn a_non_rag_agent_property_without_a_family_is_still_refused() {
    // Proving the rule is still enforced, not merely that today's registry
    // happens to satisfy it. A namespace-scoped exception that quietly became
    // a general one would be invisible otherwise.
    let mut value: serde_json::Value =
        serde_json::from_str(dare_coverage::AGENTIC_REGISTRY_JSON).expect("registry parses");
    let properties = value["properties"].as_array_mut().expect("array");
    let mut smuggled = properties[0].clone();
    smuggled["id"] = serde_json::json!("AGENT.SOMETHING.NEW");
    smuggled
        .as_object_mut()
        .expect("object")
        .remove("risk_family");
    properties.push(smuggled);

    let raw = serde_json::to_string(&value).expect("serializes");
    let err = dare_coverage::load_registry(&raw).expect_err("must be refused");
    assert!(
        err.to_string().contains("risk_family"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_rag_property_declaring_a_family_is_refused() {
    // The exception runs both ways: a retrieval property may not smuggle itself
    // into the Agentic taxonomy by declaring a family either.
    let mut value: serde_json::Value =
        serde_json::from_str(dare_coverage::AGENTIC_REGISTRY_JSON).expect("registry parses");
    let properties = value["properties"].as_array_mut().expect("array");
    let index = properties
        .iter()
        .position(|property| property["id"] == "AGENT.RAG.PROVENANCE_INTEGRITY")
        .expect("declared");
    properties[index]["risk_family"] = serde_json::json!("MEMORY_CONTEXT_POISONING");

    let raw = serde_json::to_string(&value).expect("serializes");
    assert!(
        dare_coverage::load_registry(&raw).is_err(),
        "a RAG property was allowed to claim an Agentic family"
    );
}

#[test]
fn retrieval_is_its_own_category_and_not_folded_into_memory() {
    // Reusing MEMORY_CONTEXT would conflate retrieval with persisted memory,
    // which is precisely the distinction Cycles 016 and 017 exist to keep.
    let registry = registry();
    for id in RAG_PROPERTIES {
        let property = registry.get(id).expect("declared");
        assert_eq!(
            property.category,
            PropertyCategory::Retrieval,
            "{id} is filed under the wrong category"
        );
    }
}

#[test]
fn every_rag_property_maps_to_llm09_and_nothing_else() {
    let registry = registry();
    for id in RAG_PROPERTIES {
        let property = registry.get(id).expect("declared");
        assert_eq!(property.standards.len(), 1, "{id}");
        let mapping = &property.standards[0];
        assert_eq!(mapping.source, "OWASP_LLM_TOP10_2026");
        assert!(
            mapping.reference.contains("LLM09:2026"),
            "{id} maps to `{}`",
            mapping.reference
        );
        assert_eq!(mapping.status, "NORMATIVE");
    }
}

#[test]
fn no_rag_property_references_an_asi_identifier() {
    // Inventing an equivalence with an Agentic identifier is the other way the
    // taxonomy boundary could erode.
    let registry = registry();
    for id in RAG_PROPERTIES {
        let property = registry.get(id).expect("declared");
        let text = format!("{property:?}").to_uppercase();
        for asi in ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06"] {
            assert!(!text.contains(asi), "{id} references {asi}");
        }
    }
}

#[test]
fn the_five_new_predicates_exist_and_are_closed() {
    let registry = registry();
    let declared: BTreeSet<&str> = registry
        .properties
        .iter()
        .flat_map(|property| property.applicability.predicates.iter())
        .map(|predicate| predicate.as_str())
        .collect();

    for predicate in RAG_PREDICATES {
        assert!(declared.contains(predicate), "{predicate} is unused");
    }
}

#[test]
fn an_unknown_predicate_fails_closed() {
    let mut value: serde_json::Value =
        serde_json::from_str(dare_coverage::AGENTIC_REGISTRY_JSON).expect("registry parses");
    let properties = value["properties"].as_array_mut().expect("array");
    let index = properties
        .iter()
        .position(|property| property["id"] == "AGENT.RAG.PROVENANCE_INTEGRITY")
        .expect("declared");
    properties[index]["applicability"]["predicates"] =
        serde_json::json!(["agent_present", "retrieval_vibes_present"]);

    let raw = serde_json::to_string(&value).expect("serializes");
    assert!(
        dare_coverage::load_registry(&raw).is_err(),
        "an unknown predicate was accepted"
    );
}

#[test]
fn a_target_without_retrieval_is_not_applicable_rather_than_failing() {
    // `rag_present` is a target-shape predicate. A target with no retrieval
    // surface has nothing to answer here, and must not be scored as a gap.
    let registry = registry();
    let property = registry
        .get("AGENT.RAG.PROVENANCE_INTEGRITY")
        .expect("declared");
    assert!(property
        .applicability
        .predicates
        .iter()
        .any(|predicate| predicate.as_str() == "rag_present"));
}

#[test]
fn the_new_predicates_do_not_change_an_existing_property() {
    // Every pre-Cycle-017 property keeps the exact predicate list it had.
    let registry = registry();
    for (id, expected) in [
        (
            "AGENT.MEMORY.CONTEXT_INTEGRITY",
            vec!["agent_present", "memory_present"],
        ),
        (
            "AGENT.MEMORY.TENANT_BOUNDARY",
            vec!["agent_present", "memory_present", "authorization_present"],
        ),
        ("AGENT.GOAL.INSTRUCTION_INTEGRITY", vec!["agent_present"]),
    ] {
        let property = registry.get(id).expect("declared");
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
fn facts_that_predate_this_cycle_still_decode() {
    // The new fact fields carry `#[serde(default)]`. A fixture written before
    // Cycle 017 must keep loading, or every prior assessment input breaks.
    let raw = r#"{
        "tools_count": 1, "resources_count": 0, "prompts_count": 0,
        "transport": "stdio", "authorization_present": true,
        "dynamic_authorization_allowed": false,
        "execution_integrity_supported": false,
        "confused_deputy_supported": false
    }"#;
    let facts: AssessmentFacts = serde_json::from_str(raw).expect("older facts still decode");
    assert!(!facts.retrieval_trace_present);
    assert!(!facts.retrieval_policy_present);
    assert!(!facts.document_acl_present);
    assert!(!facts.retrieval_provenance_present);
    assert!(!facts.retrieval_tenant_context_present);
    assert!(matches!(facts.transport, TransportKind::Stdio));
}

#[test]
fn the_provenance_manifest_and_the_registry_agree_on_the_six_properties() {
    // Two files, one list. A property present in one and absent from the other
    // would leave either an unattributed property or an attribution to nothing.
    let provenance = rag_security_provenance().expect("manifest validates");
    let mapped: BTreeSet<&str> = provenance
        .property_mappings
        .iter()
        .map(|mapping| mapping.property_id.as_str())
        .collect();
    assert_eq!(mapped, BTreeSet::from(RAG_PROPERTIES));
}
