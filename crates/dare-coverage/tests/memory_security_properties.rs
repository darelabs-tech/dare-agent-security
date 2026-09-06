//! Cycle 016 memory-security properties and predicates.
//!
//! Two claims are under test here, and they pull in opposite directions:
//! the registry must have *grown* by exactly the four approved memory
//! properties, and it must not have moved anything that was already there.

use std::collections::HashSet;

use dare_coverage::{
    agentic_profile, agentic_registry, evaluate_applicability, AssessmentFacts, CoverageStatus,
    Predicate, PropertyRegistry, RiskFamily,
};

const CONTEXT_INTEGRITY: &str = "AGENT.MEMORY.CONTEXT_INTEGRITY";
const TENANT_BOUNDARY: &str = "AGENT.MEMORY.TENANT_BOUNDARY";
const PROVENANCE_INTEGRITY: &str = "AGENT.MEMORY.PROVENANCE_INTEGRITY";
const WRITE_TRUST_BOUNDARY: &str = "AGENT.MEMORY.WRITE_TRUST_BOUNDARY";
const RECALL_AUTHORITY_BOUNDARY: &str = "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY";
const LIFECYCLE_VALIDITY: &str = "AGENT.MEMORY.LIFECYCLE_VALIDITY";

/// The four properties Cycle 016 appended.
const ADDED: [&str; 4] = [
    PROVENANCE_INTEGRITY,
    WRITE_TRUST_BOUNDARY,
    RECALL_AUTHORITY_BOUNDARY,
    LIFECYCLE_VALIDITY,
];

/// The two that predate this cycle and must survive it byte for byte.
const PRE_EXISTING: [&str; 2] = [CONTEXT_INTEGRITY, TENANT_BOUNDARY];

fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

fn facts(memory: bool, provenance: bool, recall: bool, lifecycle: bool) -> AssessmentFacts {
    let raw = serde_json::json!({
        "tools_count": 1,
        "resources_count": 0,
        "prompts_count": 0,
        "transport": "stdio",
        "dynamic_authorization_allowed": false,
        "execution_integrity_supported": false,
        "confused_deputy_supported": false,
        "agent_present": true,
        "memory_present": memory,
        "authorization_present": true,
        "memory_provenance_present": provenance,
        "memory_recall_present": recall,
        "memory_lifecycle_present": lifecycle,
        "memory_namespace_present": false,
    });
    serde_json::from_value(raw).expect("facts decode")
}

#[test]
fn the_memory_family_holds_exactly_six_properties() {
    let registry = registry();
    let family: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .filter(|id| id.starts_with("AGENT.MEMORY."))
        .collect();

    assert_eq!(
        family.len(),
        6,
        "two properties predate Cycle 016 and four were appended: {family:?}"
    );
    for id in PRE_EXISTING.iter().chain(ADDED.iter()) {
        assert!(family.contains(id), "{id} is missing");
    }
}

#[test]
fn the_two_pre_existing_properties_are_unchanged_field_for_field() {
    // Cycle 016 was allowed to add beside these, never to re-word or re-scope
    // them. Every field is pinned, because a changed description silently
    // changes what a prior assessment claimed to have tested.
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/coverage/v2/registry.json"))
            .expect("registry parses");
    let properties = raw["properties"].as_array().expect("array");

    let context = properties
        .iter()
        .find(|property| property["id"] == CONTEXT_INTEGRITY)
        .expect("context integrity present");
    assert_eq!(context["title"], "Memory and context integrity");
    assert_eq!(context["risk_family"], "MEMORY_CONTEXT_POISONING");
    assert_eq!(context["category"], "MEMORY_CONTEXT");
    assert_eq!(
        context["description"],
        "Persisted memory and context must retain provenance and integrity boundaries before influencing future agent decisions."
    );
    assert_eq!(
        context["applicability"]["predicates"],
        serde_json::json!(["agent_present", "memory_present"])
    );
    assert_eq!(context["maturity"], "EXPERIMENTAL");

    let tenant = properties
        .iter()
        .find(|property| property["id"] == TENANT_BOUNDARY)
        .expect("tenant boundary present");
    assert_eq!(tenant["title"], "Memory tenant boundary");
    assert_eq!(
        tenant["description"],
        "Agent memory must not cross principal or tenant boundaries without explicit authorization."
    );
    assert_eq!(
        tenant["applicability"]["predicates"],
        serde_json::json!(["agent_present", "memory_present", "authorization_present"])
    );
}

#[test]
fn every_added_property_joins_the_existing_memory_family() {
    // A new risk family or category would fragment memory coverage reporting.
    let registry = registry();
    for id in ADDED {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        assert_eq!(
            property.risk_family,
            Some(RiskFamily::MemoryContextPoisoning),
            "{id}"
        );
        assert!(!property.applicability.predicates.is_empty(), "{id}");
        assert!(
            property
                .applicability
                .predicates
                .contains(&Predicate::AgentPresent),
            "{id} must require an agent"
        );
        assert!(
            property
                .applicability
                .predicates
                .contains(&Predicate::MemoryPresent),
            "{id} must require memory"
        );
    }
}

#[test]
fn the_four_new_predicates_exist_and_are_closed() {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/coverage/v2/property.schema.json"
    ))
    .expect("schema parses");
    let enum_values: Vec<&str> = raw["properties"]["applicability"]["properties"]["predicates"]
        ["items"]["enum"]
        .as_array()
        .expect("enum")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect();

    // The predicate enum only ever grows; asserting an exact total would make
    // every later cycle edit this line, which turns a real check into a chore.
    // What matters is that Cycle 016's four are present and none was removed.
    assert!(
        enum_values.len() >= 32,
        "the predicate enum must never shrink, found {}",
        enum_values.len()
    );
    for predicate in [
        "memory_provenance_present",
        "memory_recall_present",
        "memory_lifecycle_present",
        "memory_namespace_present",
    ] {
        assert!(enum_values.contains(&predicate), "{predicate} is missing");
    }

    // Closed: an unknown predicate is refused rather than defaulted.
    assert!(serde_json::from_str::<Predicate>("\"memory_teleport_present\"").is_err());
    assert!(serde_json::from_str::<Predicate>("null").is_err());
}

#[test]
fn a_target_without_memory_reports_not_applicable_rather_than_passing() {
    // "The target has no memory" and "the memory boundary held" are different
    // answers. Only the first is honest when nothing was exercised.
    let registry = registry();
    let without_memory = facts(false, false, false, false);

    for id in PRE_EXISTING.iter().chain(ADDED.iter()) {
        let property = registry
            .properties
            .iter()
            .find(|property| &property.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        let decision = evaluate_applicability(property, &without_memory)
            .expect("applicability evaluates")
            .status;
        assert_eq!(decision, CoverageStatus::NotApplicable, "{id}");
    }
}

#[test]
fn a_memory_capable_target_makes_the_memory_properties_applicable() {
    let registry = registry();
    let capable = facts(true, true, true, true);

    for id in [
        CONTEXT_INTEGRITY,
        PROVENANCE_INTEGRITY,
        RECALL_AUTHORITY_BOUNDARY,
    ] {
        let property = registry
            .properties
            .iter()
            .find(|property| property.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        let decision = evaluate_applicability(property, &capable)
            .expect("applicability evaluates")
            .status;
        assert_ne!(decision, CoverageStatus::NotApplicable, "{id}");
    }
}

#[test]
fn each_specialized_property_requires_its_own_capability() {
    // Provenance, recall and lifecycle are separate observation surfaces. A
    // target that recalls memory but records no lifecycle metadata must not
    // have the lifecycle property silently counted as exercisable.
    let registry = registry();
    let recall_only = facts(true, false, true, false);

    let lifecycle = registry
        .properties
        .iter()
        .find(|property| property.id == LIFECYCLE_VALIDITY)
        .expect("lifecycle property present");
    assert_eq!(
        evaluate_applicability(lifecycle, &recall_only)
            .expect("evaluates")
            .status,
        CoverageStatus::NotApplicable
    );

    let provenance = registry
        .properties
        .iter()
        .find(|property| property.id == PROVENANCE_INTEGRITY)
        .expect("provenance property present");
    assert_eq!(
        evaluate_applicability(provenance, &recall_only)
            .expect("evaluates")
            .status,
        CoverageStatus::NotApplicable
    );

    let recall = registry
        .properties
        .iter()
        .find(|property| property.id == RECALL_AUTHORITY_BOUNDARY)
        .expect("recall property present");
    assert_ne!(
        evaluate_applicability(recall, &recall_only)
            .expect("evaluates")
            .status,
        CoverageStatus::NotApplicable
    );
}

#[test]
fn registry_growth_is_additive_and_ids_stay_unique() {
    let registry = registry();
    let ids: Vec<&str> = registry
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate property id introduced");
    assert!(
        registry.properties.len() >= 34,
        "the registry must never shrink, found {}",
        registry.properties.len()
    );
    // The number that must not move is the size of the memory family itself.
    assert_eq!(
        registry
            .properties
            .iter()
            .filter(|property| property.id.starts_with("AGENT.MEMORY."))
            .count(),
        6,
        "the memory property family changed size"
    );

    // Every family that existed before is still represented.
    for id in [
        "AGENT.GOAL.INSTRUCTION_INTEGRITY",
        "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
        "AGENT.IDENTITY.DELEGATION_INTEGRITY",
        "AGENT.IDENTITY.PRINCIPAL_BINDING",
        CONTEXT_INTEGRITY,
        TENANT_BOUNDARY,
    ] {
        assert!(ids.contains(&id), "{id} disappeared");
    }
}

#[test]
fn no_earlier_profile_selects_a_memory_property() {
    // Overlap would make one property count toward two denominators, which is
    // how a coverage number quietly inflates.
    let agentic = agentic_profile().expect("agentic profile");
    let selected: Vec<&str> = agentic
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    for id in ADDED {
        assert!(
            !selected.contains(&id),
            "{id} is selected by the agentic baseline"
        );
    }
}

#[test]
fn no_memory_property_declares_an_executable_or_credential_field() {
    // A property is declarative data. A field that could carry a token, a
    // callback or a store endpoint has no business in the registry.
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/coverage/v2/registry.json"))
            .expect("registry parses");
    let text = serde_json::to_string(&raw)
        .expect("serializes")
        .to_lowercase();

    for banned in [
        "redis://",
        "postgres://",
        "mongodb://",
        "\"command\"",
        "\"callback\"",
        "\"shell\"",
        "\"eval\"",
        "\"token\"",
        "\"api_key\"",
        "\"connection_string\"",
        "expected_verdict",
    ] {
        assert!(!text.contains(banned), "the registry contains `{banned}`");
    }
}

#[test]
fn the_memory_properties_reference_asi06_without_claiming_conformance() {
    let registry = registry();
    for id in PRE_EXISTING.iter().chain(ADDED.iter()) {
        let property = registry
            .properties
            .iter()
            .find(|property| &property.id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        assert_eq!(property.standards.len(), 1, "{id}");
        assert_eq!(
            property.standards[0].reference, "ASI06 Memory and Context Poisoning",
            "{id}"
        );
        assert_eq!(property.standards[0].status, "NORMATIVE", "{id}");
    }
}
