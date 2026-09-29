//! Cycle 025 registry additions: two `AGENT.TELEMETRY.*` properties and the
//! `runtime_trace_present` predicate (BLUEPRINT AD-12, BQ-1).
//!
//! The change is append-only. Every entry that existed before Cycle 025 keeps
//! its bytes and its position, the v1 registry is untouched, and the two new
//! properties are the only additions. The predicate is target-shape: an
//! assessment given no runtime trace has no telemetry to judge, so the two
//! properties are NOT_APPLICABLE there, never a hidden gap.

use sha2::{Digest, Sha256};

use dare_coverage::{
    agentic_registry, builtin_registry, evaluate_applicability, AssessmentFacts, CoverageStatus,
    Predicate, PropertyRegistry,
};

const REGISTRY: &str = include_str!("../../../schemas/coverage/v2/registry.json");
const PROPERTY_SCHEMA: &str = include_str!("../../../schemas/coverage/v2/property.schema.json");

/// The registry bytes before Cycle 025, as pinned by the BQ-1 prefix rule.
const PRE_025_PREFIX_LEN: usize = 63_498;
const PRE_025_PREFIX_SHA256: &str =
    "5364f9dcae24e08e2aa90163d7f92cf08afb3f6cb7f9dffaa0666625fef91ec4";
const PRE_025_COUNT: usize = 65;

const ADDED: [&str; 2] = [
    "AGENT.TELEMETRY.CONFIDENTIALITY",
    "AGENT.TELEMETRY.COMPLETENESS",
];

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn registry() -> PropertyRegistry {
    agentic_registry().expect("v2 registry loads")
}

fn facts(runtime_trace_present: bool) -> AssessmentFacts {
    AssessmentFacts {
        agent_present: true,
        runtime_trace_present,
        ..Default::default()
    }
}

#[test]
fn exactly_two_properties_were_appended_after_the_pre_025_entries() {
    let r = registry();
    assert_eq!(r.properties.len(), PRE_025_COUNT + ADDED.len());
    let appended: Vec<&str> = r.properties[PRE_025_COUNT..]
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(appended, ADDED);
    let telemetry: Vec<&str> = r
        .properties
        .iter()
        .map(|p| p.id.as_str())
        .filter(|id| id.starts_with("AGENT.TELEMETRY."))
        .collect();
    assert_eq!(telemetry, ADDED, "no other telemetry property exists");
}

#[test]
fn every_pre_025_entry_is_byte_identical() {
    let bytes = REGISTRY.as_bytes();
    assert_eq!(
        hex(&bytes[..PRE_025_PREFIX_LEN]),
        PRE_025_PREFIX_SHA256,
        "an entry that existed before Cycle 025 changed"
    );
    assert!(bytes[PRE_025_PREFIX_LEN..].starts_with(b",\n"));
}

#[test]
fn the_v1_registry_is_unchanged() {
    let v1 = builtin_registry().expect("v1 registry loads");
    assert!(v1
        .properties
        .iter()
        .all(|p| !p.id.starts_with("AGENT.TELEMETRY.")));
    assert!(v1.get(ADDED[0]).is_none() && v1.get(ADDED[1]).is_none());
}

#[test]
fn the_predicate_is_declared_in_the_schema_and_is_target_shape() {
    let schema: serde_json::Value = serde_json::from_str(PROPERTY_SCHEMA).expect("schema");
    let values = schema["properties"]["applicability"]["properties"]["predicates"]["items"]["enum"]
        .as_array()
        .expect("enum");
    assert!(values.iter().any(|v| v == "runtime_trace_present"));
    assert_eq!(
        Predicate::RuntimeTracePresent.as_str(),
        "runtime_trace_present"
    );
    assert!(Predicate::RuntimeTracePresent.is_target_shape());
}

#[test]
fn the_predicate_gates_both_properties() {
    let r = registry();
    for id in ADDED {
        let p = r.get(id).expect("registered");
        assert!(p
            .applicability
            .predicates
            .contains(&Predicate::RuntimeTracePresent));
        assert_eq!(
            evaluate_applicability(p, &facts(true))
                .expect("decides")
                .status,
            CoverageStatus::Applicable,
            "{id}"
        );
        assert_eq!(
            evaluate_applicability(p, &facts(false))
                .expect("decides")
                .status,
            CoverageStatus::NotApplicable,
            "{id}"
        );
    }
}

#[test]
fn no_pre_025_property_uses_the_new_predicate() {
    let r = registry();
    assert!(r.properties[..PRE_025_COUNT].iter().all(|p| !p
        .applicability
        .predicates
        .contains(&Predicate::RuntimeTracePresent)));
    // And setting it changes no earlier property's applicability.
    for p in &r.properties[..PRE_025_COUNT] {
        assert_eq!(
            evaluate_applicability(p, &facts(true)).expect("decides"),
            evaluate_applicability(p, &facts(false)).expect("decides"),
            "{}",
            p.id
        );
    }
}

#[test]
fn the_new_properties_are_passive_trace_evidence() {
    let r = registry();
    for id in ADDED {
        let p = r.get(id).expect("registered");
        let modes = serde_json::to_value(&p.supported_modes).expect("modes");
        assert_eq!(modes, serde_json::json!(["passive"]), "{id}");
        let classes = serde_json::to_value(&p.evidence.accepted_classes).expect("classes");
        assert_eq!(classes, serde_json::json!(["TRACE"]), "{id}");
        assert!(p.evidence.required_for_confirmed_verdict);
        assert!(!p.standards.is_empty());
    }
}
