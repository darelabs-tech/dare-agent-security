//! Cycle 014 tool-security standards provenance.
//!
//! Local committed snapshot only: no network fetch happens at validation time.
//! This module records attribution and enforces that DARE never claims a
//! one-to-one equivalence with ASI02, and never conflates tool poisoning (a
//! corrupted tool surface) with tool misuse (an outcome).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

pub const TOOL_SECURITY_PROVENANCE_JSON: &str =
    include_str!("../../../standards/tool-security/2026/provenance.json");

/// Cycle 012 properties Cycle 014 preserves unchanged.
pub const TOOL_AUTHORIZATION_BOUNDARY_PROPERTY: &str = "AGENT.TOOL.AUTHORIZATION_BOUNDARY";
pub const TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY";

/// Property IDs introduced by Cycle 014.
pub const TOOL_METADATA_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.TOOL.METADATA_TRUST_BOUNDARY";
pub const TOOL_SELECTION_INTENT_BINDING_PROPERTY: &str = "AGENT.TOOL.SELECTION_INTENT_BINDING";
pub const TOOL_ARGUMENT_INTEGRITY_PROPERTY: &str = "AGENT.TOOL.ARGUMENT_INTEGRITY";
pub const TOOL_CHAIN_BOUNDARY_PROPERTY: &str = "AGENT.TOOL.CHAIN_BOUNDARY";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecuritySource {
    pub id: String,
    pub title: String,
    pub version: String,
    pub published_at: String,
    pub canonical_reference: String,
    pub status: String,
    pub mapping_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTaxonomyDistinction {
    pub statement: String,
    pub tool_poisoning: String,
    pub tool_misuse: String,
    pub non_equivalence_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceClass {
    pub id: String,
    pub description: String,
    pub primary_source: String,
    pub primary_reference: String,
    pub dare_properties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPropertyMapping {
    pub property_id: String,
    pub relation: String,
    pub sources: Vec<String>,
    pub references: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDeferredTopic {
    pub topic: String,
    pub deferred_to: String,
}

/// A concrete lesson inherited from an earlier cycle, with the rule it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InheritedLesson {
    pub id: String,
    pub source_cycle: String,
    pub lesson: String,
    pub cycle_014_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub sources: Vec<ToolSecuritySource>,
    pub taxonomy_distinction: ToolTaxonomyDistinction,
    pub surface_classes: Vec<ToolSurfaceClass>,
    pub property_mappings: Vec<ToolPropertyMapping>,
    pub explicitly_out_of_scope: Vec<ToolDeferredTopic>,
    pub inherited_lessons: Vec<InheritedLesson>,
}

/// Relations a Cycle 014 property may declare against upstream guidance.
///
/// `EQUIVALENT` is deliberately absent: DARE never asserts normative equivalence.
const ALLOWED_RELATIONS: [&str; 2] = ["PARENT_INVARIANT", "SPECIALIZES"];
const ALLOWED_STATUS: [&str; 3] = ["NORMATIVE", "DRAFT", "INFORMATIVE"];

/// The five Cycle 013 lessons that must remain recorded.
const REQUIRED_LESSONS: [&str; 5] = [
    "INDEPENDENT_FACTS",
    "POSITIVE_COVERAGE",
    "CLEAN_OBSERVATION_SIGNAL",
    "FULL_VALUE_SECRET_SCAN",
    "EXACT_CI_ASSERTIONS",
];

pub fn load_tool_security_provenance() -> Result<ToolSecurityProvenance, CoverageError> {
    serde_json::from_str(TOOL_SECURITY_PROVENANCE_JSON).map_err(|_| CoverageError::Serialization {
        kind: "tool-security-provenance",
    })
}

pub fn validate_tool_security_provenance(
    manifest: &ToolSecurityProvenance,
) -> Result<(), CoverageError> {
    if manifest.schema_version != "1.0.0" {
        return Err(CoverageError::schema(
            "/schema_version",
            "unsupported tool-security provenance schema version",
        ));
    }
    if manifest.fetch_policy != "OFFLINE_LOCAL_SNAPSHOT" {
        return Err(CoverageError::schema(
            "/fetch_policy",
            "tool-security provenance must be an offline local snapshot",
        ));
    }

    let mut source_ids = HashSet::new();
    for source in &manifest.sources {
        if !source_ids.insert(source.id.as_str()) {
            return Err(CoverageError::schema(
                "/sources",
                format!("duplicate standards source {}", source.id),
            ));
        }
        if !ALLOWED_STATUS.contains(&source.status.as_str()) {
            return Err(CoverageError::schema(
                "/sources/status",
                format!("unknown standards status {}", source.status),
            ));
        }
        if source.canonical_reference.trim().is_empty() {
            return Err(CoverageError::schema(
                "/sources/canonical_reference",
                "empty canonical reference",
            ));
        }
    }

    if manifest
        .taxonomy_distinction
        .non_equivalence_rules
        .is_empty()
    {
        return Err(CoverageError::schema(
            "/taxonomy_distinction/non_equivalence_rules",
            "tool poisoning vs tool misuse distinction must be explicit",
        ));
    }

    let mut class_ids = HashSet::new();
    for class in &manifest.surface_classes {
        if !class_ids.insert(class.id.as_str()) {
            return Err(CoverageError::schema(
                "/surface_classes",
                format!("duplicate surface class {}", class.id),
            ));
        }
        if !source_ids.contains(class.primary_source.as_str()) {
            return Err(CoverageError::schema(
                "/surface_classes/primary_source",
                format!("unknown standards source {}", class.primary_source),
            ));
        }
        if class.dare_properties.is_empty() {
            return Err(CoverageError::schema(
                "/surface_classes/dare_properties",
                format!("surface class {} maps to no property", class.id),
            ));
        }
    }
    if !class_ids.contains("TOOL_POISONING") || !class_ids.contains("TOOL_MISUSE") {
        return Err(CoverageError::schema(
            "/surface_classes",
            "both TOOL_POISONING and TOOL_MISUSE classes must be recorded",
        ));
    }

    let mut mapped = HashSet::new();
    for mapping in &manifest.property_mappings {
        if !mapped.insert(mapping.property_id.as_str()) {
            return Err(CoverageError::schema(
                "/property_mappings",
                format!("duplicate property mapping {}", mapping.property_id),
            ));
        }
        if !ALLOWED_RELATIONS.contains(&mapping.relation.as_str()) {
            return Err(CoverageError::schema(
                "/property_mappings/relation",
                format!(
                    "relation {} overclaims standards equivalence",
                    mapping.relation
                ),
            ));
        }
        if mapping.sources.is_empty() || mapping.references.is_empty() {
            return Err(CoverageError::schema(
                "/property_mappings",
                format!("mapping {} lacks attribution", mapping.property_id),
            ));
        }
        for source in &mapping.sources {
            if !source_ids.contains(source.as_str()) {
                return Err(CoverageError::schema(
                    "/property_mappings/sources",
                    format!("unknown standards source {source}"),
                ));
            }
        }
    }

    for required in [
        TOOL_AUTHORIZATION_BOUNDARY_PROPERTY,
        TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY,
        TOOL_METADATA_TRUST_BOUNDARY_PROPERTY,
        TOOL_SELECTION_INTENT_BINDING_PROPERTY,
        TOOL_ARGUMENT_INTEGRITY_PROPERTY,
        TOOL_CHAIN_BOUNDARY_PROPERTY,
    ] {
        if !mapped.contains(required) {
            return Err(CoverageError::schema(
                "/property_mappings",
                format!("missing standards mapping for {required}"),
            ));
        }
    }

    if manifest.explicitly_out_of_scope.is_empty() {
        return Err(CoverageError::schema(
            "/explicitly_out_of_scope",
            "deferred tool-security scope must be recorded explicitly",
        ));
    }

    let recorded: HashSet<&str> = manifest
        .inherited_lessons
        .iter()
        .map(|lesson| lesson.id.as_str())
        .collect();
    for lesson in REQUIRED_LESSONS {
        if !recorded.contains(lesson) {
            return Err(CoverageError::schema(
                "/inherited_lessons",
                format!("missing inherited Cycle 013 lesson {lesson}"),
            ));
        }
    }

    Ok(())
}

/// Load and validate the committed snapshot. Offline and deterministic.
pub fn validate_tool_security_standards() -> Result<(), CoverageError> {
    let manifest = load_tool_security_provenance()?;
    validate_tool_security_provenance(&manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_snapshot_validates_offline() {
        validate_tool_security_standards().expect("tool-security provenance");
    }

    #[test]
    fn snapshot_records_both_surface_classes_with_their_properties() {
        let manifest = load_tool_security_provenance().unwrap();
        let poisoning = manifest
            .surface_classes
            .iter()
            .find(|class| class.id == "TOOL_POISONING")
            .expect("poisoning class");
        assert!(poisoning
            .dare_properties
            .contains(&TOOL_METADATA_TRUST_BOUNDARY_PROPERTY.to_owned()));

        let misuse = manifest
            .surface_classes
            .iter()
            .find(|class| class.id == "TOOL_MISUSE")
            .expect("misuse class");
        assert!(misuse
            .dare_properties
            .contains(&TOOL_SELECTION_INTENT_BINDING_PROPERTY.to_owned()));
        assert!(misuse
            .dare_properties
            .contains(&TOOL_ARGUMENT_INTEGRITY_PROPERTY.to_owned()));
        assert!(misuse
            .dare_properties
            .contains(&TOOL_CHAIN_BOUNDARY_PROPERTY.to_owned()));
    }

    #[test]
    fn poisoning_and_misuse_are_not_equated_with_each_other_or_with_asi02() {
        let manifest = load_tool_security_provenance().unwrap();
        let rules = manifest
            .taxonomy_distinction
            .non_equivalence_rules
            .join(" ");
        assert!(rules.contains("does not by itself prove misuse"));
        assert!(rules.contains("does not by itself prove poisoning"));
        assert!(rules.contains("never as a claim of full ASI02 coverage"));

        assert!(manifest
            .property_mappings
            .iter()
            .all(|mapping| mapping.relation != "EQUIVALENT"));
    }

    #[test]
    fn equivalence_relation_fails_closed() {
        let mut manifest = load_tool_security_provenance().unwrap();
        manifest.property_mappings[2].relation = "EQUIVALENT".to_owned();
        assert!(validate_tool_security_provenance(&manifest).is_err());
    }

    #[test]
    fn unknown_source_reference_fails_closed() {
        let mut manifest = load_tool_security_provenance().unwrap();
        manifest.property_mappings[0].sources = vec!["UNTRUSTED_SOURCE".to_owned()];
        assert!(validate_tool_security_provenance(&manifest).is_err());
    }

    #[test]
    fn network_fetch_policy_cannot_be_downgraded() {
        let mut manifest = load_tool_security_provenance().unwrap();
        manifest.fetch_policy = "REMOTE_FETCH".to_owned();
        assert!(validate_tool_security_provenance(&manifest).is_err());
    }

    #[test]
    fn the_two_cycle_012_properties_are_recorded_as_parent_invariants() {
        let manifest = load_tool_security_provenance().unwrap();
        for id in [
            TOOL_AUTHORIZATION_BOUNDARY_PROPERTY,
            TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY,
        ] {
            let mapping = manifest
                .property_mappings
                .iter()
                .find(|mapping| mapping.property_id == id)
                .unwrap_or_else(|| panic!("missing mapping for {id}"));
            assert_eq!(mapping.relation, "PARENT_INVARIANT");
        }
    }

    #[test]
    fn deferred_cycles_are_recorded_and_not_silently_absorbed() {
        let manifest = load_tool_security_provenance().unwrap();
        let deferred: Vec<&str> = manifest
            .explicitly_out_of_scope
            .iter()
            .map(|topic| topic.deferred_to.as_str())
            .collect();
        for cycle in [
            "Cycle 015",
            "Cycle 016",
            "Cycle 017",
            "Cycle 019",
            "Cycle 020",
            "Cycle 021",
            "Cycle 022",
        ] {
            assert!(deferred.contains(&cycle), "missing deferral for {cycle}");
        }
    }

    #[test]
    fn all_five_cycle_013_lessons_are_carried_forward_with_rules() {
        let manifest = load_tool_security_provenance().unwrap();
        assert_eq!(manifest.inherited_lessons.len(), 5);
        for lesson in &manifest.inherited_lessons {
            assert_eq!(lesson.source_cycle, "013");
            assert!(!lesson.lesson.trim().is_empty());
            assert!(
                !lesson.cycle_014_rule.trim().is_empty(),
                "{} records a lesson with no Cycle 014 rule",
                lesson.id
            );
        }

        // Dropping a lesson fails closed rather than quietly regressing.
        let mut stripped = manifest.clone();
        stripped
            .inherited_lessons
            .retain(|l| l.id != "POSITIVE_COVERAGE");
        assert!(validate_tool_security_provenance(&stripped).is_err());
    }

    #[test]
    fn unknown_manifest_field_fails_closed() {
        let mut value: serde_json::Value =
            serde_json::from_str(TOOL_SECURITY_PROVENANCE_JSON).unwrap();
        value["remote_endpoint"] = serde_json::json!("https://example.invalid");
        assert!(serde_json::from_value::<ToolSecurityProvenance>(value).is_err());
    }
}
