//! Cycle 013 prompt-injection standards provenance.
//!
//! Local committed snapshot only: no network fetch happens at validation time.
//! This module records attribution and enforces that DARE never claims a
//! one-to-one equivalence between Prompt Injection (a delivery technique) and
//! ASI01 Agent Goal Hijacking (an outcome class).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

pub const PROMPT_INJECTION_PROVENANCE_JSON: &str =
    include_str!("../../../standards/prompt-injection/2026/provenance.json");

/// Property IDs introduced by Cycle 013.
pub const USER_INPUT_BOUNDARY_PROPERTY: &str = "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY";
pub const EXTERNAL_CONTENT_BOUNDARY_PROPERTY: &str =
    "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY";
/// Cycle 012 parent property, preserved unchanged.
pub const INSTRUCTION_INTEGRITY_PROPERTY: &str = "AGENT.GOAL.INSTRUCTION_INTEGRITY";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionSource {
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
pub struct TaxonomyDistinction {
    pub statement: String,
    pub prompt_injection: String,
    pub agent_goal_hijack: String,
    pub non_equivalence_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorClass {
    pub id: String,
    pub description: String,
    pub primary_source: String,
    pub primary_reference: String,
    pub dare_property: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyMapping {
    pub property_id: String,
    pub relation: String,
    pub sources: Vec<String>,
    pub references: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredTopic {
    pub topic: String,
    pub deferred_to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub sources: Vec<PromptInjectionSource>,
    pub taxonomy_distinction: TaxonomyDistinction,
    pub vector_classes: Vec<VectorClass>,
    pub property_mappings: Vec<PropertyMapping>,
    pub explicitly_out_of_scope: Vec<DeferredTopic>,
}

/// Relations a Cycle 013 property may declare against upstream guidance.
///
/// `EQUIVALENT` is deliberately absent: DARE never asserts normative equivalence.
const ALLOWED_RELATIONS: [&str; 2] = ["PARENT_INVARIANT", "SPECIALIZES"];
const ALLOWED_STATUS: [&str; 3] = ["NORMATIVE", "DRAFT", "INFORMATIVE"];

pub fn load_prompt_injection_provenance() -> Result<PromptInjectionProvenance, CoverageError> {
    serde_json::from_str(PROMPT_INJECTION_PROVENANCE_JSON).map_err(|_| {
        CoverageError::Serialization {
            kind: "prompt-injection-provenance",
        }
    })
}

pub fn validate_prompt_injection_provenance(
    manifest: &PromptInjectionProvenance,
) -> Result<(), CoverageError> {
    if manifest.schema_version != "1.0.0" {
        return Err(CoverageError::schema(
            "/schema_version",
            "unsupported prompt-injection provenance schema version",
        ));
    }
    if manifest.fetch_policy != "OFFLINE_LOCAL_SNAPSHOT" {
        return Err(CoverageError::schema(
            "/fetch_policy",
            "prompt-injection provenance must be an offline local snapshot",
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
            "prompt injection vs agent goal hijack distinction must be explicit",
        ));
    }

    let mut vector_ids = HashSet::new();
    for class in &manifest.vector_classes {
        if !vector_ids.insert(class.id.as_str()) {
            return Err(CoverageError::schema(
                "/vector_classes",
                format!("duplicate vector class {}", class.id),
            ));
        }
        if !source_ids.contains(class.primary_source.as_str()) {
            return Err(CoverageError::schema(
                "/vector_classes/primary_source",
                format!("unknown standards source {}", class.primary_source),
            ));
        }
    }
    if !vector_ids.contains("DIRECT") || !vector_ids.contains("INDIRECT") {
        return Err(CoverageError::schema(
            "/vector_classes",
            "both DIRECT and INDIRECT vector classes must be recorded",
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
        INSTRUCTION_INTEGRITY_PROPERTY,
        USER_INPUT_BOUNDARY_PROPERTY,
        EXTERNAL_CONTENT_BOUNDARY_PROPERTY,
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
            "deferred prompt-injection scope must be recorded explicitly",
        ));
    }

    Ok(())
}

/// Load and validate the committed snapshot. Offline and deterministic.
pub fn validate_prompt_injection_standards() -> Result<(), CoverageError> {
    let manifest = load_prompt_injection_provenance()?;
    validate_prompt_injection_provenance(&manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_snapshot_validates_offline() {
        validate_prompt_injection_standards().expect("prompt-injection provenance");
    }

    #[test]
    fn snapshot_records_both_injection_directions() {
        let manifest = load_prompt_injection_provenance().unwrap();
        let ids: Vec<&str> = manifest
            .vector_classes
            .iter()
            .map(|class| class.id.as_str())
            .collect();
        assert!(ids.contains(&"DIRECT"));
        assert!(ids.contains(&"INDIRECT"));
        let direct = manifest
            .vector_classes
            .iter()
            .find(|class| class.id == "DIRECT")
            .unwrap();
        assert_eq!(direct.dare_property, USER_INPUT_BOUNDARY_PROPERTY);
        let indirect = manifest
            .vector_classes
            .iter()
            .find(|class| class.id == "INDIRECT")
            .unwrap();
        assert_eq!(indirect.dare_property, EXTERNAL_CONTENT_BOUNDARY_PROPERTY);
    }

    #[test]
    fn prompt_injection_is_not_equated_with_goal_hijack() {
        let manifest = load_prompt_injection_provenance().unwrap();
        assert!(!manifest
            .taxonomy_distinction
            .non_equivalence_rules
            .is_empty());
        // No mapping may assert equivalence with an upstream control.
        assert!(manifest
            .property_mappings
            .iter()
            .all(|mapping| mapping.relation != "EQUIVALENT"));
    }

    #[test]
    fn equivalence_relation_fails_closed() {
        let mut manifest = load_prompt_injection_provenance().unwrap();
        manifest.property_mappings[1].relation = "EQUIVALENT".to_owned();
        assert!(validate_prompt_injection_provenance(&manifest).is_err());
    }

    #[test]
    fn unknown_source_reference_fails_closed() {
        let mut manifest = load_prompt_injection_provenance().unwrap();
        manifest.property_mappings[0].sources = vec!["UNTRUSTED_SOURCE".to_owned()];
        assert!(validate_prompt_injection_provenance(&manifest).is_err());
    }

    #[test]
    fn network_fetch_policy_cannot_be_downgraded() {
        let mut manifest = load_prompt_injection_provenance().unwrap();
        manifest.fetch_policy = "REMOTE_FETCH".to_owned();
        assert!(validate_prompt_injection_provenance(&manifest).is_err());
    }

    #[test]
    fn parent_property_mapping_is_present_and_unchanged_in_role() {
        let manifest = load_prompt_injection_provenance().unwrap();
        let parent = manifest
            .property_mappings
            .iter()
            .find(|mapping| mapping.property_id == INSTRUCTION_INTEGRITY_PROPERTY)
            .expect("parent mapping");
        assert_eq!(parent.relation, "PARENT_INVARIANT");
    }

    #[test]
    fn deferred_cycles_are_recorded_and_not_silently_absorbed() {
        let manifest = load_prompt_injection_provenance().unwrap();
        let deferred: Vec<&str> = manifest
            .explicitly_out_of_scope
            .iter()
            .map(|topic| topic.deferred_to.as_str())
            .collect();
        for cycle in ["Cycle 014", "Cycle 016", "Cycle 017", "Cycle 020"] {
            assert!(deferred.contains(&cycle), "missing deferral for {cycle}");
        }
    }

    #[test]
    fn unknown_manifest_field_fails_closed() {
        let mut value: serde_json::Value =
            serde_json::from_str(PROMPT_INJECTION_PROVENANCE_JSON).unwrap();
        value["remote_endpoint"] = serde_json::json!("https://example.invalid");
        assert!(serde_json::from_value::<PromptInjectionProvenance>(value).is_err());
    }
}
