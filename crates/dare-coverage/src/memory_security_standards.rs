//! Cycle 016 memory-security standards provenance.
//!
//! Local committed snapshot only: no network fetch happens at validation time,
//! and no memory store, cache, database, vector store or SaaS memory provider
//! is contacted by anything in this crate.
//!
//! This module records attribution and enforces three things prose alone
//! cannot. First, that DARE never claims conformance with an upstream
//! specification merely because a data model resembles one. Second, that a
//! draft or open proposal is never presented as a final normative requirement.
//! Third, that the memory trust statement — the rule that persisting data does
//! not convert it into authority — stays recorded as data rather than as a
//! comment somebody can quietly drop.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

pub const MEMORY_SECURITY_PROVENANCE_JSON: &str =
    include_str!("../../../standards/memory-security/2026/provenance.json");

const MANIFEST_PATH: &str = "standards/memory-security/2026/provenance.json";

/// Properties that predate Cycle 016 and must survive it unchanged.
pub const MEMORY_CONTEXT_INTEGRITY_PROPERTY: &str = "AGENT.MEMORY.CONTEXT_INTEGRITY";
pub const MEMORY_TENANT_BOUNDARY_PROPERTY: &str = "AGENT.MEMORY.TENANT_BOUNDARY";

/// Property IDs introduced by Cycle 016.
pub const MEMORY_PROVENANCE_INTEGRITY_PROPERTY: &str = "AGENT.MEMORY.PROVENANCE_INTEGRITY";
pub const MEMORY_WRITE_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.MEMORY.WRITE_TRUST_BOUNDARY";
pub const MEMORY_RECALL_AUTHORITY_BOUNDARY_PROPERTY: &str =
    "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY";
pub const MEMORY_LIFECYCLE_VALIDITY_PROPERTY: &str = "AGENT.MEMORY.LIFECYCLE_VALIDITY";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecuritySource {
    pub id: String,
    pub title: String,
    pub version: String,
    pub published_at: String,
    pub canonical_reference: String,
    pub status: String,
    pub usage: String,
    pub mapping_notes: String,
}

/// The trust relation the whole cycle rests on, recorded as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrustStatement {
    pub core_relation: String,
    pub availability_rule: String,
    pub recall_rule: String,
    pub storage_rule: String,
    pub promotion_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySurfaceClass {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDeferredTopic {
    pub topic: String,
    pub deferred_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInheritedLesson {
    pub id: String,
    pub from_cycle: String,
    pub lesson: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub conformance_disclaimer: String,
    pub sources: Vec<MemorySecuritySource>,
    pub memory_trust_statement: MemoryTrustStatement,
    pub surface_classes: Vec<MemorySurfaceClass>,
    pub property_mappings: Vec<MemoryPropertyMapping>,
    pub explicitly_out_of_scope: Vec<MemoryDeferredTopic>,
    pub inherited_lessons: Vec<MemoryInheritedLesson>,
}

/// Relations a Cycle 016 property may declare against upstream guidance.
///
/// `EQUIVALENT` and `CONFORMS_TO` are deliberately absent: DARE never asserts
/// normative equivalence with, or conformance to, an upstream specification.
const ALLOWED_RELATIONS: [&str; 2] = ["PARENT_INVARIANT", "SPECIALIZES"];

/// Statuses a source may carry, kept distinct on purpose.
const ALLOWED_SOURCE_STATUS: [&str; 5] = [
    "NORMATIVE",
    "FINAL_SPECIFICATION",
    "DRAFT",
    "OPEN_PROPOSAL",
    "INFORMATIVE",
];

/// Statuses a property mapping may carry.
///
/// A mapping cannot claim `NORMATIVE` or `FINAL_SPECIFICATION`: a DARE property
/// is never part of an upstream specification, however closely it was informed
/// by one.
const ALLOWED_MAPPING_STATUS: [&str; 2] = ["DRAFT", "INFORMATIVE"];

/// Sources whose status is fixed by what upstream actually published.
const PINNED_SOURCE_STATUS: [(&str, &str); 3] = [
    ("OWASP_AGENTIC_TOP10_2026", "NORMATIVE"),
    ("OWASP_LLM_TOP10_2025", "NORMATIVE"),
    ("MEMORY_PROVENANCE_BINDING", "OPEN_PROPOSAL"),
];

/// The eight lessons inherited from Cycles 013, 014 and 015.
const REQUIRED_LESSONS: [&str; 8] = [
    "SECRET_SHAPE_NOT_VOCABULARY",
    "MASK_WHOLE_ARMOURED_BLOCK",
    "SWEEP_VALUES_NOT_ONLY_FIELD_NAMES",
    "NO_EXPECTED_VERDICT_IN_A_FIXTURE",
    "PROVE_BOTH_DIRECTIONS_ARE_REACHABLE",
    "A_CONTROL_TEST_MUST_BE_ABLE_TO_FIRE",
    "ABSENCE_OF_EVIDENCE_IS_NOT_ABSENCE_OF_VIOLATION",
    "INDEPENDENT_VIOLATIONS_STAY_INDEPENDENT",
];

/// The five reporting surfaces coverage must be separable by.
const REQUIRED_SURFACE_CLASSES: [&str; 5] = [
    "PROVENANCE",
    "TRUST_BOUNDARY",
    "TENANT_PRINCIPAL",
    "LIFECYCLE",
    "DECISION_INFLUENCE",
];

/// The six properties the memory profile is built from.
const REQUIRED_MAPPED_PROPERTIES: [&str; 6] = [
    MEMORY_CONTEXT_INTEGRITY_PROPERTY,
    MEMORY_TENANT_BOUNDARY_PROPERTY,
    MEMORY_PROVENANCE_INTEGRITY_PROPERTY,
    MEMORY_WRITE_TRUST_BOUNDARY_PROPERTY,
    MEMORY_RECALL_AUTHORITY_BOUNDARY_PROPERTY,
    MEMORY_LIFECYCLE_VALIDITY_PROPERTY,
];

/// Deferrals that must stay recorded so a later reader knows what this cycle
/// deliberately did not do.
const REQUIRED_DEFERRALS: [&str; 2] = ["Cycle 017", "Cycle 018"];

/// Words that would turn a recorded reference into a conformance claim.
const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 8] = [
    "owasp compliant",
    "owasp-compliant",
    "asi06 compliant",
    "certified against",
    "memory secure",
    "poisoning impossible",
    "no memory poisoning",
    "fully protected",
];

pub fn load_memory_security_provenance() -> Result<MemorySecurityProvenance, CoverageError> {
    serde_json::from_str(MEMORY_SECURITY_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(
            MANIFEST_PATH,
            format!("memory-security provenance is not valid: {err}"),
        )
    })
}

pub fn validate_memory_security_provenance(
    provenance: &MemorySecurityProvenance,
) -> Result<(), CoverageError> {
    let schema = |reason: String| CoverageError::schema(MANIFEST_PATH, reason);

    if provenance.fetch_policy != "OFFLINE_LOCAL_SNAPSHOT" {
        return Err(schema(format!(
            "fetch policy must remain OFFLINE_LOCAL_SNAPSHOT, found `{}`",
            provenance.fetch_policy
        )));
    }

    // Sources.
    let mut seen_sources = HashSet::new();
    for source in &provenance.sources {
        if !seen_sources.insert(source.id.as_str()) {
            return Err(schema(format!("duplicate source `{}`", source.id)));
        }
        if !ALLOWED_SOURCE_STATUS.contains(&source.status.as_str()) {
            return Err(schema(format!(
                "source `{}` carries unknown status `{}`",
                source.id, source.status
            )));
        }
    }
    for (id, expected) in PINNED_SOURCE_STATUS {
        let source = provenance
            .sources
            .iter()
            .find(|candidate| candidate.id == id)
            .ok_or_else(|| schema(format!("required source `{id}` is missing")))?;
        if source.status != expected {
            return Err(schema(format!(
                "source `{id}` must stay `{expected}`, found `{}`",
                source.status
            )));
        }
    }

    // Surfaces.
    for required in REQUIRED_SURFACE_CLASSES {
        if !provenance
            .surface_classes
            .iter()
            .any(|class| class.id == required)
        {
            return Err(schema(format!("surface class `{required}` is missing")));
        }
    }

    // Property mappings.
    let mut seen_properties = HashSet::new();
    for mapping in &provenance.property_mappings {
        if !seen_properties.insert(mapping.property_id.as_str()) {
            return Err(schema(format!(
                "duplicate property mapping `{}`",
                mapping.property_id
            )));
        }
        if !ALLOWED_RELATIONS.contains(&mapping.relation.as_str()) {
            return Err(schema(format!(
                "property `{}` declares relation `{}`; DARE never asserts equivalence with or \
                 conformance to an upstream specification",
                mapping.property_id, mapping.relation
            )));
        }
        if !ALLOWED_MAPPING_STATUS.contains(&mapping.status.as_str()) {
            return Err(schema(format!(
                "property `{}` declares status `{}`; a DARE property is never part of an \
                 upstream specification",
                mapping.property_id, mapping.status
            )));
        }
        if !provenance
            .sources
            .iter()
            .any(|source| source.id == mapping.standard)
        {
            return Err(schema(format!(
                "property `{}` maps to unknown source `{}`",
                mapping.property_id, mapping.standard
            )));
        }
    }
    for required in REQUIRED_MAPPED_PROPERTIES {
        if !seen_properties.contains(required) {
            return Err(schema(format!("property mapping `{required}` is missing")));
        }
    }

    // Deferrals.
    for required in REQUIRED_DEFERRALS {
        if !provenance
            .explicitly_out_of_scope
            .iter()
            .any(|topic| topic.deferred_to == required)
        {
            return Err(schema(format!(
                "no topic is recorded as deferred to {required}"
            )));
        }
    }

    // Lessons.
    let recorded: HashSet<&str> = provenance
        .inherited_lessons
        .iter()
        .map(|lesson| lesson.id.as_str())
        .collect();
    for required in REQUIRED_LESSONS {
        if !recorded.contains(required) {
            return Err(schema(format!("inherited lesson `{required}` is missing")));
        }
    }

    // The trust statement is the cycle's thesis; it stays recorded verbatim.
    let statement = &provenance.memory_trust_statement;
    if !statement.core_relation.contains("stored_data")
        || !statement.core_relation.contains("trusted_instruction")
    {
        return Err(schema(
            "the core relation must state that stored data is not a trusted instruction".to_owned(),
        ));
    }
    if !statement.availability_rule.contains("not authorization") {
        return Err(schema(
            "the availability rule must state that memory availability is not authorization"
                .to_owned(),
        ));
    }
    if !statement.recall_rule.contains("not permission") {
        return Err(schema(
            "the recall rule must state that recall is not permission to influence".to_owned(),
        ));
    }

    // Conformance wording, checked across everything a reader would see.
    assert_no_conformance_claim(&provenance.conformance_disclaimer, "conformance disclaimer")?;
    for source in &provenance.sources {
        assert_no_conformance_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_conformance_claim(
            &mapping.notes,
            &format!("property `{}`", mapping.property_id),
        )?;
    }

    Ok(())
}

/// Refuse wording that would read as conformance or as a universal claim.
///
/// Anchored on the *claim*, not the vocabulary. Denying conformance is exactly
/// what this manifest exists to do, so a sentence such as "not because the
/// engine implements or is certified against any specification" has to stay
/// writable while the affirmative form does not. The Cycle 015 lesson
/// `SECRET_SHAPE_NOT_VOCABULARY` is the same shape of mistake: a check that
/// fires on honest prose is a check someone eventually deletes.
fn assert_no_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    let lowered = text.to_lowercase();
    for phrase in FORBIDDEN_CONFORMANCE_PHRASES {
        let mut from = 0usize;
        while let Some(offset) = lowered[from..].find(phrase) {
            let index = from + offset;
            if !sentence_denies(&lowered[..index]) {
                return Err(CoverageError::schema(
                    MANIFEST_PATH,
                    format!("{where_found} contains the conformance claim `{phrase}`"),
                ));
            }
            from = index + phrase.len();
        }
    }
    Ok(())
}

/// Whether the sentence leading up to a phrase negates it.
///
/// Scans back only to the start of the current sentence, so a denial in one
/// sentence cannot launder a claim made in the next.
fn sentence_denies(prefix: &str) -> bool {
    let sentence_start = prefix
        .rfind(['.', ';', '!', '?'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let sentence = &prefix[sentence_start..];
    ["not ", "no ", "never ", "cannot ", "nor "]
        .iter()
        .any(|marker| sentence.contains(marker))
}

/// Load and validate in one step.
pub fn memory_security_provenance() -> Result<MemorySecurityProvenance, CoverageError> {
    let provenance = load_memory_security_provenance()?;
    validate_memory_security_provenance(&provenance)?;
    Ok(provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> MemorySecurityProvenance {
        load_memory_security_provenance().expect("the shipped manifest parses")
    }

    #[test]
    fn the_shipped_manifest_is_valid() {
        let provenance = memory_security_provenance().expect("the shipped manifest validates");
        assert_eq!(provenance.schema_version, "1.0.0");
        assert_eq!(provenance.fetch_policy, "OFFLINE_LOCAL_SNAPSHOT");
        assert_eq!(provenance.sources.len(), 6);
        assert_eq!(provenance.surface_classes.len(), 5);
        assert_eq!(provenance.property_mappings.len(), 6);
        assert_eq!(provenance.inherited_lessons.len(), 8);
    }

    #[test]
    fn the_manifest_never_reaches_the_network() {
        let mut provenance = valid();
        provenance.fetch_policy = "LIVE_FETCH".to_owned();
        let err = validate_memory_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("OFFLINE_LOCAL_SNAPSHOT"));
    }

    #[test]
    fn a_property_can_never_declare_equivalence_or_conformance() {
        for relation in ["EQUIVALENT", "CONFORMS_TO", "IMPLEMENTS", "CERTIFIED"] {
            let mut provenance = valid();
            provenance.property_mappings[2].relation = relation.to_owned();
            let err =
                validate_memory_security_provenance(&provenance).expect_err("must be refused");
            assert!(err.to_string().contains(relation), "{relation}");
        }
    }

    #[test]
    fn a_dare_property_is_never_part_of_an_upstream_specification() {
        for status in ["NORMATIVE", "FINAL_SPECIFICATION"] {
            let mut provenance = valid();
            provenance.property_mappings[2].status = status.to_owned();
            let err =
                validate_memory_security_provenance(&provenance).expect_err("must be refused");
            assert!(err.to_string().contains(status), "{status}");
        }
    }

    #[test]
    fn a_pinned_source_keeps_the_status_upstream_actually_published() {
        let mut provenance = valid();
        let index = provenance
            .sources
            .iter()
            .position(|source| source.id == "MEMORY_PROVENANCE_BINDING")
            .expect("the open proposal is present");
        provenance.sources[index].status = "NORMATIVE".to_owned();
        let err = validate_memory_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("OPEN_PROPOSAL"));
    }

    #[test]
    fn an_affirmative_conformance_claim_is_refused_but_the_denial_is_not() {
        // The disclaimer legitimately says "is not conformance"; only the
        // affirmative form is a problem.
        let mut provenance = valid();
        provenance.conformance_disclaimer = "DARE is OWASP compliant.".to_owned();
        assert!(validate_memory_security_provenance(&provenance).is_err());

        let provenance = valid();
        validate_memory_security_provenance(&provenance)
            .expect("the shipped disclaimer denies conformance and must stay writable");
        assert!(provenance
            .conformance_disclaimer
            .contains("is not conformance"));
    }

    #[test]
    fn a_denial_in_one_sentence_cannot_launder_a_claim_in_the_next() {
        // The negation has to govern the claim, not merely appear somewhere
        // earlier in the paragraph.
        let mut provenance = valid();
        provenance.property_mappings[0].notes =
            "This is not a conformance statement. DARE is certified against ASI06.".to_owned();
        assert!(validate_memory_security_provenance(&provenance).is_err());
    }

    #[test]
    fn a_universal_security_claim_is_refused() {
        for claim in [
            "Memory Secure after this cycle.",
            "Poisoning Impossible once deployed.",
            "No Memory Poisoning can occur.",
            "Fully Protected against context poisoning.",
        ] {
            let mut provenance = valid();
            provenance.property_mappings[0].notes = claim.to_owned();
            assert!(
                validate_memory_security_provenance(&provenance).is_err(),
                "{claim}"
            );
        }
    }

    #[test]
    fn the_two_pre_existing_properties_stay_mapped() {
        let provenance = valid();
        for id in [
            MEMORY_CONTEXT_INTEGRITY_PROPERTY,
            MEMORY_TENANT_BOUNDARY_PROPERTY,
        ] {
            let mapping = provenance
                .property_mappings
                .iter()
                .find(|mapping| mapping.property_id == id)
                .unwrap_or_else(|| panic!("{id} is missing"));
            assert_eq!(mapping.relation, "PARENT_INVARIANT");
            assert!(mapping.notes.contains("Pre-existing"));
        }
    }

    #[test]
    fn every_required_property_mapping_is_present() {
        for required in REQUIRED_MAPPED_PROPERTIES {
            let mut provenance = valid();
            provenance
                .property_mappings
                .retain(|mapping| mapping.property_id != required);
            let err =
                validate_memory_security_provenance(&provenance).expect_err("must be refused");
            assert!(err.to_string().contains(required), "{required}");
        }
    }

    #[test]
    fn a_mapping_cannot_reference_a_source_that_is_not_recorded() {
        let mut provenance = valid();
        provenance.property_mappings[2].standard = "SOME_OTHER_STANDARD".to_owned();
        let err = validate_memory_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("SOME_OTHER_STANDARD"));
    }

    #[test]
    fn every_inherited_lesson_stays_recorded() {
        for required in REQUIRED_LESSONS {
            let mut provenance = valid();
            provenance
                .inherited_lessons
                .retain(|lesson| lesson.id != required);
            let err =
                validate_memory_security_provenance(&provenance).expect_err("must be refused");
            assert!(err.to_string().contains(required), "{required}");
        }
    }

    #[test]
    fn every_surface_class_stays_recorded() {
        for required in REQUIRED_SURFACE_CLASSES {
            let mut provenance = valid();
            provenance
                .surface_classes
                .retain(|class| class.id != required);
            let err =
                validate_memory_security_provenance(&provenance).expect_err("must be refused");
            assert!(err.to_string().contains(required), "{required}");
        }
    }

    #[test]
    fn the_trust_statement_is_recorded_as_data_not_as_a_comment() {
        let provenance = valid();
        let statement = &provenance.memory_trust_statement;
        assert!(statement.core_relation.contains("stored_data"));
        assert!(statement.core_relation.contains("trusted_instruction"));
        assert!(statement.availability_rule.contains("not authorization"));
        assert!(statement.recall_rule.contains("not permission"));
        assert!(statement.storage_rule.contains("does not convert"));
        assert!(statement.promotion_rule.contains("machine-readable"));
    }

    #[test]
    fn dropping_any_part_of_the_trust_statement_is_refused() {
        let mut provenance = valid();
        provenance.memory_trust_statement.core_relation = "memory is fine".to_owned();
        assert!(validate_memory_security_provenance(&provenance).is_err());

        let mut provenance = valid();
        provenance.memory_trust_statement.availability_rule = "memory is available".to_owned();
        assert!(validate_memory_security_provenance(&provenance).is_err());

        let mut provenance = valid();
        provenance.memory_trust_statement.recall_rule = "recall happens".to_owned();
        assert!(validate_memory_security_provenance(&provenance).is_err());
    }

    #[test]
    fn the_rag_and_identity_deferrals_stay_recorded() {
        // Cycle 016 must keep saying what it deliberately did not do.
        let provenance = valid();
        let rag = provenance
            .explicitly_out_of_scope
            .iter()
            .find(|topic| topic.deferred_to == "Cycle 017")
            .expect("the RAG deferral is recorded");
        assert!(rag.topic.to_lowercase().contains("vector"));
        assert!(rag.topic.to_lowercase().contains("rag"));

        let identity = provenance
            .explicitly_out_of_scope
            .iter()
            .find(|topic| topic.deferred_to == "Cycle 018")
            .expect("the identity deferral is recorded");
        assert!(identity.topic.to_lowercase().contains("oauth"));

        let live = provenance
            .explicitly_out_of_scope
            .iter()
            .find(|topic| topic.topic.to_lowercase().contains("live memory stores"))
            .expect("live stores are recorded as out of scope");
        assert!(live
            .note
            .as_deref()
            .expect("the live-store deferral carries a note")
            .contains("No mode, flag or code path"));
    }

    #[test]
    fn a_duplicate_source_or_mapping_is_refused() {
        let mut provenance = valid();
        let duplicate = provenance.sources[0].clone();
        provenance.sources.push(duplicate);
        assert!(validate_memory_security_provenance(&provenance).is_err());

        let mut provenance = valid();
        let duplicate = provenance.property_mappings[0].clone();
        provenance.property_mappings.push(duplicate);
        assert!(validate_memory_security_provenance(&provenance).is_err());
    }

    #[test]
    fn the_manifest_rejects_unknown_fields() {
        let hostile = r#"{"schema_version":"1.0.0","surprise":true}"#;
        assert!(serde_json::from_str::<MemorySecurityProvenance>(hostile).is_err());
    }

    #[test]
    fn no_source_names_a_memory_store_or_provider_endpoint() {
        // Attribution URLs are documentation references. None of them may be a
        // store, cache, database or vector-store endpoint.
        let provenance = valid();
        for source in &provenance.sources {
            let lowered = source.canonical_reference.to_lowercase();
            for banned in [
                "redis://",
                "postgres://",
                "postgresql://",
                "mongodb://",
                "pinecone",
                "weaviate",
                "qdrant",
                "localhost",
                "127.0.0.1",
            ] {
                assert!(!lowered.contains(banned), "{}: {banned}", source.id);
            }
        }
    }
}
