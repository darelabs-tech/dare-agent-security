//! Cycle 017 RAG-security standards provenance.
//!
//! A recorded, versioned snapshot of what this cycle attributes its properties
//! to — never a live dependency. Nothing here fetches a document, resolves a
//! canonical reference over the network, or treats an upstream specification as
//! something to retrieve at runtime.
//!
//! The manifest exists to keep two distinctions from eroding.
//!
//! **Attribution is not conformance.** Mapping a property onto LLM09:2026 says
//! where the idea came from. It does not say DARE implements that document, and
//! [`assert_no_conformance_claim`] refuses wording that would imply otherwise.
//! The check is anchored on the *claim* rather than the vocabulary, because
//! denying conformance is exactly what this manifest is for: "not certified
//! against any of these documents" has to stay writable while the affirmative
//! form does not.
//!
//! **LLM09 is not an Agentic risk family.** It belongs to the OWASP Top 10 for
//! LLM Applications, a separate taxonomy from the Agentic Top 10. The ten
//! Agentic families stay ten, and no equivalence with ASI04, ASI06 or any other
//! ASI identifier is asserted anywhere in this cycle.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

const MANIFEST_PATH: &str = "standards/rag-security/2026/provenance.json";

pub const RAG_SECURITY_PROVENANCE_JSON: &str =
    include_str!("../../../standards/rag-security/2026/provenance.json");

pub const RAG_RETRIEVAL_AUTHORIZATION_BOUNDARY_PROPERTY: &str =
    "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY";
pub const RAG_TENANT_DOCUMENT_ISOLATION_PROPERTY: &str = "AGENT.RAG.TENANT_DOCUMENT_ISOLATION";
pub const RAG_PROVENANCE_INTEGRITY_PROPERTY: &str = "AGENT.RAG.PROVENANCE_INTEGRITY";
pub const RAG_CONTENT_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.RAG.CONTENT_TRUST_BOUNDARY";
pub const RAG_RESULT_SET_INTEGRITY_PROPERTY: &str = "AGENT.RAG.RESULT_SET_INTEGRITY";
pub const RAG_PROTECTED_DOCUMENT_NONDISCLOSURE_PROPERTY: &str =
    "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecuritySource {
    pub id: String,
    pub title: String,
    pub version: String,
    pub published_at: String,
    pub canonical_reference: String,
    pub status: String,
    pub usage: String,
    pub mapping_notes: String,
}

/// The thesis of the cycle, recorded so it cannot drift out of the artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTrustStatement {
    pub core_relation: String,
    pub content_rule: String,
    pub score_rule: String,
    pub authorization_rule: String,
    pub ranking_rule: String,
    pub memory_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSurfaceClass {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagDeferredTopic {
    pub topic: String,
    pub deferred_to: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagInheritedLesson {
    pub id: String,
    pub from_cycle: String,
    pub lesson: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub conformance_disclaimer: String,
    pub taxonomy_note: String,
    pub sources: Vec<RagSecuritySource>,
    pub retrieval_trust_statement: RetrievalTrustStatement,
    pub surface_classes: Vec<RagSurfaceClass>,
    pub property_mappings: Vec<RagPropertyMapping>,
    pub explicitly_out_of_scope: Vec<RagDeferredTopic>,
    pub inherited_lessons: Vec<RagInheritedLesson>,
}

/// Relations a Cycle 017 property may declare against upstream guidance.
///
/// `EQUIVALENT` and `CONFORMS_TO` are deliberately absent: DARE never asserts
/// normative equivalence with, or conformance to, an upstream specification.
const ALLOWED_RELATIONS: [&str; 2] = ["PARENT_INVARIANT", "SPECIALIZES"];

/// Statuses a source may carry, kept distinct on purpose.
const ALLOWED_SOURCE_STATUS: [&str; 6] = [
    "NORMATIVE",
    "FINAL_SPECIFICATION",
    "DRAFT",
    "OPEN_PROPOSAL",
    "INFORMATIVE",
    "INTERNAL_CONTRACT",
];

/// Statuses a property mapping may carry.
///
/// A mapping cannot claim `NORMATIVE` or `FINAL_SPECIFICATION`: a DARE property
/// is never part of an upstream specification, however closely it was informed
/// by one.
const ALLOWED_MAPPING_STATUS: [&str; 2] = ["DRAFT", "INFORMATIVE"];

/// Sources whose status is fixed by what upstream actually published.
const PINNED_SOURCE_STATUS: [(&str, &str); 4] = [
    ("OWASP_LLM_TOP10_2026", "NORMATIVE"),
    ("OWASP_LLM09_2026", "NORMATIVE"),
    ("OWASP_AGENTIC_TOP10_2026", "NORMATIVE"),
    ("NIST_AI_600_1", "INFORMATIVE"),
];

/// The six reporting surfaces coverage must be separable by.
const REQUIRED_SURFACE_CLASSES: [&str; 6] = [
    "RETRIEVAL_AUTHORIZATION",
    "DOCUMENT_ISOLATION",
    "PROVENANCE",
    "RESULT_INTEGRITY",
    "CONTENT_TRUST",
    "PROTECTED_NONDISCLOSURE",
];

/// The six properties the RAG profile is built from.
const REQUIRED_MAPPED_PROPERTIES: [&str; 6] = [
    RAG_RETRIEVAL_AUTHORIZATION_BOUNDARY_PROPERTY,
    RAG_TENANT_DOCUMENT_ISOLATION_PROPERTY,
    RAG_PROVENANCE_INTEGRITY_PROPERTY,
    RAG_CONTENT_TRUST_BOUNDARY_PROPERTY,
    RAG_RESULT_SET_INTEGRITY_PROPERTY,
    RAG_PROTECTED_DOCUMENT_NONDISCLOSURE_PROPERTY,
];

/// Deferrals that must stay recorded so a later reader knows what this cycle
/// deliberately did not do.
const REQUIRED_DEFERRALS: [&str; 3] = ["CYCLE_013", "CYCLE_016", "CYCLE_018"];

/// The lessons carried in from earlier cycles.
const REQUIRED_LESSONS: [&str; 8] = [
    "RELEVANCE_IS_NOT_AUTHORIZATION",
    "SCORE_IS_NOT_AUTHORITY",
    "REFUSAL_IS_A_PERSISTENCE_SURFACE",
    "STAGE_AGAINST_THE_INVARIANT_JUDGED",
    "AN_ADAPTER_ASSERTS_ONLY_WHAT_IT_OBSERVED",
    "ABSENCE_OF_EVIDENCE_IS_NOT_A_PASS",
    "GENERATE_FIXTURES_NEVER_HAND_EDIT_THEM",
    "RUN_THE_REAL_CI_JOB_LOCALLY",
];

/// Words that would turn a recorded reference into a conformance claim, or a
/// bounded result into a universal one.
const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 11] = [
    "owasp compliant",
    "owasp-compliant",
    "llm09 compliant",
    "certified against",
    "rag secure",
    "vector database secure",
    "no leakage possible",
    "no retrieval attack possible",
    // Both spellings: "retrieval secure" catches "makes retrieval secure",
    // and the copular form is written out because it does not contain the
    // other as a substring.
    "retrieval secure",
    "retrieval is secure",
    "fully protected",
];

/// Phrases that would fold LLM09 into the Agentic taxonomy.
///
/// The two are separate documents with separate identifiers. Calling LLM09 an
/// Agentic risk family, or equating it with an ASI identifier, would make a
/// reader believe the Agentic family count had grown when it has not.
const FORBIDDEN_TAXONOMY_CLAIMS: [&str; 5] = [
    "llm09 is an agentic",
    "llm09 agentic risk family",
    "equivalent to asi04",
    "equivalent to asi06",
    "eleventh agentic",
];

pub fn load_rag_security_provenance() -> Result<RagSecurityProvenance, CoverageError> {
    serde_json::from_str(RAG_SECURITY_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(
            MANIFEST_PATH,
            format!("rag-security provenance is not valid: {err}"),
        )
    })
}

pub fn validate_rag_security_provenance(
    provenance: &RagSecurityProvenance,
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
    let statement = &provenance.retrieval_trust_statement;
    if !statement.core_relation.contains("similarity_match")
        || !statement.core_relation.contains("permission")
    {
        return Err(schema(
            "the core relation must state that a similarity match is not permission".to_owned(),
        ));
    }
    if !statement.content_rule.contains("retrieved_content")
        || !statement.content_rule.contains("trusted_instruction")
    {
        return Err(schema(
            "the content rule must state that retrieved content is not a trusted instruction"
                .to_owned(),
        ));
    }
    if !statement.score_rule.contains("high_score") || !statement.score_rule.contains("safe_source")
    {
        return Err(schema(
            "the score rule must state that a high score is not a safe source".to_owned(),
        ));
    }
    if !statement.ranking_rule.contains("final security judge") {
        return Err(schema(
            "the ranking rule must state that ranking is never the final security judge".to_owned(),
        ));
    }
    if !statement.memory_rule.contains("not persisted memory") {
        return Err(schema(
            "the memory rule must state that retrieved content is not persisted memory".to_owned(),
        ));
    }

    // Conformance wording, checked across everything a reader would see.
    assert_no_conformance_claim(&provenance.conformance_disclaimer, "conformance disclaimer")?;
    assert_no_conformance_claim(&provenance.taxonomy_note, "taxonomy note")?;
    for source in &provenance.sources {
        assert_no_conformance_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_conformance_claim(
            &mapping.notes,
            &format!("property `{}`", mapping.property_id),
        )?;
    }

    // Taxonomy wording, checked the same way and for the same reason.
    assert_no_taxonomy_claim(&provenance.taxonomy_note, "taxonomy note")?;
    for source in &provenance.sources {
        assert_no_taxonomy_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_taxonomy_claim(
            &mapping.notes,
            &format!("property `{}`", mapping.property_id),
        )?;
    }

    Ok(())
}

/// Refuse wording that would read as conformance or as a universal claim.
///
/// Anchored on the *claim*, not the vocabulary. Denying conformance is exactly
/// what this manifest exists to do, so a sentence such as "not certified against
/// any of these documents" has to stay writable while the affirmative form does
/// not. A check that fires on honest prose is a check someone eventually
/// deletes.
fn assert_no_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(text, where_found, &FORBIDDEN_CONFORMANCE_PHRASES, "claim")
}

/// Refuse wording that would fold LLM09 into the Agentic taxonomy.
fn assert_no_taxonomy_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(
        text,
        where_found,
        &FORBIDDEN_TAXONOMY_CLAIMS,
        "taxonomy claim",
    )
}

fn assert_claim_absent(
    text: &str,
    where_found: &str,
    phrases: &[&str],
    label: &str,
) -> Result<(), CoverageError> {
    let lowered = text.to_lowercase();
    for phrase in phrases {
        let mut from = 0usize;
        while let Some(offset) = lowered[from..].find(phrase) {
            let index = from + offset;
            if !sentence_denies(&lowered[..index]) {
                return Err(CoverageError::schema(
                    MANIFEST_PATH,
                    format!("{where_found} contains the {label} `{phrase}`"),
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
pub fn rag_security_provenance() -> Result<RagSecurityProvenance, CoverageError> {
    let provenance = load_rag_security_provenance()?;
    validate_rag_security_provenance(&provenance)?;
    Ok(provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> RagSecurityProvenance {
        load_rag_security_provenance().expect("the shipped manifest parses")
    }

    #[test]
    fn the_shipped_manifest_is_valid() {
        let provenance = rag_security_provenance().expect("the shipped manifest validates");
        assert_eq!(provenance.schema_version, "1.0.0");
        assert_eq!(provenance.fetch_policy, "OFFLINE_LOCAL_SNAPSHOT");
        assert_eq!(provenance.property_mappings.len(), 6);
        assert_eq!(provenance.surface_classes.len(), 6);
    }

    #[test]
    fn llm09_is_recorded_as_the_primary_normative_mapping() {
        let provenance = valid();
        let llm09 = provenance
            .sources
            .iter()
            .find(|source| source.id == "OWASP_LLM09_2026")
            .expect("LLM09 is recorded");
        assert_eq!(llm09.status, "NORMATIVE");
        assert!(llm09.canonical_reference.contains("LLM09:2026"));

        // Every RAG property maps to the LLM Top 10, not to the Agentic one.
        for mapping in &provenance.property_mappings {
            assert!(
                mapping.reference.contains("LLM09:2026"),
                "{} does not map to LLM09",
                mapping.property_id
            );
        }
    }

    #[test]
    fn a_property_mapping_can_never_claim_to_be_normative() {
        // A DARE property is informed by an upstream document; it is never part
        // of one. Allowing NORMATIVE here would let an artifact imply that
        // OWASP published this property.
        let mut provenance = valid();
        provenance.property_mappings[0].status = "NORMATIVE".to_owned();
        let err = validate_rag_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("never part of an upstream"));
    }

    #[test]
    fn a_property_mapping_can_never_claim_equivalence() {
        let mut provenance = valid();
        provenance.property_mappings[0].relation = "EQUIVALENT".to_owned();
        assert!(validate_rag_security_provenance(&provenance).is_err());

        provenance.property_mappings[0].relation = "CONFORMS_TO".to_owned();
        assert!(validate_rag_security_provenance(&provenance).is_err());
    }

    #[test]
    fn a_conformance_claim_is_refused_wherever_it_appears() {
        for claim in [
            "DARE is OWASP compliant",
            "the engine is certified against LLM09",
            "this makes retrieval secure",
            "no leakage possible with this engine",
        ] {
            let mut provenance = valid();
            provenance.conformance_disclaimer = claim.to_owned();
            assert!(
                validate_rag_security_provenance(&provenance).is_err(),
                "`{claim}` was allowed"
            );
        }
    }

    #[test]
    fn denying_conformance_stays_writable() {
        // The manifest's whole job is to deny conformance. A checker that could
        // not express the denial would make the honest sentence impossible.
        let mut provenance = valid();
        provenance.conformance_disclaimer =
            "DARE is not certified against any of these documents and is not OWASP compliant."
                .to_owned();
        validate_rag_security_provenance(&provenance).expect("a denial is allowed");
    }

    #[test]
    fn a_denial_in_one_sentence_cannot_launder_a_claim_in_the_next() {
        let mut provenance = valid();
        provenance.conformance_disclaimer =
            "This is not a certification. DARE is OWASP compliant.".to_owned();
        assert!(validate_rag_security_provenance(&provenance).is_err());
    }

    #[test]
    fn llm09_can_never_be_recorded_as_an_agentic_risk_family() {
        // The two taxonomies are separate documents. Folding one into the other
        // would make a reader believe the Agentic family count had grown.
        for claim in [
            "LLM09 is an agentic risk family",
            "this property is equivalent to ASI06",
            "adding an eleventh agentic family for retrieval",
        ] {
            let mut provenance = valid();
            provenance.taxonomy_note = claim.to_owned();
            assert!(
                validate_rag_security_provenance(&provenance).is_err(),
                "`{claim}` was allowed"
            );
        }
    }

    #[test]
    fn the_taxonomy_note_states_the_separation_it_is_there_to_state() {
        let provenance = valid();
        let note = provenance.taxonomy_note.to_lowercase();
        assert!(note.contains("not an owasp agentic top 10 risk family"));
        assert!(note.contains("remain exactly ten"));
    }

    #[test]
    fn the_trust_statement_records_all_three_relations() {
        let provenance = valid();
        let statement = &provenance.retrieval_trust_statement;
        assert_eq!(statement.core_relation, "similarity_match != permission");
        assert_eq!(
            statement.content_rule,
            "retrieved_content != trusted_instruction"
        );
        assert_eq!(statement.score_rule, "high_score != safe_source");
    }

    #[test]
    fn a_missing_relation_is_refused() {
        for mutate in [
            |p: &mut RagSecurityProvenance| {
                p.retrieval_trust_statement.core_relation = "retrieval is fine".to_owned()
            },
            |p: &mut RagSecurityProvenance| {
                p.retrieval_trust_statement.content_rule = "content is fine".to_owned()
            },
            |p: &mut RagSecurityProvenance| {
                p.retrieval_trust_statement.score_rule = "scores are fine".to_owned()
            },
            |p: &mut RagSecurityProvenance| {
                p.retrieval_trust_statement.ranking_rule = "ranking decides".to_owned()
            },
            |p: &mut RagSecurityProvenance| {
                p.retrieval_trust_statement.memory_rule = "retrieval is memory".to_owned()
            },
        ] {
            let mut provenance = valid();
            mutate(&mut provenance);
            assert!(validate_rag_security_provenance(&provenance).is_err());
        }
    }

    #[test]
    fn the_ranking_rule_denies_ranking_the_final_word() {
        let provenance = valid();
        let rule = &provenance.retrieval_trust_statement.ranking_rule;
        assert!(rule.contains("final security judge"));
        assert!(rule.contains("None of them may widen what policy allows"));
    }

    #[test]
    fn every_required_deferral_is_recorded() {
        let provenance = valid();
        for cycle in REQUIRED_DEFERRALS {
            assert!(
                provenance
                    .explicitly_out_of_scope
                    .iter()
                    .any(|topic| topic.deferred_to == cycle),
                "{cycle} is not recorded as a deferral"
            );
        }

        // The two boundaries most likely to be blurred are named explicitly.
        let topics: Vec<&str> = provenance
            .explicitly_out_of_scope
            .iter()
            .map(|topic| topic.topic.as_str())
            .collect();
        assert!(topics
            .iter()
            .any(|topic| topic.contains("Prompt-injection")));
        assert!(topics
            .iter()
            .any(|topic| topic.contains("Persisted memory")));
    }

    #[test]
    fn a_missing_deferral_is_refused() {
        let mut provenance = valid();
        provenance
            .explicitly_out_of_scope
            .retain(|topic| topic.deferred_to != "CYCLE_018");
        let err = validate_rag_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("CYCLE_018"));
    }

    #[test]
    fn the_live_store_exclusion_names_the_stores_by_name() {
        // A generic "no external systems" would leave a reader guessing. The
        // named list is what makes the boundary checkable.
        let provenance = valid();
        let note = provenance
            .explicitly_out_of_scope
            .iter()
            .find(|topic| topic.topic.contains("Live vector databases"))
            .expect("recorded");
        for store in [
            "Pinecone",
            "Weaviate",
            "Qdrant",
            "OpenSearch",
            "Elasticsearch",
        ] {
            assert!(note.note.contains(store), "{store} is not named");
        }
    }

    #[test]
    fn every_required_lesson_is_carried_forward() {
        let provenance = valid();
        for lesson in REQUIRED_LESSONS {
            assert!(
                provenance
                    .inherited_lessons
                    .iter()
                    .any(|recorded| recorded.id == lesson),
                "{lesson} is missing"
            );
        }
    }

    #[test]
    fn a_missing_source_or_mapping_is_refused() {
        let mut provenance = valid();
        provenance
            .sources
            .retain(|source| source.id != "OWASP_LLM09_2026");
        assert!(validate_rag_security_provenance(&provenance).is_err());

        let mut provenance = valid();
        provenance.property_mappings.pop();
        assert!(validate_rag_security_provenance(&provenance).is_err());
    }

    #[test]
    fn a_mapping_to_an_undeclared_source_is_refused() {
        let mut provenance = valid();
        provenance.property_mappings[0].standard = "SOME_OTHER_DOCUMENT".to_owned();
        let err = validate_rag_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("unknown source"));
    }

    #[test]
    fn a_pinned_source_status_cannot_be_downgraded_or_promoted() {
        let mut provenance = valid();
        provenance
            .sources
            .iter_mut()
            .find(|source| source.id == "NIST_AI_600_1")
            .expect("recorded")
            .status = "NORMATIVE".to_owned();
        assert!(validate_rag_security_provenance(&provenance).is_err());
    }

    #[test]
    fn the_manifest_is_never_fetched_at_runtime() {
        let mut provenance = valid();
        provenance.fetch_policy = "FETCH_ON_DEMAND".to_owned();
        let err = validate_rag_security_provenance(&provenance).expect_err("must be refused");
        assert!(err.to_string().contains("OFFLINE_LOCAL_SNAPSHOT"));
    }

    #[test]
    fn the_manifest_carries_no_credential_or_endpoint() {
        // It is a shipped artifact like any other and is swept like one.
        let raw = RAG_SECURITY_PROVENANCE_JSON.to_lowercase();
        for marker in [
            "sk-live-",
            "-----begin",
            "bearer ey",
            "api_key",
            "redis://",
            "postgresql://",
            "https://api.",
        ] {
            assert!(!raw.contains(marker), "the manifest carries `{marker}`");
        }
    }
}
