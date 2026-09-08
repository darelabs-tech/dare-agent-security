//! The Cycle 019 supply-chain standards record, and the checks that keep it
//! honest.
//!
//! A provenance file is a place where a cycle records which specifications it
//! read and what status each one has. Left as prose, it decays in one specific
//! direction: a `DRAFT` becomes a requirement, an `INFORMATIVE` reference
//! becomes a conformance claim, and nobody notices because nothing failed.
//!
//! So the record is data with a validator behind it. Three rules it enforces
//! that are worth stating outright:
//!
//! 1. **A source's status is pinned.** `SIGSTORE_COSIGN` is `INFORMATIVE` and
//!    `CYCLONEDX_2_0_TEL` is `FUTURE`. Editing either to `NORMATIVE` fails here
//!    rather than in a later cycle's reasoning.
//! 2. **No property mapping may be `NORMATIVE`.** A mapping says where a
//!    property borrowed its vocabulary. It never says the specification
//!    requires the property, and the type system is where that distinction is
//!    kept rather than the reader's memory.
//! 3. **No text may claim conformance.** A PASS in this cycle is a statement
//!    about evidence, and "CycloneDX compliant" is a statement about a
//!    document. The detector is sentence-scoped, so an honest denial — "nothing
//!    here is SPDX compliant" — stays writable.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

const MANIFEST_PATH: &str = "standards/supply-chain-security/2026/provenance.json";

pub const SUPPLY_CHAIN_PROVENANCE_JSON: &str =
    include_str!("../../../standards/supply-chain-security/2026/provenance.json");

pub const SUPPLY_CHAIN_COMPONENT_PROVENANCE_PROPERTY: &str =
    "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE";
pub const SUPPLY_CHAIN_CAPABILITY_DRIFT_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT";
pub const SUPPLY_CHAIN_COMPONENT_IDENTITY_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY";
pub const SUPPLY_CHAIN_ARTIFACT_INTEGRITY_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY";
pub const SUPPLY_CHAIN_SOURCE_TRUST_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.SOURCE_TRUST";
pub const SUPPLY_CHAIN_ATTESTATION_BINDING_PROPERTY: &str =
    "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING";
pub const SUPPLY_CHAIN_DEPENDENCY_INTEGRITY_PROPERTY: &str =
    "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY";
pub const SUPPLY_CHAIN_MODEL_LINEAGE_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE";
pub const SUPPLY_CHAIN_DATASET_PROVENANCE_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE";
pub const SUPPLY_CHAIN_BOM_COMPLETENESS_PROPERTY: &str = "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSource {
    pub id: String,
    pub title: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    pub canonical_reference: String,
    pub status: String,
    pub usage: String,
    pub mapping_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainTrustStatement {
    pub id: String,
    pub summary: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSurfaceClass {
    pub id: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainInheritedLesson {
    pub from: String,
    pub lesson: String,
    pub applied_as: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub cycle: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub reverification_note: String,
    pub conformance_disclaimer: String,
    pub status_discipline_note: String,
    pub sources: Vec<SupplyChainSource>,
    pub supply_chain_trust_statement: SupplyChainTrustStatement,
    pub surface_classes: Vec<SupplyChainSurfaceClass>,
    pub property_mappings: Vec<SupplyChainPropertyMapping>,
    pub explicitly_out_of_scope: Vec<String>,
    pub inherited_lessons: Vec<SupplyChainInheritedLesson>,
}

/// How a property may relate to a specification it borrowed vocabulary from.
///
/// Deliberately two. `IMPLEMENTS` and `CONFORMS_TO` are absent because neither
/// is true of anything this cycle does.
const ALLOWED_RELATIONS: [&str; 2] = ["SPECIALIZES", "COMPOSES_WITH"];

const ALLOWED_SOURCE_STATUS: [&str; 4] = ["NORMATIVE", "INFORMATIVE", "DRAFT", "FUTURE"];

/// A mapping records where vocabulary came from. It may never claim the
/// specification requires the property, so `NORMATIVE` is not available here
/// even though it is available to a source.
const ALLOWED_MAPPING_STATUS: [&str; 3] = ["INFORMATIVE", "DRAFT", "FUTURE"];

/// The statuses the Cycle 019 approval froze. Editing one is a decision that
/// belongs to a later approval, not to a later edit.
const PINNED_SOURCE_STATUS: [(&str, &str); 8] = [
    ("OWASP_AGENTIC_TOP10_2026_ASI04", "NORMATIVE"),
    ("CYCLONEDX_1_7", "NORMATIVE"),
    ("ECMA_424_2ND", "NORMATIVE"),
    ("SPDX_3_0_1", "NORMATIVE"),
    ("SLSA_1_2", "NORMATIVE"),
    ("IN_TOTO_ATTESTATION_1_2", "NORMATIVE"),
    ("SIGSTORE_COSIGN", "INFORMATIVE"),
    ("CYCLONEDX_2_0_TEL", "FUTURE"),
];

const REQUIRED_SURFACE_CLASSES: [&str; 10] = [
    "COMPONENT_IDENTITY",
    "ARTIFACT_INTEGRITY",
    "SOURCE_TRUST",
    "PROVENANCE_BINDING",
    "ATTESTATION_BINDING",
    "DEPENDENCY_INTEGRITY",
    "CAPABILITY_DRIFT",
    "MODEL_LINEAGE",
    "DATASET_PROVENANCE",
    "BOM_COMPLETENESS",
];

/// Every property this cycle reports under, including the two it inherited.
pub const REQUIRED_MAPPED_PROPERTIES: [&str; 10] = [
    SUPPLY_CHAIN_COMPONENT_PROVENANCE_PROPERTY,
    SUPPLY_CHAIN_CAPABILITY_DRIFT_PROPERTY,
    SUPPLY_CHAIN_COMPONENT_IDENTITY_PROPERTY,
    SUPPLY_CHAIN_ARTIFACT_INTEGRITY_PROPERTY,
    SUPPLY_CHAIN_SOURCE_TRUST_PROPERTY,
    SUPPLY_CHAIN_ATTESTATION_BINDING_PROPERTY,
    SUPPLY_CHAIN_DEPENDENCY_INTEGRITY_PROPERTY,
    SUPPLY_CHAIN_MODEL_LINEAGE_PROPERTY,
    SUPPLY_CHAIN_DATASET_PROVENANCE_PROPERTY,
    SUPPLY_CHAIN_BOM_COMPLETENESS_PROPERTY,
];

/// Exclusions the record must state rather than leave to inference.
///
/// Each names a thing a reader might otherwise assume this cycle does, and the
/// most consequential is the first: nothing here reaches a network.
const REQUIRED_EXCLUSION_MARKERS: [&str; 8] = [
    "Remote package, registry",
    "Vulnerability database",
    "Malware analysis",
    "Licence-compliance",
    "Real signing",
    "Remote signature verification",
    "A2A protocol",
    "Attack-path construction",
];

const REQUIRED_LESSON_SOURCES: [&str; 2] = ["cycle-017", "cycle-018"];

/// The eleven distinctions from `DESIGN.md` §2, each a place where two things
/// that look alike are not the same thing.
const REQUIRED_TRUST_RULE_MARKERS: [&str; 11] = [
    "inventory != trust",
    "component name != component identity",
    "version string != immutable artifact",
    "digest presence != provenance",
    "valid signature evidence != authorized signer",
    "provenance presence != trusted provenance",
    "complete AI-BOM != secure supply chain",
    "declared dependency != observed dependency",
    "same name and version != same artifact",
    "component URL != authorization to fetch",
    "external agent inventory != A2A authorization",
];

const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 12] = [
    "cyclonedx compliant",
    "spdx compliant",
    "slsa compliant",
    "in-toto compliant",
    "sbom compliant",
    "fully compliant",
    "certified",
    "conformance verified",
    "supply chain secure",
    "supply-chain secure",
    "ai-bom secure",
    "agent secure",
];

const FORBIDDEN_STATUS_CLAIMS: [&str; 8] = [
    "future requirement",
    "required by cyclonedx 2.0",
    "tel is required",
    "sigstore is required",
    "cosign is required",
    "mandatory attestation standard",
    "slsa level achieved",
    "slsa level verified",
];

pub fn load_supply_chain_provenance() -> Result<SupplyChainProvenance, CoverageError> {
    serde_json::from_str(SUPPLY_CHAIN_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(
            MANIFEST_PATH,
            format!("supply-chain provenance is not valid: {err}"),
        )
    })
}

/// Load and validate in one step.
pub fn supply_chain_provenance() -> Result<SupplyChainProvenance, CoverageError> {
    let provenance = load_supply_chain_provenance()?;
    validate_supply_chain_provenance(&provenance)?;
    Ok(provenance)
}

pub fn validate_supply_chain_provenance(
    provenance: &SupplyChainProvenance,
) -> Result<(), CoverageError> {
    let schema = |reason: String| CoverageError::schema(MANIFEST_PATH, reason);

    if provenance.fetch_policy != "NO_NETWORK_ACCESS" {
        return Err(schema(format!(
            "fetch policy must remain NO_NETWORK_ACCESS, found `{}`",
            provenance.fetch_policy
        )));
    }

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

    let surfaces: HashSet<&str> = provenance
        .surface_classes
        .iter()
        .map(|class| class.id.as_str())
        .collect();
    for required in REQUIRED_SURFACE_CLASSES {
        if !surfaces.contains(required) {
            return Err(schema(format!("surface class `{required}` is missing")));
        }
    }

    let mut mapped = HashSet::new();
    for mapping in &provenance.property_mappings {
        if !mapped.insert(mapping.property_id.as_str()) {
            return Err(schema(format!(
                "property `{}` is mapped twice",
                mapping.property_id
            )));
        }
        if !ALLOWED_RELATIONS.contains(&mapping.relation.as_str()) {
            return Err(schema(format!(
                "property `{}` uses relation `{}`, which is not one this cycle may claim",
                mapping.property_id, mapping.relation
            )));
        }
        if !ALLOWED_MAPPING_STATUS.contains(&mapping.status.as_str()) {
            return Err(schema(format!(
                "property `{}` maps at status `{}`; a mapping records where vocabulary came \
                 from and may never assert the specification requires the property",
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
        if !mapped.contains(required) {
            return Err(schema(format!("property `{required}` has no mapping")));
        }
    }
    if mapped.len() != REQUIRED_MAPPED_PROPERTIES.len() {
        return Err(schema(format!(
            "expected {} mapped properties, found {}",
            REQUIRED_MAPPED_PROPERTIES.len(),
            mapped.len()
        )));
    }

    for marker in REQUIRED_TRUST_RULE_MARKERS {
        if !provenance
            .supply_chain_trust_statement
            .rules
            .iter()
            .any(|rule| rule.contains(marker))
        {
            return Err(schema(format!(
                "the trust statement no longer states `{marker}`"
            )));
        }
    }

    for marker in REQUIRED_EXCLUSION_MARKERS {
        if !provenance
            .explicitly_out_of_scope
            .iter()
            .any(|entry| entry.contains(marker))
        {
            return Err(schema(format!(
                "the record no longer excludes `{marker}` explicitly"
            )));
        }
    }

    for source in REQUIRED_LESSON_SOURCES {
        if !provenance
            .inherited_lessons
            .iter()
            .any(|lesson| lesson.from == source)
        {
            return Err(schema(format!("no lesson is recorded from `{source}`")));
        }
    }

    // Every free-text surface is held to the same rule. A disclaimer that
    // itself claimed conformance would be the exact failure it exists to
    // prevent.
    for (label, text) in [
        ("fetch policy note", provenance.fetch_policy_note.as_str()),
        (
            "reverification note",
            provenance.reverification_note.as_str(),
        ),
        (
            "conformance disclaimer",
            provenance.conformance_disclaimer.as_str(),
        ),
        (
            "status discipline note",
            provenance.status_discipline_note.as_str(),
        ),
        (
            "trust statement summary",
            provenance.supply_chain_trust_statement.summary.as_str(),
        ),
    ] {
        assert_no_conformance_claim(text, label)?;
        assert_no_status_promotion(text, label)?;
    }
    for source in &provenance.sources {
        assert_no_conformance_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
        assert_no_status_promotion(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_conformance_claim(
            &mapping.notes,
            &format!("mapping `{}`", mapping.property_id),
        )?;
        assert_no_status_promotion(
            &mapping.notes,
            &format!("mapping `{}`", mapping.property_id),
        )?;
    }

    Ok(())
}

/// Refuse wording that would turn a bounded run into a conformance assertion.
pub fn assert_no_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(text, where_found, &FORBIDDEN_CONFORMANCE_PHRASES, "claim")
}

/// Refuse wording that would promote an informative or future source into a
/// Cycle 019 requirement.
pub fn assert_no_status_promotion(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(
        text,
        where_found,
        &FORBIDDEN_STATUS_CLAIMS,
        "status promotion",
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

/// Whether the sentence leading up to an occurrence negates it.
///
/// Scoped to the current sentence rather than the whole text, so a denial in
/// one sentence cannot license an affirmative claim three sentences later. The
/// alternative — banning the words outright — would push the next author to
/// reword an honest denial in order to satisfy a checker, which is worse than
/// the problem.
fn sentence_denies(prefix: &str) -> bool {
    let sentence_start = prefix
        .rfind(['.', ';', '!', '?'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let sentence = &prefix[sentence_start..];
    ["not ", "no ", "never ", "cannot ", "nor ", "nothing "]
        .iter()
        .any(|marker| sentence.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> SupplyChainProvenance {
        supply_chain_provenance().expect("the committed record validates")
    }

    #[test]
    fn the_committed_record_loads_and_validates() {
        let record = provenance();
        assert_eq!(record.cycle, "019-agentic-supply-chain-aibom");
        assert_eq!(record.sources.len(), 8);
        assert_eq!(record.property_mappings.len(), 10);
    }

    #[test]
    fn every_source_status_is_pinned_to_what_the_approval_froze() {
        let record = provenance();
        for (id, expected) in PINNED_SOURCE_STATUS {
            let source = record
                .sources
                .iter()
                .find(|source| source.id == id)
                .unwrap_or_else(|| panic!("{id} is missing"));
            assert_eq!(source.status, expected, "{id} drifted");
        }
    }

    #[test]
    fn promoting_an_informative_source_to_normative_is_refused() {
        // Sigstore is the one most likely to be promoted by accident: it is a
        // real verification system, and it is easy to write as though this
        // cycle used it. It does not — it models a status field a document
        // already carried.
        let mut record = provenance();
        let sigstore = record
            .sources
            .iter_mut()
            .find(|source| source.id == "SIGSTORE_COSIGN")
            .expect("present");
        sigstore.status = "NORMATIVE".to_owned();
        let err = validate_supply_chain_provenance(&record).expect_err("must be refused");
        assert!(err.to_string().contains("SIGSTORE_COSIGN"));
    }

    #[test]
    fn promoting_the_future_source_is_refused() {
        let mut record = provenance();
        let future = record
            .sources
            .iter_mut()
            .find(|source| source.id == "CYCLONEDX_2_0_TEL")
            .expect("present");
        future.status = "NORMATIVE".to_owned();
        assert!(validate_supply_chain_provenance(&record).is_err());
    }

    #[test]
    fn no_property_mapping_may_be_normative() {
        // The distinction the whole file exists for. A mapping says a property
        // borrowed vocabulary from a specification; it never says the
        // specification requires the property.
        let record = provenance();
        for mapping in &record.property_mappings {
            assert_ne!(
                mapping.status, "NORMATIVE",
                "{} claims its standard requires it",
                mapping.property_id
            );
        }

        let mut hostile = provenance();
        hostile.property_mappings[0].status = "NORMATIVE".to_owned();
        assert!(validate_supply_chain_provenance(&hostile).is_err());
    }

    #[test]
    fn a_mapping_may_not_claim_a_relation_this_cycle_does_not_have() {
        let mut record = provenance();
        record.property_mappings[0].relation = "IMPLEMENTS".to_owned();
        let err = validate_supply_chain_provenance(&record).expect_err("must be refused");
        assert!(err.to_string().contains("IMPLEMENTS"));
    }

    #[test]
    fn a_mapping_to_an_unknown_source_is_refused() {
        let mut record = provenance();
        record.property_mappings[0].standard = "SOME_SPEC_NOBODY_RECORDED".to_owned();
        assert!(validate_supply_chain_provenance(&record).is_err());
    }

    #[test]
    fn all_ten_properties_are_mapped_including_the_two_inherited_ones() {
        let record = provenance();
        let mapped: HashSet<&str> = record
            .property_mappings
            .iter()
            .map(|mapping| mapping.property_id.as_str())
            .collect();
        for property in REQUIRED_MAPPED_PROPERTIES {
            assert!(mapped.contains(property), "{property} is unmapped");
        }
        // The two from Cycle 012 are mapped rather than silently inherited, so
        // a reader can see they were considered rather than forgotten.
        assert!(mapped.contains(SUPPLY_CHAIN_COMPONENT_PROVENANCE_PROPERTY));
        assert!(mapped.contains(SUPPLY_CHAIN_CAPABILITY_DRIFT_PROPERTY));
    }

    #[test]
    fn dropping_a_mapping_is_refused() {
        let mut record = provenance();
        record.property_mappings.pop();
        assert!(validate_supply_chain_provenance(&record).is_err());
    }

    #[test]
    fn the_eleven_trust_distinctions_are_all_stated() {
        let record = provenance();
        assert_eq!(record.supply_chain_trust_statement.rules.len(), 11);
        for marker in REQUIRED_TRUST_RULE_MARKERS {
            assert!(
                record
                    .supply_chain_trust_statement
                    .rules
                    .iter()
                    .any(|rule| rule.contains(marker)),
                "`{marker}` is no longer stated"
            );
        }
    }

    #[test]
    fn removing_a_trust_distinction_is_refused() {
        let mut record = provenance();
        record
            .supply_chain_trust_statement
            .rules
            .retain(|rule| !rule.contains("component URL != authorization to fetch"));
        let err = validate_supply_chain_provenance(&record).expect_err("must be refused");
        assert!(err.to_string().contains("authorization to fetch"));
    }

    #[test]
    fn the_fetch_policy_cannot_be_edited_to_something_permissive() {
        let mut record = provenance();
        record.fetch_policy = "BOUNDED_REGISTRY_LOOKUP".to_owned();
        let err = validate_supply_chain_provenance(&record).expect_err("must be refused");
        assert!(err.to_string().contains("NO_NETWORK_ACCESS"));
    }

    #[test]
    fn every_required_exclusion_is_stated_rather_than_inferred() {
        let record = provenance();
        for marker in REQUIRED_EXCLUSION_MARKERS {
            assert!(
                record
                    .explicitly_out_of_scope
                    .iter()
                    .any(|entry| entry.contains(marker)),
                "`{marker}` is no longer excluded explicitly"
            );
        }
    }

    #[test]
    fn a_conformance_claim_anywhere_in_the_record_is_refused() {
        for hostile in [
            "this engine is CycloneDX compliant",
            "the result is SPDX compliant",
            "the build is SLSA compliant",
            "the deployment is supply chain secure",
            "the inventory is AI-BOM secure",
        ] {
            assert!(
                assert_no_conformance_claim(hostile, "test").is_err(),
                "`{hostile}` was allowed"
            );
        }
    }

    #[test]
    fn an_honest_denial_stays_writable() {
        // The reason the detector is sentence-scoped rather than a word ban. A
        // record must be able to say what it is not, and the natural phrasing
        // contains the phrase being denied.
        for honest in [
            "nothing here is CycloneDX compliant",
            "no result is SPDX compliant, and none claims to be",
            "this is never a claim that the deployment is supply chain secure",
            "the engine cannot report that anything is AI-BOM secure",
        ] {
            assert!(
                assert_no_conformance_claim(honest, "test").is_ok(),
                "`{honest}` was refused"
            );
        }
    }

    #[test]
    fn a_denial_in_one_sentence_does_not_license_a_claim_in_the_next() {
        let hostile = "nothing here is SPDX compliant. The build is SLSA compliant.";
        assert!(assert_no_conformance_claim(hostile, "test").is_err());
    }

    #[test]
    fn promoting_a_status_in_prose_is_refused() {
        for hostile in [
            "TEL is required for a passing result",
            "Sigstore is required by this cycle",
            "the SLSA level achieved is 3",
        ] {
            assert!(
                assert_no_status_promotion(hostile, "test").is_err(),
                "`{hostile}` was allowed"
            );
        }
    }

    #[test]
    fn the_record_says_plainly_that_nothing_was_reverified() {
        // The claim a reader is most likely to assume from the presence of
        // version numbers. It is denied in the record's own words rather than
        // left to inference.
        let record = provenance();
        let note = record.reverification_note.to_lowercase();
        assert!(note.contains("no upstream re-verification"));
        assert!(note.contains("re-checked"));
    }

    #[test]
    fn the_record_says_plainly_that_nothing_is_fetched() {
        let record = provenance();
        let note = record.fetch_policy_note.to_lowercase();
        assert!(note.contains("inert metadata"));
        assert!(note.contains("naming something is not authorization"));
    }

    #[test]
    fn the_lessons_from_cycles_017_and_018_are_carried_forward() {
        let record = provenance();
        for source in REQUIRED_LESSON_SOURCES {
            assert!(
                record.inherited_lessons.iter().any(|l| l.from == source),
                "no lesson from {source}"
            );
        }
        // Each lesson says how it was applied, not merely that it exists.
        for lesson in &record.inherited_lessons {
            assert!(!lesson.applied_as.trim().is_empty(), "{:?}", lesson.from);
        }
    }

    #[test]
    fn the_record_carries_no_credential_or_reachable_target() {
        // Provenance files name specifications, and a specification has a URL.
        // This one records references by title and version instead, so there is
        // nothing in it that a reader's tooling could follow.
        let raw = SUPPLY_CHAIN_PROVENANCE_JSON;
        for marker in ["http://", "https://", "sk-live-", "-----BEGIN", "eyJhbGci"] {
            assert!(!raw.contains(marker), "the record carries `{marker}`");
        }
    }

    #[test]
    fn an_unknown_field_in_the_record_is_refused() {
        // `deny_unknown_fields` across the board: an authority-bearing field
        // nobody modelled must not ride along unread.
        let hostile = r#"{"id":"X","title":"t","version":"1","canonical_reference":"r",
            "status":"NORMATIVE","usage":"u","mapping_notes":"n","verdict":"PASS"}"#;
        assert!(serde_json::from_str::<SupplyChainSource>(hostile).is_err());
    }
}
