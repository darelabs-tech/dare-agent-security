//! Cycle 015 identity-security standards provenance.
//!
//! Local committed snapshot only: no network fetch happens at validation time,
//! and no identity provider, authorization server or policy decision point is
//! contacted by anything in this crate.
//!
//! This module records attribution and enforces two things the prose alone
//! cannot. First, that DARE never claims conformance with AuthZEN, COAZ or MCP
//! merely because an internal data model resembles theirs. Second, that a draft
//! or open proposal is never presented as a final normative requirement —
//! `FINAL_SPECIFICATION`, `DRAFT` and `OPEN_PROPOSAL` are distinct statuses and
//! the validator refuses to let them blur.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

pub const IDENTITY_SECURITY_PROVENANCE_JSON: &str =
    include_str!("../../../standards/identity-security/2026/provenance.json");

/// Cycle 012 properties Cycle 015 preserves unchanged.
pub const IDENTITY_DELEGATION_INTEGRITY_PROPERTY: &str = "AGENT.IDENTITY.DELEGATION_INTEGRITY";
pub const IDENTITY_PRIVILEGE_AMPLIFICATION_PROPERTY: &str =
    "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION";

/// Property IDs introduced by Cycle 015.
pub const IDENTITY_PRINCIPAL_BINDING_PROPERTY: &str = "AGENT.IDENTITY.PRINCIPAL_BINDING";
pub const IDENTITY_DELEGATION_SCOPE_BOUNDARY_PROPERTY: &str =
    "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY";
pub const IDENTITY_TENANT_RESOURCE_BOUNDARY_PROPERTY: &str =
    "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY";
pub const IDENTITY_AUTHORIZATION_EXECUTION_BINDING_PROPERTY: &str =
    "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecuritySource {
    pub id: String,
    pub title: String,
    pub version: String,
    pub published_at: String,
    pub canonical_reference: String,
    pub status: String,
    pub usage: String,
    pub mapping_notes: String,
}

/// The authority relation the whole cycle rests on, recorded as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityModelStatement {
    pub core_relation: String,
    pub statement: String,
    pub credential_rule: String,
    pub non_equivalence_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySurfaceClass {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeferredTopic {
    pub topic: String,
    pub deferred_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInheritedLesson {
    pub id: String,
    pub from_cycle: String,
    pub lesson: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub conformance_disclaimer: String,
    pub sources: Vec<IdentitySecuritySource>,
    pub authority_model_statement: AuthorityModelStatement,
    pub surface_classes: Vec<IdentitySurfaceClass>,
    pub property_mappings: Vec<IdentityPropertyMapping>,
    pub explicitly_out_of_scope: Vec<IdentityDeferredTopic>,
    pub inherited_lessons: Vec<IdentityInheritedLesson>,
}

/// Relations a Cycle 015 property may declare against upstream guidance.
///
/// `EQUIVALENT` and `CONFORMS_TO` are deliberately absent: DARE never asserts
/// normative equivalence with, or conformance to, an upstream specification.
const ALLOWED_RELATIONS: [&str; 2] = ["PARENT_INVARIANT", "SPECIALIZES"];

/// Statuses a source may carry.
///
/// These are kept distinct on purpose. A `DRAFT` or an `OPEN_PROPOSAL` may
/// inform modeling; neither may be reported as a normative requirement, and a
/// `FINAL_SPECIFICATION` being final says nothing about DARE conforming to it.
const ALLOWED_SOURCE_STATUS: [&str; 5] = [
    "NORMATIVE",
    "FINAL_SPECIFICATION",
    "DRAFT",
    "OPEN_PROPOSAL",
    "INFORMATIVE",
];

/// Statuses a property mapping may carry.
///
/// A mapping cannot claim `FINAL_SPECIFICATION`: a DARE property is never part
/// of an upstream specification, however closely it was informed by one.
const ALLOWED_MAPPING_STATUS: [&str; 3] = ["NORMATIVE", "DRAFT", "INFORMATIVE"];

/// Sources whose status is fixed by what upstream actually published.
const PINNED_SOURCE_STATUS: [(&str, &str); 5] = [
    ("OWASP_AGENTIC_TOP10_2026", "NORMATIVE"),
    ("OPENID_AUTHZEN_1_0", "FINAL_SPECIFICATION"),
    ("COAZ_FRAMEWORK_1_0", "DRAFT"),
    ("COAZ_MCP_BINDING_1_0", "DRAFT"),
    ("AUTHORIZATION_TO_EXECUTION_BINDING", "OPEN_PROPOSAL"),
];

/// The six lessons inherited from Cycles 013 and 014 that must stay recorded.
const REQUIRED_LESSONS: [&str; 6] = [
    "POSITIVE_PASS_COVERAGE",
    "INDEPENDENT_VIOLATIONS",
    "SYNTHETIC_IS_NOT_PRODUCTION",
    "EXECUTE_THE_ACTUAL_CI_JOB",
    "EXACT_STRUCTURED_ASSERTIONS",
    "NO_RAW_CREDENTIALS_IN_EVIDENCE",
];

/// The five reporting surfaces coverage must be separable by.
const REQUIRED_SURFACE_CLASSES: [&str; 5] = [
    "PRINCIPAL_BINDING",
    "DELEGATION",
    "PRIVILEGE",
    "TENANT_RESOURCE",
    "AUTHORIZATION_BINDING",
];

/// The six properties the identity profile is built from.
const REQUIRED_MAPPED_PROPERTIES: [&str; 6] = [
    IDENTITY_DELEGATION_INTEGRITY_PROPERTY,
    IDENTITY_PRIVILEGE_AMPLIFICATION_PROPERTY,
    IDENTITY_PRINCIPAL_BINDING_PROPERTY,
    IDENTITY_DELEGATION_SCOPE_BOUNDARY_PROPERTY,
    IDENTITY_TENANT_RESOURCE_BOUNDARY_PROPERTY,
    IDENTITY_AUTHORIZATION_EXECUTION_BINDING_PROPERTY,
];

/// Words that would turn a recorded reference into a conformance claim.
const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 6] = [
    "authzen compliant",
    "authzen-compliant",
    "coaz compliant",
    "coaz-compliant",
    "mcp compliant",
    "certified against",
];

pub fn load_identity_security_provenance() -> Result<IdentitySecurityProvenance, CoverageError> {
    serde_json::from_str(IDENTITY_SECURITY_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(
            "standards/identity-security/2026/provenance.json",
            format!("identity-security provenance is not valid: {err}"),
        )
    })
}

pub fn validate_identity_security_provenance(
    provenance: &IdentitySecurityProvenance,
) -> Result<(), CoverageError> {
    let schema = |reason: String| {
        CoverageError::schema("standards/identity-security/2026/provenance.json", reason)
    };

    if provenance.schema_version != "1.0.0" {
        return Err(schema(format!(
            "unsupported identity-security provenance version `{}`",
            provenance.schema_version
        )));
    }
    if provenance.fetch_policy != "OFFLINE_LOCAL_SNAPSHOT" {
        return Err(schema(format!(
            "identity-security provenance must be an offline local snapshot, found `{}`",
            provenance.fetch_policy
        )));
    }

    // The disclaimer is load-bearing, not decorative: it is the sentence that
    // keeps a resemblance from being read as a conformance claim.
    let disclaimer = provenance.conformance_disclaimer.to_ascii_lowercase();
    if !disclaimer.contains("does not claim") {
        return Err(schema(
            "the conformance disclaimer must state plainly that DARE does not claim conformance"
                .to_owned(),
        ));
    }

    let mut seen_sources = HashSet::new();
    for source in &provenance.sources {
        if !seen_sources.insert(source.id.as_str()) {
            return Err(schema(format!(
                "duplicate provenance source `{}`",
                source.id
            )));
        }
        if !ALLOWED_SOURCE_STATUS.contains(&source.status.as_str()) {
            return Err(schema(format!(
                "source `{}` declares unsupported status `{}`",
                source.id, source.status
            )));
        }
        if source.published_at.trim().is_empty() || source.version.trim().is_empty() {
            return Err(schema(format!(
                "source `{}` must record an exact version and date",
                source.id
            )));
        }
        assert_no_conformance_claim(&source.mapping_notes, &source.id)?;
    }

    // Upstream status is a fact about upstream, not a field an author may
    // adjust. A draft promoted to final here would be a false claim about
    // someone else's specification.
    for (id, expected) in PINNED_SOURCE_STATUS {
        let source = provenance
            .sources
            .iter()
            .find(|source| source.id == id)
            .ok_or_else(|| schema(format!("provenance is missing required source `{id}`")))?;
        if source.status != expected {
            return Err(schema(format!(
                "source `{id}` must be recorded as `{expected}`, found `{}`",
                source.status
            )));
        }
    }

    let authority = &provenance.authority_model_statement;
    if !authority.core_relation.contains("<=") {
        return Err(schema(
            "the authority model must record the ceiling relation as an inequality".to_owned(),
        ));
    }
    if !authority
        .credential_rule
        .to_ascii_lowercase()
        .contains("not delegated authority")
    {
        return Err(schema(
            "the authority model must state that credential availability is not delegated authority"
                .to_owned(),
        ));
    }
    if authority.non_equivalence_rules.len() < 4 {
        return Err(schema(
            "the authority model must record its non-equivalence rules explicitly".to_owned(),
        ));
    }

    let surfaces: HashSet<&str> = provenance
        .surface_classes
        .iter()
        .map(|class| class.id.as_str())
        .collect();
    for required in REQUIRED_SURFACE_CLASSES {
        if !surfaces.contains(required) {
            return Err(schema(format!(
                "provenance is missing the `{required}` surface class, which reports must separate"
            )));
        }
    }

    let known_sources: HashSet<&str> = provenance
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    let mut mapped = HashSet::new();
    for mapping in &provenance.property_mappings {
        if !mapped.insert(mapping.property_id.as_str()) {
            return Err(schema(format!(
                "duplicate property mapping for `{}`",
                mapping.property_id
            )));
        }
        if !ALLOWED_RELATIONS.contains(&mapping.relation.as_str()) {
            return Err(schema(format!(
                "property `{}` declares relation `{}`; DARE asserts only {ALLOWED_RELATIONS:?}",
                mapping.property_id, mapping.relation
            )));
        }
        if !ALLOWED_MAPPING_STATUS.contains(&mapping.status.as_str()) {
            return Err(schema(format!(
                "property `{}` declares mapping status `{}`; a DARE property is never part of an \
                 upstream specification",
                mapping.property_id, mapping.status
            )));
        }
        if !known_sources.contains(mapping.standard.as_str()) {
            return Err(schema(format!(
                "property `{}` maps to unknown source `{}`",
                mapping.property_id, mapping.standard
            )));
        }
        assert_no_conformance_claim(&mapping.notes, &mapping.property_id)?;
    }

    for required in REQUIRED_MAPPED_PROPERTIES {
        if !mapped.contains(required) {
            return Err(schema(format!(
                "provenance is missing a mapping for `{required}`"
            )));
        }
    }

    let deferred: HashSet<&str> = provenance
        .explicitly_out_of_scope
        .iter()
        .map(|topic| topic.deferred_to.as_str())
        .collect();
    // The OAuth/JWT/live-PDP boundary is the one most likely to erode, so the
    // handoff to Cycle 018 must be recorded rather than assumed.
    if !deferred.contains("Cycle 018") {
        return Err(schema(
            "provenance must record the OAuth/JWT/live-provider deferral to Cycle 018".to_owned(),
        ));
    }

    let lessons: HashSet<&str> = provenance
        .inherited_lessons
        .iter()
        .map(|lesson| lesson.id.as_str())
        .collect();
    for required in REQUIRED_LESSONS {
        if !lessons.contains(required) {
            return Err(schema(format!(
                "provenance is missing the inherited lesson `{required}`"
            )));
        }
    }

    Ok(())
}

/// Refuse text that would turn attribution into a conformance claim.
fn assert_no_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    let lowered = text.to_ascii_lowercase();
    for phrase in FORBIDDEN_CONFORMANCE_PHRASES {
        if lowered.contains(phrase) {
            return Err(CoverageError::schema(
                "standards/identity-security/2026/provenance.json",
                format!(
                    "`{where_found}` contains the conformance claim `{phrase}`; DARE records \
                     attribution, never conformance"
                ),
            ));
        }
    }
    Ok(())
}

/// Load and validate the shipped snapshot.
pub fn validate_identity_security_standards() -> Result<(), CoverageError> {
    let provenance = load_identity_security_provenance()?;
    validate_identity_security_provenance(&provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> IdentitySecurityProvenance {
        load_identity_security_provenance().expect("provenance loads")
    }

    #[test]
    fn the_shipped_snapshot_is_valid() {
        validate_identity_security_standards().expect("shipped provenance validates");
    }

    #[test]
    fn the_snapshot_is_offline_and_dated() {
        let provenance = provenance();
        assert_eq!(provenance.fetch_policy, "OFFLINE_LOCAL_SNAPSHOT");
        assert_eq!(provenance.recorded_at, "2026-09-05");
        for source in &provenance.sources {
            assert!(!source.version.trim().is_empty(), "{}", source.id);
            assert!(!source.published_at.trim().is_empty(), "{}", source.id);
        }
    }

    #[test]
    fn upstream_status_is_recorded_exactly_as_upstream_published_it() {
        // The distinction the approval insists on: AuthZEN is final, COAZ is
        // draft, and the binding behavior is an open proposal. Recording any of
        // them differently would be a false claim about someone else's work.
        let provenance = provenance();
        let status = |id: &str| {
            provenance
                .sources
                .iter()
                .find(|source| source.id == id)
                .map(|source| source.status.clone())
                .unwrap_or_default()
        };
        assert_eq!(status("OWASP_AGENTIC_TOP10_2026"), "NORMATIVE");
        assert_eq!(status("OPENID_AUTHZEN_1_0"), "FINAL_SPECIFICATION");
        assert_eq!(status("COAZ_FRAMEWORK_1_0"), "DRAFT");
        assert_eq!(status("COAZ_MCP_BINDING_1_0"), "DRAFT");
        assert_eq!(
            status("AUTHORIZATION_TO_EXECUTION_BINDING"),
            "OPEN_PROPOSAL"
        );
    }

    #[test]
    fn a_draft_cannot_be_promoted_to_final() {
        let mut provenance = provenance();
        let coaz = provenance
            .sources
            .iter_mut()
            .find(|source| source.id == "COAZ_FRAMEWORK_1_0")
            .expect("coaz source");
        coaz.status = "FINAL_SPECIFICATION".to_owned();
        let err = validate_identity_security_provenance(&provenance)
            .expect_err("a promoted draft must be refused");
        assert!(err.to_string().contains("COAZ_FRAMEWORK_1_0"));
    }

    #[test]
    fn an_open_proposal_cannot_be_promoted_to_normative() {
        let mut provenance = provenance();
        let binding = provenance
            .sources
            .iter_mut()
            .find(|source| source.id == "AUTHORIZATION_TO_EXECUTION_BINDING")
            .expect("binding source");
        binding.status = "NORMATIVE".to_owned();
        assert!(validate_identity_security_provenance(&provenance).is_err());
    }

    #[test]
    fn equivalence_and_conformance_relations_do_not_exist() {
        assert_eq!(ALLOWED_RELATIONS.len(), 2);
        assert!(!ALLOWED_RELATIONS.contains(&"EQUIVALENT"));
        assert!(!ALLOWED_RELATIONS.contains(&"CONFORMS_TO"));

        let mut provenance = provenance();
        provenance.property_mappings[0].relation = "EQUIVALENT".to_owned();
        assert!(validate_identity_security_provenance(&provenance).is_err());
    }

    #[test]
    fn a_property_mapping_cannot_claim_to_be_part_of_a_specification() {
        let mut provenance = provenance();
        provenance.property_mappings[0].status = "FINAL_SPECIFICATION".to_owned();
        let err = validate_identity_security_provenance(&provenance)
            .expect_err("a DARE property is never part of an upstream specification");
        assert!(err.to_string().contains("never part of"));
    }

    #[test]
    fn conformance_wording_is_refused_wherever_it_appears() {
        for claim in [
            "DARE is AuthZEN compliant",
            "fully coaz-compliant behavior",
            "MCP compliant authorization",
            "certified against the specification",
        ] {
            assert!(
                assert_no_conformance_claim(claim, "test").is_err(),
                "must refuse: {claim}"
            );
        }
        assert!(assert_no_conformance_claim(
            "The SARC shape informs modeling only and establishes no conformance claim.",
            "test"
        )
        .is_ok());
    }

    #[test]
    fn the_disclaimer_must_actually_disclaim() {
        let mut provenance = provenance();
        provenance.conformance_disclaimer =
            "DARE uses an AuthZEN-shaped model internally.".to_owned();
        let err = validate_identity_security_provenance(&provenance)
            .expect_err("a disclaimer that disclaims nothing must be refused");
        assert!(err.to_string().contains("does not claim"));
    }

    #[test]
    fn the_authority_relation_is_recorded_as_an_inequality() {
        let provenance = provenance();
        assert!(provenance
            .authority_model_statement
            .core_relation
            .contains("<="));
        assert!(provenance
            .authority_model_statement
            .statement
            .to_ascii_lowercase()
            .contains("never silently expand"));

        let mut broken = provenance;
        broken.authority_model_statement.core_relation =
            "effective_authority == ceiling".to_owned();
        assert!(validate_identity_security_provenance(&broken).is_err());
    }

    #[test]
    fn credential_availability_is_recorded_as_not_being_authority() {
        let provenance = provenance();
        let rule = provenance
            .authority_model_statement
            .credential_rule
            .to_ascii_lowercase();
        assert!(rule.contains("not delegated authority"));

        let mut broken = provenance;
        broken.authority_model_statement.credential_rule =
            "credentials are checked at runtime".to_owned();
        assert!(validate_identity_security_provenance(&broken).is_err());
    }

    #[test]
    fn every_identity_property_is_mapped_and_the_pre_existing_two_are_parents() {
        let provenance = provenance();
        let relation = |id: &str| {
            provenance
                .property_mappings
                .iter()
                .find(|mapping| mapping.property_id == id)
                .map(|mapping| mapping.relation.clone())
                .unwrap_or_default()
        };
        // The Cycle 012 properties are parents; Cycle 015 narrows them and does
        // not restate them.
        assert_eq!(
            relation(IDENTITY_DELEGATION_INTEGRITY_PROPERTY),
            "PARENT_INVARIANT"
        );
        assert_eq!(
            relation(IDENTITY_PRIVILEGE_AMPLIFICATION_PROPERTY),
            "PARENT_INVARIANT"
        );
        for added in [
            IDENTITY_PRINCIPAL_BINDING_PROPERTY,
            IDENTITY_DELEGATION_SCOPE_BOUNDARY_PROPERTY,
            IDENTITY_TENANT_RESOURCE_BOUNDARY_PROPERTY,
            IDENTITY_AUTHORIZATION_EXECUTION_BINDING_PROPERTY,
        ] {
            assert_eq!(relation(added), "SPECIALIZES", "{added}");
        }
    }

    #[test]
    fn a_missing_property_mapping_fails_closed() {
        let mut provenance = provenance();
        provenance
            .property_mappings
            .retain(|mapping| mapping.property_id != IDENTITY_TENANT_RESOURCE_BOUNDARY_PROPERTY);
        assert!(validate_identity_security_provenance(&provenance).is_err());
    }

    #[test]
    fn the_five_reporting_surfaces_are_all_declared() {
        let provenance = provenance();
        let ids: Vec<&str> = provenance
            .surface_classes
            .iter()
            .map(|class| class.id.as_str())
            .collect();
        assert_eq!(ids, REQUIRED_SURFACE_CLASSES);
    }

    #[test]
    fn the_oauth_and_live_provider_boundary_is_deferred_explicitly() {
        let provenance = provenance();
        let deferred: Vec<&str> = provenance
            .explicitly_out_of_scope
            .iter()
            .filter(|topic| topic.deferred_to == "Cycle 018")
            .map(|topic| topic.topic.as_str())
            .collect();
        assert!(
            deferred.len() >= 4,
            "OAuth, JWT, live providers and remote MCP must each be named: {deferred:?}"
        );

        let mut broken = provenance;
        broken
            .explicitly_out_of_scope
            .retain(|topic| topic.deferred_to != "Cycle 018");
        assert!(validate_identity_security_provenance(&broken).is_err());
    }

    #[test]
    fn later_cycles_are_named_rather_than_left_implicit() {
        let provenance = provenance();
        let deferred: Vec<&str> = provenance
            .explicitly_out_of_scope
            .iter()
            .map(|topic| topic.deferred_to.as_str())
            .collect();
        for cycle in [
            "Cycle 016",
            "Cycle 017",
            "Cycle 019",
            "Cycle 020",
            "Cycle 022",
        ] {
            assert!(deferred.contains(&cycle), "{cycle} must be named");
        }
    }

    #[test]
    fn all_six_inherited_lessons_are_recorded() {
        let provenance = provenance();
        let ids: HashSet<&str> = provenance
            .inherited_lessons
            .iter()
            .map(|lesson| lesson.id.as_str())
            .collect();
        for required in REQUIRED_LESSONS {
            assert!(ids.contains(required), "{required} is missing");
        }

        let mut broken = provenance;
        broken
            .inherited_lessons
            .retain(|lesson| lesson.id != "NO_RAW_CREDENTIALS_IN_EVIDENCE");
        assert!(validate_identity_security_provenance(&broken).is_err());
    }

    #[test]
    fn the_document_rejects_unknown_fields() {
        let mut value: serde_json::Value =
            serde_json::from_str(IDENTITY_SECURITY_PROVENANCE_JSON).expect("parses");
        value["live_pdp_url"] = serde_json::json!("https://example.invalid");
        assert!(serde_json::from_value::<IdentitySecurityProvenance>(value).is_err());
    }

    #[test]
    fn the_snapshot_names_no_reachable_endpoint() {
        // Canonical references are attribution. None of them is fetched, and
        // none may point at something the engine could be pointed at.
        let provenance = provenance();
        for source in &provenance.sources {
            let reference = &source.canonical_reference;
            let is_local = !reference.starts_with("http");
            let is_published_spec = reference.starts_with("https://openid.net/specs/")
                || reference.starts_with("https://genai.owasp.org/resource/");
            assert!(
                is_local || is_published_spec,
                "{} references {reference}",
                source.id
            );
        }
    }
}
