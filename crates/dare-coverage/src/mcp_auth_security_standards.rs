//! Cycle 018 MCP auth-security standards provenance.
//!
//! A recorded, versioned snapshot of what this cycle attributes its properties
//! to — never a live dependency. Nothing here fetches a document, resolves a
//! canonical reference over the network, or treats an upstream specification as
//! something to retrieve at runtime.
//!
//! That distinction carries more weight in this cycle than in most. Several of
//! the documents recorded below describe endpoints an implementation is
//! supposed to *call* — authorization servers, token endpoints, metadata URLs,
//! JWKS, registration. Cycle 018 calls none of them, and a manifest that
//! quietly turned a reference into a fetch would be the first step toward doing
//! so.
//!
//! The manifest exists to keep four distinctions from eroding.
//!
//! **Attribution is not conformance.** Mapping a property onto the MCP
//! authorization specification says where the idea came from. It does not say
//! DARE implements that document, and [`assert_no_conformance_claim`] refuses
//! wording that would imply otherwise. The check is anchored on the *claim*
//! rather than the vocabulary, because denying conformance is exactly what this
//! manifest is for: "not certified against any of these documents" has to stay
//! writable while the affirmative form does not.
//!
//! **A DARE property is never part of an upstream specification.** However
//! closely a property was informed by a normative document, the property itself
//! is DARE's. A source may be `NORMATIVE`; a property mapping may not.
//!
//! **A draft is not a requirement, and an open proposal is not a draft.** COAZ
//! and COAZ-MCP are published drafts. `openid/authzen#603` is an open upstream
//! discussion with no normative force at all. Promoting either into a Cycle 018
//! PASS requirement would manufacture a standard that does not exist.
//!
//! **Forward-looking is not mandatory.** DPoP, workload identity federation,
//! ID-JAG, token exchange and Enterprise-Managed Authorization are real
//! hardening surfaces and are deliberately not PASS requirements here. A
//! deployment without DPoP violates no Cycle 018 invariant, and the manifest is
//! where that stays written down.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

const MANIFEST_PATH: &str = "standards/mcp-auth-security/2026/provenance.json";

pub const MCP_AUTH_SECURITY_PROVENANCE_JSON: &str =
    include_str!("../../../standards/mcp-auth-security/2026/provenance.json");

pub const MCP_AUTH_PROTOCOL_BINDING_PROPERTY: &str = "MCP.AUTH.PROTOCOL_BINDING";
pub const MCP_AUTH_PROTECTED_RESOURCE_METADATA_PROPERTY: &str =
    "MCP.AUTH.PROTECTED_RESOURCE_METADATA";
pub const MCP_AUTH_AUTHORIZATION_SERVER_BINDING_PROPERTY: &str =
    "MCP.AUTH.AUTHORIZATION_SERVER_BINDING";
pub const MCP_AUTH_TOKEN_AUDIENCE_RESOURCE_BINDING_PROPERTY: &str =
    "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING";
pub const MCP_AUTH_PKCE_REDIRECT_STATE_INTEGRITY_PROPERTY: &str =
    "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY";
pub const MCP_AUTH_SCOPE_STEP_UP_INTEGRITY_PROPERTY: &str = "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY";
pub const MCP_AUTH_CLIENT_REGISTRATION_TRUST_PROPERTY: &str = "MCP.AUTH.CLIENT_REGISTRATION_TRUST";
pub const MCP_AUTH_CREDENTIAL_SEPARATION_PROPERTY: &str = "MCP.AUTH.CREDENTIAL_SEPARATION";
pub const MCP_IDENTITY_SELF_REPORTED_METADATA_BOUNDARY_PROPERTY: &str =
    "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY";
pub const MCP_AUTH_FINAL_OPERATION_BINDING_PROPERTY: &str = "MCP.AUTH.FINAL_OPERATION_BINDING";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthSource {
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
///
/// Each field is one of the distinctions the whole engine exists to preserve.
/// They live in the manifest rather than only in prose because an artifact a
/// reader holds on its own has to be able to say what a verdict means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthTrustStatement {
    pub core_relation: String,
    pub presence_rule: String,
    pub audience_rule: String,
    pub operation_rule: String,
    pub credential_rule: String,
    pub scope_rule: String,
    pub self_description_rule: String,
    pub replay_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthSurfaceClass {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthExclusion {
    pub id: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthInheritedLesson {
    pub id: String,
    pub from: String,
    pub lesson: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthSecurityProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub cycle: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub reverification_note: String,
    pub conformance_disclaimer: String,
    pub status_discipline_note: String,
    pub sources: Vec<McpAuthSource>,
    pub auth_trust_statement: AuthTrustStatement,
    pub surface_classes: Vec<McpAuthSurfaceClass>,
    pub property_mappings: Vec<McpAuthPropertyMapping>,
    pub explicitly_out_of_scope: Vec<McpAuthExclusion>,
    pub inherited_lessons: Vec<McpAuthInheritedLesson>,
}

/// Relations a Cycle 018 property may declare against upstream guidance.
///
/// `EQUIVALENT` and `CONFORMS_TO` are deliberately absent: DARE never asserts
/// normative equivalence with, or conformance to, an upstream specification.
/// `COMPOSES_WITH` exists for the final-operation property, which builds on a
/// Cycle 003 implementation rather than specialising an upstream requirement.
const ALLOWED_RELATIONS: [&str; 2] = ["SPECIALIZES", "COMPOSES_WITH"];

/// Statuses a source may carry, kept distinct on purpose.
const ALLOWED_SOURCE_STATUS: [&str; 6] = [
    "NORMATIVE",
    "DRAFT",
    "OPEN_PROPOSAL",
    "FUTURE",
    "INFORMATIVE",
    "INTERNAL",
];

/// Statuses a property mapping may carry.
///
/// `NORMATIVE` is absent by design. A DARE property is never part of an
/// upstream specification, however closely it was informed by one; the *source*
/// carries the normative status, and the mapping carries the attribution.
const ALLOWED_MAPPING_STATUS: [&str; 3] = ["INFORMATIVE", "DRAFT", "OPEN_PROPOSAL"];

/// Sources whose status is fixed by what upstream actually published.
///
/// These are pinned because getting one of them wrong would change what the
/// cycle claims. Promoting COAZ to NORMATIVE would invent a requirement;
/// promoting `authzen#603` would invent a specification; demoting MCP would
/// dissolve the baseline; and marking the roadmap items anything but `FUTURE`
/// would make the absence of DPoP look like a finding.
const PINNED_SOURCE_STATUS: [(&str, &str); 8] = [
    ("MCP_2026_07_28", "NORMATIVE"),
    ("MCP_AUTHORIZATION_2026_07_28", "NORMATIVE"),
    ("OAUTH_2_1_METADATA_DEPENDENCIES", "NORMATIVE"),
    ("OPENID_AUTHZEN_1_0", "NORMATIVE"),
    ("COAZ_FRAMEWORK", "DRAFT"),
    ("COAZ_MCP", "DRAFT"),
    ("AUTHZEN_603", "OPEN_PROPOSAL"),
    ("MCP_ROADMAP_FORWARD_LOOKING", "FUTURE"),
];

/// The ten reporting surfaces coverage must be separable by.
const REQUIRED_SURFACE_CLASSES: [&str; 10] = [
    "PROTOCOL_BINDING",
    "RESOURCE_METADATA",
    "AUTHORIZATION_SERVER",
    "TOKEN_BINDING",
    "FLOW_INTEGRITY",
    "SCOPE_INTEGRITY",
    "REGISTRATION_TRUST",
    "CREDENTIAL_SEPARATION",
    "IDENTITY_METADATA",
    "FINAL_OPERATION",
];

/// The ten properties the Cycle 018 profile is built from.
pub const REQUIRED_MAPPED_PROPERTIES: [&str; 10] = [
    MCP_AUTH_PROTOCOL_BINDING_PROPERTY,
    MCP_AUTH_PROTECTED_RESOURCE_METADATA_PROPERTY,
    MCP_AUTH_AUTHORIZATION_SERVER_BINDING_PROPERTY,
    MCP_AUTH_TOKEN_AUDIENCE_RESOURCE_BINDING_PROPERTY,
    MCP_AUTH_PKCE_REDIRECT_STATE_INTEGRITY_PROPERTY,
    MCP_AUTH_SCOPE_STEP_UP_INTEGRITY_PROPERTY,
    MCP_AUTH_CLIENT_REGISTRATION_TRUST_PROPERTY,
    MCP_AUTH_CREDENTIAL_SEPARATION_PROPERTY,
    MCP_IDENTITY_SELF_REPORTED_METADATA_BOUNDARY_PROPERTY,
    MCP_AUTH_FINAL_OPERATION_BINDING_PROPERTY,
];

/// Exclusions that must stay recorded so a later reader knows what this cycle
/// deliberately did not do.
const REQUIRED_EXCLUSIONS: [&str; 8] = [
    "LIVE_OAUTH",
    "LIVE_METADATA",
    "LIVE_REGISTRATION",
    "SIGNATURE_VERIFICATION",
    "REAL_CREDENTIALS",
    "BROWSER_FLOWS",
    "DPOP_AND_ROADMAP",
    "REMOTE_DYNAMIC_VALIDATION",
];

/// The lessons carried in from earlier cycles.
const REQUIRED_LESSONS: [&str; 4] = [
    "REPLAY_IS_NOT_AUTHORITY",
    "ABSENCE_IS_NOT_A_PASS",
    "SELF_REPORT_IS_NOT_A_CHECK",
    "COUNT_THE_WORD_OR_THE_TARGET",
];

/// Words that would turn a recorded reference into a conformance claim, or a
/// bounded result into a universal one.
const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 12] = [
    "mcp compliant",
    "mcp-compliant",
    "oauth compliant",
    "authzen compliant",
    "certified against",
    "mcp auth secure",
    "authentication is secure",
    "authorization is secure",
    "no token attack possible",
    "cannot be spoofed",
    "fully protected",
    "guaranteed secure",
];

/// Phrases that would promote a draft, an open proposal or a roadmap item into
/// a requirement.
///
/// This is the status-discipline check. The manifest is allowed — required,
/// even — to *deny* these, so the same sentence-level negation rule applies:
/// "DPoP is not a required control" stays writable while the affirmative form
/// does not.
const FORBIDDEN_STATUS_CLAIMS: [&str; 8] = [
    "coaz is normative",
    "coaz requires",
    "authzen#603 requires",
    "603 is normative",
    "dpop is required",
    "dpop is mandatory",
    "workload identity is required",
    "token exchange is required",
];

pub fn load_mcp_auth_security_provenance() -> Result<McpAuthSecurityProvenance, CoverageError> {
    serde_json::from_str(MCP_AUTH_SECURITY_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(
            MANIFEST_PATH,
            format!("mcp-auth-security provenance is not valid: {err}"),
        )
    })
}

/// Load and validate in one step.
pub fn mcp_auth_security_provenance() -> Result<McpAuthSecurityProvenance, CoverageError> {
    let provenance = load_mcp_auth_security_provenance()?;
    validate_mcp_auth_security_provenance(&provenance)?;
    Ok(provenance)
}

pub fn validate_mcp_auth_security_provenance(
    provenance: &McpAuthSecurityProvenance,
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
            return Err(schema(format!("property `{required}` has no mapping")));
        }
    }

    // Exclusions and lessons.
    for required in REQUIRED_EXCLUSIONS {
        if !provenance
            .explicitly_out_of_scope
            .iter()
            .any(|entry| entry.id == required)
        {
            return Err(schema(format!("exclusion `{required}` is missing")));
        }
    }
    for required in REQUIRED_LESSONS {
        if !provenance
            .inherited_lessons
            .iter()
            .any(|lesson| lesson.id == required)
        {
            return Err(schema(format!("inherited lesson `{required}` is missing")));
        }
    }

    // Wording. Every free-text field a reader might quote is checked, because a
    // conformance claim buried in a note is still a conformance claim.
    assert_no_conformance_claim(&provenance.conformance_disclaimer, "conformance disclaimer")?;
    assert_no_conformance_claim(&provenance.status_discipline_note, "status discipline note")?;
    assert_no_conformance_claim(&provenance.reverification_note, "reverification note")?;
    for source in &provenance.sources {
        assert_no_conformance_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_conformance_claim(
            &mapping.notes,
            &format!("property `{}`", mapping.property_id),
        )?;
    }

    // Status discipline, checked the same way and for the same reason.
    assert_no_status_promotion(&provenance.status_discipline_note, "status discipline note")?;
    for source in &provenance.sources {
        assert_no_status_promotion(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_status_promotion(
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
pub fn assert_no_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(text, where_found, &FORBIDDEN_CONFORMANCE_PHRASES, "claim")
}

/// Refuse wording that would promote a draft, open proposal or roadmap item
/// into a Cycle 018 requirement.
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
/// Scoped to the current sentence rather than the whole text, so a denial in one
/// sentence cannot license an affirmative claim three sentences later.
fn sentence_denies(prefix: &str) -> bool {
    let sentence_start = prefix
        .rfind(['.', ';', '!', '?'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let sentence = &prefix[sentence_start..];
    // "nothing " is carried beyond the inherited list: "nothing here is MCP
    // compliant" is a natural denial, and a detector that refused it would push
    // the next author to reword an honest sentence to satisfy a checker.
    ["not ", "no ", "never ", "cannot ", "nor ", "nothing "]
        .iter()
        .any(|marker| sentence.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> McpAuthSecurityProvenance {
        load_mcp_auth_security_provenance().expect("manifest parses")
    }

    #[test]
    fn the_shipped_manifest_loads_and_validates() {
        let provenance = provenance();
        validate_mcp_auth_security_provenance(&provenance).expect("manifest validates");
        assert_eq!(provenance.schema_version, "1");
        assert_eq!(provenance.cycle, "018-mcp-2026-security-auth-hardening");
    }

    #[test]
    fn every_property_the_profile_needs_has_a_mapping() {
        let provenance = provenance();
        for required in REQUIRED_MAPPED_PROPERTIES {
            let mapping = provenance
                .property_mappings
                .iter()
                .find(|mapping| mapping.property_id == required)
                .unwrap_or_else(|| panic!("{required} has no mapping"));
            assert!(!mapping.reference.trim().is_empty());
            assert!(!mapping.notes.trim().is_empty());
        }
        assert_eq!(provenance.property_mappings.len(), 10);
    }

    #[test]
    fn a_property_mapping_can_never_claim_normative_status() {
        // The source may be normative. The DARE property never is, however
        // closely it was informed by one, and a reader must be able to tell the
        // two apart.
        let mut provenance = provenance();
        provenance.property_mappings[0].status = "NORMATIVE".to_owned();
        let err = validate_mcp_auth_security_provenance(&provenance)
            .expect_err("NORMATIVE must be refused on a mapping");
        assert!(err.to_string().contains("never part of an"));
    }

    #[test]
    fn a_property_mapping_can_never_claim_conformance_or_equivalence() {
        for relation in ["CONFORMS_TO", "EQUIVALENT", "IMPLEMENTS"] {
            let mut provenance = provenance();
            provenance.property_mappings[0].relation = relation.to_owned();
            let err = validate_mcp_auth_security_provenance(&provenance)
                .expect_err(&format!("`{relation}` must be refused"));
            assert!(
                err.to_string().contains("never asserts equivalence"),
                "`{relation}` was refused for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn the_draft_and_open_proposal_statuses_are_pinned() {
        // The four that would change what the cycle claims if they moved.
        for (id, expected) in [
            ("COAZ_FRAMEWORK", "DRAFT"),
            ("COAZ_MCP", "DRAFT"),
            ("AUTHZEN_603", "OPEN_PROPOSAL"),
            ("MCP_ROADMAP_FORWARD_LOOKING", "FUTURE"),
        ] {
            let provenance = provenance();
            let source = provenance
                .sources
                .iter()
                .find(|source| source.id == id)
                .expect("source present");
            assert_eq!(source.status, expected, "{id} moved");
        }
    }

    #[test]
    fn promoting_a_draft_to_normative_is_refused() {
        let mut provenance = provenance();
        for source in &mut provenance.sources {
            if source.id == "COAZ_FRAMEWORK" {
                source.status = "NORMATIVE".to_owned();
            }
        }
        let err = validate_mcp_auth_security_provenance(&provenance)
            .expect_err("a promoted draft must be refused");
        assert!(err.to_string().contains("COAZ_FRAMEWORK"));
    }

    #[test]
    fn promoting_the_open_proposal_to_a_requirement_is_refused() {
        let mut provenance = provenance();
        for source in &mut provenance.sources {
            if source.id == "AUTHZEN_603" {
                source.status = "NORMATIVE".to_owned();
            }
        }
        assert!(validate_mcp_auth_security_provenance(&provenance).is_err());
    }

    #[test]
    fn the_roadmap_items_stay_forward_looking() {
        // If this ever became NORMATIVE, the absence of DPoP in a deployment
        // would start reading as a finding, which is exactly the overclaim the
        // approval forbids.
        let mut provenance = provenance();
        for source in &mut provenance.sources {
            if source.id == "MCP_ROADMAP_FORWARD_LOOKING" {
                source.status = "NORMATIVE".to_owned();
            }
        }
        assert!(validate_mcp_auth_security_provenance(&provenance).is_err());
    }

    #[test]
    fn wording_that_would_read_as_conformance_is_refused() {
        for hostile in [
            "DARE is MCP compliant",
            "this engine is certified against the MCP authorization specification",
            "the result proves authentication is secure",
            "no token attack possible",
        ] {
            assert!(
                assert_no_conformance_claim(hostile, "test").is_err(),
                "`{hostile}` was allowed"
            );
        }
    }

    #[test]
    fn denying_conformance_stays_writable() {
        // The manifest's entire purpose. A check that fired on this sentence
        // would be a check the next author deletes.
        for honest in [
            "DARE is not certified against any of these documents.",
            "This is attribution and not conformance; nothing here is MCP compliant.",
            "No result here means authentication is secure.",
        ] {
            assert_no_conformance_claim(honest, "test").expect("honest denial must stay writable");
        }
    }

    #[test]
    fn wording_that_would_promote_a_draft_is_refused() {
        for hostile in [
            "COAZ is normative for this cycle",
            "DPoP is required for a PASS",
            "token exchange is required",
        ] {
            assert!(
                assert_no_status_promotion(hostile, "test").is_err(),
                "`{hostile}` was allowed"
            );
        }
    }

    #[test]
    fn denying_a_promotion_stays_writable() {
        for honest in [
            "DPoP is not required by any Cycle 018 invariant.",
            "COAZ is not normative here; it is a published draft.",
            "No roadmap item, and never token exchange, is required.",
        ] {
            assert_no_status_promotion(honest, "test").expect("honest denial must stay writable");
        }
    }

    #[test]
    fn a_denial_in_one_sentence_does_not_license_a_claim_in_the_next() {
        let text = "DARE is not certified against anything. This engine is MCP compliant.";
        assert!(assert_no_conformance_claim(text, "test").is_err());
    }

    #[test]
    fn every_recorded_exclusion_and_lesson_is_present() {
        let provenance = provenance();
        for required in REQUIRED_EXCLUSIONS {
            assert!(
                provenance
                    .explicitly_out_of_scope
                    .iter()
                    .any(|entry| entry.id == required),
                "exclusion {required} missing"
            );
        }
        for required in REQUIRED_LESSONS {
            assert!(
                provenance
                    .inherited_lessons
                    .iter()
                    .any(|lesson| lesson.id == required),
                "lesson {required} missing"
            );
        }
    }

    #[test]
    fn the_replay_lesson_from_cycle_017_is_recorded_with_its_generalization() {
        // The specific defect and the general rule both have to survive, because
        // the next cycle inherits the rule, not the RAG-shaped instance of it.
        let provenance = provenance();
        let lesson = provenance
            .inherited_lessons
            .iter()
            .find(|lesson| lesson.id == "REPLAY_IS_NOT_AUTHORITY")
            .expect("lesson recorded");
        assert!(lesson.lesson.contains("scenario_id"));
        assert!(lesson.lesson.contains("before evaluation"));
        assert!(lesson.from.contains("940b920"));
    }

    #[test]
    fn the_trust_statement_carries_every_distinction_the_cycle_rests_on() {
        let statement = provenance().auth_trust_statement;
        assert!(statement.core_relation.contains("!="));
        assert!(statement.presence_rule.contains("token_presence"));
        assert!(statement.audience_rule.contains("resource B"));
        assert!(statement.operation_rule.contains("Cycle 003"));
        assert!(statement.credential_rule.contains("inbound_mcp_token"));
        assert!(statement.scope_rule.contains("step-up"));
        assert!(statement.self_description_rule.contains("clientInfo"));
        assert!(statement.replay_rule.contains("scenario_id"));
    }

    #[test]
    fn the_manifest_names_no_reachable_target() {
        // The documents this manifest attributes to describe endpoints an
        // implementation would call. The manifest itself must not carry one, or
        // the "offline snapshot" claim would be doing no work.
        let text = MCP_AUTH_SECURITY_PROVENANCE_JSON;
        for scheme in ["http://", "https://", "ws://", "wss://"] {
            assert!(
                !text.contains(scheme),
                "the provenance manifest names a `{scheme}` target"
            );
        }
    }

    #[test]
    fn a_mapping_to_an_unknown_source_is_refused() {
        let mut provenance = provenance();
        provenance.property_mappings[0].standard = "SOME_DOCUMENT_NOBODY_RECORDED".to_owned();
        let err = validate_mcp_auth_security_provenance(&provenance).expect_err("must refuse");
        assert!(err.to_string().contains("unknown source"));
    }

    #[test]
    fn the_fetch_policy_cannot_be_relaxed() {
        let mut provenance = provenance();
        provenance.fetch_policy = "LIVE".to_owned();
        assert!(validate_mcp_auth_security_provenance(&provenance).is_err());
    }
}
