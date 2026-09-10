//! The Cycle 020 A2A standards record, and the checks that keep it honest.
//!
//! A provenance file is where a cycle records which specifications it read and
//! what status each one has. Left as prose it decays in one specific direction:
//! an `INFORMATIVE` reference becomes a requirement, a vocabulary borrowing
//! becomes a conformance claim, and nobody notices because nothing failed.
//!
//! So the record is data with a validator behind it. Four rules it enforces
//! that are worth stating outright:
//!
//! 1. **A source's status is pinned.** `RFC_7515_JWS` is `INFORMATIVE` and
//!    `OAUTH2_OIDC_CONCEPTS` is `INFORMATIVE`. Editing either to `NORMATIVE`
//!    fails here rather than in a later cycle's reasoning — the difference
//!    matters because a normative JWS source would imply this engine verifies
//!    signatures, and it does not.
//! 2. **No property mapping may be `NORMATIVE`.** A mapping says where a
//!    property borrowed its vocabulary. It never says the specification
//!    requires the property.
//! 3. **No text may claim conformance.** A PASS here is a statement about local
//!    evidence, and "A2A compliant" is a statement about a deployment. The
//!    detector is sentence-scoped, so an honest denial stays writable.
//! 4. **The sixteen trust distinctions must all be stated.** They are the
//!    cycle's entire subject matter, and a record that quietly dropped one
//!    would be a record of a different cycle.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;

const MANIFEST_PATH: &str = "standards/a2a-security/2026/provenance.json";

pub const A2A_PROVENANCE_JSON: &str =
    include_str!("../../../standards/a2a-security/2026/provenance.json");

pub const A2A_MESSAGE_AUTHENTICITY_PROPERTY: &str = "AGENT.A2A.MESSAGE_AUTHENTICITY";
pub const A2A_AUTHORITY_PROPAGATION_PROPERTY: &str = "AGENT.A2A.AUTHORITY_PROPAGATION";
pub const A2A_PEER_IDENTITY_BINDING_PROPERTY: &str = "AGENT.A2A.PEER_IDENTITY_BINDING";
pub const A2A_DISCOVERY_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY";
pub const A2A_SKILL_AUTHORIZATION_PROPERTY: &str = "AGENT.A2A.SKILL_AUTHORIZATION";
pub const A2A_MESSAGE_CONTEXT_BINDING_PROPERTY: &str = "AGENT.A2A.MESSAGE_CONTEXT_BINDING";
pub const A2A_TENANT_BOUNDARY_PROPERTY: &str = "AGENT.A2A.TENANT_BOUNDARY";
pub const A2A_DATA_SCOPE_BOUNDARY_PROPERTY: &str = "AGENT.A2A.DATA_SCOPE_BOUNDARY";
pub const A2A_REPLAY_BOUNDARY_PROPERTY: &str = "AGENT.A2A.REPLAY_BOUNDARY";
pub const A2A_PROTOCOL_NEGOTIATION_INTEGRITY_PROPERTY: &str =
    "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY";
pub const A2A_EXTENSION_TRUST_BOUNDARY_PROPERTY: &str = "AGENT.A2A.EXTENSION_TRUST_BOUNDARY";
pub const A2A_PUSH_NOTIFICATION_BOUNDARY_PROPERTY: &str = "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aSource {
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
pub struct A2aTrustStatement {
    pub id: String,
    pub summary: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aSurfaceClass {
    pub id: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aPropertyMapping {
    pub property_id: String,
    pub standard: String,
    pub reference: String,
    pub relation: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aInheritedLesson {
    pub from: String,
    pub lesson: String,
    pub applied_as: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aProvenance {
    pub schema_version: String,
    pub recorded_at: String,
    pub cycle: String,
    pub fetch_policy: String,
    pub fetch_policy_note: String,
    pub reverification_note: String,
    pub conformance_disclaimer: String,
    pub status_discipline_note: String,
    pub sources: Vec<A2aSource>,
    pub inter_agent_trust_statement: A2aTrustStatement,
    pub surface_classes: Vec<A2aSurfaceClass>,
    pub property_mappings: Vec<A2aPropertyMapping>,
    pub explicitly_out_of_scope: Vec<String>,
    pub inherited_lessons: Vec<A2aInheritedLesson>,
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

/// The statuses the Cycle 020 approval froze.
///
/// `RFC_7515_JWS` being `INFORMATIVE` is the load-bearing one. A normative JWS
/// source would imply this engine verifies signatures; it reads a verification
/// status somebody else recorded, resolves no key and follows no `jku`.
const PINNED_SOURCE_STATUS: [(&str, &str); 8] = [
    ("OWASP_AGENTIC_TOP10_2026_ASI07", "NORMATIVE"),
    ("A2A_PROTOCOL_1_0_0", "NORMATIVE"),
    ("A2A_AGENT_CARD_1_0_0", "NORMATIVE"),
    ("A2A_PUSH_NOTIFICATION_1_0_0", "NORMATIVE"),
    ("RFC_7515_JWS", "INFORMATIVE"),
    ("RFC_8785_JCS", "INFORMATIVE"),
    ("OAUTH2_OIDC_CONCEPTS", "INFORMATIVE"),
    ("HTTPS_TLS_CONCEPTS", "INFORMATIVE"),
];

const REQUIRED_SURFACE_CLASSES: [&str; 14] = [
    "DISCOVERY_BINDING",
    "PEER_IDENTITY",
    "MESSAGE_AUTHENTICITY",
    "SECURITY_REQUIREMENT",
    "SKILL_AUTHORIZATION",
    "MESSAGE_AUTHORITY",
    "TASK_CONTEXT_BINDING",
    "AUTHORITY_PROPAGATION",
    "TENANT_BOUNDARY",
    "DATA_SCOPE",
    "REPLAY_BOUNDARY",
    "PROTOCOL_NEGOTIATION",
    "EXTENSION_TRUST",
    "PUSH_NOTIFICATION",
];

/// Every property this cycle reports under, including the two it inherited.
pub const REQUIRED_MAPPED_PROPERTIES: [&str; 12] = [
    A2A_MESSAGE_AUTHENTICITY_PROPERTY,
    A2A_AUTHORITY_PROPAGATION_PROPERTY,
    A2A_PEER_IDENTITY_BINDING_PROPERTY,
    A2A_DISCOVERY_TRUST_BOUNDARY_PROPERTY,
    A2A_SKILL_AUTHORIZATION_PROPERTY,
    A2A_MESSAGE_CONTEXT_BINDING_PROPERTY,
    A2A_TENANT_BOUNDARY_PROPERTY,
    A2A_DATA_SCOPE_BOUNDARY_PROPERTY,
    A2A_REPLAY_BOUNDARY_PROPERTY,
    A2A_PROTOCOL_NEGOTIATION_INTEGRITY_PROPERTY,
    A2A_EXTENSION_TRUST_BOUNDARY_PROPERTY,
    A2A_PUSH_NOTIFICATION_BOUNDARY_PROPERTY,
];

/// Exclusions the record must state rather than leave to inference.
///
/// Each names a thing a reader might otherwise assume this cycle does. The
/// first four are the ones an A2A engine is most likely to be assumed to do,
/// because every one of them is a single HTTP call away in any other tool.
const REQUIRED_EXCLUSION_MARKERS: [&str; 9] = [
    "Connecting to a live A2A agent",
    "Downloading an Agent Card",
    "Fetching JWK",
    "Obtaining, exchanging, introspecting",
    "TLS handshake",
    "Sending an A2A message",
    "push-notification or webhook destination",
    "Multi-turn adaptive adversarial",
    "attack-path construction",
];

const REQUIRED_LESSON_SOURCES: [&str; 3] = ["cycle-017", "cycle-018", "cycle-019"];

/// The sixteen distinctions from `BASELINE.md`, each a place where two things
/// that look alike are not the same thing.
const REQUIRED_TRUST_RULE_MARKERS: [&str; 16] = [
    "external agent appearing in an inventory is not a trusted peer",
    "discovered Agent Card is not an authenticated identity",
    "signed Agent Card is not an authorized provider",
    "TLS server identity is not agent-level authorization",
    "declared security scheme is not a successful authentication",
    "successful authentication is not skill authorization",
    "schema-valid message is not an authentic message",
    "authentic message is not an authorized instruction",
    "Peer content is not a privileged instruction",
    "matching taskId is not a matching principal or context",
    "Delegation is not privilege amplification",
    "message retry is not a safe replay",
    "Protocol compatibility is not permission to downgrade",
    "extension declaration is not extension authority",
    "webhook URL is not permission to connect",
    "tenant routing value is not proof of tenant authorization",
];

const FORBIDDEN_CONFORMANCE_PHRASES: [&str; 12] = [
    "a2a compliant",
    "a2a-compliant",
    "protocol compliant",
    "oauth compliant",
    "jws compliant",
    "fully compliant",
    "certified",
    "conformance verified",
    "inter-agent secure",
    "peer is secure",
    "agent is secure",
    "communication is secure",
];

const FORBIDDEN_STATUS_CLAIMS: [&str; 8] = [
    "jws verification is required",
    "signature verification is performed",
    "keys are resolved",
    "tokens are obtained",
    "tls is validated",
    "required by rfc 7515",
    "oauth is required",
    "mandatory authentication standard",
];

pub fn load_a2a_provenance() -> Result<A2aProvenance, CoverageError> {
    serde_json::from_str(A2A_PROVENANCE_JSON).map_err(|err| {
        CoverageError::schema(MANIFEST_PATH, format!("A2A provenance is not valid: {err}"))
    })
}

/// Load and validate in one step.
pub fn a2a_provenance() -> Result<A2aProvenance, CoverageError> {
    let provenance = load_a2a_provenance()?;
    validate_a2a_provenance(&provenance)?;
    Ok(provenance)
}

pub fn validate_a2a_provenance(provenance: &A2aProvenance) -> Result<(), CoverageError> {
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
            .inter_agent_trust_statement
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
            provenance.inter_agent_trust_statement.summary.as_str(),
        ),
    ] {
        assert_no_a2a_conformance_claim(text, label)?;
        assert_no_a2a_status_promotion(text, label)?;
    }
    for source in &provenance.sources {
        assert_no_a2a_conformance_claim(&source.mapping_notes, &format!("source `{}`", source.id))?;
        assert_no_a2a_status_promotion(&source.mapping_notes, &format!("source `{}`", source.id))?;
    }
    for mapping in &provenance.property_mappings {
        assert_no_a2a_conformance_claim(
            &mapping.notes,
            &format!("mapping `{}`", mapping.property_id),
        )?;
        assert_no_a2a_status_promotion(
            &mapping.notes,
            &format!("mapping `{}`", mapping.property_id),
        )?;
    }

    Ok(())
}

/// Refuse wording that would turn a bounded run into a conformance assertion.
pub fn assert_no_a2a_conformance_claim(text: &str, where_found: &str) -> Result<(), CoverageError> {
    assert_claim_absent(text, where_found, &FORBIDDEN_CONFORMANCE_PHRASES, "claim")
}

/// Refuse wording that would promote an informative source into a Cycle 020
/// requirement, or describe an operation this cycle does not perform.
pub fn assert_no_a2a_status_promotion(text: &str, where_found: &str) -> Result<(), CoverageError> {
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

    fn provenance() -> A2aProvenance {
        a2a_provenance().expect("the committed record loads and validates")
    }

    #[test]
    fn the_committed_record_loads_and_validates() {
        let record = provenance();
        assert_eq!(record.cycle, "020-a2a-inter-agent-security");
        assert_eq!(record.fetch_policy, "NO_NETWORK_ACCESS");
        assert_eq!(record.sources.len(), PINNED_SOURCE_STATUS.len());
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
            assert_eq!(source.status, expected, "{id}");
        }
    }

    #[test]
    fn promoting_jws_to_normative_is_refused() {
        // The load-bearing pin. A normative JWS source would imply this engine
        // verifies signatures — it reads a status another verifier recorded,
        // resolves no key and follows no `jku`.
        let mut record = provenance();
        let jws = record
            .sources
            .iter_mut()
            .find(|source| source.id == "RFC_7515_JWS")
            .expect("the JWS source");
        jws.status = "NORMATIVE".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn promoting_oauth_concepts_to_normative_is_refused() {
        let mut record = provenance();
        let oauth = record
            .sources
            .iter_mut()
            .find(|source| source.id == "OAUTH2_OIDC_CONCEPTS")
            .expect("the OAuth source");
        oauth.status = "NORMATIVE".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn no_property_mapping_may_be_normative() {
        // A mapping records where vocabulary came from. Letting one be
        // normative would make the specification appear to require the
        // property, which is the inference this whole record exists to block.
        let record = provenance();
        for mapping in &record.property_mappings {
            assert_ne!(mapping.status, "NORMATIVE", "{}", mapping.property_id);
        }

        let mut hostile = provenance();
        hostile.property_mappings[0].status = "NORMATIVE".to_owned();
        assert!(validate_a2a_provenance(&hostile).is_err());
    }

    #[test]
    fn a_mapping_may_not_claim_a_relation_this_cycle_does_not_have() {
        let mut record = provenance();
        record.property_mappings[0].relation = "IMPLEMENTS".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn a_mapping_to_an_unknown_source_is_refused() {
        let mut record = provenance();
        record.property_mappings[0].standard = "SOME_OTHER_SPEC".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn all_twelve_properties_are_mapped_including_the_two_inherited_ones() {
        let record = provenance();
        let mapped: HashSet<&str> = record
            .property_mappings
            .iter()
            .map(|mapping| mapping.property_id.as_str())
            .collect();
        for required in REQUIRED_MAPPED_PROPERTIES {
            assert!(mapped.contains(required), "{required} is unmapped");
        }
        assert!(mapped.contains(A2A_MESSAGE_AUTHENTICITY_PROPERTY));
        assert!(mapped.contains(A2A_AUTHORITY_PROPAGATION_PROPERTY));
    }

    #[test]
    fn dropping_a_mapping_is_refused() {
        let mut record = provenance();
        record.property_mappings.pop();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn the_sixteen_trust_distinctions_are_all_stated() {
        let record = provenance();
        assert_eq!(record.inter_agent_trust_statement.rules.len(), 16);
        for marker in REQUIRED_TRUST_RULE_MARKERS {
            assert!(
                record
                    .inter_agent_trust_statement
                    .rules
                    .iter()
                    .any(|rule| rule.contains(marker)),
                "the record no longer states `{marker}`"
            );
        }
    }

    #[test]
    fn removing_a_trust_distinction_is_refused() {
        // They are the cycle's entire subject matter. A record that quietly
        // dropped one would be a record of a different cycle.
        let mut record = provenance();
        record.inter_agent_trust_statement.rules.remove(0);
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn the_fetch_policy_cannot_be_edited_to_something_permissive() {
        let mut record = provenance();
        record.fetch_policy = "ALLOW_WELL_KNOWN".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn every_required_exclusion_is_stated_rather_than_inferred() {
        // Each names something a reader might assume an A2A engine does,
        // because in any other tool it is one HTTP call away.
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
        let mut record = provenance();
        record.conformance_disclaimer = "This engine is A2A compliant.".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());

        let mut record = provenance();
        record.sources[0].mapping_notes = "The peer is secure once this passes.".to_owned();
        assert!(validate_a2a_provenance(&record).is_err());
    }

    #[test]
    fn an_honest_denial_stays_writable() {
        // Banning the words outright would push the next author to reword a
        // true statement in order to satisfy a checker.
        assert_no_a2a_conformance_claim(
            "Nothing here is A2A compliant, and no run asserts that a peer is secure.",
            "a denial",
        )
        .expect("a denial is writable");
    }

    #[test]
    fn a_denial_in_one_sentence_does_not_license_a_claim_in_the_next() {
        assert!(assert_no_a2a_conformance_claim(
            "This is not a conformance tool. The result proves the agent is secure.",
            "a smuggled claim",
        )
        .is_err());
    }

    #[test]
    fn describing_an_operation_this_cycle_does_not_perform_is_refused() {
        // The status-promotion detector, aimed at the specific overclaims an
        // A2A engine invites: that it verified a signature, resolved a key,
        // obtained a token or validated TLS.
        for overclaim in [
            "Signature verification is performed for every card.",
            "Keys are resolved from the jku when present.",
            "Tokens are obtained through the declared flow.",
            "TLS is validated against the endpoint.",
        ] {
            assert!(
                assert_no_a2a_status_promotion(overclaim, "an overclaim").is_err(),
                "`{overclaim}` was allowed"
            );
        }
    }

    #[test]
    fn the_record_says_plainly_that_nothing_is_fetched() {
        let record = provenance();
        let note = record.fetch_policy_note.to_lowercase();
        assert!(note.contains("inert metadata"));
        assert!(note.contains("naming a place is not authorization"));
    }

    #[test]
    fn the_record_says_plainly_that_nothing_was_reverified() {
        let record = provenance();
        assert!(record
            .reverification_note
            .to_lowercase()
            .contains("no upstream re-verification"));
    }

    #[test]
    fn the_lessons_from_cycles_017_018_and_019_are_carried_forward() {
        let record = provenance();
        for source in REQUIRED_LESSON_SOURCES {
            assert!(
                record
                    .inherited_lessons
                    .iter()
                    .any(|lesson| lesson.from == source),
                "no lesson from {source}"
            );
        }
    }

    #[test]
    fn the_record_carries_no_credential_or_reachable_target() {
        // The record names specifications, not places. A URL here would be the
        // first place somebody added one.
        let raw = A2A_PROVENANCE_JSON.to_lowercase();
        for forbidden in ["https://", "http://", "-----begin"] {
            assert!(
                !raw.contains(forbidden),
                "the standards record carries `{forbidden}`"
            );
        }

        // Anchored on shape rather than on the word. The record's own
        // out-of-scope list says "bearer token" in order to deny using one, and
        // a checker that banned the word would force the next author to reword
        // an honest denial. What must be absent is a bearer *value*.
        for (index, _) in raw.match_indices("bearer ") {
            let tail: String = raw[index + "bearer ".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || "._~+/-".contains(*c))
                .collect();
            assert!(
                tail.len() < 16,
                "the standards record carries something shaped like a bearer credential"
            );
        }
    }

    #[test]
    fn an_unknown_field_in_the_record_is_refused() {
        let mut value: serde_json::Value =
            serde_json::from_str(A2A_PROVENANCE_JSON).expect("parses");
        value
            .as_object_mut()
            .expect("an object")
            .insert("fetch_allowed".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<A2aProvenance>(value).is_err());
    }

    #[test]
    fn the_fourteen_surface_classes_match_the_fourteen_invariants() {
        let record = provenance();
        assert_eq!(record.surface_classes.len(), REQUIRED_SURFACE_CLASSES.len());
        for required in REQUIRED_SURFACE_CLASSES {
            assert!(
                record
                    .surface_classes
                    .iter()
                    .any(|class| class.id == required),
                "{required} is missing"
            );
        }
    }
}
