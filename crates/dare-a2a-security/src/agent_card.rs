//! The Agent Card, as bounded local evidence.
//!
//! ```text
//! discovered Agent Card != authenticated identity
//! signed Agent Card     != authorized provider
//! ```
//!
//! A card is a description a peer publishes about itself. Discovering it
//! answers where a description came from; it does not answer whether the
//! description is true, and a signature over it does not answer whether the
//! provider was ever approved.
//!
//! # Descriptive text never grants authority
//!
//! `name` and `description` are retained because an operator reading a report
//! needs to know which peer is being discussed. They are marked untrusted and
//! no evaluator reads them for a decision — a card that described itself as
//! "the trusted internal orchestrator" would be describing itself.
//!
//! # Locations are stored and never resolved
//!
//! Interface URLs, a token endpoint, an issuer, a `jku`: all retained as inert
//! metadata, because a report that could not say which endpoint a peer
//! advertised would be less useful and no safer. Nothing here resolves one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::{assert_safe_identifier, digest};
use crate::error::{A2aSecurityError, Result};
use crate::limits;
use crate::source::{EvidenceSource, SecuritySchemeKind, TransportKind, VerificationStatus};

/// One interface a card advertises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardInterface {
    /// The advertised location. Inert metadata: retained so a report can name
    /// it, resolved by nothing.
    pub url: String,
    pub transport: TransportKind,
    pub protocol_version: String,
}

impl CardInterface {
    pub fn validate(&self) -> Result<()> {
        if self.url.trim().is_empty() {
            return Err(A2aSecurityError::invalid("an interface has no url"));
        }
        if self.url.len() > 2048 {
            return Err(A2aSecurityError::refusal(
                "an interface url is longer than 2048 bytes".to_owned(),
            ));
        }
        if self.url.chars().any(char::is_control) {
            return Err(A2aSecurityError::refusal(
                "an interface url carries a control character".to_owned(),
            ));
        }
        assert_safe_identifier(&self.protocol_version, "a protocol version")?;
        Ok(())
    }
}

/// A security scheme the card declares it accepts.
///
/// Declaring a scheme says what the peer will accept. It is not evidence that
/// authentication under it succeeded, and this type has no field that could
/// say otherwise.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredSecurityScheme {
    pub scheme_id: String,
    pub kind: SecuritySchemeKind,
    /// Issuer, token endpoint or similar. Inert metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub scopes: BTreeSet<String>,
}

impl DeclaredSecurityScheme {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.scheme_id, "a security scheme id")?;
        for scope in &self.scopes {
            assert_safe_identifier(scope, "a declared scope")?;
        }
        Ok(())
    }
}

/// A skill the card advertises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSkill {
    pub skill_id: String,
    /// Untrusted descriptive text. No evaluator reads it for a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Security scheme ids this skill requires, as the card declares them.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub security_requirements: BTreeSet<String>,
}

impl CardSkill {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.skill_id, "a skill id")?;
        for requirement in &self.security_requirements {
            assert_safe_identifier(requirement, "a security requirement")?;
        }
        Ok(())
    }
}

/// An extension the card declares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardExtension {
    pub extension_id: String,
    /// Whether the card marks the extension as required.
    ///
    /// A required extension nobody locally approved is the case that must fail
    /// closed: proceeding would mean speaking a protocol whose meaning this
    /// side does not know.
    #[serde(default)]
    pub required: bool,
    /// Whether the extension claims to affect authorization or identity.
    ///
    /// Declared by the extension, so it is a claim. It decides how carefully
    /// the extension must be approved, never whether it is approved.
    #[serde(default)]
    pub claims_authority: bool,
}

impl CardExtension {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.extension_id, "an extension id")?;
        Ok(())
    }
}

/// Signature evidence over a card.
///
/// A *recorded* verification, never one this engine performed. `signer_key_id`
/// and `key_location` are inert: no key is resolved and no `jku` is followed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSignatureEvidence {
    pub status: VerificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    /// A `jku` or key-set location. Retained so a report can name it; resolved
    /// by nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_location: Option<String>,
    /// Who recorded the verification. Never this engine.
    pub recorded_by: EvidenceSource,
}

impl CardSignatureEvidence {
    pub fn validate(&self) -> Result<()> {
        if let Some(key_id) = &self.signer_key_id {
            assert_safe_identifier(key_id, "a signer key id")?;
        }
        if self.recorded_by == EvidenceSource::LocalPolicy {
            // A policy may approve a *signer*. It cannot be the thing that
            // performed a verification, and letting it claim so would turn an
            // approval into evidence of a cryptographic fact.
            return Err(A2aSecurityError::refusal(
                "a local policy cannot be the source of a signature verification; policy \
                 approves signers and a verifier verifies signatures"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether this evidence may satisfy a positive PASS condition.
    pub fn may_satisfy_positive_evidence(&self) -> bool {
        self.status.may_satisfy_positive_evidence()
    }
}

/// The bounded Agent Card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCard {
    pub card_id: String,
    /// Untrusted descriptive text, retained so a report can name the peer.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The provider the card claims. A claim by the thing being judged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<CardInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_schemes: Vec<DeclaredSecurityScheme>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<CardSkill>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CardExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<CardSignatureEvidence>,
    /// Whether the card declares push-notification support.
    #[serde(default)]
    pub declares_push_notifications: bool,
    /// Bounded free-form metadata. Never authority-bearing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    pub evidence_source: EvidenceSource,
}

impl AgentCard {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.card_id, "a card id")?;
        assert_safe_identifier(&self.name, "a card name")?;
        if let Some(provider) = &self.provider {
            assert_safe_identifier(provider, "a card provider")?;
        }

        if self.interfaces.len() as u32 > limits::HARD_MAX_INTERFACES_PER_CARD {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "card `{}` declares more interfaces than the hard maximum",
                self.card_id
            )));
        }
        if self.security_schemes.len() as u32 > limits::HARD_MAX_SECURITY_SCHEMES_PER_CARD {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "card `{}` declares more security schemes than the hard maximum",
                self.card_id
            )));
        }
        if self.skills.len() as u32 > limits::HARD_MAX_SKILLS_PER_CARD {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "card `{}` declares more skills than the hard maximum",
                self.card_id
            )));
        }
        if self.extensions.len() as u32 > limits::HARD_MAX_EXTENSIONS {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "card `{}` declares more extensions than the hard maximum",
                self.card_id
            )));
        }

        for interface in &self.interfaces {
            interface.validate()?;
        }
        for scheme in &self.security_schemes {
            scheme.validate()?;
        }
        for skill in &self.skills {
            skill.validate()?;
        }
        for extension in &self.extensions {
            extension.validate()?;
        }
        if let Some(signature) = &self.signature {
            signature.validate()?;
        }

        let metadata_bytes: usize = self
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        if metadata_bytes > limits::HARD_MAX_METADATA_BYTES {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "card `{}` carries more metadata than the hard maximum",
                self.card_id
            )));
        }

        // A skill may only require a scheme the card actually declares.
        // Requiring one it does not declare is a requirement nobody can satisfy
        // and nobody can check, which reads as security and is not.
        let declared: BTreeSet<&str> = self
            .security_schemes
            .iter()
            .map(|scheme| scheme.scheme_id.as_str())
            .collect();
        for skill in &self.skills {
            for requirement in &skill.security_requirements {
                if !declared.contains(requirement.as_str()) {
                    return Err(A2aSecurityError::invalid(format!(
                        "skill `{}` requires scheme `{requirement}`, which the card does not \
                         declare; a requirement nobody can satisfy reads as security and is not",
                        skill.skill_id
                    )));
                }
            }
        }

        Ok(())
    }

    /// A digest over the card's security-relevant content.
    ///
    /// The comparison surface for discovery binding: a policy pins this, and a
    /// substituted card produces a different one.
    pub fn card_digest(&self) -> Result<String> {
        digest(self)
    }

    pub fn skill(&self, skill_id: &str) -> Option<&CardSkill> {
        self.skills.iter().find(|skill| skill.skill_id == skill_id)
    }

    pub fn scheme(&self, scheme_id: &str) -> Option<&DeclaredSecurityScheme> {
        self.security_schemes
            .iter()
            .find(|scheme| scheme.scheme_id == scheme_id)
    }

    /// Protocol versions this card says it supports.
    pub fn protocol_versions(&self) -> BTreeSet<&str> {
        self.interfaces
            .iter()
            .map(|interface| interface.protocol_version.as_str())
            .collect()
    }

    /// Whether the card carries positively valid signature evidence.
    ///
    /// `false` covers three different situations — no signature, an invalid
    /// one, and one nobody could conclude about — which is why the evaluator
    /// reads the status rather than this helper when the difference matters.
    pub fn has_valid_signature_evidence(&self) -> bool {
        self.signature
            .as_ref()
            .is_some_and(CardSignatureEvidence::may_satisfy_positive_evidence)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn card(id: &str) -> AgentCard {
        AgentCard {
            card_id: id.to_owned(),
            name: "planner-agent".to_owned(),
            description: Some("plans things".to_owned()),
            provider: Some("acme".to_owned()),
            interfaces: vec![CardInterface {
                url: "https://peer.example/a2a".to_owned(),
                transport: TransportKind::JsonRpc,
                protocol_version: "1.0.0".to_owned(),
            }],
            security_schemes: vec![DeclaredSecurityScheme {
                scheme_id: "oauth-main".to_owned(),
                kind: SecuritySchemeKind::OAuth2AuthorizationCode,
                issuer: Some("https://issuer.example".to_owned()),
                token_endpoint: Some("https://issuer.example/token".to_owned()),
                scopes: BTreeSet::from(["a2a.invoke".to_owned()]),
            }],
            skills: vec![CardSkill {
                skill_id: "summarize".to_owned(),
                name: Some("Summarize".to_owned()),
                security_requirements: BTreeSet::from(["oauth-main".to_owned()]),
            }],
            extensions: Vec::new(),
            signature: Some(CardSignatureEvidence {
                status: VerificationStatus::Valid,
                signer_key_id: Some("key-1".to_owned()),
                key_location: Some("https://peer.example/jwks".to_owned()),
                recorded_by: EvidenceSource::RecordedVerification,
            }),
            declares_push_notifications: false,
            metadata: BTreeMap::new(),
            evidence_source: EvidenceSource::AgentCard,
        }
    }

    #[test]
    fn the_fixture_card_validates() {
        card("card-1").validate().expect("valid");
    }

    #[test]
    fn a_card_retains_its_advertised_locations_and_resolves_none() {
        // Refusing location fields would refuse every real card. What matters
        // is that nothing here goes to one.
        let card = card("card-1");
        assert_eq!(card.interfaces[0].url, "https://peer.example/a2a");
        assert_eq!(
            card.security_schemes[0].token_endpoint.as_deref(),
            Some("https://issuer.example/token")
        );
        assert_eq!(
            card.signature.as_ref().unwrap().key_location.as_deref(),
            Some("https://peer.example/jwks")
        );
    }

    #[test]
    fn a_local_policy_cannot_be_the_source_of_a_signature_verification() {
        // A policy approves signers. A verifier verifies signatures. Letting a
        // policy claim it verified something would turn an approval into
        // evidence of a cryptographic fact.
        let mut hostile = card("card-1");
        hostile.signature.as_mut().unwrap().recorded_by = EvidenceSource::LocalPolicy;
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn a_signature_that_did_not_conclude_does_not_satisfy_positive_evidence() {
        for status in [
            VerificationStatus::Indeterminate,
            VerificationStatus::Unrecorded,
            VerificationStatus::Invalid,
        ] {
            let mut card = card("card-1");
            card.signature.as_mut().unwrap().status = status;
            assert!(
                !card.has_valid_signature_evidence(),
                "{} satisfied positive evidence",
                status.as_str()
            );
        }
    }

    #[test]
    fn a_skill_cannot_require_a_scheme_the_card_does_not_declare() {
        // A requirement nobody can satisfy and nobody can check reads as
        // security and is not.
        let mut hostile = card("card-1");
        hostile.skills[0]
            .security_requirements
            .insert("scheme-that-does-not-exist".to_owned());
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn the_card_digest_changes_when_security_relevant_content_changes() {
        // The comparison surface for discovery binding. A substituted card must
        // produce a different digest, or pinning one would pin nothing.
        let original = card("card-1");
        let baseline = original.card_digest().expect("digests");

        let mut substituted = original.clone();
        substituted.provider = Some("attacker".to_owned());
        assert_ne!(baseline, substituted.card_digest().expect("digests"));

        let mut extra_skill = original.clone();
        extra_skill.skills.push(CardSkill {
            skill_id: "transfer-funds".to_owned(),
            name: None,
            security_requirements: BTreeSet::new(),
        });
        assert_ne!(baseline, extra_skill.card_digest().expect("digests"));

        let mut moved_interface = original.clone();
        moved_interface.interfaces[0].url = "https://attacker.example/a2a".to_owned();
        assert_ne!(baseline, moved_interface.card_digest().expect("digests"));
    }

    #[test]
    fn the_card_digest_is_stable_across_runs() {
        let card = card("card-1");
        assert_eq!(
            card.card_digest().expect("digests"),
            card.card_digest().expect("digests")
        );
    }

    #[test]
    fn a_card_cannot_declare_itself_authorized() {
        // Structural. A card that could state an outcome would make the policy
        // decorative.
        for hostile in [
            serde_json::json!({ "card_id": "c", "name": "n", "evidence_source": "AGENT_CARD",
                                "trusted": true }),
            serde_json::json!({ "card_id": "c", "name": "n", "evidence_source": "AGENT_CARD",
                                "authorized": true }),
            serde_json::json!({ "card_id": "c", "name": "n", "evidence_source": "AGENT_CARD",
                                "expected_verdict": "PASS" }),
        ] {
            assert!(serde_json::from_value::<AgentCard>(hostile).is_err());
        }
    }

    #[test]
    fn a_card_declaring_too_many_skills_is_refused() {
        let mut oversized = card("card-1");
        oversized.skills = (0..=limits::HARD_MAX_SKILLS_PER_CARD)
            .map(|index| CardSkill {
                skill_id: format!("skill-{index}"),
                name: None,
                security_requirements: BTreeSet::new(),
            })
            .collect();
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn a_hostile_identifier_anywhere_in_the_card_is_refused() {
        let mut hostile = card("card-1");
        hostile.skills[0].skill_id = "summarize\u{202E}evil".to_owned();
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn protocol_versions_come_from_interfaces_rather_than_from_a_claim() {
        // The card cannot state a supported version outside an interface, so a
        // version it "supports" is always attached to somewhere it can be
        // reached.
        let card = card("card-1");
        assert_eq!(card.protocol_versions(), BTreeSet::from(["1.0.0"]));
    }
}
