//! Authentication evidence, recorded rather than performed.
//!
//! ```text
//! declared security scheme  != successful authentication
//! successful authentication != skill authorization
//! ```
//!
//! Nothing here verifies anything. No token is obtained, exchanged or
//! introspected; no signature is checked; no key is resolved; no TLS handshake
//! occurs. What this module reads is a status **another verifier recorded**,
//! and [`crate::source::VerificationStatus`] keeps "a status exists" and "the
//! status was favourable" in different answers — because Cycle 018 paid for
//! conflating them, with a token its own verifier had rejected being accepted.

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{A2aSecurityError, Result};
use crate::source::{EvidenceSource, SecuritySchemeKind, VerificationStatus};

/// What a verifier recorded about one peer's authentication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthenticationEvidence {
    pub peer_id: String,
    /// The scheme the exchange actually used.
    pub scheme_kind: SecuritySchemeKind,
    /// The declared scheme id it was meant to satisfy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme_id: Option<String>,
    pub status: VerificationStatus,
    /// The principal the authentication established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// The subject the authentication asserts is being acted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    /// The audience the credential was issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The issuer named by the credential. Inert metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Who performed the verification. Never this engine.
    pub recorded_by: EvidenceSource,
}

impl PeerAuthenticationEvidence {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.peer_id, "an authentication peer id")?;
        for (label, value) in [
            ("a scheme id", &self.scheme_id),
            ("an authenticated principal", &self.principal),
            ("a delegated subject", &self.delegated_subject),
            ("an audience", &self.audience),
        ] {
            if let Some(value) = value {
                assert_safe_identifier(value, label)?;
            }
        }
        if self.recorded_by == EvidenceSource::AgentCard {
            // A card is the peer describing itself. Letting it record that its
            // own authentication succeeded would be asking the peer whether the
            // peer authenticated.
            return Err(A2aSecurityError::refusal(
                "an Agent Card cannot be the source of an authentication verification; the card \
                 is the peer describing itself"
                    .to_owned(),
            ));
        }
        if self.delegated_subject.is_some() && !self.scheme_kind.may_carry_delegated_subject() {
            // The specific confusion this check exists for: client credentials
            // authenticate a service to a service. There is no user in the
            // flow, so a subject claimed under it was never established by it.
            return Err(A2aSecurityError::BindingMismatch(format!(
                "authentication for `{}` claims a delegated subject under {}, a scheme that \
                 authenticates a service to a service and carries no user",
                self.peer_id,
                self.scheme_kind.as_str()
            )));
        }
        Ok(())
    }

    /// Whether this evidence may satisfy a positive PASS condition.
    pub fn may_satisfy_positive_evidence(&self) -> bool {
        self.status.may_satisfy_positive_evidence()
    }

    /// Whether this evidence is a concrete failure.
    pub fn is_concrete_failure(&self) -> bool {
        self.status.is_concrete_failure()
    }
}

/// What a verifier recorded about one message's authenticity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAuthenticationEvidence {
    pub message_id: String,
    pub status: VerificationStatus,
    /// The signer the verification named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    /// The digest of the envelope the signature actually covered.
    ///
    /// The binding that matters most. A signature over *a* message is not a
    /// signature over *this* message, and without this field the two would be
    /// indistinguishable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_envelope_digest: Option<String>,
    pub recorded_by: EvidenceSource,
}

impl MessageAuthenticationEvidence {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.message_id, "a message id")?;
        if let Some(signer) = &self.signer_key_id {
            assert_safe_identifier(signer, "a signer key id")?;
        }
        if let Some(digest) = &self.covered_envelope_digest {
            crate::canonical::assert_digest_shape(digest, "a covered envelope digest")?;
        }
        if self.recorded_by == EvidenceSource::AgentCard {
            return Err(A2aSecurityError::refusal(
                "an Agent Card cannot be the source of a message verification".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn may_satisfy_positive_evidence(&self) -> bool {
        self.status.may_satisfy_positive_evidence()
    }

    /// Whether the signature covered the envelope that was actually observed.
    ///
    /// Three answers. `None` means one side recorded no digest, so there is
    /// nothing to compare — distinct from "compared and differed", which is a
    /// signature over a different message.
    pub fn covers(&self, observed_envelope_digest: &str) -> Option<bool> {
        self.covered_envelope_digest
            .as_deref()
            .map(|covered| covered == observed_envelope_digest)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn peer_auth(peer_id: &str) -> PeerAuthenticationEvidence {
        PeerAuthenticationEvidence {
            peer_id: peer_id.to_owned(),
            scheme_kind: SecuritySchemeKind::OAuth2AuthorizationCode,
            scheme_id: Some("oauth-main".to_owned()),
            status: VerificationStatus::Valid,
            principal: Some("svc-planner".to_owned()),
            delegated_subject: Some("user-alice".to_owned()),
            audience: Some("local-orchestrator".to_owned()),
            issuer: Some("https://issuer.example".to_owned()),
            recorded_by: EvidenceSource::RecordedVerification,
        }
    }

    pub(crate) fn message_auth(message_id: &str, digest: &str) -> MessageAuthenticationEvidence {
        MessageAuthenticationEvidence {
            message_id: message_id.to_owned(),
            status: VerificationStatus::Valid,
            signer_key_id: Some("key-1".to_owned()),
            covered_envelope_digest: Some(digest.to_owned()),
            recorded_by: EvidenceSource::RecordedVerification,
        }
    }

    #[test]
    fn the_fixtures_validate() {
        peer_auth("planner").validate().expect("valid");
        message_auth("msg-1", &crate::canonical::digest_bytes(b"envelope"))
            .validate()
            .expect("valid");
    }

    #[test]
    fn an_agent_card_cannot_record_its_own_authentication() {
        // A card is the peer describing itself. Letting it record that its own
        // authentication succeeded would be asking the peer whether the peer
        // authenticated.
        let mut hostile = peer_auth("planner");
        hostile.recorded_by = EvidenceSource::AgentCard;
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn client_credentials_cannot_carry_a_delegated_subject() {
        // The flow authenticates a service to a service. A subject claimed
        // under it was never established by it, and accepting the claim would
        // let a service act as any user it names.
        let mut hostile = peer_auth("planner");
        hostile.scheme_kind = SecuritySchemeKind::OAuth2ClientCredentials;
        let error = hostile.validate().expect_err("refused");
        assert!(matches!(error, A2aSecurityError::BindingMismatch(_)));
    }

    #[test]
    fn client_credentials_without_a_delegated_subject_are_fine() {
        // The control. Service-to-service authentication is legitimate; what is
        // not is using it to assert a user.
        let mut service_only = peer_auth("planner");
        service_only.scheme_kind = SecuritySchemeKind::OAuth2ClientCredentials;
        service_only.delegated_subject = None;
        service_only.validate().expect("valid");
    }

    #[test]
    fn only_valid_satisfies_positive_evidence() {
        for status in VerificationStatus::all() {
            let mut evidence = peer_auth("planner");
            evidence.status = status;
            assert_eq!(
                evidence.may_satisfy_positive_evidence(),
                status == VerificationStatus::Valid,
                "{}",
                status.as_str()
            );
            assert_eq!(
                evidence.is_concrete_failure(),
                status == VerificationStatus::Invalid,
                "{}",
                status.as_str()
            );
        }
    }

    #[test]
    fn a_signature_over_another_message_does_not_cover_this_one() {
        // The binding that matters most. A signature over *a* message is not a
        // signature over *this* message.
        let observed = crate::canonical::digest_bytes(b"observed-envelope");
        let evidence = message_auth("msg-1", &crate::canonical::digest_bytes(b"other-envelope"));
        assert_eq!(evidence.covers(&observed), Some(false));

        let matching = message_auth("msg-1", &observed);
        assert_eq!(matching.covers(&observed), Some(true));
    }

    #[test]
    fn an_absent_covered_digest_answers_nothing_rather_than_no() {
        // "Nothing to compare" and "compared and differed" are different
        // situations: one is a gap, the other is a substituted message.
        let mut evidence = message_auth("msg-1", &crate::canonical::digest_bytes(b"x"));
        evidence.covered_envelope_digest = None;
        assert_eq!(evidence.covers("sha256:whatever"), None);
    }

    #[test]
    fn authentication_evidence_carries_no_credential_material() {
        // Structural: there is nowhere to put one, and `deny_unknown_fields`
        // means adding one fails to decode.
        for hostile in [
            serde_json::json!({ "peer_id": "p", "scheme_kind": "API_KEY", "status": "VALID",
                                "recorded_by": "RECORDED_VERIFICATION", "api_key": "x" }),
            serde_json::json!({ "peer_id": "p", "scheme_kind": "HTTP_BEARER", "status": "VALID",
                                "recorded_by": "RECORDED_VERIFICATION", "access_token": "x" }),
        ] {
            assert!(serde_json::from_value::<PeerAuthenticationEvidence>(hostile).is_err());
        }
    }

    #[test]
    fn an_issuer_is_retained_and_never_resolved() {
        // A report that could not name the issuer would be less useful and no
        // safer. What matters is that nothing goes there.
        let evidence = peer_auth("planner");
        assert_eq!(evidence.issuer.as_deref(), Some("https://issuer.example"));
    }
}
