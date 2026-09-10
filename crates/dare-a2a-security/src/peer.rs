//! Peer identity, with the six kinds kept apart.
//!
//! ```text
//! TLS server identity  != agent-level authorization
//! discovered Agent Card != authenticated identity
//! ```
//!
//! The whole module exists because these are six different facts that a
//! deployment routinely stores in one variable:
//!
//! - the **logical agent** local policy names;
//! - the **provider** an Agent Card claims;
//! - the **endpoint** that answered;
//! - the **principal** an authentication established;
//! - the **subject** a delegation names as the one being acted for;
//! - the **tenant** the exchange claims.
//!
//! No two may be silently substituted, so they are six fields rather than one,
//! and [`PeerIdentity::authorization_subject`] returns only the kinds that can
//! actually be the subject of a decision. An endpoint identity cannot: it
//! answers which host replied, and no authorization question has "a host" as
//! its subject.

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{A2aSecurityError, Result};
use crate::source::{EvidenceSource, IdentityKind};

/// One identity claim, with where it came from attached.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityClaim {
    pub kind: IdentityKind,
    pub value: String,
    /// Where the claim came from. A claim in an Agent Card is the peer
    /// describing itself; a claim in local policy is the deployment deciding.
    pub evidence_source: EvidenceSource,
}

impl IdentityClaim {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.value, "an identity claim")?;
        Ok(())
    }

    /// Whether this claim can establish that the identity was **approved**.
    pub fn may_establish_approval(&self) -> bool {
        self.evidence_source.may_establish_approval()
    }
}

/// The peer, as six separate facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentity {
    /// The engine's canonical id for this peer.
    pub peer_id: String,
    /// The logical agent the local policy names.
    pub logical_agent_id: String,
    /// The provider an Agent Card claims. A claim, never an approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_provider: Option<String>,
    /// The host or interface that answered. Never an authorization subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_identity: Option<String>,
    /// The principal an authentication established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_principal: Option<String>,
    /// The subject a delegation names as the one being acted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    /// The tenant the exchange claims. A routing value, not authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The audience an authentication was issued for, if one was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub evidence_source: EvidenceSource,
}

impl PeerIdentity {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.peer_id, "a peer id")?;
        assert_safe_identifier(&self.logical_agent_id, "a logical agent id")?;
        for (label, value) in [
            ("a card provider", &self.card_provider),
            ("an endpoint identity", &self.endpoint_identity),
            ("an authenticated principal", &self.authenticated_principal),
            ("a delegated subject", &self.delegated_subject),
            ("a tenant", &self.tenant),
            ("an audience", &self.audience),
        ] {
            if let Some(value) = value {
                assert_safe_identifier(value, label)?;
            }
        }
        Ok(())
    }

    /// The identity a decision may be made about.
    ///
    /// The delegated subject when one exists, otherwise the authenticated
    /// principal. Never the provider and never the endpoint: a card's provider
    /// is a claim by the thing being judged, and an endpoint answers which host
    /// replied.
    ///
    /// `None` means nothing authenticated, which is a gap rather than a
    /// finding — and specifically **not** the logical agent id, because falling
    /// back to it would let an unauthenticated exchange be judged as though the
    /// peer it claimed to be had proved it.
    pub fn authorization_subject(&self) -> Option<&str> {
        self.delegated_subject
            .as_deref()
            .or(self.authenticated_principal.as_deref())
    }

    /// Which kind the authorization subject came from.
    pub fn authorization_subject_kind(&self) -> Option<IdentityKind> {
        if self.delegated_subject.is_some() {
            Some(IdentityKind::DelegatedSubject)
        } else if self.authenticated_principal.is_some() {
            Some(IdentityKind::AuthenticatedPrincipal)
        } else {
            None
        }
    }

    /// Whether anything at all authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated_principal.is_some()
    }

    /// Whether the card's provider agrees with what local policy expected.
    ///
    /// Three answers. `None` means one side named nothing, which is a gap; the
    /// two `Some` answers are agreement and a substitution.
    pub fn provider_matches(&self, expected: Option<&str>) -> Option<bool> {
        match (self.card_provider.as_deref(), expected) {
            (Some(actual), Some(expected)) => Some(actual == expected),
            _ => None,
        }
    }

    /// Whether the authenticated audience is the one policy expected.
    pub fn audience_matches(&self, expected: Option<&str>) -> Option<bool> {
        match (self.audience.as_deref(), expected) {
            (Some(actual), Some(expected)) => Some(actual == expected),
            _ => None,
        }
    }
}

/// Every peer the run observed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSet {
    #[serde(default)]
    pub peers: Vec<PeerIdentity>,
}

impl PeerSet {
    pub fn get(&self, peer_id: &str) -> Option<&PeerIdentity> {
        self.peers.iter().find(|peer| peer.peer_id == peer_id)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for peer in &self.peers {
            peer.validate()?;
            if !seen.insert(peer.peer_id.as_str()) {
                return Err(A2aSecurityError::BindingMismatch(format!(
                    "peer `{}` appears twice; two rows under one id means a finding about one \
                     silently omits the other",
                    peer.peer_id
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn peer(id: &str) -> PeerIdentity {
        PeerIdentity {
            peer_id: id.to_owned(),
            logical_agent_id: id.to_owned(),
            card_provider: Some("acme".to_owned()),
            endpoint_identity: Some("peer.example".to_owned()),
            authenticated_principal: Some("svc-planner".to_owned()),
            delegated_subject: Some("user-alice".to_owned()),
            tenant: Some("tenant-a".to_owned()),
            audience: Some("local-orchestrator".to_owned()),
            evidence_source: EvidenceSource::CapturedTrace,
        }
    }

    #[test]
    fn the_fixture_peer_validates() {
        peer("planner").validate().expect("valid");
    }

    #[test]
    fn the_six_identity_kinds_are_six_fields() {
        // A deployment routinely stores all six in one variable. Substituting
        // one for another is the failure this module exists to prevent, so they
        // cannot be the same field.
        let peer = peer("planner");
        let values = [
            peer.card_provider.as_deref(),
            peer.endpoint_identity.as_deref(),
            peer.authenticated_principal.as_deref(),
            peer.delegated_subject.as_deref(),
            peer.tenant.as_deref(),
        ];
        let unique: std::collections::BTreeSet<Option<&str>> = values.into_iter().collect();
        assert_eq!(unique.len(), 5, "two identity kinds share a value slot");
    }

    #[test]
    fn the_authorization_subject_is_the_delegated_one_when_present() {
        let peer = peer("planner");
        assert_eq!(peer.authorization_subject(), Some("user-alice"));
        assert_eq!(
            peer.authorization_subject_kind(),
            Some(IdentityKind::DelegatedSubject)
        );
    }

    #[test]
    fn the_authorization_subject_falls_back_to_the_principal_and_no_further() {
        let mut peer = peer("planner");
        peer.delegated_subject = None;
        assert_eq!(peer.authorization_subject(), Some("svc-planner"));
        assert_eq!(
            peer.authorization_subject_kind(),
            Some(IdentityKind::AuthenticatedPrincipal)
        );
    }

    #[test]
    fn an_unauthenticated_peer_has_no_authorization_subject() {
        // Deliberately not the logical agent id. Falling back to it would let
        // an unauthenticated exchange be judged as though the peer it claimed
        // to be had proved it.
        let mut peer = peer("planner");
        peer.delegated_subject = None;
        peer.authenticated_principal = None;
        assert_eq!(peer.authorization_subject(), None);
        assert!(!peer.is_authenticated());
        assert_eq!(peer.logical_agent_id, "planner");
    }

    #[test]
    fn an_endpoint_identity_is_never_the_authorization_subject() {
        // TLS server identity answers which host replied. It is present here
        // and unreachable from the subject accessor.
        let mut peer = peer("planner");
        peer.delegated_subject = None;
        peer.authenticated_principal = None;
        peer.endpoint_identity = Some("peer.example".to_owned());
        assert_eq!(peer.authorization_subject(), None);
    }

    #[test]
    fn a_card_provider_is_never_the_authorization_subject() {
        let mut peer = peer("planner");
        peer.delegated_subject = None;
        peer.authenticated_principal = None;
        peer.card_provider = Some("acme".to_owned());
        assert_eq!(peer.authorization_subject(), None);
    }

    #[test]
    fn provider_and_audience_agreement_have_three_answers() {
        // "Nothing to compare" and "compared and differed" are different
        // situations, and the evaluators treat them differently.
        let peer = peer("planner");
        assert_eq!(peer.provider_matches(Some("acme")), Some(true));
        assert_eq!(peer.provider_matches(Some("other")), Some(false));
        assert_eq!(peer.provider_matches(None), None);

        assert_eq!(
            peer.audience_matches(Some("local-orchestrator")),
            Some(true)
        );
        assert_eq!(peer.audience_matches(Some("someone-else")), Some(false));
        assert_eq!(peer.audience_matches(None), None);
    }

    #[test]
    fn only_a_local_claim_may_establish_approval() {
        let card_claim = IdentityClaim {
            kind: IdentityKind::CardProvider,
            value: "acme".to_owned(),
            evidence_source: EvidenceSource::AgentCard,
        };
        assert!(!card_claim.may_establish_approval());

        let policy_claim = IdentityClaim {
            kind: IdentityKind::LogicalAgent,
            value: "planner".to_owned(),
            evidence_source: EvidenceSource::LocalPolicy,
        };
        assert!(policy_claim.may_establish_approval());
    }

    #[test]
    fn a_duplicate_peer_id_is_refused() {
        // Two rows under one id means a finding about one silently omits the
        // other.
        let set = PeerSet {
            peers: vec![peer("planner"), peer("planner")],
        };
        assert!(set.validate().is_err());
    }

    #[test]
    fn a_hostile_identity_value_is_refused() {
        let mut hostile = peer("planner");
        hostile.tenant = Some("tenant\u{202E}evil".to_owned());
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn a_peer_cannot_declare_itself_trusted() {
        // Structural: there is no field for it, and `deny_unknown_fields` means
        // adding one fails to decode.
        let hostile = serde_json::json!({
            "peer_id": "planner",
            "logical_agent_id": "planner",
            "evidence_source": "AGENT_CARD",
            "trusted": true
        });
        assert!(serde_json::from_value::<PeerIdentity>(hostile).is_err());
    }
}
