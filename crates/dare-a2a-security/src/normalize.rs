//! The assembled evidence bundle.
//!
//! Everything the evaluators read, assembled once and then treated as
//! immutable. An evaluator that could mutate the evidence it judges would make
//! findings depend on evaluation order.
//!
//! # Why validation runs on the assembled bundle
//!
//! Several of the things worth refusing are invisible from inside any single
//! document. A card and a trace can each be internally consistent while naming
//! different providers for one peer; a delegation chain can be well-formed while
//! referring to a peer nobody supplied. Those only exist once the documents are
//! together, so `build` validates the whole rather than each part as it arrives.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::agent_card::AgentCard;
use crate::authentication::{MessageAuthenticationEvidence, PeerAuthenticationEvidence};
use crate::budget::AdmissionLedger;
use crate::canonical::digest;
use crate::delegation::DelegationChain;
use crate::error::{A2aSecurityError, Result};
use crate::message::{Exchange, ExchangeLog};
use crate::peer::{PeerIdentity, PeerSet};
use crate::policy::A2aPolicy;
use crate::push_notification::PushNotificationConfig;

/// A document the run read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRef {
    pub document_id: String,
    pub kind: String,
    pub bytes: usize,
    /// A digest of the raw document, so a substituted input is visible in the
    /// artifact rather than only to whoever ran it.
    pub content_digest: String,
}

/// Everything the evaluators read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aEvidence {
    #[serde(default)]
    pub documents: Vec<DocumentRef>,
    #[serde(default)]
    pub cards: Vec<AgentCard>,
    #[serde(default)]
    pub peers: PeerSet,
    #[serde(default)]
    pub exchanges: ExchangeLog,
    #[serde(default)]
    pub peer_authentication: Vec<PeerAuthenticationEvidence>,
    #[serde(default)]
    pub message_authentication: Vec<MessageAuthenticationEvidence>,
    #[serde(default)]
    pub delegation_chains: Vec<DelegationChain>,
    #[serde(default)]
    pub push_configs: Vec<PushNotificationConfig>,
    #[serde(default, skip_serializing_if = "A2aPolicy::is_empty")]
    pub policy: A2aPolicy,
}

impl A2aEvidence {
    pub fn peer(&self, peer_id: &str) -> Option<&PeerIdentity> {
        self.peers.get(peer_id)
    }

    /// The card supplied for a peer.
    ///
    /// Matched by the peer's own `card_id` reference rather than by name: a
    /// card matched by name would let a second card claiming the same name
    /// stand in for the first.
    pub fn card_for(&self, peer_id: &str) -> Option<&AgentCard> {
        self.cards.iter().find(|card| card.card_id == peer_id)
    }

    pub fn authentication_for(&self, peer_id: &str) -> Option<&PeerAuthenticationEvidence> {
        self.peer_authentication
            .iter()
            .find(|evidence| evidence.peer_id == peer_id)
    }

    pub fn message_authentication_for(
        &self,
        message_id: &str,
    ) -> Option<&MessageAuthenticationEvidence> {
        self.message_authentication
            .iter()
            .find(|evidence| evidence.message_id == message_id)
    }

    pub fn chain(&self, chain_id: &str) -> Option<&DelegationChain> {
        self.delegation_chains
            .iter()
            .find(|chain| chain.chain_id == chain_id)
    }

    pub fn push_config(&self, config_id: &str) -> Option<&PushNotificationConfig> {
        self.push_configs
            .iter()
            .find(|config| config.config_id == config_id)
    }

    /// A digest of the exact envelope one exchange presents.
    ///
    /// The comparison surface for message authenticity: a signature covering a
    /// different envelope produces a different digest.
    pub fn envelope_digest(&self, exchange: &Exchange) -> Result<String> {
        digest(exchange)
    }

    /// Extensions used anywhere in the run.
    pub fn extensions_used(&self) -> BTreeSet<String> {
        self.exchanges
            .exchanges
            .iter()
            .flat_map(|exchange| exchange.extensions_used.iter().cloned())
            .collect()
    }

    /// The checks that only make sense once everything is present.
    pub fn validate(&self) -> Result<()> {
        for card in &self.cards {
            card.validate()?;
        }
        self.peers.validate()?;
        self.exchanges.validate()?;
        for evidence in &self.peer_authentication {
            evidence.validate()?;
        }
        for evidence in &self.message_authentication {
            evidence.validate()?;
        }
        for chain in &self.delegation_chains {
            chain.validate()?;
        }
        for config in &self.push_configs {
            config.validate()?;
        }
        self.policy.validate()?;

        // An exchange naming a peer nobody supplied is an exchange with a
        // counterparty nobody described. Evaluating it would mean deciding
        // about a peer with no evidence at all, which reads as a clean result.
        let known_peers: BTreeSet<&str> = self
            .peers
            .peers
            .iter()
            .map(|peer| peer.peer_id.as_str())
            .collect();
        for exchange in &self.exchanges.exchanges {
            if !known_peers.contains(exchange.peer_id.as_str()) {
                return Err(A2aSecurityError::invalid(format!(
                    "message `{}` names peer `{}`, which no evidence describes",
                    exchange.message_id, exchange.peer_id
                )));
            }
        }

        // Two authentication records for one peer would let an evaluator pick
        // whichever it read first, and the two could disagree.
        let mut seen_auth = BTreeSet::new();
        for evidence in &self.peer_authentication {
            if !seen_auth.insert(evidence.peer_id.as_str()) {
                return Err(A2aSecurityError::BindingMismatch(format!(
                    "peer `{}` has two authentication records; whichever an evaluator read \
                     first would decide, and the two can disagree",
                    evidence.peer_id
                )));
            }
        }

        let mut seen_message_auth = BTreeSet::new();
        for evidence in &self.message_authentication {
            if !seen_message_auth.insert(evidence.message_id.as_str()) {
                return Err(A2aSecurityError::BindingMismatch(format!(
                    "message `{}` has two authentication records",
                    evidence.message_id
                )));
            }
        }

        let mut seen_chains = BTreeSet::new();
        for chain in &self.delegation_chains {
            if !seen_chains.insert(chain.chain_id.as_str()) {
                return Err(A2aSecurityError::BindingMismatch(format!(
                    "delegation chain `{}` appears twice",
                    chain.chain_id
                )));
            }
        }

        Ok(())
    }

    /// Peers described by a card whose provider disagrees with the peer record.
    ///
    /// Retained rather than refused: a card and a trace naming different
    /// providers for one peer is the substitution the discovery invariant
    /// exists to report, and refusing the bundle would hand an operator a run
    /// that could not observe instead of the disagreement it observed
    /// perfectly well.
    pub fn provider_disagreements(&self) -> Vec<ProviderDisagreement> {
        let mut found = Vec::new();
        for peer in &self.peers.peers {
            let Some(card) = self.card_for(&peer.peer_id) else {
                continue;
            };
            if let (Some(card_provider), Some(peer_provider)) =
                (card.provider.as_deref(), peer.card_provider.as_deref())
            {
                if card_provider != peer_provider {
                    found.push(ProviderDisagreement {
                        peer_id: peer.peer_id.clone(),
                        card_provider: card_provider.to_owned(),
                        observed_provider: peer_provider.to_owned(),
                    });
                }
            }
        }
        found
    }
}

/// A card and an observation disagreeing about who provides a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDisagreement {
    pub peer_id: String,
    pub card_provider: String,
    pub observed_provider: String,
}

/// Assemble an evidence bundle.
///
/// Admission happens here, before the bundle exists: the merged set can exceed
/// a bound that no single document did.
#[derive(Debug, Default)]
pub struct EvidenceBuilder {
    evidence: A2aEvidence,
}

impl EvidenceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_document(mut self, document_id: &str, kind: &str, raw: &[u8]) -> Self {
        self.evidence.documents.push(DocumentRef {
            document_id: document_id.to_owned(),
            kind: kind.to_owned(),
            bytes: raw.len(),
            content_digest: crate::canonical::digest_bytes(raw),
        });
        self
    }

    /// Carry forward a document reference a capture already recorded.
    ///
    /// The digest comes from the capture rather than being recomputed, because
    /// the bytes are gone: what is being replayed is the record of having read
    /// them, and recomputing over a reconstructed bundle would digest something
    /// the run never saw.
    pub fn with_recorded_document(mut self, document: DocumentRef) -> Self {
        self.evidence.documents.push(document);
        self
    }

    pub fn with_card(mut self, card: AgentCard) -> Self {
        self.evidence.cards.push(card);
        self
    }

    pub fn with_peer(mut self, peer: PeerIdentity) -> Self {
        self.evidence.peers.peers.push(peer);
        self
    }

    pub fn with_exchange(mut self, exchange: Exchange) -> Self {
        self.evidence.exchanges.exchanges.push(exchange);
        self
    }

    pub fn with_peer_authentication(mut self, evidence: PeerAuthenticationEvidence) -> Self {
        self.evidence.peer_authentication.push(evidence);
        self
    }

    pub fn with_message_authentication(mut self, evidence: MessageAuthenticationEvidence) -> Self {
        self.evidence.message_authentication.push(evidence);
        self
    }

    pub fn with_delegation_chain(mut self, chain: DelegationChain) -> Self {
        self.evidence.delegation_chains.push(chain);
        self
    }

    pub fn with_push_config(mut self, config: PushNotificationConfig) -> Self {
        self.evidence.push_configs.push(config);
        self
    }

    /// Apply the local policy.
    ///
    /// The only input that can establish approval, and applied last so nothing
    /// depends on the order documents arrived in.
    pub fn with_policy(mut self, policy: A2aPolicy) -> Self {
        self.evidence.policy = policy;
        self
    }

    /// Finish, admitting the assembled objects and validating the whole.
    pub fn build(self, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        let evidence = self.evidence;

        for _ in &evidence.peers.peers {
            ledger.admit_peer()?;
        }
        for _ in &evidence.exchanges.exchanges {
            ledger.admit_exchange()?;
        }
        for chain in &evidence.delegation_chains {
            ledger.assert_delegation_depth(chain.hops.len() as u32)?;
        }

        evidence.validate()?;
        Ok(evidence)
    }
}

/// Facts about the target, for Cycle 006 applicability.
///
/// Derived from what was actually observed rather than declared, so a target
/// cannot claim a surface it never showed.
pub fn assessment_facts(evidence: &A2aEvidence) -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        ("agent_present", true),
        ("multi_agent_present", !evidence.peers.peers.is_empty()),
        ("a2a_exchange_present", !evidence.exchanges.is_empty()),
        ("agent_card_present", !evidence.cards.is_empty()),
        (
            "a2a_extension_present",
            !evidence.extensions_used().is_empty()
                || evidence
                    .cards
                    .iter()
                    .any(|card| !card.extensions.is_empty()),
        ),
        (
            "push_notification_config_present",
            !evidence.push_configs.is_empty(),
        ),
        (
            "peer_authentication_evidence_present",
            !evidence.peer_authentication.is_empty(),
        ),
        (
            "skill_authorization_policy_present",
            !evidence.policy.skill_grants.is_empty(),
        ),
        (
            "task_context_binding_present",
            evidence
                .exchanges
                .exchanges
                .iter()
                .any(|exchange| exchange.task_id.is_some() && exchange.context_id.is_some()),
        ),
        (
            "a2a_tenant_policy_present",
            !evidence.policy.tenant_policy.is_empty(),
        ),
        (
            "data_scope_policy_present",
            !evidence.policy.data_scope_policy.is_empty(),
        ),
        (
            "replay_policy_present",
            !evidence.policy.replay_policy.is_empty(),
        ),
        (
            "protocol_policy_present",
            !evidence.policy.protocol_policy.is_empty(),
        ),
        (
            "delegated_identity_present",
            !evidence.delegation_chains.is_empty(),
        ),
    ])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::agent_card::tests::card;
    use crate::authentication::tests::{message_auth, peer_auth};
    use crate::delegation::tests::chain;
    use crate::message::tests::exchange;
    use crate::peer::tests::peer;
    use crate::policy::tests::policy;

    pub(crate) fn evidence() -> A2aEvidence {
        let mut ledger = AdmissionLedger::new();
        let base = exchange("msg-1");
        let envelope = digest(&base).expect("digests");
        EvidenceBuilder::new()
            .with_document("card.json", "AGENT_CARD", b"{}")
            .with_card(card("planner"))
            .with_peer(peer("planner"))
            .with_exchange(base)
            .with_peer_authentication(peer_auth("planner"))
            .with_message_authentication(message_auth("msg-1", &envelope))
            .with_delegation_chain(chain("chain-1"))
            .with_policy(policy())
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn the_fixture_bundle_builds_and_validates() {
        let evidence = evidence();
        assert_eq!(evidence.peers.peers.len(), 1);
        assert_eq!(evidence.exchanges.exchanges.len(), 1);
        assert!(evidence.card_for("planner").is_some());
    }

    #[test]
    fn an_exchange_naming_an_unknown_peer_is_refused() {
        // Evaluating it would mean deciding about a peer with no evidence at
        // all, which reads as a clean result.
        let mut ledger = AdmissionLedger::new();
        let mut orphan = exchange("msg-1");
        orphan.peer_id = "nobody".to_owned();
        let result = EvidenceBuilder::new()
            .with_peer(peer("planner"))
            .with_exchange(orphan)
            .build(&mut ledger);
        assert!(result.is_err());
    }

    #[test]
    fn two_authentication_records_for_one_peer_are_refused() {
        // Whichever an evaluator read first would decide, and the two can
        // disagree.
        let mut ledger = AdmissionLedger::new();
        let mut second = peer_auth("planner");
        second.status = crate::source::VerificationStatus::Invalid;
        let result = EvidenceBuilder::new()
            .with_peer(peer("planner"))
            .with_peer_authentication(peer_auth("planner"))
            .with_peer_authentication(second)
            .build(&mut ledger);
        assert!(result.is_err());
    }

    #[test]
    fn a_provider_disagreement_is_retained_rather_than_refused() {
        // A card and an observation naming different providers is the
        // substitution the discovery invariant exists to report. Refusing the
        // bundle would hand an operator a run that could not observe instead of
        // the disagreement it observed perfectly well.
        let mut ledger = AdmissionLedger::new();
        let mut observed = peer("planner");
        observed.card_provider = Some("attacker".to_owned());
        let evidence = EvidenceBuilder::new()
            .with_card(card("planner"))
            .with_peer(observed)
            .with_policy(policy())
            .build(&mut ledger)
            .expect("an ambiguous bundle is evaluated, not refused");

        let disagreements = evidence.provider_disagreements();
        assert_eq!(disagreements.len(), 1);
        assert_eq!(disagreements[0].card_provider, "acme");
        assert_eq!(disagreements[0].observed_provider, "attacker");
    }

    #[test]
    fn the_envelope_digest_changes_when_the_envelope_changes() {
        // The comparison surface for message authenticity. A signature covering
        // a different envelope must produce a different digest, or covering
        // "some message" would be indistinguishable from covering this one.
        let evidence = evidence();
        let base = evidence.exchanges.get("msg-1").expect("present");
        let baseline = evidence.envelope_digest(base).expect("digests");

        let mut substituted = base.clone();
        substituted.task_id = Some("task-2".to_owned());
        assert_ne!(
            baseline,
            evidence.envelope_digest(&substituted).expect("digests")
        );

        let mut skill_changed = base.clone();
        skill_changed.requested_skill = Some("transfer-funds".to_owned());
        assert_ne!(
            baseline,
            evidence.envelope_digest(&skill_changed).expect("digests")
        );
    }

    #[test]
    fn a_card_is_matched_by_reference_and_never_by_name() {
        // A card matched by name would let a second card claiming the same name
        // stand in for the first.
        let mut ledger = AdmissionLedger::new();
        let mut impostor = card("impostor");
        impostor.name = "planner-agent".to_owned();
        let evidence = EvidenceBuilder::new()
            .with_card(impostor)
            .with_peer(peer("planner"))
            .build(&mut ledger)
            .expect("builds");
        assert!(evidence.card_for("planner").is_none());
    }

    #[test]
    fn assessment_facts_come_from_what_was_observed() {
        // A target cannot claim a surface it never showed.
        let facts = assessment_facts(&evidence());
        assert!(facts["a2a_exchange_present"]);
        assert!(facts["agent_card_present"]);
        assert!(facts["peer_authentication_evidence_present"]);
        assert!(!facts["push_notification_config_present"]);

        let empty = A2aEvidence::default();
        let facts = assessment_facts(&empty);
        assert!(!facts["a2a_exchange_present"]);
        assert!(!facts["agent_card_present"]);
        assert!(!facts["multi_agent_present"]);
    }

    #[test]
    fn the_bundle_carries_a_digest_of_every_document_it_read() {
        let evidence = evidence();
        assert_eq!(evidence.documents.len(), 1);
        assert!(evidence.documents[0].content_digest.starts_with("sha256:"));
    }

    #[test]
    fn the_bundle_cannot_carry_a_verdict() {
        let hostile = serde_json::json!({ "documents": [], "verdict": "PASS" });
        assert!(serde_json::from_value::<A2aEvidence>(hostile).is_err());
    }

    #[test]
    fn building_is_deterministic() {
        assert_eq!(
            digest(&evidence()).expect("digests"),
            digest(&evidence()).expect("digests")
        );
    }
}
