//! The normalized observation model.
//!
//! Closed, typed, and carrying no verdict. An adapter reports what it saw; it
//! never reports what that means. There is deliberately no `Verdict` variant,
//! no `Violation` variant and no `expected_outcome` field — an adapter able to
//! emit one would be deciding the result, and the evaluator would be reduced to
//! transcribing whatever the fixture author wrote.
//!
//! # Why observations exist, given the evidence bundle already does
//!
//! [`crate::normalize::A2aEvidence`] is what was *imported*. Observations are
//! what a run *saw*, and the difference is the whole basis for `INCONCLUSIVE`:
//! an evaluator asks whether a channel is present, and a channel no evidence
//! supported is simply absent from the set. A missing channel is then a gap the
//! evaluator can report, rather than a `false` it would have to interpret.
//!
//! This is why [`project`] emits nothing for a peer with no authentication
//! evidence instead of emitting one saying `authenticated: false`. The second
//! shape reads as an answer; the first is honestly the absence of one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::authorization::{self, SkillAuthorizationAssessment};
use crate::canonical::digest;
use crate::data_scope::{self, DataScopeAssessment};
use crate::delegation::ChainAmplification;
use crate::error::Result;
use crate::extension::{self, ExtensionAssessment};
use crate::normalize::{A2aEvidence, ProviderDisagreement};
use crate::protocol::{self, ProtocolAssessment};
use crate::push_notification::{self, PushNotificationAssessment};
use crate::replay::{self, ReplayAssessment};
use crate::source::{
    EvidenceSource, HarnessErrorKind, MessageRole, SecuritySchemeKind, VerificationStatus,
};
use crate::tenant::{self, TenantAssessment};

/// The observation channels an invariant may require.
///
/// Closed. An unknown wire value fails to decode rather than becoming an
/// unrecognized channel that every coverage contract would silently ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationChannel {
    AgentCardContext,
    PeerIdentityContext,
    PeerAuthenticationContext,
    MessageContext,
    MessageAuthenticationContext,
    SecurityRequirementContext,
    SkillAuthorizationContext,
    MessageAuthorityContext,
    TaskContextBindingContext,
    DelegationContext,
    TenantContext,
    DataScopeContext,
    ReplayContext,
    ProtocolContext,
    ExtensionContext,
    PushNotificationContext,
    HarnessError,
}

impl ObservationChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentCardContext => "AGENT_CARD_CONTEXT",
            Self::PeerIdentityContext => "PEER_IDENTITY_CONTEXT",
            Self::PeerAuthenticationContext => "PEER_AUTHENTICATION_CONTEXT",
            Self::MessageContext => "MESSAGE_CONTEXT",
            Self::MessageAuthenticationContext => "MESSAGE_AUTHENTICATION_CONTEXT",
            Self::SecurityRequirementContext => "SECURITY_REQUIREMENT_CONTEXT",
            Self::SkillAuthorizationContext => "SKILL_AUTHORIZATION_CONTEXT",
            Self::MessageAuthorityContext => "MESSAGE_AUTHORITY_CONTEXT",
            Self::TaskContextBindingContext => "TASK_CONTEXT_BINDING_CONTEXT",
            Self::DelegationContext => "DELEGATION_CONTEXT",
            Self::TenantContext => "TENANT_CONTEXT",
            Self::DataScopeContext => "DATA_SCOPE_CONTEXT",
            Self::ReplayContext => "REPLAY_CONTEXT",
            Self::ProtocolContext => "PROTOCOL_CONTEXT",
            Self::ExtensionContext => "EXTENSION_CONTEXT",
            Self::PushNotificationContext => "PUSH_NOTIFICATION_CONTEXT",
            Self::HarnessError => "HARNESS_ERROR",
        }
    }

    pub fn all() -> [Self; 17] {
        [
            Self::AgentCardContext,
            Self::PeerIdentityContext,
            Self::PeerAuthenticationContext,
            Self::MessageContext,
            Self::MessageAuthenticationContext,
            Self::SecurityRequirementContext,
            Self::SkillAuthorizationContext,
            Self::MessageAuthorityContext,
            Self::TaskContextBindingContext,
            Self::DelegationContext,
            Self::TenantContext,
            Self::DataScopeContext,
            Self::ReplayContext,
            Self::ProtocolContext,
            Self::ExtensionContext,
            Self::PushNotificationContext,
            Self::HarnessError,
        ]
    }
}

/// One Agent Card, as it binds to what policy approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCardContext {
    pub peer_id: String,
    pub card_digest: String,
    /// Whether the digest matches the one policy pinned. `None` when policy
    /// pinned none.
    pub digest_matches_policy: Option<bool>,
    /// Whether the card's provider matches what policy expected.
    pub provider_matches_policy: Option<bool>,
    /// The signature status, as another verifier recorded it.
    pub signature_status: VerificationStatus,
    /// Whether the signer is one policy approved. `None` when no signer was
    /// named or no policy names any.
    pub signer_approved: Option<bool>,
    /// Interfaces the card advertises that policy did not approve.
    pub unapproved_interfaces: Vec<String>,
    /// A card and an observation disagreeing about the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_disagreement: Option<ProviderDisagreement>,
}

/// One peer, as identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityContext {
    pub peer_id: String,
    pub logical_agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_subject: Option<String>,
    pub is_authenticated: bool,
    /// Whether the authenticated audience is the one policy expected.
    pub audience_matches_policy: Option<bool>,
    /// Whether the observed provider matches what policy expected.
    pub provider_matches_policy: Option<bool>,
    pub evidence_source: EvidenceSource,
}

/// What a verifier recorded about a peer's authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthenticationContext {
    pub peer_id: String,
    pub scheme_kind: SecuritySchemeKind,
    pub status: VerificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    pub recorded_by: EvidenceSource,
}

/// One message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageContext {
    pub message_id: String,
    pub peer_id: String,
    pub role: MessageRole,
    pub envelope_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_skill: Option<String>,
    pub correlation_key: String,
}

/// What a verifier recorded about a message's authenticity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAuthenticationContext {
    pub message_id: String,
    pub status: VerificationStatus,
    /// Whether the signature covered the envelope actually observed. `None`
    /// when no covered digest was recorded.
    pub covers_observed_envelope: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
}

/// Whether the mechanism used satisfied an approved requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRequirementContext {
    pub message_id: String,
    pub peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme_used: Option<String>,
    /// Whether the scheme the exchange used is one the card declares for the
    /// skill it invoked.
    pub satisfies_card_requirement: Option<bool>,
    /// Whether the scheme kind is one policy approved for this peer.
    pub kind_approved_by_policy: Option<bool>,
}

/// Whether peer content reached an authority position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAuthorityContext {
    pub message_id: String,
    pub peer_id: String,
    pub is_peer_controlled: bool,
    /// Whether the local side let peer content direct behaviour.
    pub content_became_instruction: bool,
    /// The parts that crossed, so a finding can name them.
    pub crossing_part_ids: Vec<String>,
}

/// Whether task, context and principal stayed the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContextBindingContext {
    pub task_id: String,
    /// Distinct context ids seen under this task. More than one is a
    /// substitution.
    pub context_ids: BTreeSet<String>,
    /// Distinct initiating principals seen under this task.
    pub initiating_principals: BTreeSet<String>,
    /// Distinct peers seen under this task.
    pub peer_ids: BTreeSet<String>,
    pub message_count: usize,
}

/// One delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationContext {
    pub chain_id: String,
    pub hop_count: usize,
    pub is_connected: bool,
    /// Where the chain widened, if it did.
    pub amplifications: Vec<ChainAmplification>,
}

/// One normalized observation.
///
/// The closed set. Note what is missing: there is no `Verdict`, `Violation`,
/// `Finding` or `ExpectedOutcome` variant, and no variant carries a field
/// shaped like one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub enum A2aObservation {
    AgentCardContext(AgentCardContext),
    PeerIdentityContext(PeerIdentityContext),
    PeerAuthenticationContext(PeerAuthenticationContext),
    MessageContext(MessageContext),
    MessageAuthenticationContext(MessageAuthenticationContext),
    SecurityRequirementContext(SecurityRequirementContext),
    SkillAuthorizationContext(SkillAuthorizationAssessment),
    MessageAuthorityContext(MessageAuthorityContext),
    TaskContextBindingContext(TaskContextBindingContext),
    DelegationContext(DelegationContext),
    TenantContext(TenantAssessment),
    DataScopeContext(DataScopeAssessment),
    ReplayContext(ReplayAssessment),
    ProtocolContext(ProtocolAssessment),
    ExtensionContext(ExtensionAssessment),
    PushNotificationContext(PushNotificationAssessment),
    HarnessError(HarnessErrorContext),
}

/// Why a run could not observe.
///
/// Not a finding. A harness that failed produces no security conclusion in
/// either direction, and an evaluator that read this as evidence of a problem
/// would turn every broken adapter into a vulnerability report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessErrorContext {
    pub kind: HarnessErrorKind,
    /// Operator-facing, and never an echo of refused input.
    pub reason: String,
}

impl A2aObservation {
    pub fn channel(&self) -> ObservationChannel {
        match self {
            Self::AgentCardContext(_) => ObservationChannel::AgentCardContext,
            Self::PeerIdentityContext(_) => ObservationChannel::PeerIdentityContext,
            Self::PeerAuthenticationContext(_) => ObservationChannel::PeerAuthenticationContext,
            Self::MessageContext(_) => ObservationChannel::MessageContext,
            Self::MessageAuthenticationContext(_) => {
                ObservationChannel::MessageAuthenticationContext
            }
            Self::SecurityRequirementContext(_) => ObservationChannel::SecurityRequirementContext,
            Self::SkillAuthorizationContext(_) => ObservationChannel::SkillAuthorizationContext,
            Self::MessageAuthorityContext(_) => ObservationChannel::MessageAuthorityContext,
            Self::TaskContextBindingContext(_) => ObservationChannel::TaskContextBindingContext,
            Self::DelegationContext(_) => ObservationChannel::DelegationContext,
            Self::TenantContext(_) => ObservationChannel::TenantContext,
            Self::DataScopeContext(_) => ObservationChannel::DataScopeContext,
            Self::ReplayContext(_) => ObservationChannel::ReplayContext,
            Self::ProtocolContext(_) => ObservationChannel::ProtocolContext,
            Self::ExtensionContext(_) => ObservationChannel::ExtensionContext,
            Self::PushNotificationContext(_) => ObservationChannel::PushNotificationContext,
            Self::HarnessError(_) => ObservationChannel::HarnessError,
        }
    }

    /// A stable digest, for citation as deciding evidence.
    ///
    /// A finding with no deciding evidence is an assertion rather than a
    /// finding: an operator has to be able to get from the verdict back to what
    /// was observed.
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

/// Everything one run observed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSet {
    #[serde(default)]
    pub observations: Vec<A2aObservation>,
}

impl ObservationSet {
    pub fn new(observations: Vec<A2aObservation>) -> Self {
        Self { observations }
    }

    pub fn channels(&self) -> BTreeSet<ObservationChannel> {
        self.observations
            .iter()
            .map(A2aObservation::channel)
            .collect()
    }

    pub fn has_channel(&self, channel: ObservationChannel) -> bool {
        self.observations
            .iter()
            .any(|observation| observation.channel() == channel)
    }

    pub fn has_harness_error(&self) -> bool {
        self.has_channel(ObservationChannel::HarnessError)
    }
}

/// Project an evidence bundle into normalized observations.
///
/// Deterministic and total: the same bundle always produces the same
/// observations in the same order.
pub fn project(evidence: &A2aEvidence) -> ObservationSet {
    let mut observations = Vec::new();
    let policy = &evidence.policy;
    let disagreements = evidence.provider_disagreements();

    for card in &evidence.cards {
        let approved = policy.approved_peer(&card.card_id);
        let card_digest = match card.card_digest() {
            Ok(digest) => digest,
            Err(_) => continue,
        };

        let digest_matches_policy = approved
            .and_then(|approved| approved.expected_card_digest.as_deref())
            .map(|pinned| pinned == card_digest);
        let provider_matches_policy = match (
            card.provider.as_deref(),
            approved.and_then(|approved| approved.expected_provider.as_deref()),
        ) {
            (Some(actual), Some(expected)) => Some(actual == expected),
            _ => None,
        };
        let signer_approved = match (
            card.signature
                .as_ref()
                .and_then(|signature| signature.signer_key_id.as_deref()),
            approved.map(|approved| &approved.approved_signers),
        ) {
            (Some(signer), Some(approved)) if !approved.is_empty() => {
                Some(approved.contains(signer))
            }
            _ => None,
        };
        let unapproved_interfaces = approved
            .map(|approved| {
                if approved.approved_interfaces.is_empty() {
                    Vec::new()
                } else {
                    card.interfaces
                        .iter()
                        .filter(|interface| !approved.approved_interfaces.contains(&interface.url))
                        .map(|interface| interface.url.clone())
                        .collect()
                }
            })
            .unwrap_or_default();

        observations.push(A2aObservation::AgentCardContext(AgentCardContext {
            peer_id: card.card_id.clone(),
            card_digest,
            digest_matches_policy,
            provider_matches_policy,
            signature_status: card
                .signature
                .as_ref()
                .map(|signature| signature.status)
                .unwrap_or(VerificationStatus::Unrecorded),
            signer_approved,
            unapproved_interfaces,
            provider_disagreement: disagreements
                .iter()
                .find(|disagreement| disagreement.peer_id == card.card_id)
                .cloned(),
        }));
    }

    for peer in &evidence.peers.peers {
        let approved = policy.approved_peer(&peer.peer_id);
        observations.push(A2aObservation::PeerIdentityContext(PeerIdentityContext {
            peer_id: peer.peer_id.clone(),
            logical_agent_id: peer.logical_agent_id.clone(),
            authorization_subject: peer.authorization_subject().map(ToOwned::to_owned),
            is_authenticated: peer.is_authenticated(),
            audience_matches_policy: peer.audience_matches(
                approved.and_then(|approved| approved.expected_audience.as_deref()),
            ),
            provider_matches_policy: peer.provider_matches(
                approved.and_then(|approved| approved.expected_provider.as_deref()),
            ),
            evidence_source: peer.evidence_source,
        }));

        // Emitted only when a verifier recorded something. A context saying
        // `status: UNRECORDED` would read as an answer; an absent channel is
        // honestly the absence of one.
        if let Some(authentication) = evidence.authentication_for(&peer.peer_id) {
            observations.push(A2aObservation::PeerAuthenticationContext(
                PeerAuthenticationContext {
                    peer_id: authentication.peer_id.clone(),
                    scheme_kind: authentication.scheme_kind,
                    status: authentication.status,
                    principal: authentication.principal.clone(),
                    delegated_subject: authentication.delegated_subject.clone(),
                    recorded_by: authentication.recorded_by,
                },
            ));
        }
    }

    for exchange in &evidence.exchanges.exchanges {
        let envelope_digest = match evidence.envelope_digest(exchange) {
            Ok(digest) => digest,
            Err(_) => continue,
        };
        let peer = evidence.peer(&exchange.peer_id);
        let card = evidence.card_for(&exchange.peer_id);

        observations.push(A2aObservation::MessageContext(MessageContext {
            message_id: exchange.message_id.clone(),
            peer_id: exchange.peer_id.clone(),
            role: exchange.role,
            envelope_digest: envelope_digest.clone(),
            task_id: exchange.task_id.clone(),
            context_id: exchange.context_id.clone(),
            requested_skill: exchange.requested_skill.clone(),
            correlation_key: exchange.correlation_key(),
        }));

        if let Some(authentication) = evidence.message_authentication_for(&exchange.message_id) {
            observations.push(A2aObservation::MessageAuthenticationContext(
                MessageAuthenticationContext {
                    message_id: authentication.message_id.clone(),
                    status: authentication.status,
                    covers_observed_envelope: authentication.covers(&envelope_digest),
                    signer_key_id: authentication.signer_key_id.clone(),
                },
            ));
        }

        if exchange.security_scheme_used.is_some() {
            let scheme_used = exchange.security_scheme_used.as_deref();
            let satisfies_card_requirement = match (card, exchange.requested_skill.as_deref()) {
                (Some(card), Some(skill_id)) => card.skill(skill_id).map(|skill| {
                    skill.security_requirements.is_empty()
                        || scheme_used
                            .is_some_and(|used| skill.security_requirements.contains(used))
                }),
                _ => None,
            };
            let kind_approved_by_policy = match (
                card.and_then(|card| scheme_used.and_then(|used| card.scheme(used))),
                policy.approved_peer(&exchange.peer_id),
            ) {
                (Some(scheme), Some(approved)) if !approved.approved_scheme_kinds.is_empty() => {
                    Some(approved.approved_scheme_kinds.contains(&scheme.kind))
                }
                _ => None,
            };

            observations.push(A2aObservation::SecurityRequirementContext(
                SecurityRequirementContext {
                    message_id: exchange.message_id.clone(),
                    peer_id: exchange.peer_id.clone(),
                    scheme_used: exchange.security_scheme_used.clone(),
                    satisfies_card_requirement,
                    kind_approved_by_policy,
                },
            ));
        }

        if exchange.requested_skill.is_some() {
            let card_skills = card.map(|card| {
                card.skills
                    .iter()
                    .map(|skill| skill.skill_id.clone())
                    .collect::<BTreeSet<String>>()
            });
            observations.push(A2aObservation::SkillAuthorizationContext(
                authorization::assess(exchange, peer, policy, card_skills.as_ref()),
            ));
        }

        if exchange.is_peer_controlled() {
            observations.push(A2aObservation::MessageAuthorityContext(
                MessageAuthorityContext {
                    message_id: exchange.message_id.clone(),
                    peer_id: exchange.peer_id.clone(),
                    is_peer_controlled: true,
                    content_became_instruction: exchange.peer_content_became_instruction(),
                    crossing_part_ids: exchange
                        .parts
                        .iter()
                        .filter(|part| part.treated_as_instruction)
                        .map(|part| part.part_id.clone())
                        .collect(),
                },
            ));
        }

        if exchange.tenant_claim.is_some() || !policy.tenant_policy.is_empty() {
            observations.push(A2aObservation::TenantContext(tenant::assess(
                exchange, peer, policy,
            )));
        }

        if exchange.peak_sensitivity().is_some() || !policy.data_scope_policy.is_empty() {
            observations.push(A2aObservation::DataScopeContext(data_scope::assess(
                exchange, policy,
            )));
        }

        if exchange.is_repeat {
            observations.push(A2aObservation::ReplayContext(replay::assess(
                exchange, policy,
            )));
        }

        if !policy.protocol_policy.is_empty() {
            let advertised = card
                .map(|card| {
                    card.protocol_versions()
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            observations.push(A2aObservation::ProtocolContext(protocol::assess(
                exchange, policy, advertised,
            )));
        }
    }

    // Task/context binding is a property of a *set* of messages, so it is
    // projected once per task rather than once per message: a substitution is
    // only visible across two of them.
    let mut tasks: BTreeMap<&str, Vec<&crate::message::Exchange>> = BTreeMap::new();
    for exchange in &evidence.exchanges.exchanges {
        if let Some(task_id) = exchange.task_id.as_deref() {
            tasks.entry(task_id).or_default().push(exchange);
        }
    }
    for (task_id, exchanges) in tasks {
        observations.push(A2aObservation::TaskContextBindingContext(
            TaskContextBindingContext {
                task_id: task_id.to_owned(),
                context_ids: exchanges
                    .iter()
                    .filter_map(|exchange| exchange.context_id.clone())
                    .collect(),
                initiating_principals: exchanges
                    .iter()
                    .filter_map(|exchange| exchange.initiating_principal.clone())
                    .collect(),
                peer_ids: exchanges
                    .iter()
                    .map(|exchange| exchange.peer_id.clone())
                    .collect(),
                message_count: exchanges.len(),
            },
        ));
    }

    for chain in &evidence.delegation_chains {
        observations.push(A2aObservation::DelegationContext(DelegationContext {
            chain_id: chain.chain_id.clone(),
            hop_count: chain.hops.len(),
            is_connected: chain.is_connected(),
            amplifications: chain.amplifications(),
        }));
    }

    let extensions_used = evidence.extensions_used();
    for card in &evidence.cards {
        for assessment in extension::assess(Some(card), &extensions_used, policy) {
            observations.push(A2aObservation::ExtensionContext(assessment));
        }
    }
    if evidence.cards.is_empty() {
        for assessment in extension::assess(None, &extensions_used, policy) {
            observations.push(A2aObservation::ExtensionContext(assessment));
        }
    }

    for config in &evidence.push_configs {
        observations.push(A2aObservation::PushNotificationContext(
            push_notification::assess(config, policy),
        ));
    }

    ObservationSet::new(observations)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::normalize::tests::evidence;

    #[test]
    fn the_channel_set_is_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = ObservationChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        assert_eq!(names.len(), ObservationChannel::all().len());
        for channel in ObservationChannel::all() {
            assert_eq!(channel.as_str(), channel.as_str().to_uppercase());
        }
        assert!(serde_json::from_str::<ObservationChannel>("\"SOME_NEW_CONTEXT\"").is_err());
    }

    #[test]
    fn an_observation_cannot_carry_a_verdict() {
        // The authority boundary, structural rather than checked. An adapter
        // that could emit a verdict would decide the outcome and reduce the
        // evaluator to transcribing it.
        for hostile in [
            serde_json::json!({ "channel": "MESSAGE_CONTEXT", "verdict": "PASS" }),
            serde_json::json!({ "channel": "VERDICT", "verdict": "FAIL" }),
            serde_json::json!({ "channel": "VIOLATION", "invariant": "X" }),
            serde_json::json!({ "channel": "HARNESS_ERROR", "kind": "ADAPTER_FAILURE",
                                "reason": "x", "is_secure": false }),
        ] {
            assert!(
                serde_json::from_value::<A2aObservation>(hostile).is_err(),
                "an observation carrying a verdict decoded"
            );
        }
    }

    #[test]
    fn a_peer_with_no_authentication_evidence_produces_no_authentication_channel() {
        // The basis for INCONCLUSIVE. A context saying `status: UNRECORDED`
        // reads as an answer; an absent channel is honestly the absence of one.
        let mut bare = evidence();
        bare.peer_authentication.clear();
        let set = project(&bare);
        assert!(set.has_channel(ObservationChannel::PeerIdentityContext));
        assert!(!set.has_channel(ObservationChannel::PeerAuthenticationContext));
    }

    #[test]
    fn a_compliant_bundle_produces_the_channels_its_evidence_supports() {
        let set = project(&evidence());
        for expected in [
            ObservationChannel::AgentCardContext,
            ObservationChannel::PeerIdentityContext,
            ObservationChannel::PeerAuthenticationContext,
            ObservationChannel::MessageContext,
            ObservationChannel::MessageAuthenticationContext,
            ObservationChannel::SecurityRequirementContext,
            ObservationChannel::SkillAuthorizationContext,
            ObservationChannel::MessageAuthorityContext,
            ObservationChannel::TaskContextBindingContext,
            ObservationChannel::DelegationContext,
            ObservationChannel::TenantContext,
            ObservationChannel::DataScopeContext,
            ObservationChannel::ProtocolContext,
        ] {
            assert!(
                set.has_channel(expected),
                "{} is missing",
                expected.as_str()
            );
        }
        // No repeat and no push configuration in the fixture, so neither
        // channel appears — and their absence is what makes those invariants
        // inapplicable rather than undecided.
        assert!(!set.has_channel(ObservationChannel::ReplayContext));
        assert!(!set.has_channel(ObservationChannel::PushNotificationContext));
    }

    #[test]
    fn task_binding_is_projected_once_per_task_rather_than_per_message() {
        // A substitution is only visible across two messages, so the context is
        // a property of the set.
        let evidence = evidence();
        let set = project(&evidence);
        let bindings: Vec<&TaskContextBindingContext> = set
            .observations
            .iter()
            .filter_map(|observation| match observation {
                A2aObservation::TaskContextBindingContext(context) => Some(context),
                _ => None,
            })
            .collect();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].task_id, "task-1");
        assert_eq!(bindings[0].message_count, 1);
    }

    #[test]
    fn the_message_authentication_context_records_whether_it_covered_this_envelope() {
        let set = project(&evidence());
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::MessageAuthenticationContext(context) => Some(context),
                _ => None,
            })
            .expect("a message authentication context");
        assert_eq!(context.covers_observed_envelope, Some(true));
    }

    #[test]
    fn projection_is_deterministic() {
        assert_eq!(
            digest(&project(&evidence())).unwrap(),
            digest(&project(&evidence())).unwrap()
        );
    }

    #[test]
    fn every_observation_digests_and_the_digests_differ() {
        // Deciding-evidence citation is only useful if two different
        // observations cite differently.
        let set = project(&evidence());
        let digests: BTreeSet<String> = set
            .observations
            .iter()
            .map(|observation| observation.digest().expect("digests"))
            .collect();
        assert_eq!(digests.len(), set.observations.len());
    }

    #[test]
    fn a_harness_error_is_a_channel_and_not_a_finding() {
        let set = ObservationSet::new(vec![A2aObservation::HarnessError(HarnessErrorContext {
            kind: HarnessErrorKind::AdapterFailure,
            reason: "the adapter could not read the local evidence directory".to_owned(),
        })]);
        assert!(set.has_harness_error());
        let rendered = serde_json::to_string(&set)
            .expect("serializes")
            .to_lowercase();
        for absent in ["violation", "verdict", "finding", "insecure"] {
            assert!(
                !rendered.contains(absent),
                "a harness error reads as `{absent}`"
            );
        }
    }

    #[test]
    fn no_observation_carries_message_content() {
        // The engine reports *that* peer content crossed into authority. A
        // report reproducing it would be a delivery mechanism for whatever the
        // part contained.
        let rendered = serde_json::to_string(&project(&evidence())).expect("serializes");
        for content_field in ["\"text\":", "\"content\":", "\"body\":", "\"payload\":"] {
            assert!(
                !rendered.contains(content_field),
                "`{content_field}` leaked"
            );
        }
    }
}
