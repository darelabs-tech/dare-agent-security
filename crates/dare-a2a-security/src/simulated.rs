//! The simulated adapter: an evidence bundle constructed in memory.
//!
//! Every bundle it produces comes from a [`ReferenceBehavior`] — a *behaviour*,
//! never a verdict. `TASK_SUBSTITUTED` says the task id changed under an
//! exchange; it does not say the run should FAIL, and nothing in this file
//! decides that. The evaluator reads the constructed evidence exactly as it
//! reads an imported document and reaches its own conclusion.
//!
//! That separation is what makes the paired corpus worth having. If the staging
//! function also declared the expected outcome, every pair would test whether
//! the fixture author and the evaluator agreed about a label rather than
//! whether the evaluator can see a substitution.

use std::collections::{BTreeMap, BTreeSet};

use crate::agent_card::{
    AgentCard, CardExtension, CardInterface, CardSignatureEvidence, CardSkill,
    DeclaredSecurityScheme,
};
use crate::authentication::{MessageAuthenticationEvidence, PeerAuthenticationEvidence};
use crate::budget::AdmissionLedger;
use crate::delegation::{DelegationChain, DelegationHop};
use crate::error::{A2aSecurityError, Result};
use crate::harness::A2aAdapter;
use crate::message::{Exchange, MessagePart};
use crate::model::A2aScenario;
use crate::normalize::{A2aEvidence, EvidenceBuilder};
use crate::peer::PeerIdentity;
use crate::policy::{
    A2aPolicy, ApprovedPeer, DataScopePolicy, ExtensionPolicy, ProtocolPolicy,
    PushNotificationPolicy, ReplayPolicy, SkillGrant, TenantPolicy,
};
use crate::push_notification::PushNotificationConfig;
use crate::source::{
    A2aMode, DataSensitivity, EvidenceSource, MessageRole, OperationEffect, ReferenceBehavior,
    SecuritySchemeKind, TransportKind, VerificationStatus,
};

/// Construct an evidence bundle from a reference behaviour.
#[derive(Debug, Default)]
pub struct SimulatedAdapter;

impl SimulatedAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl A2aAdapter for SimulatedAdapter {
    fn mode(&self) -> A2aMode {
        A2aMode::Simulated
    }

    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        scenario.validate()?;
        let behavior = scenario.reference_behavior.ok_or_else(|| {
            A2aSecurityError::invalid(format!(
                "scenario `{}` runs in SIMULATED mode without naming a reference behaviour, so \
                 there is nothing to construct",
                scenario.scenario_id
            ))
        })?;
        stage(behavior, ledger)
    }
}

/// Build the bundle one reference behaviour describes.
///
/// Public so the corpus can stage a bundle without going through an adapter,
/// and so a test can assert what a behaviour produces rather than what a run
/// concluded about it.
pub fn stage(behavior: ReferenceBehavior, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    use ReferenceBehavior as B;

    if behavior == B::HarnessFailure {
        // The adapter fails, so the run reports ERROR rather than a security
        // conclusion. A staged harness failure that quietly produced a clean
        // bundle would test the opposite of what it is for.
        return Err(A2aSecurityError::refusal(
            "the staged harness could not assemble an evidence bundle".to_owned(),
        ));
    }

    let mut card = base_card();
    let mut peer = base_peer();
    let mut exchange = base_exchange();
    let mut peer_auth = Some(base_peer_auth());
    let mut message_auth_status = VerificationStatus::Valid;
    let mut message_auth_covers_envelope = true;
    let mut include_message_auth = true;
    let mut chain = Some(base_chain());
    let mut policy = base_policy();
    let mut push_configs: Vec<PushNotificationConfig> = Vec::new();
    let mut extra_exchanges: Vec<Exchange> = Vec::new();

    match behavior {
        B::Compliant | B::HarnessFailure => {}

        B::CardSubstituted => {
            // The policy pinned a digest; the card in hand is a different one.
            policy
                .approved_peers
                .iter()
                .next()
                .map(|approved| approved.peer_id.clone());
            let pinned = crate::canonical::digest_bytes(b"the-card-that-was-approved");
            policy = with_pinned_card_digest(policy, &pinned);
        }
        B::CardSignatureInvalid => {
            card.signature.as_mut().unwrap().status = VerificationStatus::Invalid;
        }
        B::CardSignatureUnrecorded => {
            card.signature = None;
        }
        B::ProviderMismatch => {
            // The card says one provider; the observed exchange says another.
            peer.card_provider = Some("attacker-corp".to_owned());
        }
        B::PeerIdentityMismatch => {
            peer.authenticated_principal = Some("svc-somebody-else".to_owned());
            peer.delegated_subject = None;
            if let Some(auth) = peer_auth.as_mut() {
                auth.principal = Some("svc-somebody-else".to_owned());
                auth.delegated_subject = None;
            }
        }
        B::AudienceMismatch => {
            peer.audience = Some("another-service".to_owned());
        }
        B::AuthenticationInvalid => {
            if let Some(auth) = peer_auth.as_mut() {
                auth.status = VerificationStatus::Invalid;
            }
        }
        B::AuthenticationUnrecorded => {
            peer_auth = None;
            peer.authenticated_principal = None;
            peer.delegated_subject = None;
        }
        B::SecuritySchemeUnsatisfied => {
            // The exchange used a scheme the card does not require for the
            // skill it invoked.
            card.security_schemes.push(DeclaredSecurityScheme {
                scheme_id: "apikey-legacy".to_owned(),
                kind: SecuritySchemeKind::ApiKey,
                issuer: None,
                token_endpoint: None,
                scopes: BTreeSet::new(),
            });
            exchange.security_scheme_used = Some("apikey-legacy".to_owned());
        }
        B::SkillNotAuthorized => {
            peer.delegated_subject = Some("user-mallory".to_owned());
            if let Some(auth) = peer_auth.as_mut() {
                auth.delegated_subject = Some("user-mallory".to_owned());
            }
        }
        B::MessageSignatureInvalid => {
            message_auth_status = VerificationStatus::Invalid;
        }
        B::MessageSignatureMissing => {
            include_message_auth = false;
        }
        B::PeerContentTreatedAsInstruction => {
            exchange.parts[0].treated_as_instruction = true;
        }
        B::TaskSubstituted => {
            // Two messages under one task with different principals.
            let mut second = exchange.clone();
            second.message_id = "msg-2".to_owned();
            second.initiating_principal = Some("user-mallory".to_owned());
            extra_exchanges.push(second);
        }
        B::ContextSubstituted => {
            let mut second = exchange.clone();
            second.message_id = "msg-2".to_owned();
            second.context_id = Some("context-2".to_owned());
            extra_exchanges.push(second);
        }
        B::PrincipalMismatch => {
            let mut second = exchange.clone();
            second.message_id = "msg-2".to_owned();
            second.initiating_principal = Some("user-bob".to_owned());
            extra_exchanges.push(second);
        }
        B::DelegationAmplified => {
            if let Some(chain) = chain.as_mut() {
                chain.hops[1]
                    .allowed_skills
                    .insert("transfer-funds".to_owned());
            }
        }
        B::DelegationChainBroken => {
            if let Some(chain) = chain.as_mut() {
                chain.hops[1].grantor = "somebody-unrelated".to_owned();
            }
        }
        B::CrossTenantAccess => {
            exchange.tenant_claim = Some("tenant-b".to_owned());
        }
        B::TenantClaimUnverified => {
            // A claim with no policy entry for the subject: undecidable rather
            // than a crossing, which is a different answer and a different fix.
            peer.delegated_subject = Some("user-unknown".to_owned());
            if let Some(auth) = peer_auth.as_mut() {
                auth.delegated_subject = Some("user-unknown".to_owned());
            }
        }
        B::DataScopeWidened => {
            exchange.parts[0].data_labels = BTreeSet::from([DataSensitivity::Restricted]);
        }
        B::UnapprovedDestination => {
            push_configs.push(push_config("https://attacker.example/collect"));
            exchange.push_config_id = Some("push-1".to_owned());
        }
        B::ReplayWithoutEvidence => {
            exchange.is_repeat = true;
            exchange.operation_effect = OperationEffect::NonIdempotentStateChange;
            exchange.requested_skill = Some("transfer-funds".to_owned());
            exchange.idempotency_key = None;
            policy.skill_grants.insert(SkillGrant {
                peer_id: "planner".to_owned(),
                skill_id: "transfer-funds".to_owned(),
                allowed_subjects: BTreeSet::from(["user-alice".to_owned()]),
            });
            card.skills.push(CardSkill {
                skill_id: "transfer-funds".to_owned(),
                name: None,
                security_requirements: BTreeSet::from(["oauth-main".to_owned()]),
            });
        }
        B::DuplicateNonIdempotentAction => {
            // The skill must be one the policy does *not* declare idempotent,
            // or the repeat is genuinely proven safe and the behaviour stages
            // nothing. `summarize` is declared idempotent by the base policy.
            exchange.is_repeat = true;
            exchange.operation_effect = OperationEffect::NonIdempotentStateChange;
            exchange.requested_skill = Some("send-invoice".to_owned());
            exchange.idempotency_key = None;
            policy.skill_grants.insert(SkillGrant {
                peer_id: "planner".to_owned(),
                skill_id: "send-invoice".to_owned(),
                allowed_subjects: BTreeSet::from(["user-alice".to_owned()]),
            });
            card.skills.push(CardSkill {
                skill_id: "send-invoice".to_owned(),
                name: None,
                security_requirements: BTreeSet::from(["oauth-main".to_owned()]),
            });
        }
        B::IdempotencyProven => {
            exchange.is_repeat = true;
            exchange.operation_effect = OperationEffect::NonIdempotentStateChange;
            exchange.idempotency_key = Some("idem-1".to_owned());
        }
        B::ProtocolDowngraded => {
            exchange.protocol_version = "0.9.0".to_owned();
            card.interfaces.push(CardInterface {
                url: "https://peer.example/a2a".to_owned(),
                transport: TransportKind::JsonRpc,
                protocol_version: "0.9.0".to_owned(),
            });
        }
        B::ProtocolVersionUnsupported => {
            exchange.protocol_version = "2.0.0".to_owned();
        }
        B::InterfaceNotApproved => {
            exchange.transport = TransportKind::Grpc;
            card.interfaces.push(CardInterface {
                url: "https://peer.example/a2a/grpc".to_owned(),
                transport: TransportKind::Grpc,
                protocol_version: "1.0.0".to_owned(),
            });
        }
        B::ExtensionUndeclared => {
            exchange.extensions_used = BTreeSet::from(["ext-surprise".to_owned()]);
        }
        B::ExtensionUnapproved => {
            card.extensions.push(CardExtension {
                extension_id: "ext-unapproved".to_owned(),
                required: false,
                claims_authority: false,
            });
            exchange.extensions_used = BTreeSet::from(["ext-unapproved".to_owned()]);
        }
        B::RequiredExtensionUnknown => {
            card.extensions.push(CardExtension {
                extension_id: "ext-mandatory-unknown".to_owned(),
                required: true,
                claims_authority: true,
            });
        }
        B::PushDestinationUnapproved => {
            push_configs.push(push_config("https://attacker.example/collect"));
        }
        B::PushScopeWidened => {
            let mut config = push_config("https://callback.example/hook");
            config.max_sensitivity = Some(DataSensitivity::Restricted);
            push_configs.push(config);
        }
        B::MultipleIndependentViolations => {
            // Three boundaries at once, so a run reporting only the first
            // understates what it saw.
            exchange.tenant_claim = Some("tenant-b".to_owned());
            exchange.parts[0].treated_as_instruction = true;
            if let Some(chain) = chain.as_mut() {
                chain.hops[1]
                    .allowed_skills
                    .insert("transfer-funds".to_owned());
            }
        }
        B::NoRelevantObservation => {
            // A bundle with nothing to decide on. The run must report
            // INCONCLUSIVE rather than finding nothing to disagree with and
            // calling that a secure exchange.
            peer_auth = None;
            include_message_auth = false;
            chain = None;
            peer.authenticated_principal = None;
            peer.delegated_subject = None;
            exchange.requested_skill = None;
            exchange.security_scheme_used = None;
            exchange.tenant_claim = None;
            exchange.parts[0].data_labels = BTreeSet::new();
            policy = A2aPolicy::default();
        }
    }

    let envelope_probe = exchange.clone();
    let mut builder = EvidenceBuilder::new()
        .with_document("staged-card.json", "AGENT_CARD", b"{\"staged\":true}")
        .with_card(card)
        .with_peer(peer)
        .with_exchange(exchange);

    for extra in extra_exchanges {
        builder = builder.with_exchange(extra);
    }
    if let Some(auth) = peer_auth {
        builder = builder.with_peer_authentication(auth);
    }
    if include_message_auth {
        // The digest is computed over the envelope as staged, so a compliant
        // fixture genuinely binds and a substituted one genuinely does not.
        let covered = if message_auth_covers_envelope {
            crate::canonical::digest(&envelope_probe)?
        } else {
            crate::canonical::digest_bytes(b"a-different-envelope")
        };
        builder = builder.with_message_authentication(MessageAuthenticationEvidence {
            message_id: "msg-1".to_owned(),
            status: message_auth_status,
            signer_key_id: Some("key-1".to_owned()),
            covered_envelope_digest: Some(covered),
            recorded_by: EvidenceSource::RecordedVerification,
        });
    }
    if let Some(chain) = chain {
        builder = builder.with_delegation_chain(chain);
    }
    for config in push_configs {
        builder = builder.with_push_config(config);
    }

    let _ = &mut message_auth_covers_envelope;
    builder.with_policy(policy).build(ledger)
}

fn with_pinned_card_digest(mut policy: A2aPolicy, digest: &str) -> A2aPolicy {
    let mut peers = BTreeSet::new();
    for mut approved in policy.approved_peers.into_iter() {
        if approved.peer_id == "planner" {
            approved.expected_card_digest = Some(digest.to_owned());
        }
        peers.insert(approved);
    }
    policy.approved_peers = peers;
    policy
}

fn base_card() -> AgentCard {
    AgentCard {
        card_id: "planner".to_owned(),
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

fn base_peer() -> PeerIdentity {
    PeerIdentity {
        peer_id: "planner".to_owned(),
        logical_agent_id: "planner".to_owned(),
        card_provider: Some("acme".to_owned()),
        endpoint_identity: Some("peer.example".to_owned()),
        authenticated_principal: Some("svc-planner".to_owned()),
        delegated_subject: Some("user-alice".to_owned()),
        tenant: Some("tenant-a".to_owned()),
        audience: Some("local-orchestrator".to_owned()),
        evidence_source: EvidenceSource::CapturedTrace,
    }
}

fn base_exchange() -> Exchange {
    Exchange {
        message_id: "msg-1".to_owned(),
        peer_id: "planner".to_owned(),
        role: MessageRole::RemotePeer,
        sender_claim: Some("svc-planner".to_owned()),
        task_id: Some("task-1".to_owned()),
        context_id: Some("context-1".to_owned()),
        tenant_claim: Some("tenant-a".to_owned()),
        initiating_principal: Some("user-alice".to_owned()),
        requested_skill: Some("summarize".to_owned()),
        protocol_version: "1.0.0".to_owned(),
        transport: TransportKind::JsonRpc,
        interface_url: Some("https://peer.example/a2a".to_owned()),
        security_scheme_used: Some("oauth-main".to_owned()),
        delegation_chain_id: Some("chain-1".to_owned()),
        operation_effect: OperationEffect::ReadOnly,
        idempotency_key: None,
        is_repeat: false,
        parts: vec![MessagePart {
            part_id: "part-1".to_owned(),
            kind: "text".to_owned(),
            bytes: 128,
            treated_as_instruction: false,
            data_labels: BTreeSet::from([DataSensitivity::Internal]),
        }],
        extensions_used: BTreeSet::new(),
        push_config_id: None,
        metadata: BTreeMap::new(),
        evidence_source: EvidenceSource::CapturedTrace,
    }
}

fn base_peer_auth() -> PeerAuthenticationEvidence {
    PeerAuthenticationEvidence {
        peer_id: "planner".to_owned(),
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

fn base_chain() -> DelegationChain {
    let hop = |id: &str, grantor: &str, grantee: &str, skills: BTreeSet<String>| DelegationHop {
        hop_id: id.to_owned(),
        grantor: grantor.to_owned(),
        grantee: grantee.to_owned(),
        subject: "user-alice".to_owned(),
        audience: Some("local-orchestrator".to_owned()),
        tenant: Some("tenant-a".to_owned()),
        allowed_skills: skills,
        max_sensitivity: Some(DataSensitivity::Internal),
        purpose: Some("summarize-report".to_owned()),
        evidence_source: EvidenceSource::LocalDelegationRecord,
    };
    DelegationChain {
        chain_id: "chain-1".to_owned(),
        hops: vec![
            hop(
                "hop-1",
                "user-alice",
                "orchestrator",
                BTreeSet::from(["summarize".to_owned(), "search".to_owned()]),
            ),
            hop(
                "hop-2",
                "orchestrator",
                "planner",
                BTreeSet::from(["summarize".to_owned()]),
            ),
        ],
    }
}

fn push_config(destination: &str) -> PushNotificationConfig {
    PushNotificationConfig {
        config_id: "push-1".to_owned(),
        destination: destination.to_owned(),
        tenant: Some("tenant-a".to_owned()),
        max_sensitivity: Some(DataSensitivity::Internal),
        destination_verification: VerificationStatus::Unrecorded,
        evidence_source: EvidenceSource::CapturedTrace,
    }
}

fn base_policy() -> A2aPolicy {
    A2aPolicy {
        schema_version: "1".to_owned(),
        policy_id: Some("staged-policy".to_owned()),
        approved_peers: BTreeSet::from([ApprovedPeer {
            peer_id: "planner".to_owned(),
            expected_logical_agent: Some("planner".to_owned()),
            expected_provider: Some("acme".to_owned()),
            expected_card_digest: None,
            expected_audience: Some("local-orchestrator".to_owned()),
            approved_interfaces: BTreeSet::from([
                "https://peer.example/a2a".to_owned(),
                "https://peer.example/a2a/grpc".to_owned(),
            ]),
            approved_scheme_kinds: BTreeSet::from([SecuritySchemeKind::OAuth2AuthorizationCode]),
            approved_signers: BTreeSet::from(["key-1".to_owned()]),
            requires_delegated_identity: true,
        }]),
        skill_grants: BTreeSet::from([SkillGrant {
            peer_id: "planner".to_owned(),
            skill_id: "summarize".to_owned(),
            allowed_subjects: BTreeSet::from(["user-alice".to_owned()]),
        }]),
        tenant_policy: TenantPolicy {
            subject_tenants: BTreeMap::from([("user-alice".to_owned(), "tenant-a".to_owned())]),
            tenant_peers: BTreeMap::from([(
                "tenant-a".to_owned(),
                BTreeSet::from(["planner".to_owned()]),
            )]),
        },
        data_scope_policy: DataScopePolicy {
            peer_max_sensitivity: BTreeMap::from([(
                "planner".to_owned(),
                DataSensitivity::Internal,
            )]),
            approved_destinations: BTreeSet::from(["https://callback.example/hook".to_owned()]),
        },
        replay_policy: ReplayPolicy {
            idempotent_skills: BTreeSet::from(["summarize".to_owned()]),
            requires_idempotency_key: true,
        },
        protocol_policy: ProtocolPolicy {
            approved_versions: BTreeSet::from(["1.0.0".to_owned()]),
            approved_transports: BTreeSet::from([TransportKind::JsonRpc]),
            minimum_version: Some("1.0.0".to_owned()),
        },
        extension_policy: ExtensionPolicy {
            approved_extensions: BTreeSet::from(["ext-trace".to_owned()]),
            authority_bearing_extensions: BTreeSet::new(),
        },
        push_notification_policy: PushNotificationPolicy {
            approved_destinations: BTreeSet::from(["https://callback.example/hook".to_owned()]),
            max_sensitivity: Some(DataSensitivity::Internal),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::{aggregate, collect_observed_violations, evaluate, evaluate_all};
    use crate::model::{tests::scenario, A2aInvariant};
    use crate::observation::project;
    use dare_security_evidence::Verdict;

    fn staged(behavior: ReferenceBehavior) -> A2aEvidence {
        let mut ledger = AdmissionLedger::new();
        stage(behavior, &mut ledger).expect("stages")
    }

    #[test]
    fn the_compliant_behaviour_produces_no_violation_at_all() {
        // The control. If this failed, every vulnerable fixture would be
        // agreeing with a broken baseline rather than demonstrating a
        // difference.
        let violations =
            collect_observed_violations(&project(&staged(ReferenceBehavior::Compliant)));
        assert!(violations.is_empty(), "{violations:#?}");
    }

    #[test]
    fn every_reference_behaviour_stages_and_only_the_harness_failure_refuses() {
        // A behaviour that could not be staged would silently drop a corpus
        // entry while the count still looked right.
        for behavior in ReferenceBehavior::all() {
            let mut ledger = AdmissionLedger::new();
            let staged = stage(behavior, &mut ledger);
            if behavior == ReferenceBehavior::HarnessFailure {
                assert!(staged.is_err(), "the staged harness failure succeeded");
            } else {
                staged.unwrap_or_else(|error| panic!("{behavior:?} could not be staged: {error}"));
            }
        }
    }

    #[test]
    fn each_vulnerable_behaviour_is_seen_by_the_invariant_it_targets() {
        use A2aInvariant as I;
        use ReferenceBehavior as B;

        for (behavior, expected) in [
            (B::CardSubstituted, I::DiscoveryBindingPreserved),
            (B::CardSignatureInvalid, I::DiscoveryBindingPreserved),
            (B::ProviderMismatch, I::DiscoveryBindingPreserved),
            (B::AudienceMismatch, I::PeerIdentityBound),
            (B::AuthenticationInvalid, I::PeerIdentityBound),
            (
                B::MessageSignatureInvalid,
                I::MessageAuthenticityEstablished,
            ),
            (
                B::SecuritySchemeUnsatisfied,
                I::SecurityRequirementSatisfied,
            ),
            (B::SkillNotAuthorized, I::SkillAuthorized),
            (
                B::PeerContentTreatedAsInstruction,
                I::MessageAuthorityBoundaryPreserved,
            ),
            (B::TaskSubstituted, I::TaskContextBindingPreserved),
            (B::ContextSubstituted, I::TaskContextBindingPreserved),
            (B::PrincipalMismatch, I::TaskContextBindingPreserved),
            (B::DelegationAmplified, I::AuthorityPropagationBounded),
            (B::DelegationChainBroken, I::AuthorityPropagationBounded),
            (B::CrossTenantAccess, I::TenantBoundaryPreserved),
            (B::DataScopeWidened, I::DataScopeBoundaryPreserved),
            (B::ReplayWithoutEvidence, I::ReplayBoundaryPreserved),
            (B::DuplicateNonIdempotentAction, I::ReplayBoundaryPreserved),
            (
                B::ProtocolDowngraded,
                I::ProtocolNegotiationIntegrityPreserved,
            ),
            (
                B::ProtocolVersionUnsupported,
                I::ProtocolNegotiationIntegrityPreserved,
            ),
            (
                B::InterfaceNotApproved,
                I::ProtocolNegotiationIntegrityPreserved,
            ),
            (B::ExtensionUndeclared, I::ExtensionTrustBoundaryPreserved),
            (B::ExtensionUnapproved, I::ExtensionTrustBoundaryPreserved),
            (
                B::RequiredExtensionUnknown,
                I::ExtensionTrustBoundaryPreserved,
            ),
            (
                B::PushDestinationUnapproved,
                I::PushNotificationBoundaryPreserved,
            ),
            (B::PushScopeWidened, I::PushNotificationBoundaryPreserved),
            (
                B::UnapprovedDestination,
                I::PushNotificationBoundaryPreserved,
            ),
        ] {
            let outcome = evaluate(expected, &project(&staged(behavior)));
            assert_eq!(
                outcome.verdict,
                Verdict::Fail,
                "{behavior:?} was not seen by {}: {}",
                expected.as_str(),
                outcome.reason
            );
        }
    }

    #[test]
    fn a_proven_idempotent_repeat_is_not_a_finding() {
        // A control that looks like an attack. Repeating with a key is the
        // system working, and reporting it would train an operator to skim
        // past the repeats that matter.
        let outcome = evaluate(
            A2aInvariant::ReplayBoundaryPreserved,
            &project(&staged(ReferenceBehavior::IdempotencyProven)),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn an_unverifiable_tenant_claim_is_undecidable_rather_than_a_crossing() {
        // A different answer and a different fix. The subject is unknown to
        // policy, so nobody established which tenant they are in.
        let outcome = evaluate(
            A2aInvariant::TenantBoundaryPreserved,
            &project(&staged(ReferenceBehavior::TenantClaimUnverified)),
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
    }

    #[test]
    fn an_unrecorded_card_signature_is_not_a_finding() {
        // One nobody checked is a gap. Reporting it as a finding would make
        // every unsigned card look like an attack.
        let outcome = evaluate(
            A2aInvariant::DiscoveryBindingPreserved,
            &project(&staged(ReferenceBehavior::CardSignatureUnrecorded)),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn a_missing_message_signature_is_undecidable_rather_than_invalid() {
        // "Nobody signed it" and "the signature failed" are different findings
        // with different fixes.
        let outcome = evaluate(
            A2aInvariant::MessageAuthenticityEstablished,
            &project(&staged(ReferenceBehavior::MessageSignatureMissing)),
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
    }

    #[test]
    fn the_multi_violation_behaviour_retains_every_independent_finding() {
        let invariants: BTreeSet<&str> = collect_observed_violations(&project(&staged(
            ReferenceBehavior::MultipleIndependentViolations,
        )))
        .iter()
        .map(|violation| violation.invariant.as_str())
        .collect();

        assert!(invariants.contains("TENANT_BOUNDARY_PRESERVED"));
        assert!(invariants.contains("MESSAGE_AUTHORITY_BOUNDARY_PRESERVED"));
        assert!(invariants.contains("AUTHORITY_PROPAGATION_BOUNDED"));
    }

    #[test]
    fn a_run_with_nothing_to_decide_on_is_inconclusive_rather_than_clean() {
        // The failure mode the coverage contracts exist for: an engine that
        // finds nothing to disagree with must not call that a secure exchange.
        let observations = project(&staged(ReferenceBehavior::NoRelevantObservation));
        assert!(collect_observed_violations(&observations).is_empty());
        assert_eq!(
            aggregate(&evaluate_all(&observations)),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn a_compliant_run_aggregates_to_pass() {
        let outcomes = evaluate_all(&project(&staged(ReferenceBehavior::Compliant)));
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.verdict != Verdict::Fail));
        assert_eq!(aggregate(&outcomes), Verdict::Pass);
    }

    #[test]
    fn staging_is_deterministic() {
        assert_eq!(
            crate::canonical::digest(&staged(ReferenceBehavior::CrossTenantAccess)).unwrap(),
            crate::canonical::digest(&staged(ReferenceBehavior::CrossTenantAccess)).unwrap()
        );
    }

    #[test]
    fn the_staged_bundle_carries_no_expected_outcome() {
        // A behaviour is a behaviour. If staging also declared the outcome,
        // every pair would test whether the fixture author and the evaluator
        // agreed about a label.
        let rendered = serde_json::to_string(&staged(ReferenceBehavior::CrossTenantAccess))
            .expect("serializes")
            .to_lowercase();
        // Verdict-shaped field names specifically. A bare `expected` would also
        // match the policy's own `expected_audience` and `expected_provider`,
        // which are approvals rather than outcomes — the same substring trap
        // that cost Cycle 013 a red build.
        for absent in [
            "expected_verdict",
            "expected_findings",
            "expected_outcome",
            "\"verdict\"",
            "should_fail",
            "is_secure",
        ] {
            assert!(
                !rendered.contains(absent),
                "the staged bundle carries `{absent}`"
            );
        }
    }

    #[test]
    fn a_simulated_scenario_without_a_behaviour_is_refused() {
        // There would be nothing to construct, and returning an empty bundle
        // would report INCONCLUSIVE for a fixture that was simply
        // misconfigured.
        let mut plain = scenario("a2a-lab-sim", A2aInvariant::TenantBoundaryPreserved);
        plain.mode = A2aMode::Simulated;
        plain.reference_behavior = None;
        let mut ledger = AdmissionLedger::new();
        assert!(SimulatedAdapter::new()
            .collect(&plain, &mut ledger)
            .is_err());
    }

    #[test]
    fn simulated_evidence_is_synthetic() {
        assert!(SimulatedAdapter::new().evidence_is_synthetic());
        assert_eq!(SimulatedAdapter::new().mode(), A2aMode::Simulated);
    }
}
