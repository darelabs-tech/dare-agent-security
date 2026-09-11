//! Positive PASS contracts.
//!
//! Every invariant declares the observation channels a run must actually have
//! produced before it may report `PASS`. Without this an invariant would pass
//! whenever nothing contradicted it, and a run that observed nothing at all
//! would be indistinguishable from a run that observed a clean exchange.
//!
//! Presence alone is not enough. Coverage is evaluated per applicable security
//! subject: one authenticated peer cannot cover another peer, one authenticated
//! message cannot cover another message, and one decided exchange cannot lend
//! its evidence to a second undecided exchange.

use serde::{Deserialize, Serialize};

use crate::model::A2aInvariant;
use crate::observation::{A2aObservation, ObservationChannel, ObservationSet};

/// How the required channels combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRequirement {
    /// Every listed channel must be present.
    AllOf,
}

/// What one invariant needs before it may report `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageContract {
    pub invariant: A2aInvariant,
    pub requirement: ChannelRequirement,
    pub required: Vec<ObservationChannel>,
    /// Why a missing channel makes the question undecidable, in operator terms.
    pub reason: &'static str,
}

/// The outcome of checking a contract against what a run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDecision {
    pub satisfied: bool,
    pub missing: Vec<ObservationChannel>,
    pub reason: String,
}

/// The contract for one invariant.
pub fn contract(invariant: A2aInvariant) -> CoverageContract {
    use A2aInvariant as I;
    use ObservationChannel as C;

    let (required, reason): (Vec<C>, &'static str) = match invariant {
        I::DiscoveryBindingPreserved => (
            vec![C::AgentCardContext],
            "no Agent Card was read, so there was no discovery document to bind against a policy",
        ),
        I::PeerIdentityBound => (
            vec![C::PeerIdentityContext, C::PeerAuthenticationContext],
            "no authentication evidence was collected, so whether the authenticated party is the intended one was never asked",
        ),
        I::MessageAuthenticityEstablished => (
            vec![C::MessageContext, C::MessageAuthenticationContext],
            "no message authentication evidence was collected, so a schema-valid message could not be shown to be an authentic one",
        ),
        I::SecurityRequirementSatisfied => (
            vec![C::MessageContext, C::SecurityRequirementContext],
            "no security-scheme usage was observed, so whether an approved requirement was satisfied could not be decided",
        ),
        I::SkillAuthorized => (
            vec![C::MessageContext, C::SkillAuthorizationContext],
            "no skill invocation was observed against a local grant, so authentication could not be distinguished from authorization",
        ),
        I::MessageAuthorityBoundaryPreserved => (
            vec![C::MessageAuthorityContext],
            "no peer-controlled message was observed, so whether peer content stayed data was never tested",
        ),
        I::TaskContextBindingPreserved => (
            vec![C::MessageContext, C::TaskContextBindingContext],
            "no task correlation was observed, so task, context and principal could not be compared across an exchange",
        ),
        I::AuthorityPropagationBounded => (
            vec![C::DelegationContext],
            "no delegation chain was observed, so whether authority held or widened across a hop was never asked",
        ),
        I::TenantBoundaryPreserved => (
            vec![C::TenantContext],
            "no tenant evidence was observed, so a routing value could not be compared with what policy says the subject belongs to",
        ),
        I::DataScopeBoundaryPreserved => (
            vec![C::DataScopeContext],
            "no data-scope evidence was observed, so disclosure could not be compared with what policy allows",
        ),
        I::ReplayBoundaryPreserved => (
            vec![C::ReplayContext],
            "no repeated exchange was observed, so replay safety was never in question",
        ),
        I::ProtocolNegotiationIntegrityPreserved => (
            vec![C::MessageContext, C::ProtocolContext],
            "no protocol policy was applied, so the version and interface used could not be compared with what is permitted",
        ),
        I::ExtensionTrustBoundaryPreserved => (
            vec![C::ExtensionContext],
            "no extension was declared or used, so extension trust was never in question",
        ),
        I::PushNotificationBoundaryPreserved => (
            vec![C::PushNotificationContext],
            "no push-notification configuration was observed, so its destination and scope could not be compared with policy",
        ),
    };

    CoverageContract {
        invariant,
        requirement: ChannelRequirement::AllOf,
        required,
        reason,
    }
}

/// Every contract, in invariant order.
pub fn contracts() -> Vec<CoverageContract> {
    A2aInvariant::all().iter().copied().map(contract).collect()
}

fn subject_gap(kind: &str, id: &str, detail: &str) -> String {
    format!("the {kind} `{id}` remained undecided: {detail}")
}

/// Whether every applicable subject for an invariant carried enough evidence
/// to support a positive decision.
///
/// This is intentionally universal, not existential. `any(decided)` is unsafe
/// for multi-peer and multi-message runs because a single good subject can then
/// lend its evidence to a second subject that has no deciding evidence at all.
fn comparison_reason(invariant: A2aInvariant, observations: &ObservationSet) -> Option<String> {
    use A2aInvariant as I;
    use A2aObservation as O;

    match invariant {
        I::DiscoveryBindingPreserved => {
            for observation in &observations.observations {
                let O::AgentCardContext(context) = observation else {
                    continue;
                };
                let compared = context.digest_matches_policy.is_some()
                    || context.provider_matches_policy.is_some()
                    || context.signer_approved.is_some();
                if !compared {
                    return Some(subject_gap(
                        "Agent Card for peer",
                        &context.peer_id,
                        "no digest, provider or approved-signer comparison was available",
                    ));
                }
            }
            None
        }
        I::PeerIdentityBound => {
            for observation in &observations.observations {
                let O::PeerIdentityContext(identity) = observation else {
                    continue;
                };

                if !identity.binding_established() {
                    return Some(subject_gap(
                        "peer",
                        &identity.peer_id,
                        "the logical agent/provider/audience/delegated-identity binding was not fully established",
                    ));
                }

                let authentication = observations.observations.iter().find_map(|candidate| {
                    match candidate {
                        O::PeerAuthenticationContext(authentication)
                            if authentication.peer_id == identity.peer_id =>
                        {
                            Some(authentication)
                        }
                        _ => None,
                    }
                });

                match authentication {
                    Some(authentication)
                        if authentication.status.may_satisfy_positive_evidence() => {}
                    Some(_) => {
                        return Some(subject_gap(
                            "peer",
                            &identity.peer_id,
                            "authentication evidence exists for this peer but is not VALID",
                        ));
                    }
                    None => {
                        return Some(subject_gap(
                            "peer",
                            &identity.peer_id,
                            "no authentication evidence is bound to this peer",
                        ));
                    }
                }
            }
            None
        }
        I::MessageAuthenticityEstablished => {
            for observation in &observations.observations {
                let O::MessageContext(message) = observation else {
                    continue;
                };

                let authentication = observations.observations.iter().find_map(|candidate| {
                    match candidate {
                        O::MessageAuthenticationContext(authentication)
                            if authentication.message_id == message.message_id =>
                        {
                            Some(authentication)
                        }
                        _ => None,
                    }
                });

                match authentication {
                    Some(authentication)
                        if authentication.status.may_satisfy_positive_evidence()
                            && authentication.covers_observed_envelope == Some(true) => {}
                    Some(_) => {
                        return Some(subject_gap(
                            "message",
                            &message.message_id,
                            "its authentication is not both VALID and bound to the exact observed envelope",
                        ));
                    }
                    None => {
                        return Some(subject_gap(
                            "message",
                            &message.message_id,
                            "no authentication evidence is bound to this message",
                        ));
                    }
                }
            }
            None
        }
        I::SecurityRequirementSatisfied => {
            for observation in &observations.observations {
                let O::MessageContext(message) = observation else {
                    continue;
                };

                let requirement = observations.observations.iter().find_map(|candidate| {
                    match candidate {
                        O::SecurityRequirementContext(requirement)
                            if requirement.message_id == message.message_id
                                && requirement.peer_id == message.peer_id =>
                        {
                            Some(requirement)
                        }
                        _ => None,
                    }
                });

                match requirement {
                    Some(requirement) if requirement.requirement_established() => {}
                    Some(_) => {
                        return Some(subject_gap(
                            "message",
                            &message.message_id,
                            "the security mechanism used by this exchange was not fully established against card, policy and VALID verification evidence",
                        ));
                    }
                    None => {
                        return Some(subject_gap(
                            "message",
                            &message.message_id,
                            "no security-requirement evidence is bound to this exchange",
                        ));
                    }
                }
            }
            None
        }
        I::SkillAuthorized => {
            for observation in &observations.observations {
                let O::SkillAuthorizationContext(assessment) = observation else {
                    continue;
                };
                if !assessment.is_decidable() {
                    return Some(subject_gap(
                        "skill invocation in message",
                        &assessment.message_id,
                        "the effective subject and local grant were not both established",
                    ));
                }
            }
            None
        }
        I::MessageAuthorityBoundaryPreserved => None,
        I::TaskContextBindingPreserved => {
            for observation in &observations.observations {
                let O::TaskContextBindingContext(context) = observation else {
                    continue;
                };
                if context.context_ids.len() != 1 {
                    return Some(subject_gap(
                        "task",
                        &context.task_id,
                        "exactly one observed context id is required to establish context preservation",
                    ));
                }
                if context.initiating_principals.len() != 1 {
                    return Some(subject_gap(
                        "task",
                        &context.task_id,
                        "exactly one initiating principal is required to establish principal preservation",
                    ));
                }
            }
            None
        }
        I::AuthorityPropagationBounded => None,
        I::TenantBoundaryPreserved => {
            for observation in &observations.observations {
                let O::TenantContext(assessment) = observation else {
                    continue;
                };
                if assessment.claim_matches_policy != Some(true) {
                    return Some(subject_gap(
                        "tenant binding for message",
                        &assessment.message_id,
                        "the claimed tenant was not positively matched to local policy",
                    ));
                }
                if assessment.tenant_may_reach_peer != Some(true) {
                    return Some(subject_gap(
                        "tenant routing for message",
                        &assessment.message_id,
                        "local policy did not positively establish that the policy tenant may reach this peer",
                    ));
                }
            }
            None
        }
        I::DataScopeBoundaryPreserved => {
            for observation in &observations.observations {
                let O::DataScopeContext(assessment) = observation else {
                    continue;
                };
                if assessment.within_ceiling != Some(true) {
                    return Some(subject_gap(
                        "data scope for message",
                        &assessment.message_id,
                        "the message was not positively shown to remain within the peer sensitivity ceiling",
                    ));
                }
            }
            None
        }
        I::ReplayBoundaryPreserved => {
            let mut saw_applicable = false;
            for observation in &observations.observations {
                let O::ReplayContext(assessment) = observation else {
                    continue;
                };
                if !assessment.is_applicable() {
                    continue;
                }
                saw_applicable = true;
                if assessment.replay_is_safe != Some(true) {
                    return Some(subject_gap(
                        "replay for message",
                        &assessment.message_id,
                        "the repeated state-changing operation was not positively proven safe to repeat",
                    ));
                }
            }
            if saw_applicable {
                None
            } else {
                Some(
                    "the replay channel was observed but contained no state-changing repeat that requires replay evidence"
                        .to_owned(),
                )
            }
        }
        I::ProtocolNegotiationIntegrityPreserved => {
            for observation in &observations.observations {
                let O::ProtocolContext(assessment) = observation else {
                    continue;
                };
                if !assessment.is_decidable() {
                    return Some(subject_gap(
                        "protocol negotiation for message",
                        &assessment.message_id,
                        "neither version nor transport could be compared with local policy",
                    ));
                }
            }
            None
        }
        I::ExtensionTrustBoundaryPreserved => None,
        I::PushNotificationBoundaryPreserved => {
            for observation in &observations.observations {
                let O::PushNotificationContext(assessment) = observation else {
                    continue;
                };
                if assessment.destination_approved != Some(true) {
                    return Some(subject_gap(
                        "push configuration",
                        &assessment.config_id,
                        "the callback destination was not positively matched to local policy",
                    ));
                }
                if !assessment
                    .destination_verification
                    .may_satisfy_positive_evidence()
                {
                    return Some(subject_gap(
                        "push configuration",
                        &assessment.config_id,
                        "destination verification is missing, inconclusive or otherwise not VALID",
                    ));
                }
            }
            None
        }
    }
}

/// Check one invariant's contract against what a run observed.
pub fn assess_coverage(invariant: A2aInvariant, observations: &ObservationSet) -> CoverageDecision {
    let contract = contract(invariant);
    let present = observations.channels();
    let missing: Vec<ObservationChannel> = contract
        .required
        .iter()
        .copied()
        .filter(|channel| !present.contains(channel))
        .collect();

    if missing.is_empty() {
        if let Some(undecided) = comparison_reason(invariant, observations) {
            return CoverageDecision {
                satisfied: false,
                missing,
                reason: format!("{} ({undecided})", contract.reason),
            };
        }
        return CoverageDecision {
            satisfied: true,
            missing,
            reason: format!(
                "every channel {} needs was observed for every applicable subject",
                invariant.as_str()
            ),
        };
    }

    let names: Vec<&str> = missing.iter().map(|channel| channel.as_str()).collect();
    CoverageDecision {
        satisfied: false,
        reason: format!("{} (missing: {})", contract.reason, names.join(", ")),
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::tests::evidence;
    use crate::observation::project;
    use dare_security_evidence::Verdict;
    use std::collections::BTreeSet;

    #[test]
    fn every_invariant_has_a_contract_and_every_contract_requires_something() {
        assert_eq!(contracts().len(), A2aInvariant::all().len());
        for contract in contracts() {
            assert!(!contract.required.is_empty());
            assert!(!contract.reason.trim().is_empty());
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        let empty = ObservationSet::default();
        for invariant in A2aInvariant::all() {
            let decision = assess_coverage(invariant, &empty);
            assert!(!decision.satisfied, "{} passed coverage having observed nothing", invariant.as_str());
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_missing_channel_is_named_in_the_reason() {
        let mut bare = evidence();
        bare.push_configs.clear();
        let observations = project(&bare);
        let decision = assess_coverage(
            A2aInvariant::PushNotificationBoundaryPreserved,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("PUSH_NOTIFICATION_CONTEXT"));
    }

    #[test]
    fn a_present_channel_that_compared_nothing_does_not_satisfy_a_contract() {
        let mut one_sided = evidence();
        one_sided.policy.tenant_policy = Default::default();
        let observations = project(&one_sided);
        let decision = assess_coverage(A2aInvariant::TenantBoundaryPreserved, &observations);
        assert!(!decision.satisfied);
    }

    #[test]
    fn observation_only_invariants_need_no_approved_side() {
        let observations = project(&evidence());
        for invariant in [
            A2aInvariant::MessageAuthorityBoundaryPreserved,
            A2aInvariant::AuthorityPropagationBounded,
        ] {
            assert!(assess_coverage(invariant, &observations).satisfied);
        }
    }

    #[test]
    fn a_compliant_bundle_covers_the_invariants_its_evidence_supports() {
        let observations = project(&evidence());
        let satisfied: BTreeSet<&str> = A2aInvariant::all()
            .iter()
            .filter(|invariant| assess_coverage(**invariant, &observations).satisfied)
            .map(|invariant| invariant.as_str())
            .collect();

        assert!(satisfied.contains("DISCOVERY_BINDING_PRESERVED"));
        assert!(satisfied.contains("PEER_IDENTITY_BOUND"));
        assert!(satisfied.contains("MESSAGE_AUTHENTICITY_ESTABLISHED"));
        assert!(satisfied.contains("SKILL_AUTHORIZED"));
        assert!(satisfied.contains("TENANT_BOUNDARY_PRESERVED"));
        assert!(!satisfied.contains("REPLAY_BOUNDARY_PRESERVED"));
        assert!(!satisfied.contains("PUSH_NOTIFICATION_BOUNDARY_PRESERVED"));
    }

    #[test]
    fn message_authenticity_requires_the_authentication_channel_and_not_just_a_message() {
        let contract = contract(A2aInvariant::MessageAuthenticityEstablished);
        assert!(contract
            .required
            .contains(&crate::observation::ObservationChannel::MessageAuthenticationContext));
    }

    #[test]
    fn a_satisfied_contract_says_so_without_claiming_a_verdict() {
        let observations = project(&evidence());
        let decision = assess_coverage(A2aInvariant::TaskContextBindingPreserved, &observations);
        assert!(decision.satisfied);
        for absent in ["pass", "fail", "secure", "violation"] {
            assert!(!decision.reason.to_lowercase().contains(absent));
        }
    }

    #[test]
    fn one_valid_peer_does_not_cover_a_second_peer_without_authentication() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::PeerIdentityContext(context) => Some(context.clone()),
                _ => None,
            })
            .expect("baseline peer identity");
        second.peer_id = "reviewer".to_owned();
        second.logical_agent_id = "reviewer".to_owned();
        observations
            .observations
            .push(A2aObservation::PeerIdentityContext(second));

        let decision = assess_coverage(A2aInvariant::PeerIdentityBound, &observations);
        assert!(!decision.satisfied);
        let outcome = crate::invariant::evaluate(A2aInvariant::PeerIdentityBound, &observations);
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn one_authenticated_message_does_not_cover_a_second_message_without_authentication() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::MessageContext(context) => Some(context.clone()),
                _ => None,
            })
            .expect("baseline message");
        second.message_id = "msg-2".to_owned();
        second.correlation_key = "correlation-2".to_owned();
        observations
            .observations
            .push(A2aObservation::MessageContext(second));

        let decision = assess_coverage(A2aInvariant::MessageAuthenticityEstablished, &observations);
        assert!(!decision.satisfied);
        let outcome = crate::invariant::evaluate(
            A2aInvariant::MessageAuthenticityEstablished,
            &observations,
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn one_established_security_requirement_does_not_cover_a_second_exchange() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::MessageContext(context) => Some(context.clone()),
                _ => None,
            })
            .expect("baseline message");
        second.message_id = "msg-2".to_owned();
        second.correlation_key = "correlation-2".to_owned();
        observations
            .observations
            .push(A2aObservation::MessageContext(second));

        let decision = assess_coverage(A2aInvariant::SecurityRequirementSatisfied, &observations);
        assert!(!decision.satisfied);
        let outcome = crate::invariant::evaluate(
            A2aInvariant::SecurityRequirementSatisfied,
            &observations,
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn a_decided_skill_invocation_does_not_cover_an_undecided_one() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::SkillAuthorizationContext(assessment) => Some(assessment.clone()),
                _ => None,
            })
            .expect("baseline skill assessment");
        second.message_id = "msg-2".to_owned();
        second.allowed = None;
        observations
            .observations
            .push(A2aObservation::SkillAuthorizationContext(second));
        assert!(!assess_coverage(A2aInvariant::SkillAuthorized, &observations).satisfied);
    }

    #[test]
    fn a_decided_tenant_binding_does_not_cover_an_undecided_one() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::TenantContext(assessment) => Some(assessment.clone()),
                _ => None,
            })
            .expect("baseline tenant assessment");
        second.message_id = "msg-2".to_owned();
        second.claim_matches_policy = None;
        observations
            .observations
            .push(A2aObservation::TenantContext(second));
        assert!(!assess_coverage(A2aInvariant::TenantBoundaryPreserved, &observations).satisfied);
    }

    #[test]
    fn a_decided_data_scope_does_not_cover_an_undecided_one() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::DataScopeContext(assessment) => Some(assessment.clone()),
                _ => None,
            })
            .expect("baseline data-scope assessment");
        second.message_id = "msg-2".to_owned();
        second.within_ceiling = None;
        observations
            .observations
            .push(A2aObservation::DataScopeContext(second));
        assert!(!assess_coverage(A2aInvariant::DataScopeBoundaryPreserved, &observations).satisfied);
    }

    #[test]
    fn a_decided_protocol_exchange_does_not_cover_an_undecided_one() {
        let mut observations = project(&evidence());
        let mut second = observations
            .observations
            .iter()
            .find_map(|observation| match observation {
                A2aObservation::ProtocolContext(assessment) => Some(assessment.clone()),
                _ => None,
            })
            .expect("baseline protocol assessment");
        second.message_id = "msg-2".to_owned();
        second.version_approved = None;
        second.transport_approved = None;
        observations
            .observations
            .push(A2aObservation::ProtocolContext(second));
        assert!(!assess_coverage(
            A2aInvariant::ProtocolNegotiationIntegrityPreserved,
            &observations,
        )
        .satisfied);
    }

    #[test]
    fn push_destination_verification_must_be_valid_for_positive_coverage() {
        use crate::push_notification::PushNotificationAssessment;
        use crate::source::VerificationStatus;

        let observations = ObservationSet::new(vec![A2aObservation::PushNotificationContext(
            PushNotificationAssessment {
                config_id: "push-1".to_owned(),
                destination: "https://callback.example/hook".to_owned(),
                destination_approved: Some(true),
                within_sensitivity_ceiling: Some(true),
                destination_verification: VerificationStatus::Unrecorded,
            },
        )]);

        let decision = assess_coverage(A2aInvariant::PushNotificationBoundaryPreserved, &observations);
        assert!(!decision.satisfied);
        let outcome = crate::invariant::evaluate(
            A2aInvariant::PushNotificationBoundaryPreserved,
            &observations,
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
    }
}
