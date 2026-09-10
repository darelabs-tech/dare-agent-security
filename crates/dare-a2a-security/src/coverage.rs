//! Positive PASS contracts.
//!
//! Every invariant declares the observation channels a run must actually have
//! produced before it may report `PASS`. Without this an invariant would pass
//! whenever nothing contradicted it, and a run that observed nothing at all
//! would be indistinguishable from a run that observed a clean exchange.
//!
//! That failure mode is specific and cheap here: hand the engine **an empty
//! trace**. No messages, no peers, no evidence, nothing to disagree with. A
//! coverage contract is what turns that from `PASS` into `INCONCLUSIVE`.
//!
//! # Presence is not comparison
//!
//! A channel can be *present* and carry nothing to compare — the Cycle 019
//! correction, and it applies at least as sharply here. A tenant context exists
//! as soon as either a claim or a policy exists; with only one of them there is
//! no comparison, and reporting `PASS` would be reporting that a boundary held
//! when nothing checked it.
//!
//! So `assess_coverage` runs two steps: the channels the invariant needs must
//! be present, **and** the comparison it makes must have been possible.

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
            "no authentication evidence was collected, so whether the authenticated party is the \
             intended one was never asked",
        ),
        I::MessageAuthenticityEstablished => (
            vec![C::MessageContext, C::MessageAuthenticationContext],
            "no message authentication evidence was collected, so a schema-valid message could \
             not be shown to be an authentic one",
        ),
        I::SecurityRequirementSatisfied => (
            vec![C::MessageContext, C::SecurityRequirementContext],
            "no security-scheme usage was observed, so whether an approved requirement was \
             satisfied could not be decided",
        ),
        I::SkillAuthorized => (
            vec![C::MessageContext, C::SkillAuthorizationContext],
            "no skill invocation was observed against a local grant, so authentication could not \
             be distinguished from authorization",
        ),
        I::MessageAuthorityBoundaryPreserved => (
            vec![C::MessageAuthorityContext],
            "no peer-controlled message was observed, so whether peer content stayed data was \
             never tested",
        ),
        I::TaskContextBindingPreserved => (
            vec![C::MessageContext, C::TaskContextBindingContext],
            "no task correlation was observed, so task, context and principal could not be \
             compared across an exchange",
        ),
        I::AuthorityPropagationBounded => (
            vec![C::DelegationContext],
            "no delegation chain was observed, so whether authority held or widened across a hop \
             was never asked",
        ),
        I::TenantBoundaryPreserved => (
            vec![C::TenantContext],
            "no tenant evidence was observed, so a routing value could not be compared with what \
             policy says the subject belongs to",
        ),
        I::DataScopeBoundaryPreserved => (
            vec![C::DataScopeContext],
            "no data-scope evidence was observed, so disclosure could not be compared with what \
             policy allows",
        ),
        I::ReplayBoundaryPreserved => (
            vec![C::ReplayContext],
            "no repeated exchange was observed, so replay safety was never in question",
        ),
        I::ProtocolNegotiationIntegrityPreserved => (
            vec![C::MessageContext, C::ProtocolContext],
            "no protocol policy was applied, so the version and interface used could not be \
             compared with what is permitted",
        ),
        I::ExtensionTrustBoundaryPreserved => (
            vec![C::ExtensionContext],
            "no extension was declared or used, so extension trust was never in question",
        ),
        I::PushNotificationBoundaryPreserved => (
            vec![C::PushNotificationContext],
            "no push-notification configuration was observed, so its destination and scope could \
             not be compared with policy",
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

/// Whether the comparison an invariant makes could actually be made.
///
/// A channel can be present and carry nothing to compare. A tenant context
/// exists as soon as *either* a claim or a policy does; a protocol context
/// exists whenever a policy does. Without this second step an invariant would
/// report `PASS` because the channel it needed was there, having compared
/// nothing — the same false `PASS` the contracts exist to prevent, one level
/// in.
fn comparison_reason(
    invariant: A2aInvariant,
    observations: &ObservationSet,
) -> Option<&'static str> {
    use A2aInvariant as I;
    use A2aObservation as O;

    let any = |predicate: &dyn Fn(&A2aObservation) -> bool| {
        observations.observations.iter().any(predicate)
    };

    let decided = match invariant {
        I::DiscoveryBindingPreserved => any(&|observation| {
            matches!(observation, O::AgentCardContext(context)
                if context.digest_matches_policy.is_some()
                    || context.provider_matches_policy.is_some()
                    || context.signer_approved.is_some())
        }),
        // Two questions, and the old contract asked only the first.
        // `is_recorded_evidence` answers "was it checked?", which is true of an
        // INDETERMINATE result; positive binding needs "did it pass?", and then
        // needs the authenticated party to be the one policy approved for the
        // role. Every peer must bind: one proven peer does not vouch for a
        // second the run never established.
        I::PeerIdentityBound => {
            let authenticated = observations.observations.iter().any(|observation| {
                matches!(observation, O::PeerAuthenticationContext(context)
                    if context.status.may_satisfy_positive_evidence())
            });
            let every_peer_bound =
                observations
                    .observations
                    .iter()
                    .all(|observation| match observation {
                        O::PeerIdentityContext(context) => context.binding_established(),
                        O::PeerAuthenticationContext(context) => {
                            context.status.may_satisfy_positive_evidence()
                        }
                        _ => true,
                    });
            authenticated && every_peer_bound
        }
        // Two facts, not one. `covers_observed_envelope` says a comparison was
        // made; the status says what the verifier concluded. A signature that
        // covers this envelope under a verification that could not conclude
        // establishes nothing, and accepting it would turn somebody else's
        // uncertainty into our confidence.
        I::MessageAuthenticityEstablished => any(&|observation| {
            matches!(observation, O::MessageAuthenticationContext(context)
                if context.status.may_satisfy_positive_evidence()
                    && context.covers_observed_envelope == Some(true))
        }),
        // Declaring a scheme is not satisfying it. The old contract accepted
        // either comparison merely having been *made*, so a card that requires
        // OAuth and an exchange that named OAuth satisfied coverage with no
        // verification behind them at all.
        I::SecurityRequirementSatisfied => any(&|observation| {
            matches!(observation, O::SecurityRequirementContext(context)
                if context.requirement_established())
        }),
        I::SkillAuthorized => any(&|observation| {
            matches!(observation, O::SkillAuthorizationContext(assessment)
                if assessment.is_decidable())
        }),
        I::TenantBoundaryPreserved => any(
            &|observation| matches!(observation, O::TenantContext(assessment) if assessment.is_decidable()),
        ),
        I::DataScopeBoundaryPreserved => any(
            &|observation| matches!(observation, O::DataScopeContext(assessment) if assessment.is_decidable()),
        ),
        I::ReplayBoundaryPreserved => any(
            &|observation| matches!(observation, O::ReplayContext(assessment) if assessment.is_applicable()),
        ),
        I::ProtocolNegotiationIntegrityPreserved => any(
            &|observation| matches!(observation, O::ProtocolContext(assessment) if assessment.is_decidable()),
        ),
        I::PushNotificationBoundaryPreserved => any(&|observation| {
            matches!(observation, O::PushNotificationContext(assessment)
                if assessment.is_decidable())
        }),
        // These four decide from what was observed alone. There is no approved
        // side that could be missing: a task carrying two contexts is a
        // substitution whatever policy says, a chain that widens has widened,
        // peer content that became instruction crossed, and an extension either
        // was declared and approved or was not.
        I::MessageAuthorityBoundaryPreserved
        | I::TaskContextBindingPreserved
        | I::AuthorityPropagationBounded
        | I::ExtensionTrustBoundaryPreserved => true,
    };

    (!decided).then_some(
        "the channel was observed and carried nothing to compare, so the question stayed open",
    )
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
            reason: format!("every channel {} needs was observed", invariant.as_str()),
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
    use std::collections::BTreeSet;

    #[test]
    fn every_invariant_has_a_contract_and_every_contract_requires_something() {
        // An invariant with an empty contract would pass on an empty run, which
        // is the exact failure the contracts exist to prevent.
        assert_eq!(contracts().len(), A2aInvariant::all().len());
        for contract in contracts() {
            assert!(
                !contract.required.is_empty(),
                "{} may pass having observed nothing",
                contract.invariant.as_str()
            );
            assert!(
                !contract.reason.trim().is_empty(),
                "{} explains nothing when it is undecidable",
                contract.invariant.as_str()
            );
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        // The cheapest false PASS available: hand the engine an empty trace.
        let empty = ObservationSet::default();
        for invariant in A2aInvariant::all() {
            let decision = assess_coverage(invariant, &empty);
            assert!(
                !decision.satisfied,
                "{} passed coverage having observed nothing",
                invariant.as_str()
            );
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_missing_channel_is_named_in_the_reason() {
        // An operator handed "INCONCLUSIVE" learns nothing. One handed the
        // channel that was missing knows what to collect next.
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
        // The false PASS one level in: the channel an invariant needed was
        // there, and it carried one side of a two-sided comparison.
        let mut one_sided = evidence();
        // A tenant claim with no policy to compare it against.
        one_sided.policy.tenant_policy = Default::default();
        let observations = project(&one_sided);

        assert!(observations.has_channel(crate::observation::ObservationChannel::TenantContext));
        let decision = assess_coverage(A2aInvariant::TenantBoundaryPreserved, &observations);
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("nothing to compare"));
    }

    #[test]
    fn the_four_observation_only_invariants_need_no_approved_side() {
        // A task carrying two contexts is a substitution whatever policy says,
        // and a chain that widens has widened. Requiring an approved side for
        // those would make a legitimate PASS impossible without a policy.
        let observations = project(&evidence());
        for invariant in [
            A2aInvariant::MessageAuthorityBoundaryPreserved,
            A2aInvariant::TaskContextBindingPreserved,
            A2aInvariant::AuthorityPropagationBounded,
        ] {
            assert!(
                assess_coverage(invariant, &observations).satisfied,
                "{} was undecidable on a complete bundle",
                invariant.as_str()
            );
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
        // No repeat and no push configuration were staged, so neither is
        // covered — and that is the honest answer rather than a PASS.
        assert!(!satisfied.contains("REPLAY_BOUNDARY_PRESERVED"));
        assert!(!satisfied.contains("PUSH_NOTIFICATION_BOUNDARY_PRESERVED"));
    }

    #[test]
    fn message_authenticity_requires_the_authentication_channel_and_not_just_a_message() {
        // A schema-valid message is not an authentic one, and requiring only
        // the message would let the first stand in for the second.
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
            assert!(
                !decision.reason.to_lowercase().contains(absent),
                "a coverage decision reads as a verdict"
            );
        }
    }
}
