//! Positive PASS coverage contracts.
//!
//! Every invariant declares the observation channels a run must actually have
//! produced before it may report `PASS`. Without this, an invariant would pass
//! whenever nothing contradicted it, and a run that observed nothing at all
//! would be indistinguishable from a run that observed a clean flow.
//!
//! Some invariants need an extra thing: an **exercise** channel. Seeing an
//! authorization server's metadata proves nothing about whether a token was
//! ever presented to a resource. The distinction is between what the
//! deployment *is* and what it *did*, and only the second kind of evidence can
//! support a claim that a boundary held under use.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::McpAuthInvariantType;
use crate::observation::{CoverageChannel, McpAuthObservation};

/// How the required channels combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRequirement {
    /// Every listed channel must be present.
    AllOf,
}

/// What one invariant needs before it may report `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageContract {
    pub invariant: McpAuthInvariantType,
    pub requirement: ChannelRequirement,
    pub required: Vec<CoverageChannel>,
    /// Why a missing channel makes the question undecidable, in operator terms.
    pub reason: &'static str,
}

/// The outcome of checking a contract against what a run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDecision {
    pub satisfied: bool,
    pub missing: Vec<CoverageChannel>,
    pub reason: String,
}

/// Channels that prove the deployment *did* something rather than merely
/// *has* something.
///
/// An invariant requiring one of these cannot pass on configuration evidence
/// alone.
pub const EXERCISE_CHANNELS: [CoverageChannel; 4] = [
    CoverageChannel::OperationContext,
    CoverageChannel::AuthorizationResponse,
    CoverageChannel::ResourceAudience,
    CoverageChannel::CredentialFlow,
];

/// Invariants that are about what was done, not what exists.
pub fn requires_exercise_channel(invariant: McpAuthInvariantType) -> bool {
    use McpAuthInvariantType as I;
    matches!(
        invariant,
        I::McpMethodHeaderBodyBindingPreserved
            | I::McpNameHeaderBodyBindingPreserved
            | I::AuthorizationResponseIssuerPreserved
            | I::TokenResourceAudienceBoundaryPreserved
            | I::InboundCredentialNotReusedAsUpstreamAuthority
            | I::FinalOperationAuthorizationBindingPreserved
    )
}

/// The contract for one invariant. Total over all fifteen.
pub fn coverage_contract(invariant: McpAuthInvariantType) -> CoverageContract {
    use CoverageChannel as C;
    use McpAuthInvariantType as I;

    let (required, reason): (Vec<C>, &'static str) = match invariant {
        I::McpProtocolRevisionPreserved => (
            vec![C::ProtocolContext],
            "deciding whether a supported revision was in use needs the revision the request \
             actually declared",
        ),
        I::McpMethodHeaderBodyBindingPreserved => (
            vec![C::HeaderContext, C::OperationContext],
            "deciding whether routing agreed with the body needs both sides; one alone is a \
             statement about what was routed or what was asked, never about whether they matched",
        ),
        I::McpNameHeaderBodyBindingPreserved => (
            vec![C::HeaderContext, C::OperationContext],
            "the operation name has the same two sides as the method, and the same rule",
        ),
        I::ProtectedResourceMetadataBoundToResource => (
            vec![C::ProtectedResourceMetadata],
            "deciding whether metadata is bound to the resource under test needs the metadata and \
             the resource",
        ),
        I::AuthorizationServerIssuerBoundaryPreserved => (
            vec![C::ProtectedResourceMetadata, C::AuthorizationServerMetadata],
            "deciding whether the selected authorization server was one the resource advertises \
             needs both the resource's advertisement and the server's own metadata",
        ),
        I::AuthorizationResponseIssuerPreserved => (
            vec![C::AuthorizationRequest, C::AuthorizationResponse],
            "an issuer mix-up is a disagreement between what was selected and what answered; \
             observing only one side cannot show a disagreement",
        ),
        I::TokenResourceAudienceBoundaryPreserved => (
            vec![C::TokenClaims, C::ResourceAudience],
            "deciding whether a token is for this resource needs the token's claims and the \
             resource the request was actually for",
        ),
        I::TokenValidityEvidencePresent => (
            vec![C::TokenClaims],
            "deciding whether validity evidence exists needs the token projection that would \
             carry it",
        ),
        I::PkceBindingPreserved => (
            vec![C::Pkce],
            "deciding whether a challenge and a verifier correspond needs the flow evidence that \
             records both",
        ),
        I::RedirectStateBindingPreserved => (
            vec![C::RedirectState],
            "deciding whether a response arrived where it was meant to needs the redirect and \
             state correlation evidence",
        ),
        I::ScopeStepUpDoesNotDropRequiredScope => (
            vec![C::ScopeChallenge],
            "deciding whether a step-up dropped a scope needs the challenge and the retry it \
             produced",
        ),
        I::ClientRegistrationMetadataTrustPreserved => (
            vec![C::ClientRegistration],
            "deciding whether registration metadata was over-trusted needs the metadata and its \
             recorded provenance",
        ),
        I::InboundCredentialNotReusedAsUpstreamAuthority => (
            vec![C::CredentialFlow],
            "deciding whether an inbound credential was forwarded needs both sides of the \
             credential flow; a run that never observed an upstream call has nothing to say",
        ),
        I::SelfReportedMetadataNotAuthority => (
            vec![C::IdentityMetadata],
            "deciding whether self-description was promoted to authority needs the identity \
             evidence that would show the promotion; without it the run has nothing to say in \
             either direction",
        ),
        I::FinalOperationAuthorizationBindingPreserved => (
            vec![C::FinalOperationBinding, C::OperationContext],
            "deciding whether authorization still covers what was performed needs the binding and \
             the operation that was actually performed",
        ),
    };

    CoverageContract {
        invariant,
        requirement: ChannelRequirement::AllOf,
        required,
        reason,
    }
}

/// Check what a run observed against an invariant's contract.
pub fn assess_coverage(
    invariant: McpAuthInvariantType,
    observations: &[McpAuthObservation],
) -> CoverageDecision {
    let contract = coverage_contract(invariant);
    let present: BTreeSet<CoverageChannel> =
        observations.iter().filter_map(|o| o.channel()).collect();

    let missing: Vec<CoverageChannel> = contract
        .required
        .iter()
        .copied()
        .filter(|channel| !present.contains(channel))
        .collect();

    if missing.is_empty() {
        // One channel needs more than presence to satisfy its contract.
        //
        // `TOKEN_CLAIMS_CONTEXT` is the projection that *would* carry a
        // verification result. Observing it proves the projection exists, not
        // that anybody verified anything — and for
        // `TOKEN_VALIDITY_EVIDENCE_PRESENT` the projection is the container,
        // not the answer.
        //
        // Without this, a run that observed a token whose validity was UNKNOWN
        // and was never accepted had its required channel present, no violation
        // to report, and therefore PASSed — reporting "validity evidence is
        // present" about a token nobody had checked. That is the exact shape of
        // absence-as-satisfaction this cycle exists to refuse.
        if invariant == McpAuthInvariantType::TokenValidityEvidencePresent {
            if let Some(reason) = unverified_token_reason(observations) {
                return CoverageDecision {
                    satisfied: false,
                    missing: vec![CoverageChannel::TokenClaims],
                    reason,
                };
            }
        }
        return CoverageDecision {
            satisfied: true,
            missing,
            reason: format!("every channel {} requires was observed", invariant.as_str()),
        };
    }

    let names: Vec<&str> = missing.iter().map(|channel| channel.as_str()).collect();
    CoverageDecision {
        satisfied: false,
        missing,
        reason: format!("{}: missing {}", contract.reason, names.join(", ")),
    }
}

/// Why an observed token projection does not itself answer the validity
/// question.
///
/// `None` when every observed token carries a recorded verification result,
/// whatever that result was. A REJECTED or EXPIRED token *has* been verified;
/// the answer was unfavourable, which is a verdict rather than a gap.
fn unverified_token_reason(observations: &[McpAuthObservation]) -> Option<String> {
    for observation in observations {
        let McpAuthObservation::TokenClaims { token } = observation else {
            continue;
        };
        let Some(claims) = &token.presented else {
            continue;
        };
        if !claims.validity.is_positive_evidence() {
            return Some(format!(
                "the token projection was observed but token `{}` carries validity {}: a \
                 projection that could hold a verification result is not a verification result",
                claims.token_id,
                claims.validity.as_str()
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tests::identity_context;
    use crate::metadata::tests::resource_context;

    fn operation() -> McpAuthObservation {
        McpAuthObservation::OperationContext {
            request_id: "req-1".to_owned(),
            method: "tools/call".to_owned(),
            name: Some("create-invoice".to_owned()),
        }
    }

    fn header() -> McpAuthObservation {
        McpAuthObservation::HeaderContext {
            request_id: "req-1".to_owned(),
            routed_method: Some("tools/call".to_owned()),
            routed_name: Some("create-invoice".to_owned()),
        }
    }

    #[test]
    fn the_contract_is_total_over_the_fifteen_invariants() {
        // A missing contract would mean an invariant with no stated evidence
        // requirement, which is an invariant that can pass on nothing.
        for invariant in McpAuthInvariantType::all() {
            let contract = coverage_contract(invariant);
            assert_eq!(contract.invariant, invariant);
            assert!(
                !contract.required.is_empty(),
                "{} requires no channel",
                invariant.as_str()
            );
            assert!(!contract.reason.is_empty());
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        // The failure mode the whole module exists to prevent.
        for invariant in McpAuthInvariantType::all() {
            let decision = assess_coverage(invariant, &[]);
            assert!(
                !decision.satisfied,
                "{} was satisfied by nothing",
                invariant.as_str()
            );
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_run_of_only_harness_errors_satisfies_no_contract() {
        // "We could not look" is not "we looked and it was fine".
        let observations = vec![McpAuthObservation::HarnessError {
            kind: crate::source::HarnessErrorKind::AdapterFailure,
            detail: crate::observation::EvidenceText::from_raw("stopped"),
        }];
        for invariant in McpAuthInvariantType::all() {
            assert!(!assess_coverage(invariant, &observations).satisfied);
        }
    }

    #[test]
    fn one_side_of_a_two_sided_question_is_not_enough() {
        // Routing metadata alone says what was routed. It cannot say whether
        // that matched the body.
        let decision = assess_coverage(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &[header()],
        );
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&CoverageChannel::OperationContext));

        let both = assess_coverage(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &[header(), operation()],
        );
        assert!(both.satisfied);
    }

    #[test]
    fn seeing_metadata_is_not_the_same_as_running_a_flow() {
        // Configuration evidence cannot support a claim that a boundary held
        // under use.
        let observations = vec![McpAuthObservation::ProtectedResourceMetadata {
            resource: resource_context(),
        }];
        let decision = assess_coverage(
            McpAuthInvariantType::AuthorizationResponseIssuerPreserved,
            &observations,
        );
        assert!(!decision.satisfied);
    }

    #[test]
    fn the_did_something_invariants_require_an_exercise_channel() {
        for invariant in McpAuthInvariantType::all() {
            if !requires_exercise_channel(invariant) {
                continue;
            }
            let contract = coverage_contract(invariant);
            assert!(
                contract
                    .required
                    .iter()
                    .any(|channel| EXERCISE_CHANNELS.contains(channel)),
                "{} claims to need an exercise channel but requires none",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn naming_an_invariant_as_exercise_requiring_matches_its_actual_contract() {
        // The mirror: an invariant whose contract includes an exercise channel
        // but which is not declared as needing one would have the classifier
        // and the contract disagreeing.
        for invariant in McpAuthInvariantType::all() {
            let contract = coverage_contract(invariant);
            let has_exercise = contract
                .required
                .iter()
                .any(|channel| EXERCISE_CHANNELS.contains(channel));
            assert_eq!(
                has_exercise,
                requires_exercise_channel(invariant),
                "{} disagrees with its own contract about exercise evidence",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn a_decision_reports_what_was_missing_and_why() {
        // "Inconclusive" alone is not actionable. An operator needs to know
        // which channel to go and record.
        let decision = assess_coverage(McpAuthInvariantType::PkceBindingPreserved, &[operation()]);
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("PKCE_CONTEXT"));
        assert!(decision.reason.contains("challenge"));
    }

    #[test]
    fn an_unrelated_observation_does_not_satisfy_a_contract() {
        let observations = vec![McpAuthObservation::IdentityMetadata {
            identity: identity_context(),
        }];
        assert!(
            !assess_coverage(
                McpAuthInvariantType::TokenValidityEvidencePresent,
                &observations
            )
            .satisfied
        );
    }
}
