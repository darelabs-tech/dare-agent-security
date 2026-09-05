//! Invariant-specific positive PASS coverage contracts.
//!
//! This module is the mechanism behind the rule that governs the whole cycle:
//!
//! > Absence of evidence is not evidence of absence.
//!
//! Every invariant declares the observation channels it needs before it may say
//! `PASS`. If the run did not observe them, the verdict is `INCONCLUSIVE` — not
//! `PASS`, and not `FAIL`. A run that saw nothing has established nothing, and
//! the report says so instead of rounding silence up to safety.
//!
//! The contract is total over the closed invariant set, so a new invariant
//! cannot be added without deciding what would have to be observed for it to
//! hold.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::IdentityInvariantType;
use crate::observation::{observed_channels, CoverageChannel, IdentityObservationEvent};

/// How the required channels combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChannelRequirement {
    /// Every listed channel must have been observed.
    AllOf,
    /// At least one listed channel must have been observed.
    AnyOf,
}

/// What one invariant needs before it may return `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageContract {
    pub invariant: IdentityInvariantType,
    pub requirement: ChannelRequirement,
    pub channels: Vec<CoverageChannel>,
    /// What to say when the requirement is unmet. Written for an operator who
    /// needs to know what to capture next, not for a machine.
    pub missing_reason: String,
}

/// The outcome of checking coverage for one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDecision {
    pub satisfied: bool,
    pub observed: Vec<CoverageChannel>,
    pub missing: Vec<CoverageChannel>,
    pub reason: String,
}

/// Channels that show authority was actually *exercised*, not merely described.
///
/// Several invariants require one of these in addition to their own channel.
/// Observing a principal is not observing an exercise of authority: a scenario
/// that names an effective principal and then does nothing has not shown that
/// the principal's authority was respected, only that it was written down.
pub const EXERCISE_CHANNELS: [CoverageChannel; 3] = [
    CoverageChannel::OperationRequest,
    CoverageChannel::FinalOperation,
    CoverageChannel::EffectiveAuthority,
];

/// Whether this invariant additionally requires evidence of exercise.
pub fn requires_exercise_channel(invariant: IdentityInvariantType) -> bool {
    matches!(
        invariant,
        IdentityInvariantType::InitiatingPrincipalPreserved
            | IdentityInvariantType::AgentAuthorityNotSubstitutedForUser
            | IdentityInvariantType::TenantBoundaryPreserved
            | IdentityInvariantType::ResourceOwnerBoundaryPreserved
    )
}

/// The coverage contract for one invariant.
///
/// Total over the closed set: adding an invariant forces a decision here about
/// what would have to be observed for it to hold.
pub fn coverage_contract(invariant: IdentityInvariantType) -> CoverageContract {
    use ChannelRequirement::{AllOf, AnyOf};
    use CoverageChannel as C;
    use IdentityInvariantType as I;

    let (requirement, channels, missing_reason): (_, Vec<CoverageChannel>, &str) = match invariant {
        I::InitiatingPrincipalPreserved => (
            AllOf,
            vec![C::PrincipalContext],
            "no principal context was observed, so it could not be shown that the initiating \
             principal was preserved",
        ),
        I::AgentAuthorityNotSubstitutedForUser => (
            AllOf,
            vec![C::PrincipalContext],
            "no principal context was observed, so agent-for-user substitution could not be \
             assessed",
        ),
        I::DelegatedSubjectPreserved => (
            AnyOf,
            vec![C::DelegationEdge, C::DelegationAssertion],
            "no delegation edge or assertion was observed, so subject preservation could not be \
             assessed",
        ),
        I::DelegationScopeNotExceeded => (
            AllOf,
            vec![C::DelegationEdge, C::EffectiveAuthority],
            "delegation scope requires both a delegation edge and the authority actually \
             exercised; one of them was not observed",
        ),
        I::DelegationChainNoPrivilegeAmplification => (
            AllOf,
            vec![C::DelegationEdge],
            "no delegation edge was observed, so chain amplification could not be assessed",
        ),
        I::EffectiveAuthorityWithinSourceCeiling => (
            AllOf,
            vec![C::EffectiveAuthority],
            "no effective authority was observed, so it could not be compared against a ceiling",
        ),
        I::TenantBoundaryPreserved => (
            AllOf,
            vec![C::ResourceContext],
            "no resource context was observed, so the tenant boundary could not be assessed",
        ),
        I::ResourceOwnerBoundaryPreserved => (
            AllOf,
            vec![C::ResourceContext],
            "no resource context was observed, so the resource-owner boundary could not be \
             assessed",
        ),
        I::AuthorizationBoundToFinalOperation => (
            AllOf,
            vec![C::AuthorizationDecision, C::FinalOperation],
            "binding requires both an authorization decision and the operation finally performed; \
             one of them was not observed",
        ),
        I::DenyNotBypassed => (
            AllOf,
            vec![C::PolicyDecision],
            "no policy decision was observed, so a bypass of a denial could not be assessed",
        ),
        I::CredentialContextNotExpandAuthority => (
            AllOf,
            vec![C::CredentialContext, C::EffectiveAuthority],
            "credential-context assessment requires both the credential metadata and the \
             authority actually exercised; one of them was not observed",
        ),
        I::DelegationValidAtUse => (
            AllOf,
            vec![C::DelegationEdge],
            "no delegation edge was observed, so validity at use could not be assessed",
        ),
    };

    CoverageContract {
        invariant,
        requirement,
        channels,
        missing_reason: missing_reason.to_owned(),
    }
}

/// Every contract, in invariant order.
pub fn all_contracts() -> Vec<CoverageContract> {
    IdentityInvariantType::all()
        .into_iter()
        .map(coverage_contract)
        .collect()
}

/// Whether the observed events satisfy an invariant's coverage contract.
pub fn assess_coverage(
    invariant: IdentityInvariantType,
    events: &[IdentityObservationEvent],
) -> CoverageDecision {
    let contract = coverage_contract(invariant);
    let observed = observed_channels(events);

    let mut missing: Vec<CoverageChannel> = Vec::new();
    let satisfied_by_contract = match contract.requirement {
        ChannelRequirement::AllOf => {
            for channel in &contract.channels {
                if !observed.contains(channel) {
                    missing.push(*channel);
                }
            }
            missing.is_empty()
        }
        ChannelRequirement::AnyOf => {
            let any = contract
                .channels
                .iter()
                .any(|channel| observed.contains(channel));
            if !any {
                missing.extend(contract.channels.iter().copied());
            }
            any
        }
    };

    // Some invariants additionally need evidence that authority was exercised.
    // Seeing who someone is does not show what they did.
    let exercise_needed = requires_exercise_channel(invariant);
    let exercise_present = EXERCISE_CHANNELS
        .iter()
        .any(|channel| observed.contains(channel));
    if exercise_needed && !exercise_present {
        missing.extend(EXERCISE_CHANNELS.iter().copied());
    }

    let satisfied = satisfied_by_contract && (!exercise_needed || exercise_present);

    let reason = if satisfied {
        format!(
            "coverage satisfied for {} ({} channel(s) observed)",
            invariant.as_str(),
            observed.len()
        )
    } else if exercise_needed && !exercise_present && satisfied_by_contract {
        format!(
            "{}; no operation or effective-authority observation showed the authority being \
             exercised",
            contract.missing_reason
        )
    } else {
        contract.missing_reason.clone()
    };

    let mut missing_sorted: Vec<CoverageChannel> = missing
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    missing_sorted.dedup();

    CoverageDecision {
        satisfied,
        observed: observed.into_iter().collect(),
        missing: missing_sorted,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;
    use crate::authorization::DecisionEffect;
    use crate::observation::{
        AuthorizationDecisionObserved, CredentialContextObserved, DelegationEdgeObserved,
        EffectiveAuthorityObserved, OperationObserved, PolicyDecisionObserved, PrincipalContext,
    };
    use crate::operation::tests::authorized_operation;
    use crate::resource::tests::same_tenant_resource;
    use crate::source::{DelegationKind, PrincipalKind, PrincipalRole};

    fn principal_event() -> IdentityObservationEvent {
        IdentityObservationEvent::PrincipalContext(PrincipalContext {
            role: PrincipalRole::Effective,
            principal_id: "user-7".to_owned(),
            kind: PrincipalKind::Human,
            tenant_id: Some("tenant-a".to_owned()),
        })
    }

    fn authority_event() -> IdentityObservationEvent {
        IdentityObservationEvent::EffectiveAuthority(EffectiveAuthorityObserved {
            principal_id: "user-7".to_owned(),
            authority: Authority::empty("authority-effective"),
            source_ceiling_id: Some("authority-user-read".to_owned()),
        })
    }

    fn edge_event() -> IdentityObservationEvent {
        IdentityObservationEvent::DelegationEdge(DelegationEdgeObserved {
            edge_id: "edge-1".to_owned(),
            kind: DelegationKind::OnBehalfOf,
            delegator_principal_id: "user-7".to_owned(),
            delegatee_principal_id: "agent-1".to_owned(),
            delegated_subject_id: Some("user-7".to_owned()),
            authority_ceiling_id: "authority-user-read".to_owned(),
        })
    }

    fn operation_event(final_operation: bool) -> IdentityObservationEvent {
        let operation = authorized_operation();
        let projection_digest = operation.projection_digest().expect("digest");
        let observed = OperationObserved {
            operation,
            projection_digest,
            dispatched: false,
        };
        if final_operation {
            IdentityObservationEvent::FinalOperation(observed)
        } else {
            IdentityObservationEvent::OperationRequest(observed)
        }
    }

    fn decision_event() -> IdentityObservationEvent {
        IdentityObservationEvent::AuthorizationDecision(AuthorizationDecisionObserved {
            decision_id: "decision-1".to_owned(),
            effect: DecisionEffect::Permit,
            subject_id: "user-7".to_owned(),
            policy_digest: format!("sha256:{}", "a".repeat(64)),
            bound_operation_digest: format!("sha256:{}", "b".repeat(64)),
            issued_at: Some(100),
        })
    }

    #[test]
    fn the_contract_is_total_over_the_closed_invariant_set() {
        let contracts = all_contracts();
        assert_eq!(contracts.len(), 12);
        for contract in &contracts {
            assert!(
                !contract.channels.is_empty(),
                "{} declares no required channel, so it could PASS on silence",
                contract.invariant.as_str()
            );
            assert!(!contract.missing_reason.trim().is_empty());
        }
    }

    #[test]
    fn silence_is_never_satisfied_for_any_invariant() {
        // The central rule, checked across the whole set at once.
        for invariant in IdentityInvariantType::all() {
            let decision = assess_coverage(invariant, &[]);
            assert!(
                !decision.satisfied,
                "{} claimed coverage from an empty stream",
                invariant.as_str()
            );
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_harness_error_alone_never_satisfies_coverage() {
        use crate::observation::{EvidenceText, HarnessErrorEvent, HarnessErrorKind};
        let events = vec![IdentityObservationEvent::HarnessError(HarnessErrorEvent {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("adapter stopped"),
        })];
        for invariant in IdentityInvariantType::all() {
            assert!(!assess_coverage(invariant, &events).satisfied);
        }
    }

    #[test]
    fn principal_invariants_need_evidence_that_authority_was_exercised() {
        // Seeing who someone is does not show what they did. A scenario that
        // names an effective principal and stops has not shown the boundary
        // held; it has only written the boundary down.
        let only_principal = vec![principal_event()];
        let decision = assess_coverage(
            IdentityInvariantType::InitiatingPrincipalPreserved,
            &only_principal,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("exercised"));

        let with_exercise = vec![principal_event(), operation_event(true)];
        assert!(
            assess_coverage(
                IdentityInvariantType::InitiatingPrincipalPreserved,
                &with_exercise
            )
            .satisfied
        );
    }

    #[test]
    fn tenant_and_owner_invariants_also_need_an_exercise_channel() {
        let only_resource = vec![IdentityObservationEvent::ResourceContext(
            same_tenant_resource(),
        )];
        for invariant in [
            IdentityInvariantType::TenantBoundaryPreserved,
            IdentityInvariantType::ResourceOwnerBoundaryPreserved,
        ] {
            assert!(
                !assess_coverage(invariant, &only_resource).satisfied,
                "{} must not pass on a resource description alone",
                invariant.as_str()
            );
        }

        let with_operation = vec![
            IdentityObservationEvent::ResourceContext(same_tenant_resource()),
            operation_event(false),
        ];
        for invariant in [
            IdentityInvariantType::TenantBoundaryPreserved,
            IdentityInvariantType::ResourceOwnerBoundaryPreserved,
        ] {
            assert!(assess_coverage(invariant, &with_operation).satisfied);
        }
    }

    #[test]
    fn authorization_binding_needs_both_a_decision_and_a_final_operation() {
        let invariant = IdentityInvariantType::AuthorizationBoundToFinalOperation;

        assert!(!assess_coverage(invariant, &[decision_event()]).satisfied);
        assert!(!assess_coverage(invariant, &[operation_event(true)]).satisfied);

        let both = vec![decision_event(), operation_event(true)];
        let decision = assess_coverage(invariant, &both);
        assert!(decision.satisfied, "{}", decision.reason);
    }

    #[test]
    fn a_request_alone_does_not_satisfy_a_final_operation_requirement() {
        // An operation that was asked for is not an operation that happened.
        let invariant = IdentityInvariantType::AuthorizationBoundToFinalOperation;
        let request_only = vec![decision_event(), operation_event(false)];
        let decision = assess_coverage(invariant, &request_only);
        assert!(!decision.satisfied);
        assert!(decision.missing.contains(&CoverageChannel::FinalOperation));
    }

    #[test]
    fn delegated_subject_accepts_either_an_edge_or_an_assertion() {
        use crate::observation::DelegationAssertion;
        let invariant = IdentityInvariantType::DelegatedSubjectPreserved;

        assert!(assess_coverage(invariant, &[edge_event()]).satisfied);

        let assertion = vec![IdentityObservationEvent::DelegationAssertion(
            DelegationAssertion {
                asserted_by_principal_id: "agent-1".to_owned(),
                delegated_subject_id: Some("user-7".to_owned()),
                purpose_id: None,
                backed_by_declared_chain: true,
            },
        )];
        assert!(assess_coverage(invariant, &assertion).satisfied);
    }

    #[test]
    fn delegation_scope_needs_the_edge_and_the_authority_exercised() {
        let invariant = IdentityInvariantType::DelegationScopeNotExceeded;
        assert!(!assess_coverage(invariant, &[edge_event()]).satisfied);
        assert!(!assess_coverage(invariant, &[authority_event()]).satisfied);
        assert!(assess_coverage(invariant, &[edge_event(), authority_event()]).satisfied);
    }

    #[test]
    fn credential_context_needs_the_credential_and_the_authority_exercised() {
        // The invariant is about whether a credential *expanded* authority, so
        // both the credential and the authority actually used are required.
        let invariant = IdentityInvariantType::CredentialContextNotExpandAuthority;
        let credential = IdentityObservationEvent::CredentialContext(CredentialContextObserved {
            credential_context_id: "cred-1".to_owned(),
            owner_principal_id: "svc-index".to_owned(),
            capability_labels: vec!["index.admin".to_owned()],
            tenant_labels: Vec::new(),
            capability_authority: None,
        });

        assert!(!assess_coverage(invariant, std::slice::from_ref(&credential)).satisfied);
        assert!(!assess_coverage(invariant, &[authority_event()]).satisfied);
        assert!(assess_coverage(invariant, &[credential, authority_event()]).satisfied);
    }

    #[test]
    fn deny_bypass_needs_a_policy_decision() {
        let invariant = IdentityInvariantType::DenyNotBypassed;
        assert!(!assess_coverage(invariant, &[operation_event(false)]).satisfied);

        let with_decision = vec![
            IdentityObservationEvent::PolicyDecision(PolicyDecisionObserved {
                operation_key: "document.delete".to_owned(),
                effect: DecisionEffect::Deny,
                policy_id: None,
            }),
            operation_event(false),
        ];
        assert!(assess_coverage(invariant, &with_decision).satisfied);
    }

    #[test]
    fn a_missing_channel_is_named_so_an_operator_knows_what_to_capture() {
        let decision = assess_coverage(
            IdentityInvariantType::AuthorizationBoundToFinalOperation,
            &[decision_event()],
        );
        assert!(!decision.satisfied);
        assert_eq!(decision.missing, vec![CoverageChannel::FinalOperation]);
        assert!(decision.reason.contains("finally performed"));
    }

    #[test]
    fn the_decision_lists_what_was_observed() {
        let events = vec![principal_event(), operation_event(true)];
        let decision =
            assess_coverage(IdentityInvariantType::InitiatingPrincipalPreserved, &events);
        assert!(decision.satisfied);
        assert!(decision
            .observed
            .contains(&CoverageChannel::PrincipalContext));
        assert!(decision.observed.contains(&CoverageChannel::FinalOperation));
        assert!(decision.missing.is_empty());
    }

    #[test]
    fn coverage_assessment_is_deterministic() {
        let events = vec![principal_event(), operation_event(true), authority_event()];
        for invariant in IdentityInvariantType::all() {
            assert_eq!(
                assess_coverage(invariant, &events),
                assess_coverage(invariant, &events)
            );
        }
    }

    #[test]
    fn every_exercise_channel_actually_counts_as_exercise() {
        let invariant = IdentityInvariantType::TenantBoundaryPreserved;
        for exercise in [
            operation_event(false),
            operation_event(true),
            authority_event(),
        ] {
            let events = vec![
                IdentityObservationEvent::ResourceContext(same_tenant_resource()),
                exercise,
            ];
            assert!(assess_coverage(invariant, &events).satisfied);
        }
    }
}
