//! Invariant-specific positive coverage contracts.
//!
//! The rule this module exists to enforce: **PASS is never the absence of a
//! FAIL.** Every invariant declares the observation channels a run must
//! actually have produced before it may say the boundary held. A run that
//! observed nothing observed nothing, and the honest verdict for that is
//! `INCONCLUSIVE`.
//!
//! Two ideas are kept apart here, because collapsing them is how a retrieval
//! engine ends up certifying silence:
//!
//! - a **required** channel is evidence the invariant reads;
//! - an **exercise** channel is proof the boundary was actually approached.
//!
//! Seeing a policy is not the same as running a query, and running a query is
//! not the same as returning results. An invariant about what a *result set*
//! did cannot be satisfied by a run that never produced one — so the boundary
//! invariants require a result set, not merely a policy.
//!
//! The content-trust invariant goes one step further and requires an influence
//! observation. A retriever that returned untrusted content and was never asked
//! to act on it has not demonstrated that the content stayed data; it has
//! demonstrated that nobody looked.

use serde::{Deserialize, Serialize};

use crate::model::RagInvariantType;
use crate::observation::{observed_channels, CoverageChannel, RagObservationEvent};

/// Whether every listed channel is needed, or any one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChannelRequirement {
    AllOf,
    AnyOf,
}

/// What one invariant needs before it may report `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageContract {
    pub invariant: RagInvariantType,
    pub requirement: ChannelRequirement,
    pub channels: Vec<CoverageChannel>,
    /// Why a missing channel makes the question undecidable, in operator terms.
    pub missing_reason: String,
}

/// The outcome of checking a contract against what a run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDecision {
    pub satisfied: bool,
    pub required: Vec<CoverageChannel>,
    pub observed: Vec<CoverageChannel>,
    pub missing: Vec<CoverageChannel>,
    pub reason: String,
}

/// Channels that prove the boundary was *exercised* rather than merely present.
///
/// A declared policy proves a policy exists. It proves nothing about whether a
/// retrieval was attempted under it.
pub const EXERCISE_CHANNELS: [CoverageChannel; 2] = [
    CoverageChannel::ResultSetObserved,
    CoverageChannel::InfluenceObserved,
];

/// Invariants that additionally require the boundary to have been exercised.
///
/// These are the invariants about what retrieval *did*, not about what was
/// configured. Without an exercise channel, a clean-looking run is a run where
/// nothing was tried.
pub fn requires_exercise_channel(invariant: RagInvariantType) -> bool {
    use RagInvariantType as I;
    matches!(
        invariant,
        I::RetrievalPrincipalBoundaryPreserved
            | I::RetrievalTenantBoundaryPreserved
            | I::RetrievalCollectionBoundaryPreserved
            | I::DocumentAclEnforced
            | I::ProtectedDocumentNotRetrieved
            | I::UntrustedRetrievedContentNotPromotedToAuthority
    )
}

/// The contract for one invariant. Total over the closed set.
pub fn coverage_contract(invariant: RagInvariantType) -> CoverageContract {
    use ChannelRequirement::AllOf;
    use CoverageChannel as C;
    use RagInvariantType as I;

    let (requirement, channels, missing_reason): (_, Vec<CoverageChannel>, &str) = match invariant {
        I::RetrievalPrincipalBoundaryPreserved => (
            AllOf,
            vec![
                C::RetrievalContextObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether a result crossed a principal boundary needs the acting principal, \
             the returned results and the owner each document declares; without all three the \
             comparison has no second side",
        ),
        I::RetrievalTenantBoundaryPreserved => (
            AllOf,
            vec![
                C::RetrievalContextObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether a result crossed a tenant boundary needs the acting tenant, the \
             returned results and the tenant each document declares",
        ),
        I::RetrievalCollectionBoundaryPreserved => (
            AllOf,
            vec![
                C::QueryObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether a result came from an unaddressed collection needs the query's \
             collection scope, the returned results and the collection each document belongs to",
        ),
        I::DocumentAclEnforced => (
            AllOf,
            vec![
                C::RetrievalPolicyObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether an unauthorized document was returned needs the policy, the \
             returned results and the identity of each document",
        ),
        I::MetadataFilterEnforced => (
            AllOf,
            vec![C::QueryObserved, C::FilterDecisionObserved],
            "deciding whether a mandatory filter was enforced needs the declared filter and the \
             admission decision made for each document",
        ),
        I::ProtectedDocumentNotRetrieved => (
            AllOf,
            vec![
                C::RetrievalPolicyObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether a protected document was disclosed needs the protected set, the \
             returned results and the identity and classification of each document",
        ),
        I::RetrievalProvenancePreserved => (
            AllOf,
            vec![C::RetrievedChunkObserved, C::ProvenanceContextObserved],
            "deciding whether provenance survived retrieval needs the returned chunks and the \
             provenance the corpus declares for them",
        ),
        I::ChunkDocumentBindingPreserved => (
            AllOf,
            vec![C::RetrievedChunkObserved],
            "deciding whether a chunk still belongs to the document it claims needs the returned \
             chunks, each carrying both the claim and the corpus binding",
        ),
        I::ResultSetWithinApprovedCandidates => (
            AllOf,
            vec![C::CandidateSetObserved, C::ResultSetObserved],
            "deciding whether a result was injected needs both the approved candidate set and \
             the returned results; one without the other has nothing to compare",
        ),
        I::TopKBoundPreserved => (
            AllOf,
            vec![
                C::QueryObserved,
                C::RetrievalPolicyObserved,
                C::ResultSetObserved,
            ],
            "deciding whether top-k held needs the requested count, the allowed ceiling and the \
             count actually returned",
        ),
        I::UntrustedRetrievedContentNotPromotedToAuthority => (
            AllOf,
            vec![C::TrustContextObserved, C::InfluenceObserved],
            "deciding whether untrusted content stayed data needs both the trust class it was \
             treated as and an explicit influence observation; content returned and never acted \
             on demonstrates that nobody looked, not that the boundary held",
        ),
        I::RetrievalFallbackDoesNotWidenAuthority => (
            AllOf,
            vec![
                C::RetrievalPolicyObserved,
                C::ResultSetObserved,
                C::DocumentContextObserved,
            ],
            "deciding whether a fallback widened authority needs the policy it ran under, the \
             results it produced and the scope each returned document belongs to",
        ),
    };

    CoverageContract {
        invariant,
        requirement,
        channels,
        missing_reason: missing_reason.to_owned(),
    }
}

/// Check a run's observations against one invariant's contract.
pub fn assess_coverage(
    invariant: RagInvariantType,
    events: &[RagObservationEvent],
) -> CoverageDecision {
    let contract = coverage_contract(invariant);
    let observed = observed_channels(events);

    let missing: Vec<CoverageChannel> = match contract.requirement {
        ChannelRequirement::AllOf => contract
            .channels
            .iter()
            .filter(|channel| !observed.contains(channel))
            .copied()
            .collect(),
        ChannelRequirement::AnyOf => {
            if contract
                .channels
                .iter()
                .any(|channel| observed.contains(channel))
            {
                Vec::new()
            } else {
                contract.channels.clone()
            }
        }
    };

    let exercised = !requires_exercise_channel(invariant)
        || EXERCISE_CHANNELS
            .iter()
            .any(|channel| observed.contains(channel));

    let satisfied = missing.is_empty() && exercised;
    let reason = if satisfied {
        format!(
            "every channel invariant {} requires was observed",
            invariant.as_str()
        )
    } else if !exercised {
        format!(
            "invariant {} is about what retrieval did, and no result set or influence was \
             observed; nothing was tried",
            invariant.as_str()
        )
    } else {
        contract.missing_reason.clone()
    };

    CoverageDecision {
        satisfied,
        required: contract.channels,
        observed,
        missing,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{EvidenceText, HarnessErrorKind};

    fn context_event() -> RagObservationEvent {
        RagObservationEvent::RetrievalContext {
            context_id: "context-support".to_owned(),
            acting_principal_id: "user-7".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            collection_ids: vec!["col-support".to_owned()],
        }
    }

    fn result_set_event() -> RagObservationEvent {
        RagObservationEvent::RankedResultSet {
            query_id: "query-1".to_owned(),
            result_set_digest: crate::canonical::content_digest("results"),
            result_count: 1,
            used_fallback: false,
            chunk_ids: vec!["chunk-a".to_owned()],
        }
    }

    fn document_event() -> RagObservationEvent {
        RagObservationEvent::DocumentContext {
            query_id: "query-1".to_owned(),
            document: crate::observation::ResolvedDocument::from_document(
                &crate::document::tests::store().documents[0],
            ),
        }
    }

    #[test]
    fn the_contract_is_total_over_the_twelve_invariants() {
        // A missing contract would mean an invariant with no coverage rule,
        // which is exactly the invariant that would PASS on silence.
        for invariant in RagInvariantType::all() {
            let contract = coverage_contract(invariant);
            assert_eq!(contract.invariant, invariant);
            assert!(
                !contract.channels.is_empty(),
                "{invariant:?} requires no channel at all"
            );
            assert!(
                !contract.missing_reason.trim().is_empty(),
                "{invariant:?} gives no reason a missing channel is undecidable"
            );
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        // The core rule. Nothing observed means nothing established, for every
        // invariant without exception.
        for invariant in RagInvariantType::all() {
            let decision = assess_coverage(invariant, &[]);
            assert!(
                !decision.satisfied,
                "{invariant:?} was satisfied by an empty run"
            );
            assert!(!decision.reason.trim().is_empty());
        }
    }

    #[test]
    fn a_run_of_only_harness_errors_satisfies_no_contract() {
        // A failed run is not a clean run.
        let events = vec![RagObservationEvent::HarnessError {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("failed"),
        }];
        for invariant in RagInvariantType::all() {
            assert!(!assess_coverage(invariant, &events).satisfied);
        }
    }

    #[test]
    fn seeing_a_policy_is_not_the_same_as_running_a_query() {
        // The distinction the exercise channel exists for: a target that
        // declares a perfect policy and never retrieves anything has not
        // demonstrated that the policy holds.
        let events = vec![RagObservationEvent::RetrievalPolicy {
            policy_id: "policy-1".to_owned(),
            policy_digest: crate::canonical::content_digest("policy"),
            max_top_k: 4,
            cross_tenant_allowed: false,
            cross_owner_allowed: false,
            fallback_allowed: true,
        }];
        let decision = assess_coverage(RagInvariantType::DocumentAclEnforced, &events);
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("nothing was tried") || !decision.missing.is_empty());
    }

    #[test]
    fn the_six_did_something_invariants_require_an_exercise_channel() {
        let exercise_requiring: Vec<&str> = RagInvariantType::all()
            .into_iter()
            .filter(|invariant| requires_exercise_channel(*invariant))
            .map(RagInvariantType::as_str)
            .collect();

        assert_eq!(
            exercise_requiring,
            vec![
                "RETRIEVAL_PRINCIPAL_BOUNDARY_PRESERVED",
                "RETRIEVAL_TENANT_BOUNDARY_PRESERVED",
                "RETRIEVAL_COLLECTION_BOUNDARY_PRESERVED",
                "DOCUMENT_ACL_ENFORCED",
                "PROTECTED_DOCUMENT_NOT_RETRIEVED",
                "UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY",
            ]
        );
    }

    #[test]
    fn naming_an_invariant_as_exercise_requiring_matches_its_actual_contract() {
        // An invariant flagged as exercise-requiring whose contract lists no
        // exercise channel would be unsatisfiable, and one not flagged whose
        // contract needs one would be flagged twice. Both are silent bugs.
        for invariant in RagInvariantType::all() {
            if !requires_exercise_channel(invariant) {
                continue;
            }
            let contract = coverage_contract(invariant);
            assert!(
                contract
                    .channels
                    .iter()
                    .any(|channel| EXERCISE_CHANNELS.contains(channel)),
                "{invariant:?} requires exercise but its contract lists no exercise channel"
            );
        }
    }

    #[test]
    fn the_tenant_contract_needs_all_three_of_its_channels() {
        let invariant = RagInvariantType::RetrievalTenantBoundaryPreserved;

        // Acting tenant alone: no results to compare against.
        let decision = assess_coverage(invariant, &[context_event()]);
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&CoverageChannel::ResultSetObserved));

        // Results without document facts: nothing says which tenant they are in.
        let decision = assess_coverage(invariant, &[context_event(), result_set_event()]);
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&CoverageChannel::DocumentContextObserved));

        // All three: decidable.
        let decision = assess_coverage(
            invariant,
            &[context_event(), result_set_event(), document_event()],
        );
        assert!(decision.satisfied, "{}", decision.reason);
        assert!(decision.missing.is_empty());
    }

    #[test]
    fn content_trust_needs_an_influence_observation_and_not_merely_a_retrieval() {
        // A retriever that returned untrusted content nobody acted on has
        // demonstrated that nobody looked.
        let invariant = RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority;
        let trust = RagObservationEvent::TrustContext {
            document_id: "doc-external".to_owned(),
            declared_trust_class: crate::source::DocumentTrustClass::Untrusted,
            source_trust_ceiling: crate::source::DocumentTrustClass::Reference,
            policy_trust_ceiling: crate::source::DocumentTrustClass::TrustedPolicy,
            treated_as: crate::source::DocumentTrustClass::Untrusted,
        };

        let decision = assess_coverage(invariant, &[trust.clone(), result_set_event()]);
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&CoverageChannel::InfluenceObserved));

        let influence = RagObservationEvent::Influence {
            document_id: "doc-external".to_owned(),
            chunk_id: None,
            target: crate::observation::InfluenceTarget::Objective,
            field: None,
            baseline_value: None,
            observed_value: None,
            changed: false,
            treated_as_trust_class: Some(crate::source::DocumentTrustClass::Untrusted),
        };
        let decision = assess_coverage(invariant, &[trust, influence]);
        assert!(decision.satisfied, "{}", decision.reason);
    }

    #[test]
    fn result_set_integrity_needs_both_sides_of_the_comparison() {
        let invariant = RagInvariantType::ResultSetWithinApprovedCandidates;
        let candidates = RagObservationEvent::CandidateSet {
            query_id: "query-1".to_owned(),
            candidate_set_digest: crate::canonical::content_digest("candidates"),
            chunk_ids: vec!["chunk-a".to_owned()],
            candidate_count: 1,
        };

        // Candidates with no results, and results with no candidates, are each
        // half of a comparison.
        assert!(!assess_coverage(invariant, std::slice::from_ref(&candidates)).satisfied);
        assert!(!assess_coverage(invariant, &[result_set_event()]).satisfied);
        assert!(assess_coverage(invariant, &[candidates, result_set_event()]).satisfied);
    }

    #[test]
    fn a_decision_reports_what_was_missing_and_why() {
        // An operator reading INCONCLUSIVE needs to know what to add.
        let decision = assess_coverage(RagInvariantType::TopKBoundPreserved, &[]);
        assert!(!decision.satisfied);
        assert_eq!(decision.missing.len(), decision.required.len());
        assert!(decision.reason.contains("top-k") || decision.reason.contains("nothing was tried"));
    }
}
