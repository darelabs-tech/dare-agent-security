//! The negative matrix: what may not become a `PASS`.
//!
//! Cycle 020's DESIGN gives four verification statuses and says only one of
//! them may contribute to a positive result:
//!
//! ```text
//! VALID         -> may contribute to a positive PASS
//! INVALID       -> concrete evidence of FAIL
//! INDETERMINATE -> never a positive PASS
//! UNRECORDED    -> never a positive PASS
//! ```
//!
//! A post-merge review found three paths that reached `PASS` without a `VALID`
//! verification behind them, in I02, I03 and I04. The tests here drive the
//! whole invariant rather than the status predicate on its own, because the
//! predicate was already correct: it was the evaluators and coverage contracts
//! that did not consult it.
//!
//! Every test that walks statuses walks [`VerificationStatus::all`], so a fifth
//! status added later cannot quietly default to permitted.

use dare_security_evidence::Verdict;

use crate::invariant::{evaluate, A2aInvariantOutcome};
use crate::model::A2aInvariant;
use crate::normalize::tests::evidence;
use crate::normalize::A2aEvidence;
use crate::observation::project;
use crate::source::VerificationStatus;

/// Evaluate one invariant against one bundle.
fn outcome(invariant: A2aInvariant, evidence: &A2aEvidence) -> A2aInvariantOutcome {
    evaluate(invariant, &project(evidence))
}

/// A bundle whose single message verification carries `status`.
fn with_message_status(status: VerificationStatus) -> A2aEvidence {
    let mut bundle = evidence();
    for record in &mut bundle.message_authentication {
        record.status = status;
    }
    bundle
}

/// A bundle whose single peer verification carries `status`.
fn with_peer_status(status: VerificationStatus) -> A2aEvidence {
    let mut bundle = evidence();
    for record in &mut bundle.peer_authentication {
        record.status = status;
    }
    bundle
}

/// What each status must produce for an invariant whose other bindings hold.
fn expected_for(status: VerificationStatus) -> Verdict {
    match status {
        VerificationStatus::Valid => Verdict::Pass,
        VerificationStatus::Invalid => Verdict::Fail,
        VerificationStatus::Indeterminate | VerificationStatus::Unrecorded => Verdict::Inconclusive,
    }
}

#[test]
fn the_baseline_bundle_passes_all_three_so_the_matrix_measures_the_status() {
    // Without this, a test below could "pass" because the fixture was broken
    // for some unrelated reason rather than because the status was refused.
    for invariant in [
        A2aInvariant::PeerIdentityBound,
        A2aInvariant::MessageAuthenticityEstablished,
        A2aInvariant::SecurityRequirementSatisfied,
    ] {
        let outcome = outcome(invariant, &evidence());
        assert_eq!(
            outcome.verdict,
            Verdict::Pass,
            "{} did not pass on a complete, valid bundle: {}",
            invariant.as_str(),
            outcome.reason
        );
    }
}

#[test]
fn only_a_valid_message_verification_can_establish_authenticity() {
    // I03. An INDETERMINATE verifier result is somebody else saying they could
    // not tell. Accepting it converts their uncertainty into our confidence.
    for status in VerificationStatus::all() {
        let bundle = with_message_status(status);
        let outcome = outcome(A2aInvariant::MessageAuthenticityEstablished, &bundle);
        assert_eq!(
            outcome.verdict,
            expected_for(status),
            "I03 on {}: {}",
            status.as_str(),
            outcome.reason
        );
    }
}

#[test]
fn only_a_valid_peer_verification_can_bind_peer_identity() {
    // I02. `is_recorded_evidence` answers "was it checked?", which includes
    // INDETERMINATE. Positive binding needs "did it pass?".
    for status in VerificationStatus::all() {
        let bundle = with_peer_status(status);
        let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
        assert_eq!(
            outcome.verdict,
            expected_for(status),
            "I02 on {}: {}",
            status.as_str(),
            outcome.reason
        );
    }
}

#[test]
fn only_a_valid_verification_can_satisfy_a_security_requirement() {
    // I04. A scheme the card declares and policy approves is still only a
    // declaration until a verification says the mechanism was satisfied.
    for status in VerificationStatus::all() {
        let bundle = with_peer_status(status);
        let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
        assert_eq!(
            outcome.verdict,
            expected_for(status),
            "I04 on {}: {}",
            status.as_str(),
            outcome.reason
        );
    }
}

#[test]
fn a_signature_covering_the_right_envelope_does_not_rescue_an_uncertain_verification() {
    // The specific false PASS: the envelope binding was compared and matched,
    // and that was taken as coverage without asking what the verifier said.
    let bundle = with_message_status(VerificationStatus::Indeterminate);
    let observations = project(&bundle);
    let covered = observations.observations.iter().any(|observation| {
        matches!(observation, crate::observation::A2aObservation::MessageAuthenticationContext(c)
            if c.covers_observed_envelope == Some(true))
    });
    assert!(covered, "the fixture no longer stages a covered envelope");

    let outcome = outcome(A2aInvariant::MessageAuthenticityEstablished, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
    assert!(!outcome.coverage_satisfied);
}

#[test]
fn a_valid_verification_without_a_covered_digest_cannot_establish_authenticity() {
    // Nothing was compared, so nothing was established. Distinct from
    // "compared and differed", which is a concrete FAIL.
    let mut bundle = evidence();
    for record in &mut bundle.message_authentication {
        record.covered_envelope_digest = None;
    }
    let outcome = outcome(A2aInvariant::MessageAuthenticityEstablished, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
}

#[test]
fn a_verification_for_another_scheme_never_satisfies_the_requirement() {
    // The exchange authenticated with one mechanism and a valid verification
    // exists for a different one. Finding *a* valid record is not finding the
    // one that covers what was used.
    let mut bundle = evidence();
    for record in &mut bundle.peer_authentication {
        record.scheme_id = Some("api-key-fallback".to_owned());
        record.status = VerificationStatus::Valid;
    }
    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_ne!(
        outcome.verdict,
        Verdict::Pass,
        "a verification for another scheme satisfied the requirement: {}",
        outcome.reason
    );
}

#[test]
fn an_undecided_invariant_cannot_be_masked_by_a_passing_one() {
    // Aggregation. I03 undecided plus thirteen clean answers is not a clean
    // run.
    let bundle = with_message_status(VerificationStatus::Indeterminate);
    let observations = project(&bundle);
    let outcomes = crate::invariant::evaluate_all(&observations);
    let aggregate = crate::invariant::aggregate(&outcomes);
    assert_ne!(aggregate, Verdict::Pass, "an undecided invariant passed");
}

// ---------------------------------------------------------------------------
// I02 - the identity dimensions
// ---------------------------------------------------------------------------

/// A bundle whose observed peer has been edited.
fn with_peer(edit: impl Fn(&mut crate::peer::PeerIdentity)) -> A2aEvidence {
    let mut bundle = evidence();
    for peer in &mut bundle.peers.peers {
        edit(peer);
    }
    bundle
}

/// A bundle whose approved-peer policy entry has been edited.
fn with_approved_peer(edit: impl Fn(&mut crate::policy::ApprovedPeer)) -> A2aEvidence {
    let mut bundle = evidence();
    let mut approved: Vec<crate::policy::ApprovedPeer> =
        bundle.policy.approved_peers.iter().cloned().collect();
    for entry in &mut approved {
        edit(entry);
    }
    bundle.policy.approved_peers = approved.into_iter().collect();
    bundle
}

#[test]
fn an_expected_audience_that_was_never_observed_leaves_identity_undecided() {
    // Policy pinned an audience and the evidence carried none. Absence is not
    // agreement, and the old `Option<bool>` could not tell the two apart.
    let bundle = with_peer(|peer| peer.audience = None);
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
}

#[test]
fn an_audience_that_differs_from_the_expected_one_fails() {
    let bundle = with_peer(|peer| peer.audience = Some("another-orchestrator".to_owned()));
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
}

#[test]
fn an_expected_provider_that_was_never_observed_leaves_identity_undecided() {
    let bundle = with_peer(|peer| peer.card_provider = None);
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
}

#[test]
fn a_provider_that_differs_from_the_expected_one_fails() {
    let bundle = with_peer(|peer| peer.card_provider = Some("attacker".to_owned()));
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
}

#[test]
fn a_logical_agent_policy_never_approved_cannot_bind() {
    // The peer said which agent it is and nothing local agreed. "The peer said
    // it is X" is not "X is who we approved for this role".
    let bundle = with_approved_peer(|approved| approved.expected_logical_agent = None);
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
}

#[test]
fn a_logical_agent_that_differs_from_the_approved_one_fails() {
    let bundle = with_approved_peer(|approved| {
        approved.expected_logical_agent = Some("billing-agent".to_owned());
    });
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    assert!(outcome
        .violations
        .iter()
        .any(|violation| violation.reason.contains("logical agent")));
}

#[test]
fn a_service_principal_is_not_a_finding_where_no_delegated_identity_is_expected() {
    // Legitimate service-to-service. A rule that failed every service principal
    // would break `client_credentials` deployments that never carry a user, so
    // this must stay passable.
    let mut bundle = with_approved_peer(|approved| approved.requires_delegated_identity = false);
    for peer in &mut bundle.peers.peers {
        peer.delegated_subject = None;
    }
    for record in &mut bundle.peer_authentication {
        record.delegated_subject = None;
    }
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(
        outcome.verdict,
        Verdict::Pass,
        "a legitimate service-to-service authentication was failed: {}",
        outcome.reason
    );
}

#[test]
fn a_service_principal_standing_in_for_a_required_delegated_identity_fails() {
    // Policy said this peer acts *for* somebody and only the service account
    // was established. That is the substitution, not a gap.
    let mut bundle = evidence();
    for peer in &mut bundle.peers.peers {
        peer.delegated_subject = None;
    }
    for record in &mut bundle.peer_authentication {
        record.delegated_subject = None;
    }
    let outcome = outcome(A2aInvariant::PeerIdentityBound, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    assert!(outcome
        .violations
        .iter()
        .any(|violation| violation.reason.contains("delegated subject")));
}

#[test]
fn an_undecided_identity_is_not_rescued_by_the_other_thirteen() {
    // Aggregation, from the I02 side.
    let bundle = with_peer(|peer| peer.audience = None);
    let outcomes = crate::invariant::evaluate_all(&project(&bundle));
    assert_ne!(
        crate::invariant::aggregate(&outcomes),
        Verdict::Pass,
        "an undecided identity binding aggregated to PASS"
    );
}

// ---------------------------------------------------------------------------
// I04 - the mechanism actually used
// ---------------------------------------------------------------------------

#[test]
fn a_scheme_with_no_verification_at_all_leaves_the_requirement_undecided() {
    let mut bundle = evidence();
    bundle.peer_authentication.clear();
    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_eq!(outcome.verdict, Verdict::Inconclusive, "{}", outcome.reason);
}

#[test]
fn a_scheme_kind_policy_does_not_approve_fails() {
    let bundle = with_approved_peer(|approved| {
        approved.approved_scheme_kinds =
            std::collections::BTreeSet::from([crate::source::SecuritySchemeKind::ApiKey]);
    });
    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
}

#[test]
fn a_scheme_the_card_merely_declares_is_not_a_satisfied_requirement() {
    // The card declares `oauth-main` and the exchange named it. Without a
    // verification tied to it, that is a declaration and nothing more.
    let mut bundle = evidence();
    for record in &mut bundle.peer_authentication {
        record.scheme_id = None;
    }
    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_ne!(
        outcome.verdict,
        Verdict::Pass,
        "a declared scheme satisfied a requirement: {}",
        outcome.reason
    );
}

#[test]
fn a_valid_verification_for_another_peer_never_satisfies_this_requirement() {
    // The verification is real, valid, and about somebody else.
    let mut bundle = evidence();
    let mut elsewhere = bundle.peer_authentication[0].clone();
    elsewhere.peer_id = "reviewer".to_owned();
    elsewhere.status = VerificationStatus::Valid;
    let mut other = bundle.peers.peers[0].clone();
    other.peer_id = "reviewer".to_owned();
    other.logical_agent_id = "reviewer".to_owned();
    bundle.peer_authentication.clear();
    bundle.peer_authentication.push(elsewhere);
    bundle.peers.peers.push(other);

    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_ne!(
        outcome.verdict,
        Verdict::Pass,
        "another peer verification satisfied this requirement: {}",
        outcome.reason
    );
}

#[test]
fn a_bound_verification_found_invalid_is_a_concrete_failure() {
    let bundle = with_peer_status(VerificationStatus::Invalid);
    let outcome = outcome(A2aInvariant::SecurityRequirementSatisfied, &bundle);
    assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
}

// ---------------------------------------------------------------------------
// The global rule, walked mechanically
// ---------------------------------------------------------------------------

#[test]
fn no_uncertain_verification_produces_a_pass_in_any_of_the_three() {
    // The systemic rule. Driven through the whole invariant rather than the
    // status predicate, because the predicate was never the thing that broke.
    for status in VerificationStatus::all() {
        if status.may_satisfy_positive_evidence() {
            continue;
        }
        for (invariant, bundle) in [
            (A2aInvariant::PeerIdentityBound, with_peer_status(status)),
            (
                A2aInvariant::MessageAuthenticityEstablished,
                with_message_status(status),
            ),
            (
                A2aInvariant::SecurityRequirementSatisfied,
                with_peer_status(status),
            ),
        ] {
            let outcome = outcome(invariant, &bundle);
            assert_ne!(
                outcome.verdict,
                Verdict::Pass,
                "{} passed on {}: {}",
                invariant.as_str(),
                status.as_str(),
                outcome.reason
            );
        }
    }
}

#[test]
fn only_matches_proves_a_required_binding_and_unproven_never_does() {
    // The type that replaced `Option<bool>`, walked exhaustively so a variant
    // added later cannot default to permitted.
    use crate::source::BindingCheck;
    for check in BindingCheck::all() {
        assert_eq!(
            check.is_proven(),
            check == BindingCheck::Matches,
            "{}",
            check.as_str()
        );
        assert_eq!(
            check.may_satisfy_positive_evidence(),
            matches!(check, BindingCheck::Matches | BindingCheck::NotExpected),
            "{}",
            check.as_str()
        );
        assert_eq!(
            check.is_concrete_failure(),
            check == BindingCheck::Differs,
            "{}",
            check.as_str()
        );
    }
}

#[test]
fn a_concrete_failure_still_outranks_an_undecided_invariant() {
    // FAIL precedence, with I03 undecided and a skill violation in one bundle.
    let mut bundle = with_message_status(VerificationStatus::Indeterminate);
    for exchange in &mut bundle.exchanges.exchanges {
        exchange.initiating_principal = Some("user-mallory".to_owned());
    }
    let outcomes = crate::invariant::evaluate_all(&project(&bundle));
    assert_eq!(
        crate::invariant::aggregate(&outcomes),
        Verdict::Fail,
        "a concrete failure was hidden behind a gap"
    );
}
