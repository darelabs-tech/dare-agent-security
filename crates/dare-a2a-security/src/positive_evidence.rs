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
