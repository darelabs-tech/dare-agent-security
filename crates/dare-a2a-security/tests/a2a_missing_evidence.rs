//! Regressions for the two ways a run can quietly overstate what it saw.
//!
//! The first is missing evidence read as success. Every invariant here is given
//! a run with the evidence it needs removed, and none of them may answer PASS.
//! An operator reading PASS believes a question was asked and answered; if the
//! question was never asked, that belief is the whole harm.
//!
//! The second is a partial report. An exchange that crossed three boundaries
//! and is reported as crossing one leaves an operator who fixes it believing
//! the exchange is now clean.

use std::collections::BTreeSet;

use dare_a2a_security::budget::AdmissionLedger;
use dare_a2a_security::coverage::{assess_coverage, contract};
use dare_a2a_security::invariant::{
    aggregate, collect_observed_violations, evaluate, evaluate_all, A2aInvariantOutcome,
};
use dare_a2a_security::model::A2aInvariant;
use dare_a2a_security::observation::{project, ObservationSet};
use dare_a2a_security::simulated::stage;
use dare_a2a_security::source::{ReferenceBehavior, VerificationStatus};
use dare_security_evidence::Verdict;

fn compliant() -> ObservationSet {
    let mut ledger = AdmissionLedger::new();
    let evidence = stage(ReferenceBehavior::Compliant, &mut ledger).expect("stages");
    project(&evidence)
}

/// The same run with one channel's observations removed.
fn without_channel(
    observations: &ObservationSet,
    channel: dare_a2a_security::observation::ObservationChannel,
) -> ObservationSet {
    ObservationSet::new(
        observations
            .observations
            .iter()
            .filter(|observation| observation.channel() != channel)
            .cloned()
            .collect(),
    )
}

#[test]
fn removing_any_required_channel_removes_the_pass_that_depended_on_it() {
    // The compliant run passes everything it can decide. Take away a channel an
    // invariant needs and its answer must change from PASS to undecided — not
    // stay PASS on the strength of the evidence that is still there.
    let full = compliant();
    for invariant in A2aInvariant::all() {
        let baseline = evaluate(invariant, &full);
        if baseline.verdict != Verdict::Pass {
            // Nothing to lose: the compliant run could not decide it either.
            continue;
        }
        for channel in contract(invariant).required {
            let stripped = without_channel(&full, channel);
            let outcome = evaluate(invariant, &stripped);
            assert_ne!(
                outcome.verdict,
                Verdict::Pass,
                "{} still answered PASS with {} removed: {}",
                invariant.design_id(),
                channel.as_str(),
                outcome.reason
            );
            assert!(
                !outcome.coverage_satisfied,
                "{} called its coverage satisfied with {} removed",
                invariant.design_id(),
                channel.as_str()
            );
            assert!(
                outcome.reason.contains(channel.as_str())
                    || !assess_coverage(invariant, &stripped).missing.is_empty(),
                "{} did not say which channel was missing",
                invariant.design_id()
            );
        }
    }
}

#[test]
fn an_empty_run_decides_nothing_and_aggregates_to_inconclusive() {
    // The cheapest false PASS available: hand the engine nothing at all.
    let empty = ObservationSet::default();
    let outcomes = evaluate_all(&empty);
    assert_eq!(outcomes.len(), A2aInvariant::all().len());
    for outcome in &outcomes {
        assert_ne!(
            outcome.verdict,
            Verdict::Pass,
            "{} passed having observed nothing",
            outcome.invariant.design_id()
        );
    }
    assert_eq!(aggregate(&outcomes), Verdict::Inconclusive);
}

#[test]
fn unrecorded_and_indeterminate_evidence_can_never_become_a_pass() {
    // The frozen status semantics, asserted on the type rather than on one
    // call site. VALID may satisfy positive evidence; INVALID is a concrete
    // failure; the other two are neither, and nothing may promote them.
    for status in VerificationStatus::all() {
        match status {
            VerificationStatus::Valid => {
                assert!(status.may_satisfy_positive_evidence());
                assert!(!status.is_concrete_failure());
            }
            VerificationStatus::Invalid => {
                assert!(!status.may_satisfy_positive_evidence());
                assert!(status.is_concrete_failure());
            }
            other => {
                assert!(
                    !other.may_satisfy_positive_evidence(),
                    "{} can satisfy positive evidence",
                    other.as_str()
                );
                assert!(
                    !other.is_concrete_failure(),
                    "{} is being read as a concrete failure",
                    other.as_str()
                );
            }
        }
    }
}

#[test]
fn a_missing_signature_is_undecided_and_an_invalid_one_is_a_failure() {
    // The same surface, two different answers, and conflating them would send
    // an operator to the wrong fix.
    let mut ledger = AdmissionLedger::new();
    let missing =
        project(&stage(ReferenceBehavior::MessageSignatureMissing, &mut ledger).expect("stages"));
    let undecided = evaluate(A2aInvariant::MessageAuthenticityEstablished, &missing);
    assert_eq!(
        undecided.verdict,
        Verdict::Inconclusive,
        "{}",
        undecided.reason
    );
    assert!(undecided.violations.is_empty());

    let mut ledger = AdmissionLedger::new();
    let invalid =
        project(&stage(ReferenceBehavior::MessageSignatureInvalid, &mut ledger).expect("stages"));
    let failed = evaluate(A2aInvariant::MessageAuthenticityEstablished, &invalid);
    assert_eq!(failed.verdict, Verdict::Fail, "{}", failed.reason);
    assert!(!failed.violations.is_empty());
}

#[test]
fn a_harness_failure_reports_error_rather_than_a_security_conclusion() {
    // A run that could not execute has not observed a secure exchange. Reading
    // it as one is the worst available answer, because nobody looks again.
    let mut ledger = AdmissionLedger::new();
    let error = stage(ReferenceBehavior::HarnessFailure, &mut ledger)
        .expect_err("a staged harness failure must not produce a clean bundle");
    assert!(error.is_refusal(), "{error}");
}

#[test]
fn every_boundary_a_multi_violation_exchange_crossed_is_reported() {
    let mut ledger = AdmissionLedger::new();
    let observations = project(
        &stage(
            ReferenceBehavior::MultipleIndependentViolations,
            &mut ledger,
        )
        .expect("stages"),
    );
    let outcomes = evaluate_all(&observations);

    let failed: BTreeSet<&str> = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .map(|outcome| outcome.invariant.design_id())
        .collect();
    // Tenant crossing, peer content becoming instruction, and a delegation hop
    // that widened — three independent boundaries staged together.
    for expected in ["I06", "I08", "I09"] {
        assert!(
            failed.contains(expected),
            "{expected} was crossed and not reported; reported: {failed:?}"
        );
    }

    // The flat list an artifact writes must carry every one of them, each with
    // the evidence that decided it.
    let violations = collect_observed_violations(&observations);
    let invariants: BTreeSet<&str> = violations
        .iter()
        .map(|violation| violation.invariant.design_id())
        .collect();
    assert!(invariants.len() >= 3, "{invariants:?}");
    for violation in &violations {
        assert!(
            !violation.deciding_observation_digests.is_empty(),
            "{} reported a finding with nothing to trace it to",
            violation.invariant.design_id()
        );
    }
}

#[test]
fn one_concrete_failure_outranks_every_undecided_answer() {
    // Cycle 018's precedence, asserted here because a run that averaged its
    // outcomes would hide a FAIL behind thirteen INCONCLUSIVEs.
    let mut ledger = AdmissionLedger::new();
    let observations =
        project(&stage(ReferenceBehavior::CrossTenantAccess, &mut ledger).expect("stages"));
    let outcomes = evaluate_all(&observations);
    assert!(outcomes
        .iter()
        .any(|outcome| outcome.verdict == Verdict::Inconclusive));
    assert_eq!(aggregate(&outcomes), Verdict::Fail);
}

#[test]
fn an_inapplicable_invariant_never_drags_a_clean_run_below_pass() {
    // The Cycle 019 correction, carried forward. A compliant exchange that
    // registers no push notification has not failed to prove anything about
    // push notifications — the question does not arise, and reporting the run
    // as INCONCLUSIVE for it would make every clean run unreadable.
    let outcomes = evaluate_all(&compliant());
    let inapplicable: Vec<&A2aInvariantOutcome> = outcomes
        .iter()
        .filter(|outcome| !outcome.applicable)
        .collect();
    assert!(
        !inapplicable.is_empty(),
        "the compliant fixture no longer exercises the inapplicable path"
    );
    for outcome in inapplicable {
        assert_ne!(outcome.verdict, Verdict::Fail);
    }
    assert_eq!(aggregate(&outcomes), Verdict::Pass);
}
