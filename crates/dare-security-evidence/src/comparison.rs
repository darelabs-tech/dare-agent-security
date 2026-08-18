//! Protocol-neutral deterministic comparison of expected vs observed outcomes.

use crate::error::EvidenceError;
use crate::model::{ExpectedOutcome, ObservedOutcome, SecurityEvidence};
use crate::verdict::Verdict;

/// Result of comparing expected and observed outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonResult {
    /// Deterministic agreement.
    Match,
    /// Deterministic mismatch.
    Mismatch,
    /// Not enough information for deterministic agreement or mismatch.
    Insufficient,
    /// Evaluation/infrastructure failure rather than a security outcome.
    EvaluationFailed,
}

/// Derives a verdict from a comparison result.
pub fn derive_verdict(result: ComparisonResult) -> Verdict {
    match result {
        ComparisonResult::Match => Verdict::Pass,
        ComparisonResult::Mismatch => Verdict::Fail,
        ComparisonResult::Insufficient => Verdict::Inconclusive,
        ComparisonResult::EvaluationFailed => Verdict::Error,
    }
}

/// Compares expected and observed outcomes.
pub trait OutcomeComparator {
    /// Deterministic comparison. Equal inputs must yield equal results.
    fn compare(&self, expected: &ExpectedOutcome, observed: &ObservedOutcome) -> ComparisonResult;
}

/// Exact equality comparator for generic decision/result fields only.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExactOutcomeComparator;

impl OutcomeComparator for ExactOutcomeComparator {
    fn compare(&self, expected: &ExpectedOutcome, observed: &ObservedOutcome) -> ComparisonResult {
        match (expected.decision, observed.decision) {
            (Some(exp), Some(obs)) if exp == obs => match (&expected.result, &observed.result) {
                (Some(a), Some(b)) if a != b => ComparisonResult::Mismatch,
                _ => ComparisonResult::Match,
            },
            (Some(_), Some(_)) => ComparisonResult::Mismatch,
            _ => ComparisonResult::Insufficient,
        }
    }
}

/// Apply the default exact comparator and set `evidence.verdict` from it.
///
/// Does not override an `ERROR` verdict: evaluation failure is not a
/// security PASS/FAIL and is not derived from decision equality.
pub fn apply_derived_verdict(evidence: &mut SecurityEvidence) {
    if evidence.verdict == Verdict::Error {
        return;
    }
    let result = ExactOutcomeComparator.compare(&evidence.expected, &evidence.observed);
    evidence.verdict = derive_verdict(result);
}

/// Reject verdicts that contradict the generic exact comparison.
pub fn validate_verdict_consistency(evidence: &SecurityEvidence) -> Result<(), EvidenceError> {
    let comparison = ExactOutcomeComparator.compare(&evidence.expected, &evidence.observed);
    match evidence.verdict {
        Verdict::Pass => require(
            comparison,
            ComparisonResult::Match,
            "PASS requires deterministic agreement",
        ),
        Verdict::Fail => require(
            comparison,
            ComparisonResult::Mismatch,
            "FAIL requires deterministic mismatch",
        ),
        Verdict::Inconclusive => {
            if comparison == ComparisonResult::Match {
                return Err(EvidenceError::VerdictConsistency {
                    reason: "INCONCLUSIVE cannot masquerade as PASS".into(),
                });
            }
            if comparison == ComparisonResult::Mismatch {
                return Err(EvidenceError::VerdictConsistency {
                    reason: "INCONCLUSIVE cannot masquerade as FAIL".into(),
                });
            }
            Ok(())
        }
        Verdict::Error => {
            if comparison == ComparisonResult::Match {
                return Err(EvidenceError::VerdictConsistency {
                    reason: "ERROR cannot masquerade as PASS".into(),
                });
            }
            if comparison == ComparisonResult::Mismatch {
                return Err(EvidenceError::VerdictConsistency {
                    reason: "ERROR cannot masquerade as FAIL".into(),
                });
            }
            Ok(())
        }
    }
}

fn require(
    actual: ComparisonResult,
    expected: ComparisonResult,
    reason: &str,
) -> Result<(), EvidenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(EvidenceError::VerdictConsistency {
            reason: reason.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{sample_evidence, Decision};
    use crate::validation::validate;

    fn expected_observed(
        exp: Option<Decision>,
        obs: Option<Decision>,
    ) -> (ExpectedOutcome, ObservedOutcome) {
        let mut evidence = sample_evidence();
        evidence.expected.decision = exp;
        evidence.observed.decision = obs;
        (evidence.expected, evidence.observed)
    }

    #[test]
    fn exact_match_derives_pass() {
        let (expected, observed) = expected_observed(Some(Decision::Deny), Some(Decision::Deny));
        let result = ExactOutcomeComparator.compare(&expected, &observed);
        assert_eq!(result, ComparisonResult::Match);
        assert_eq!(derive_verdict(result), Verdict::Pass);
    }

    #[test]
    fn deterministic_mismatch_derives_fail() {
        let (expected, observed) = expected_observed(Some(Decision::Deny), Some(Decision::Allow));
        let result = ExactOutcomeComparator.compare(&expected, &observed);
        assert_eq!(result, ComparisonResult::Mismatch);
        assert_eq!(derive_verdict(result), Verdict::Fail);
    }

    #[test]
    fn contradictory_pass_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.expected.decision = Some(Decision::Deny);
        evidence.observed.decision = Some(Decision::Allow);
        evidence.verdict = Verdict::Pass;
        let err = validate(&evidence).unwrap_err();
        assert!(matches!(err, EvidenceError::VerdictConsistency { .. }));
    }

    #[test]
    fn inconclusive_cannot_masquerade_as_pass() {
        let mut evidence = sample_evidence();
        evidence.expected.decision = Some(Decision::Deny);
        evidence.observed.decision = Some(Decision::Deny);
        evidence.verdict = Verdict::Inconclusive;
        evidence.observed.description = Some("insufficient".into());
        let err = validate(&evidence).unwrap_err();
        assert!(
            matches!(err, EvidenceError::VerdictConsistency { reason } if reason.contains("PASS"))
        );
    }

    #[test]
    fn error_cannot_masquerade_as_fail_or_pass() {
        let mut evidence = sample_evidence();
        evidence.expected.decision = Some(Decision::Deny);
        evidence.observed.decision = Some(Decision::Allow);
        evidence.verdict = Verdict::Error;
        evidence.observed.description = Some("transport timeout".into());
        let err = validate(&evidence).unwrap_err();
        assert!(
            matches!(err, EvidenceError::VerdictConsistency { reason } if reason.contains("FAIL"))
        );

        evidence.observed.decision = Some(Decision::Deny);
        evidence.verdict = Verdict::Error;
        let err = validate(&evidence).unwrap_err();
        assert!(
            matches!(err, EvidenceError::VerdictConsistency { reason } if reason.contains("PASS"))
        );
    }

    #[test]
    fn comparator_is_deterministic() {
        let (expected, observed) = expected_observed(Some(Decision::Allow), Some(Decision::Deny));
        let first = ExactOutcomeComparator.compare(&expected, &observed);
        for _ in 0..8 {
            assert_eq!(ExactOutcomeComparator.compare(&expected, &observed), first);
        }
    }

    #[test]
    fn apply_derived_verdict_sets_fail_for_sample() {
        let mut evidence = sample_evidence();
        evidence.verdict = Verdict::Pass;
        apply_derived_verdict(&mut evidence);
        assert_eq!(evidence.verdict, Verdict::Fail);
        validate(&evidence).expect("derived fail is consistent");
    }
}
