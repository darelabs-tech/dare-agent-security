//! Table-driven expected/observed enforcement satisfaction checks.

use crate::result::{IntegrityVerdict, ObservedEnforcement};
use crate::vector::ExpectedEnforcement;

/// Whether observed enforcement satisfies the vector expectation.
///
/// Returns `Some(true)` when enforcement matches, `Some(false)` when it
/// deterministically violates the expectation, and `None` when the pair is
/// insufficient for PASS/FAIL derivation.
pub fn enforcement_satisfies(
    expected: ExpectedEnforcement,
    observed: ObservedEnforcement,
) -> Option<bool> {
    match (expected, observed) {
        (
            ExpectedEnforcement::ForwardWithExistingPermit,
            ObservedEnforcement::ForwardedWithExistingPermit,
        ) => Some(true),
        (
            ExpectedEnforcement::ForwardWithExistingPermit,
            ObservedEnforcement::NoForwardInitialDeny,
        ) => Some(true),
        (
            ExpectedEnforcement::ForwardWithExistingPermit,
            ObservedEnforcement::ForwardedWithStalePermit
            | ObservedEnforcement::ForwardedAfterReevaluation
            | ObservedEnforcement::RefusedAfterBindingChange
            | ObservedEnforcement::DeniedAfterReevaluation,
        ) => Some(false),

        (
            ExpectedEnforcement::ReevaluateOrRefuse,
            ObservedEnforcement::RefusedAfterBindingChange
            | ObservedEnforcement::DeniedAfterReevaluation
            | ObservedEnforcement::ForwardedAfterReevaluation,
        ) => Some(true),
        (
            ExpectedEnforcement::ReevaluateOrRefuse,
            ObservedEnforcement::ForwardedWithStalePermit
            | ObservedEnforcement::ForwardedWithExistingPermit,
        ) => Some(false),
        (ExpectedEnforcement::ReevaluateOrRefuse, ObservedEnforcement::NoForwardInitialDeny) => {
            Some(true)
        }

        (
            ExpectedEnforcement::PermitRemainsBound,
            ObservedEnforcement::ForwardedWithExistingPermit
            | ObservedEnforcement::ForwardedAfterReevaluation,
        ) => Some(true),
        (
            ExpectedEnforcement::PermitRemainsBound,
            ObservedEnforcement::ForwardedWithStalePermit
            | ObservedEnforcement::RefusedAfterBindingChange
            | ObservedEnforcement::DeniedAfterReevaluation,
        ) => Some(false),

        (_, ObservedEnforcement::InconclusiveProjection | ObservedEnforcement::HarnessError) => {
            None
        }

        _ => Some(false),
    }
}

/// Validate that a verdict is consistent with expected/observed enforcement.
pub fn validate_verdict_consistency(
    expected: ExpectedEnforcement,
    observed: ObservedEnforcement,
    verdict: IntegrityVerdict,
) -> Result<(), crate::error::IntegrityError> {
    let satisfaction = enforcement_satisfies(expected, observed);
    match verdict {
        IntegrityVerdict::Pass => {
            if satisfaction != Some(true) {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "PASS requires observed enforcement to satisfy expectation".into(),
                });
            }
        }
        IntegrityVerdict::Fail => {
            if satisfaction != Some(false) {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "FAIL requires deterministic enforcement mismatch".into(),
                });
            }
        }
        IntegrityVerdict::Inconclusive => {
            if observed != ObservedEnforcement::InconclusiveProjection {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "INCONCLUSIVE requires INCONCLUSIVE_PROJECTION observed enforcement"
                        .into(),
                });
            }
            if satisfaction == Some(true) {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "INCONCLUSIVE cannot masquerade as PASS".into(),
                });
            }
        }
        IntegrityVerdict::Error => {
            if observed != ObservedEnforcement::HarnessError {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "ERROR requires HARNESS_ERROR observed enforcement".into(),
                });
            }
            if satisfaction == Some(true) || satisfaction == Some(false) {
                return Err(crate::error::IntegrityError::VerdictConsistency {
                    reason: "ERROR cannot masquerade as PASS or FAIL".into(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_permit_is_fail_for_reevaluate_or_refuse() {
        assert_eq!(
            enforcement_satisfies(
                ExpectedEnforcement::ReevaluateOrRefuse,
                ObservedEnforcement::ForwardedWithStalePermit
            ),
            Some(false)
        );
    }

    #[test]
    fn secure_refusal_satisfies_reevaluate_or_refuse() {
        assert_eq!(
            enforcement_satisfies(
                ExpectedEnforcement::ReevaluateOrRefuse,
                ObservedEnforcement::RefusedAfterBindingChange
            ),
            Some(true)
        );
    }
}
