//! Coverage math and finalization. Denominator excludes NOT_APPLICABLE and OUT_OF_SCOPE.

use dare_security_evidence::Verdict;

use crate::error::CoverageError;
use crate::profile::RequirementLevel;
use crate::status::CoverageStatus;

pub const DENOMINATOR_DOC: &str = "\
eligible = finalized properties with a verdict + NOT_TESTED + BLOCKED
tested = eligible properties that have a Cycle 001 verdict
coverage = tested / eligible (1.0 when eligible is 0)
NOT_APPLICABLE and OUT_OF_SCOPE are excluded from the denominator
required_coverage uses the same formula restricted to REQUIRED properties
";

pub fn validate_pair(
    status: CoverageStatus,
    verdict: Option<Verdict>,
    finalized: bool,
) -> Result<(), CoverageError> {
    if !finalized {
        if status == CoverageStatus::Applicable && verdict.is_none() {
            return Ok(());
        }
        if verdict.is_some() && status != CoverageStatus::Applicable {
            return Err(CoverageError::InvalidState(format!(
                "planning: verdict not allowed with {}",
                status.as_str()
            )));
        }
        return Ok(());
    }

    match (status, verdict) {
        (CoverageStatus::Applicable, Some(_)) => Ok(()),
        (CoverageStatus::Applicable, None) => Err(CoverageError::InvalidState(
            "final APPLICABLE requires a verdict or must become NOT_TESTED".to_owned(),
        )),
        (CoverageStatus::NotTested, None)
        | (CoverageStatus::Blocked, None)
        | (CoverageStatus::NotApplicable, None)
        | (CoverageStatus::OutOfScope, None) => Ok(()),
        (CoverageStatus::NotApplicable, Some(v)) => Err(CoverageError::InvalidState(format!(
            "NOT_APPLICABLE + {} is invalid",
            v.as_str()
        ))),
        (CoverageStatus::OutOfScope, Some(v)) => Err(CoverageError::InvalidState(format!(
            "OUT_OF_SCOPE + {} is invalid",
            v.as_str()
        ))),
        (CoverageStatus::NotTested, Some(v)) => Err(CoverageError::InvalidState(format!(
            "NOT_TESTED + {} is invalid",
            v.as_str()
        ))),
        (CoverageStatus::Blocked, Some(v)) => Err(CoverageError::InvalidState(format!(
            "BLOCKED + {} is invalid",
            v.as_str()
        ))),
    }
}

/// Finalize a planned applicable row with no verdict.
pub fn finalize_row(
    status: CoverageStatus,
    verdict: Option<Verdict>,
) -> Result<(CoverageStatus, Option<Verdict>), CoverageError> {
    validate_pair(status, verdict, false)?;
    if status == CoverageStatus::Applicable && verdict.is_none() {
        return Ok((CoverageStatus::NotTested, None));
    }
    validate_pair(status, verdict, true)?;
    Ok((status, verdict))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoverageCounts {
    pub applicable: u32,
    pub not_applicable: u32,
    pub not_tested: u32,
    pub out_of_scope: u32,
    pub blocked: u32,
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub error: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoverageTotals {
    pub eligible: u32,
    pub tested: u32,
    pub overall: f64,
    pub required_eligible: u32,
    pub required_tested: u32,
    pub required: f64,
}

pub fn eligible_count(status: CoverageStatus, verdict: Option<Verdict>) -> bool {
    matches!(status, CoverageStatus::NotTested | CoverageStatus::Blocked)
        || (status == CoverageStatus::Applicable && verdict.is_some())
}

pub fn tested_count(status: CoverageStatus, verdict: Option<Verdict>) -> bool {
    status == CoverageStatus::Applicable && verdict.is_some()
}

pub fn required_eligible_count(
    requirement: RequirementLevel,
    status: CoverageStatus,
    verdict: Option<Verdict>,
) -> bool {
    requirement == RequirementLevel::Required && eligible_count(status, verdict)
}

pub fn required_tested_count(
    requirement: RequirementLevel,
    status: CoverageStatus,
    verdict: Option<Verdict>,
) -> bool {
    requirement == RequirementLevel::Required && tested_count(status, verdict)
}

pub fn coverage_ratio(tested: u32, eligible: u32) -> f64 {
    if eligible == 0 {
        1.0
    } else {
        f64::from(tested) / f64::from(eligible)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoveragePolicy {
    pub min_required_coverage: f64,
    pub fail_on_required_blocked: bool,
}

impl Default for CoveragePolicy {
    fn default() -> Self {
        Self {
            min_required_coverage: 0.0,
            fail_on_required_blocked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dare_security_evidence::Verdict;

    #[test]
    fn invalid_final_combinations() {
        assert!(validate_pair(CoverageStatus::NotApplicable, Some(Verdict::Pass), true).is_err());
        assert!(validate_pair(CoverageStatus::OutOfScope, Some(Verdict::Fail), true).is_err());
        assert!(validate_pair(CoverageStatus::NotTested, Some(Verdict::Pass), true).is_err());
        assert!(validate_pair(CoverageStatus::Blocked, Some(Verdict::Inconclusive), true).is_err());
    }

    #[test]
    fn applicable_without_verdict_finalizes_to_not_tested() {
        let (status, verdict) = finalize_row(CoverageStatus::Applicable, None).unwrap();
        assert_eq!(status, CoverageStatus::NotTested);
        assert!(verdict.is_none());
    }

    #[test]
    fn denominator_excludes_na_and_oos() {
        assert!(!eligible_count(CoverageStatus::NotApplicable, None));
        assert!(!eligible_count(CoverageStatus::OutOfScope, None));
        assert!(eligible_count(CoverageStatus::NotTested, None));
        assert!(eligible_count(CoverageStatus::Blocked, None));
        assert!(eligible_count(
            CoverageStatus::Applicable,
            Some(Verdict::Pass)
        ));
        assert_eq!(coverage_ratio(2, 4), 0.5);
        assert_eq!(coverage_ratio(0, 0), 1.0);
    }
}
