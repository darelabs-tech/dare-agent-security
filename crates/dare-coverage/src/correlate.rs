//! Join assessment plan with Cycle 001 evidence references. No second evidence format.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::error::CoverageError;
use crate::math::finalize_row;
use crate::plan::AssessmentPlan;
use crate::profile::RequirementLevel;
use crate::status::CoverageStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyExecution {
    pub property_id: String,
    pub verdict: Option<Verdict>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

pub fn correlate(
    plan: &AssessmentPlan,
    executions: &[PropertyExecution],
) -> Result<Vec<CorrelatedRow>, CoverageError> {
    let mut rows = Vec::with_capacity(plan.properties.len());
    for planned in &plan.properties {
        let exec = executions
            .iter()
            .find(|e| e.property_id == planned.property_id);
        let (status, verdict) = if planned.coverage_status == CoverageStatus::Applicable {
            match exec {
                Some(e) if e.verdict.is_some() => {
                    if e.evidence_ids.is_empty() {
                        return Err(CoverageError::InvalidState(format!(
                            "APPLICABLE {} has verdict but no Cycle 001 evidence id",
                            planned.property_id
                        )));
                    }
                    finalize_row(CoverageStatus::Applicable, e.verdict)?
                }
                _ => finalize_row(CoverageStatus::Applicable, None)?,
            }
        } else {
            if let Some(e) = exec {
                if e.verdict.is_some() {
                    crate::math::validate_pair(planned.coverage_status, e.verdict, true)?;
                }
            }
            finalize_row(planned.coverage_status, None)?
        };
        rows.push(CorrelatedRow {
            property_id: planned.property_id.clone(),
            requirement: planned.requirement,
            coverage_status: status,
            verdict,
            evidence_ids: exec.map(|e| e.evidence_ids.clone()).unwrap_or_default(),
            rationale: planned.rationale.clone(),
        });
    }
    Ok(rows)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedRow {
    pub property_id: String,
    pub requirement: RequirementLevel,
    pub coverage_status: CoverageStatus,
    pub verdict: Option<Verdict>,
    pub evidence_ids: Vec<String>,
    pub rationale: String,
}
