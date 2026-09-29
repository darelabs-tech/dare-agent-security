//! Cycle 006 coverage rows (BLUEPRINT AD-04) and the executions document.
//!
//! The engine already decided each property's coverage state: a property
//! with no policy is NOT_APPLICABLE, one no trace exercised is NOT_TESTED,
//! and only a judged property is APPLICABLE with a verdict. The rows restate
//! that against a profile; they never promote a state.
use dare_coverage::{
    build_report, AssessmentFacts, AssessmentProfile, CorrelatedRow, CoveragePolicy,
    CoverageReport, CoverageStatus, EvidenceClass, ExecutionsDocument, PropertyExecution,
    SupportedMode,
};

use crate::{
    error::{Result, TelemetryError},
    policy::Policy,
    result::{CoverageState, RuntimeTelemetryResult},
};

/// What a trace export shows about the system: an agent ran. The policy
/// adds only what it names; nothing is inferred from span content.
pub fn assessment_facts(policy: Option<&Policy>) -> AssessmentFacts {
    AssessmentFacts {
        agent_present: true,
        human_approval_present: policy.is_some_and(|p| p.approval.is_some()),
        ..Default::default()
    }
}

fn status(state: CoverageState) -> CoverageStatus {
    match state {
        CoverageState::Applicable => CoverageStatus::Applicable,
        CoverageState::NotApplicable => CoverageStatus::NotApplicable,
        CoverageState::NotTested => CoverageStatus::NotTested,
    }
}

/// One row per profile property, in profile order. A property this engine
/// does not decide is NOT_TESTED, never NOT_APPLICABLE.
pub fn coverage_rows(
    result: &RuntimeTelemetryResult,
    profile: &AssessmentProfile,
) -> Vec<CorrelatedRow> {
    profile
        .properties
        .iter()
        .map(|selected| {
            match result
                .properties
                .iter()
                .find(|p| p.property_id == selected.id)
            {
                Some(p) => CorrelatedRow {
                    property_id: selected.id.clone(),
                    requirement: selected.requirement,
                    coverage_status: status(p.coverage),
                    verdict: p.verdict,
                    evidence_ids: p.evidence_ids.clone(),
                    rationale: format!(
                        "runtime telemetry {} ({}; {} trace(s) failed, {} undecided, {} passed)",
                        p.rule.code(),
                        p.reason,
                        p.traces.fail,
                        p.traces.inconclusive,
                        p.traces.pass
                    ),
                },
                None => CorrelatedRow {
                    property_id: selected.id.clone(),
                    requirement: selected.requirement,
                    coverage_status: CoverageStatus::NotTested,
                    verdict: None,
                    evidence_ids: Vec::new(),
                    rationale: "not decided by the runtime telemetry engine".to_owned(),
                },
            }
        })
        .collect()
}

pub fn coverage_report(
    result: &RuntimeTelemetryResult,
    profile: &AssessmentProfile,
) -> Result<CoverageReport> {
    build_report(
        profile,
        coverage_rows(result, profile),
        CoveragePolicy::default(),
    )
    .map_err(|_| TelemetryError::Internal("coverage report"))
}

/// The run's executions: passive observation of recorded traces. Built after
/// [`crate::evidence_bridge::bind_evidence`], so every verdict has its id.
pub fn executions_document(result: &RuntimeTelemetryResult) -> Result<ExecutionsDocument> {
    let document = ExecutionsDocument {
        schema_version: ExecutionsDocument::SCHEMA_VERSION.to_owned(),
        execution_mode: SupportedMode::Passive,
        evidence_class: EvidenceClass::Trace,
        source: format!(
            "runtime telemetry replay of {} trace file(s)",
            result.inputs.trace_files.len()
        ),
        executions: result
            .properties
            .iter()
            .map(|p| PropertyExecution {
                property_id: p.property_id.to_owned(),
                verdict: p.verdict,
                evidence_ids: p.evidence_ids.clone(),
            })
            .collect(),
    };
    document
        .check(&AssessmentFacts::default())
        .map_err(|_| TelemetryError::Internal("executions document"))?;
    Ok(document)
}
