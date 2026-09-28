//! Join assessment plan with Cycle 001 evidence references. No second evidence format.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::error::CoverageError;
use crate::facts::AssessmentFacts;
use crate::math::finalize_row;
use crate::plan::AssessmentPlan;
use crate::profile::RequirementLevel;
use crate::property::{EvidenceClass, SupportedMode};
use crate::report::CoverageReport;
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

/// Executions recorded by one run, together with the mode that produced them.
///
/// A bare `[PropertyExecution]` array says nothing about how its verdicts were
/// obtained. This document does: `validate remote` (Cycle 022) writes one
/// with `execution_mode = dynamic` and `evidence_class = DYNAMIC_AUTHORIZED`,
/// so a coverage report can say which rows rest on authorized live traffic.
/// It adds no property and changes no profile denominator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionsDocument {
    pub schema_version: String,
    pub execution_mode: SupportedMode,
    pub evidence_class: EvidenceClass,
    /// Operator-readable provenance of the run (no credential, no body).
    pub source: String,
    pub executions: Vec<PropertyExecution>,
}

impl ExecutionsDocument {
    pub const SCHEMA_VERSION: &'static str = "1";

    /// Refuse a document that contradicts itself or the assessment facts.
    pub fn check(&self, facts: &AssessmentFacts) -> Result<(), CoverageError> {
        let invalid = |why: &str| Err(CoverageError::InvalidState(format!("executions: {why}")));
        if self.schema_version != Self::SCHEMA_VERSION {
            return invalid("unsupported schema_version");
        }
        let dynamic_mode = self.execution_mode == SupportedMode::Dynamic;
        let dynamic_class = self.evidence_class == EvidenceClass::DynamicAuthorized;
        if dynamic_mode != dynamic_class {
            return invalid("dynamic mode and DYNAMIC_AUTHORIZED evidence go together");
        }
        // Evidence gathered under a dynamic authorization cannot be scored
        // against facts whose ROE prohibits dynamic testing.
        if dynamic_mode && !facts.dynamic_authorization_allowed {
            return invalid(
                "dynamic evidence was supplied but the facts deny dynamic authorization",
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for execution in &self.executions {
            if !seen.insert(execution.property_id.as_str()) {
                return invalid("a property appears twice");
            }
            if execution.verdict.is_some() && execution.evidence_ids.is_empty() {
                return invalid("a verdict without a Cycle 001 evidence id");
            }
        }
        Ok(())
    }

    /// Mark every decided row that this document supplied with its mode.
    pub fn annotate(&self, report: &mut CoverageReport) {
        let mode = match self.execution_mode {
            SupportedMode::Dynamic => "dynamic",
            SupportedMode::Passive => "passive",
            SupportedMode::Static => "static",
        };
        for row in &mut report.properties {
            let supplied = self
                .executions
                .iter()
                .any(|e| e.property_id == row.property_id && e.verdict.is_some());
            if supplied && row.verdict.is_some() {
                row.rationale = format!("{}; {mode} evidence from {}", row.rationale, self.source);
            }
        }
    }
}

/// Executions input: the original bare array, or an [`ExecutionsDocument`].
pub fn parse_executions(
    raw: &str,
) -> Result<(Vec<PropertyExecution>, Option<ExecutionsDocument>), CoverageError> {
    let parse_error =
        |e: serde_json::Error| CoverageError::InvalidState(format!("executions parse: {e}"));
    if raw.trim_start().starts_with('[') {
        return Ok((serde_json::from_str(raw).map_err(parse_error)?, None));
    }
    let document: ExecutionsDocument = serde_json::from_str(raw).map_err(parse_error)?;
    Ok((document.executions.clone(), Some(document)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agentic_registry, multi_turn_security_profile, run_assessment, CoveragePolicy};

    fn document(mode: SupportedMode, class: EvidenceClass) -> ExecutionsDocument {
        ExecutionsDocument {
            schema_version: "1".into(),
            execution_mode: mode,
            evidence_class: class,
            source: "remote run under authorization lab-auth-1".into(),
            executions: vec![PropertyExecution {
                property_id: "AGENT.GOAL.REFUSAL_PERSISTENCE".into(),
                verdict: Some(Verdict::Fail),
                evidence_ids: vec!["ev-1".into()],
            }],
        }
    }

    fn facts(dynamic_allowed: bool) -> AssessmentFacts {
        AssessmentFacts {
            agent_present: true,
            stateful_agent_present: true,
            dynamic_authorization_allowed: dynamic_allowed,
            ..Default::default()
        }
    }

    #[test]
    fn dynamic_evidence_is_refused_when_the_facts_deny_dynamic_authorization() {
        let doc = document(SupportedMode::Dynamic, EvidenceClass::DynamicAuthorized);
        assert!(doc.check(&facts(true)).is_ok());
        let error = doc.check(&facts(false)).unwrap_err().to_string();
        assert!(error.contains("deny dynamic authorization"), "{error}");
    }

    #[test]
    fn mode_and_evidence_class_must_agree() {
        for (mode, class) in [
            (SupportedMode::Dynamic, EvidenceClass::Trace),
            (SupportedMode::Static, EvidenceClass::DynamicAuthorized),
        ] {
            assert!(
                document(mode, class).check(&facts(true)).is_err(),
                "{mode:?} {class:?}"
            );
        }
        assert!(document(SupportedMode::Static, EvidenceClass::Static)
            .check(&facts(false))
            .is_ok());
    }

    #[test]
    fn duplicates_unsupported_versions_and_unevidenced_verdicts_are_refused() {
        let base = document(SupportedMode::Dynamic, EvidenceClass::DynamicAuthorized);
        let mut twice = base.clone();
        twice.executions.push(twice.executions[0].clone());
        let mut version = base.clone();
        version.schema_version = "2".into();
        let mut bare = base.clone();
        bare.executions[0].evidence_ids.clear();
        for doc in [twice, version, bare] {
            assert!(doc.check(&facts(true)).is_err());
        }
    }

    #[test]
    fn the_bare_array_is_still_accepted_and_carries_no_mode() {
        let (executions, document) = parse_executions(
            r#"[{"property_id":"AGENT.GOAL.REFUSAL_PERSISTENCE","verdict":"FAIL","evidence_ids":["ev-1"]}]"#,
        )
        .unwrap();
        assert_eq!(executions.len(), 1);
        assert!(document.is_none());
    }

    #[test]
    fn a_document_round_trips_and_refuses_unknown_fields() {
        let doc = document(SupportedMode::Dynamic, EvidenceClass::DynamicAuthorized);
        let raw = serde_json::to_string(&doc).unwrap();
        assert!(
            raw.contains(r#""execution_mode":"dynamic""#) && raw.contains("DYNAMIC_AUTHORIZED")
        );
        let (executions, parsed) = parse_executions(&raw).unwrap();
        assert_eq!(parsed.as_ref(), Some(&doc));
        assert_eq!(executions, doc.executions);
        let extra = raw.replacen('{', r#"{"verdict":"PASS","#, 1);
        assert!(parse_executions(&extra).is_err());
    }

    #[test]
    fn annotation_marks_only_rows_the_document_decided_and_moves_no_number() {
        let profile = multi_turn_security_profile().unwrap();
        let registry = agentic_registry().unwrap();
        let doc = document(SupportedMode::Dynamic, EvidenceClass::DynamicAuthorized);
        let plain = run_assessment(
            &profile,
            &registry,
            &facts(true),
            &doc.executions,
            CoveragePolicy::default(),
        )
        .unwrap();
        let mut annotated = plain.clone();
        doc.annotate(&mut annotated);
        assert_eq!(
            (
                annotated.tested,
                annotated.eligible,
                &annotated.counts,
                &annotated.gate
            ),
            (plain.tested, plain.eligible, &plain.counts, &plain.gate)
        );
        for (before, after) in plain.properties.iter().zip(&annotated.properties) {
            let decided = before.property_id == "AGENT.GOAL.REFUSAL_PERSISTENCE";
            assert_eq!(after.rationale.contains("dynamic evidence from"), decided);
            assert_eq!(
                (&after.verdict, &after.evidence_ids),
                (&before.verdict, &before.evidence_ids)
            );
        }
    }
}
