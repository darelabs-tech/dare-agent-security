//! Feeding a multi-turn result into Cycle 006 coverage.
//!
//! The mapping is honest in both directions:
//!
//! - an invariant the scenario could decide is `APPLICABLE` with its verdict;
//! - an invariant this scenario had nothing to decide is `NOT_TESTED` — the
//!   agent is stateful, so the surface exists; this run simply did not test
//!   it. Relabeling that `NOT_APPLICABLE` would let a narrower scenario score
//!   better coverage by testing less.
//!
//! Only the `multi-turn-security-baseline-2026` profile is used, so no
//! earlier profile's denominator is touched.

use dare_coverage::{
    build_report, multi_turn_security_profile, AssessmentFacts, CorrelatedRow, CoveragePolicy,
    CoverageReport, CoverageStatus,
};

use crate::error::{MultiTurnError, Result};
use crate::result::MultiTurnResult;

/// Facts every multi-turn run establishes about its target.
pub fn assessment_facts() -> AssessmentFacts {
    AssessmentFacts {
        agent_present: true,
        stateful_agent_present: true,
        ..Default::default()
    }
}

/// One coverage row per profile property, in profile order.
pub fn coverage_rows(
    result: &MultiTurnResult,
    evidence_ids: &[(String, String)],
) -> Result<Vec<CorrelatedRow>> {
    let profile = multi_turn_security_profile()
        .map_err(|_| MultiTurnError::Schema("multi-turn profile does not load".into()))?;
    profile
        .properties
        .iter()
        .map(|selected| {
            let outcome = result
                .invariants
                .iter()
                .find(|o| o.property_id == selected.id)
                .ok_or_else(|| {
                    MultiTurnError::Schema("profile property has no invariant".into())
                })?;
            let ids = evidence_ids
                .iter()
                .filter(|(property, _)| property == &selected.id)
                .map(|(_, id)| id.clone())
                .collect();
            Ok(if outcome.applicable {
                CorrelatedRow {
                    property_id: selected.id.clone(),
                    requirement: selected.requirement,
                    coverage_status: CoverageStatus::Applicable,
                    verdict: Some(outcome.verdict),
                    evidence_ids: ids,
                    rationale: format!(
                        "decided by {} ({})",
                        outcome.invariant.as_str(),
                        outcome.reason
                    ),
                }
            } else {
                CorrelatedRow {
                    property_id: selected.id.clone(),
                    requirement: selected.requirement,
                    coverage_status: CoverageStatus::NotTested,
                    verdict: None,
                    evidence_ids: Vec::new(),
                    rationale:
                        "the agent is stateful but this scenario did not exercise the property"
                            .to_owned(),
                }
            })
        })
        .collect()
}

pub fn coverage_report(
    result: &MultiTurnResult,
    evidence_ids: &[(String, String)],
) -> Result<CoverageReport> {
    let profile = multi_turn_security_profile()
        .map_err(|_| MultiTurnError::Schema("multi-turn profile does not load".into()))?;
    build_report(
        &profile,
        coverage_rows(result, evidence_ids)?,
        CoveragePolicy::default(),
    )
    .map_err(|_| MultiTurnError::Schema("coverage report could not be built".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::OutputLedger;
    use crate::graph::tests::{edge, graph, node};
    use crate::limits::EffectiveBounds;
    use crate::model::fixtures::{graph_set, scenario};
    use crate::model::{MultiTurnInvariant, ObservationClass::*};
    use crate::result::run_scenario;
    use crate::simulated::{ReferenceAgent, SimulatedAdapter};
    use dare_coverage::{agentic_registry, evaluate_applicability};
    use dare_security_evidence::Verdict;

    fn result(agent: ReferenceAgent) -> MultiTurnResult {
        let graphs = graph_set(&[graph(
            vec![node("a", false), node("b", true), node("done", true)],
            vec![edge("a", Refused, "b"), edge("a", Complied, "done")],
        )]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let mut adapter = SimulatedAdapter::new(agent, &s);
        run_scenario(
            &s,
            &graphs,
            &mut adapter,
            &mut OutputLedger::new(EffectiveBounds::default()),
            "2026-09-27T00:00:00Z",
        )
        .expect("runs")
        .0
    }

    #[test]
    fn the_facts_make_every_multi_turn_property_applicable() {
        let registry = agentic_registry().expect("registry");
        for invariant in MultiTurnInvariant::ALL {
            let property = registry.get(invariant.property_id()).expect("registered");
            assert_eq!(
                evaluate_applicability(property, &assessment_facts())
                    .expect("decides")
                    .status,
                CoverageStatus::Applicable
            );
        }
    }

    #[test]
    fn decided_invariants_are_applicable_and_the_rest_are_not_tested_never_not_applicable() {
        let r = result(ReferenceAgent::ErodingRefusal {
            refusals_before_comply: 1,
        });
        let rows = coverage_rows(&r, &[]).expect("rows");
        assert_eq!(rows.len(), 7);
        let refusal = rows
            .iter()
            .find(|row| row.property_id == "AGENT.GOAL.REFUSAL_PERSISTENCE")
            .expect("row");
        assert_eq!(
            (refusal.coverage_status, refusal.verdict),
            (CoverageStatus::Applicable, Some(Verdict::Fail))
        );
        let isolation = rows
            .iter()
            .find(|row| row.property_id == "AGENT.MEMORY.CONVERSATION_ISOLATION")
            .expect("row");
        assert_eq!(isolation.coverage_status, CoverageStatus::NotTested);
        assert!(rows
            .iter()
            .all(|row| row.coverage_status != CoverageStatus::NotApplicable));
    }

    #[test]
    fn the_report_builds_over_the_seven_property_profile() {
        let report = coverage_report(&result(ReferenceAgent::SecureRefuser), &[]).expect("report");
        assert_eq!(report.properties.len(), 7);
        assert!(report.eligible >= report.tested);
    }
}
