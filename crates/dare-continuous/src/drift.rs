use std::collections::BTreeSet;

use dare_coverage::CoverageStatus;
use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::snapshot::{PropertyState, SecurityStateSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftDisposition {
    Improved,
    Regressed,
    Unchanged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyDrift {
    pub property_id: String,
    pub before: Option<Verdict>,
    pub after: Option<Verdict>,
    pub disposition: DriftDisposition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDrift {
    pub before: f64,
    pub after: f64,
    pub delta: f64,
    pub blocked_delta: i64,
    pub not_tested_delta: i64,
    pub error_delta: i64,
    pub disposition: DriftDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphDriftKind {
    PathAdded,
    PathRemoved,
    PathStatusChanged,
    ImpactFactorChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDrift {
    pub path_id: String,
    pub kind: GraphDriftKind,
    pub risky: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationDrift {
    pub vector_id: String,
    pub before: Option<Verdict>,
    pub after: Option<Verdict>,
    pub disposition: DriftDisposition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityDrift {
    pub disposition: DriftDisposition,
    pub properties: Vec<PropertyDrift>,
    pub coverage: CoverageDrift,
    pub graph: Vec<GraphDrift>,
    pub validations: Vec<ValidationDrift>,
}

pub fn compute_drift(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> SecurityDrift {
    let property_ids: BTreeSet<_> = baseline
        .security_state
        .property_results
        .keys()
        .chain(candidate.security_state.property_results.keys())
        .collect();
    let properties: Vec<_> = property_ids
        .into_iter()
        .map(|id| {
            let before = baseline.security_state.property_results.get(id);
            let after = candidate.security_state.property_results.get(id);
            PropertyDrift {
                property_id: id.clone(),
                before: before.and_then(|state| state.verdict),
                after: after.and_then(|state| state.verdict),
                disposition: compare_property(before, after),
            }
        })
        .collect();
    let coverage = coverage_drift(baseline, candidate);
    let graph = graph_drift(baseline, candidate);
    let validations = validation_drift(baseline, candidate);
    let dispositions = properties
        .iter()
        .map(|item| item.disposition)
        .chain(std::iter::once(coverage.disposition))
        .chain(validations.iter().map(|item| item.disposition));
    let mut overall = DriftDisposition::Unchanged;
    for disposition in dispositions {
        overall = combine(overall, disposition);
    }
    if graph.iter().any(|item| item.risky) {
        overall = DriftDisposition::Regressed;
    }
    SecurityDrift {
        disposition: overall,
        properties,
        coverage,
        graph,
        validations,
    }
}

fn compare_property(
    before: Option<&PropertyState>,
    after: Option<&PropertyState>,
) -> DriftDisposition {
    match (before, after) {
        (Some(left), Some(right)) if left == right => DriftDisposition::Unchanged,
        (Some(left), Some(right)) => compare_verdict(left.verdict, right.verdict),
        (None, Some(right)) if right.verdict == Some(Verdict::Fail) => DriftDisposition::Regressed,
        (Some(left), None) if left.verdict == Some(Verdict::Pass) => DriftDisposition::Unknown,
        _ => DriftDisposition::Unknown,
    }
}

fn compare_verdict(before: Option<Verdict>, after: Option<Verdict>) -> DriftDisposition {
    match (before, after) {
        (Some(Verdict::Fail), Some(Verdict::Pass)) => DriftDisposition::Improved,
        (Some(Verdict::Pass), Some(Verdict::Fail | Verdict::Error | Verdict::Inconclusive)) => {
            DriftDisposition::Regressed
        }
        (left, right) if left == right => DriftDisposition::Unchanged,
        (None, _) | (_, None) => DriftDisposition::Unknown,
        _ => DriftDisposition::Unknown,
    }
}

fn coverage_drift(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> CoverageDrift {
    let (before, before_blocked, before_not_tested, before_error) = coverage_values(baseline);
    let (after, after_blocked, after_not_tested, after_error) = coverage_values(candidate);
    let delta = after - before;
    let disposition =
        if delta < -f64::EPSILON || after_blocked > before_blocked || after_error > before_error {
            DriftDisposition::Regressed
        } else if delta > f64::EPSILON {
            DriftDisposition::Improved
        } else {
            DriftDisposition::Unchanged
        };
    CoverageDrift {
        before,
        after,
        delta,
        blocked_delta: after_blocked as i64 - before_blocked as i64,
        not_tested_delta: after_not_tested as i64 - before_not_tested as i64,
        error_delta: after_error as i64 - before_error as i64,
        disposition,
    }
}

fn coverage_values(snapshot: &SecurityStateSnapshot) -> (f64, usize, usize, usize) {
    let values: Vec<_> = snapshot.security_state.property_results.values().collect();
    let eligible = values
        .iter()
        .filter(|state| {
            !matches!(
                state.coverage_status,
                CoverageStatus::NotApplicable | CoverageStatus::OutOfScope
            )
        })
        .count();
    let tested = values
        .iter()
        .filter(|state| state.verdict.is_some())
        .count();
    let ratio = if eligible == 0 {
        1.0
    } else {
        tested as f64 / eligible as f64
    };
    (
        ratio,
        values
            .iter()
            .filter(|state| state.coverage_status == CoverageStatus::Blocked)
            .count(),
        values
            .iter()
            .filter(|state| state.coverage_status == CoverageStatus::NotTested)
            .count(),
        values
            .iter()
            .filter(|state| state.verdict == Some(Verdict::Error))
            .count(),
    )
}

fn graph_drift(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> Vec<GraphDrift> {
    let ids: BTreeSet<_> = baseline
        .security_state
        .attack_paths
        .keys()
        .chain(candidate.security_state.attack_paths.keys())
        .collect();
    ids.into_iter()
        .filter_map(|id| {
            let before = baseline.security_state.attack_paths.get(id);
            let after = candidate.security_state.attack_paths.get(id);
            let (kind, risky) = match (before, after) {
                (None, Some(path)) => (
                    GraphDriftKind::PathAdded,
                    path.destructive || path.cross_tenant,
                ),
                (Some(_), None) => (GraphDriftKind::PathRemoved, false),
                (Some(left), Some(right)) if left.status != right.status => (
                    GraphDriftKind::PathStatusChanged,
                    right.destructive || right.cross_tenant,
                ),
                (Some(left), Some(right))
                    if left.destructive != right.destructive
                        || left.cross_tenant != right.cross_tenant =>
                {
                    (
                        GraphDriftKind::ImpactFactorChanged,
                        right.destructive || right.cross_tenant,
                    )
                }
                _ => return None,
            };
            Some(GraphDrift {
                path_id: id.clone(),
                kind,
                risky,
            })
        })
        .collect()
}

fn validation_drift(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> Vec<ValidationDrift> {
    let ids: BTreeSet<_> = baseline
        .security_state
        .validation_results
        .keys()
        .chain(candidate.security_state.validation_results.keys())
        .collect();
    ids.into_iter()
        .map(|id| {
            let before = baseline.security_state.validation_results.get(id);
            let after = candidate.security_state.validation_results.get(id);
            ValidationDrift {
                vector_id: id.clone(),
                before: before.and_then(|value| value.verdict),
                after: after.and_then(|value| value.verdict),
                disposition: compare_verdict(
                    before.and_then(|value| value.verdict),
                    after.and_then(|value| value.verdict),
                ),
            }
        })
        .collect()
}

fn combine(left: DriftDisposition, right: DriftDisposition) -> DriftDisposition {
    use DriftDisposition::*;
    match (left, right) {
        (Regressed, _) | (_, Regressed) => Regressed,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Improved, _) | (_, Improved) => Improved,
        _ => Unchanged,
    }
}
