use serde::{Deserialize, Serialize};

use crate::{
    fallback::expand_full_fallback,
    plan::{ArtifactKind, ContinuousRevalidationPlan, PlanAction},
    reuse::{can_reuse, ReuseCandidate},
    snapshot::SecurityStateSnapshot,
    Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Revalidated,
    Reused,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub kind: ArtifactKind,
    pub id: String,
    pub status: ExecutionStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationRun {
    pub full_fallback: bool,
    pub records: Vec<ExecutionRecord>,
}

pub struct IncrementalRunner;

impl IncrementalRunner {
    pub fn run(
        mut plan: ContinuousRevalidationPlan,
        baseline: &SecurityStateSnapshot,
        candidate: &SecurityStateSnapshot,
    ) -> Result<RevalidationRun> {
        if plan.full_fallback
            || plan
                .items
                .iter()
                .any(|item| item.action == PlanAction::Unknown)
        {
            expand_full_fallback(&mut plan, candidate);
        }
        let baseline_digest = baseline.digest()?;
        let records = plan
            .items
            .into_iter()
            .map(|item| {
                let (status, reason) = match item.action {
                    PlanAction::Revalidate | PlanAction::Unknown => (
                        ExecutionStatus::Revalidated,
                        "selected for deterministic offline revalidation".to_owned(),
                    ),
                    PlanAction::Invalidate => (
                        ExecutionStatus::Invalidated,
                        "result invalidated".to_owned(),
                    ),
                    PlanAction::Reuse => {
                        let decision =
                            reuse_item(item.kind, &item.id, &baseline_digest, baseline, candidate);
                        if decision.allowed {
                            (ExecutionStatus::Reused, decision.reason)
                        } else {
                            (
                                ExecutionStatus::Revalidated,
                                format!("reuse denied: {}", decision.reason),
                            )
                        }
                    }
                };
                ExecutionRecord {
                    kind: item.kind,
                    id: item.id,
                    status,
                    reason,
                }
            })
            .collect();
        Ok(RevalidationRun {
            full_fallback: plan.full_fallback,
            records,
        })
    }
}

fn reuse_item(
    kind: ArtifactKind,
    id: &str,
    baseline_digest: &str,
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> crate::reuse::ReuseDecision {
    match kind {
        ArtifactKind::Property => match (
            baseline.security_state.property_results.get(id),
            candidate.security_state.property_results.get(id),
        ) {
            (Some(before), Some(after)) => can_reuse(&ReuseCandidate {
                baseline_snapshot_digest: baseline_digest.to_owned(),
                expected_baseline_snapshot_digest: baseline_digest.to_owned(),
                original_evidence_ids: before.evidence_ids.clone(),
                baseline_dependencies: before.dependency_digests.clone(),
                candidate_dependencies: after.dependency_digests.clone(),
            }),
            _ => denied("property result is absent"),
        },
        ArtifactKind::Vector => match (
            baseline.security_state.validation_results.get(id),
            candidate.security_state.validation_results.get(id),
        ) {
            (Some(before), Some(after)) => can_reuse(&ReuseCandidate {
                baseline_snapshot_digest: baseline_digest.to_owned(),
                expected_baseline_snapshot_digest: baseline_digest.to_owned(),
                original_evidence_ids: before.evidence_ids.clone(),
                baseline_dependencies: before.dependency_digests.clone(),
                candidate_dependencies: after.dependency_digests.clone(),
            }),
            _ => denied("validation result is absent"),
        },
        ArtifactKind::Path => match (
            baseline.security_state.attack_paths.get(id),
            candidate.security_state.attack_paths.get(id),
        ) {
            (Some(before), Some(after)) if before == after => crate::reuse::ReuseDecision {
                allowed: true,
                reason: "stable Cycle 008 path artifact and graph dependencies".to_owned(),
            },
            _ => denied("path artifact changed or is absent"),
        },
    }
}

fn denied(reason: &str) -> crate::reuse::ReuseDecision {
    crate::reuse::ReuseDecision {
        allowed: false,
        reason: reason.to_owned(),
    }
}
