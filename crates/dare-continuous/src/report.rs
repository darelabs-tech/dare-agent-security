use serde::{Deserialize, Serialize};

use crate::{
    drift::SecurityDrift,
    plan::{ContinuousRevalidationPlan, PlanAction},
    policy::GateResult,
    runner::RevalidationRun,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuousValidationReport {
    pub schema_version: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub policy_digest: String,
    pub plan: ContinuousRevalidationPlan,
    #[serde(default)]
    pub run: Option<RevalidationRun>,
    pub drift: SecurityDrift,
    pub gate: GateResult,
    pub revalidate_count: usize,
    pub reuse_count: usize,
    pub reuse_ratio: f64,
    pub dynamic_approval_granted: bool,
}

impl ContinuousValidationReport {
    pub fn new(
        baseline_digest: String,
        candidate_digest: String,
        policy_digest: String,
        plan: ContinuousRevalidationPlan,
        run: Option<RevalidationRun>,
        drift: SecurityDrift,
        gate: GateResult,
    ) -> Self {
        let revalidate_count = plan
            .items
            .iter()
            .filter(|item| item.action == PlanAction::Revalidate)
            .count();
        let reuse_count = plan
            .items
            .iter()
            .filter(|item| item.action == PlanAction::Reuse)
            .count();
        let total = revalidate_count + reuse_count;
        Self {
            schema_version: "1".to_owned(),
            baseline_digest,
            candidate_digest,
            policy_digest,
            plan,
            run,
            drift,
            gate,
            revalidate_count,
            reuse_count,
            reuse_ratio: if total == 0 {
                0.0
            } else {
                reuse_count as f64 / total as f64
            },
            dynamic_approval_granted: false,
        }
    }
}
