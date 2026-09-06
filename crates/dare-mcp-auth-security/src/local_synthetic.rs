//! Local-synthetic execution, gated through the Cycle 009 controls.
//!
//! Identical observations to the simulated adapter, but routed through the
//! adversarial safety substrate so the run carries an explicit budget and a
//! kill switch. Nothing here reaches anything: the "step" it submits for
//! inspection carries identifiers and never credential material, and the budget
//! pins state changes and egress to zero.

use dare_adversarial::model::ExecutionBudget;
use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest};
use crate::model::McpAuthScenario;

/// The Cycle 009 budget a Cycle 018 run executes under.
pub fn synthetic_budget(trials: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "mcp-auth-security-synthetic".to_owned(),
        max_operations: trials.max(1),
        max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        max_state_changes: crate::limits::MAX_STATE_CHANGES,
        max_bytes_read: crate::limits::MAX_TOTAL_OUTPUT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: 1,
    }
}

/// What the controls saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthControlSnapshot {
    pub target_id: String,
    pub max_steps: u32,
    pub state_changes: u32,
    pub external_egress_bytes: u64,
    pub kill_switch_triggered: bool,
}

/// Runs the staged observations under Cycle 009 controls.
#[derive(Debug, Clone)]
pub struct LocalSyntheticAdapter {
    target_id: String,
    trials: u32,
}

impl LocalSyntheticAdapter {
    pub fn new(target_id: impl Into<String>, trials: u32) -> Self {
        Self {
            target_id: target_id.into(),
            trials,
        }
    }

    pub fn for_scenario(scenario: &McpAuthScenario, trials: u32) -> Self {
        Self::new(scenario.id.clone(), trials)
    }

    pub fn snapshot(&self) -> McpAuthControlSnapshot {
        let budget = synthetic_budget(self.trials);
        McpAuthControlSnapshot {
            target_id: self.target_id.clone(),
            max_steps: budget.max_operations,
            state_changes: budget.max_state_changes,
            external_egress_bytes: budget.max_external_egress_bytes,
            kill_switch_triggered: false,
        }
    }
}

impl HarnessAdapter for LocalSyntheticAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::LocalSynthetic
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        // The kill switch: a run pointed at a scenario other than the one it
        // was approved for stops rather than observing. Without this, an
        // approved allocation could be redirected at something else.
        if request.scenario.id != self.target_id {
            return Err(McpAuthSecurityError::refusal(format!(
                "the local-synthetic run was approved for `{}` and was pointed at another \
                 scenario",
                self.target_id
            )));
        }
        crate::simulated::SimulatedAdapter::new().observe(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;

    #[test]
    fn the_budget_pins_state_changes_and_egress_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
    }

    #[test]
    fn an_approved_run_observes_normally() {
        let base = scenario();
        let adapter = LocalSyntheticAdapter::for_scenario(&base, 3);
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &base,
            })
            .expect("observes");
        assert!(!output.observed_requests.is_empty());
        assert_eq!(adapter.mode(), HarnessMode::LocalSynthetic);
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_trips_the_kill_switch() {
        // Without this, an approved allocation could be redirected at something
        // it was never approved for.
        let adapter = LocalSyntheticAdapter::new("MCP-AUTH-LAB-OTHER", 3);
        let base = scenario();
        let err = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &base,
            })
            .expect_err("must refuse");
        assert!(err.is_refusal());
    }

    #[test]
    fn the_snapshot_records_what_the_controls_allowed() {
        let snapshot = LocalSyntheticAdapter::for_scenario(&scenario(), 3).snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
        assert!(!snapshot.kill_switch_triggered);
        assert_eq!(snapshot.target_id, "MCP-AUTH-LAB-001");
    }

    #[test]
    fn the_snapshot_carries_identifiers_and_never_credential_material() {
        let rendered =
            serde_json::to_string(&LocalSyntheticAdapter::for_scenario(&scenario(), 3).snapshot())
                .expect("serializes");
        for banned in ["Bearer", "eyJ", "sk-live", "-----BEGIN", "://"] {
            assert!(!rendered.contains(banned), "snapshot carried {banned}");
        }
    }
}
