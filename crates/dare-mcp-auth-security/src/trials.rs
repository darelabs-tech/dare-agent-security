//! Bounded trials and run-wide budgets.
//!
//! Two rules do most of the work here.
//!
//! **Refuse, never clamp.** A scenario asking for eleven trials is refused, not
//! quietly run with ten. A clamped request runs as though it had asked for
//! something reasonable and the operator never learns their scenario was out of
//! bounds.
//!
//! **Run totals do not reset.** A per-trial counter that starts again each
//! trial is not a bound on the run. The ledger charges request counts and
//! retained bytes against run-wide totals that only ever go up.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::model::McpAuthScenario;

/// The plan a run will execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_requests_per_trial: u32,
}

impl TrialPlan {
    /// Build a plan from an approved scenario, refusing anything over bound.
    pub fn from_scenario(scenario: &McpAuthScenario) -> Result<Self> {
        let trials = scenario.trials.count;
        if trials == 0 || trials > crate::limits::HARD_MAX_TRIALS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scenario `{}` asks for {trials} trials; the approved range is 1..={}",
                scenario.id,
                crate::limits::HARD_MAX_TRIALS
            )));
        }

        let requested = scenario
            .safety
            .max_requests_per_trial
            .unwrap_or(crate::limits::HARD_MAX_REQUESTS_PER_TRIAL);
        if requested == 0 || requested > crate::limits::HARD_MAX_REQUESTS_PER_TRIAL {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scenario `{}` asks for {requested} requests per trial; the approved range is \
                 1..={}",
                scenario.id,
                crate::limits::HARD_MAX_REQUESTS_PER_TRIAL
            )));
        }

        Ok(Self {
            trials,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_requests_per_trial: requested,
        })
    }

    /// Narrow the plan to an explicit trial count.
    ///
    /// Narrowing only. An override above the scenario's own count would let a
    /// flag widen what the scenario approved.
    pub fn with_trial_override(mut self, trials: Option<u32>) -> Result<Self> {
        let Some(requested) = trials else {
            return Ok(self);
        };
        if requested == 0 || requested > crate::limits::HARD_MAX_TRIALS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "requested {requested} trials; the approved range is 1..={}",
                crate::limits::HARD_MAX_TRIALS
            )));
        }
        // The override may narrow what the scenario approved. It may not widen
        // it.
        //
        // This check used to be only against HARD_MAX_TRIALS, which meant a
        // scenario approved for 3 trials could be run 10 times from the command
        // line: still under the crate ceiling, and still more authority than
        // the scenario granted. The flag is a reduction, not a second approval.
        if requested > self.trials {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "requested {requested} trials but the scenario approved {}; an override may                  narrow what a scenario approved and never widen it",
                self.trials
            )));
        }
        self.trials = requested;
        Ok(self)
    }

    /// Reduce the plan to what a bounded source can actually supply.
    ///
    /// Only ever reduces. Asking a trace for more trials than it recorded would
    /// end the run in a harness error that says nothing about the boundary
    /// under test.
    pub fn clamped_to_available(mut self, available: u32) -> Self {
        self.trials = self.trials.min(available.max(1));
        self
    }

    pub fn open(&self) -> TrialLedger {
        TrialLedger {
            plan: self.clone(),
            trials_started: 0,
            requests_observed: 0,
            output_bytes_used: 0,
            stopped: None,
        }
    }
}

/// Why a run stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopReason {
    PlanCompleted,
    FirstFail { trial_index: u32 },
    BudgetExhausted { detail: String },
}

impl StopReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PlanCompleted => "PLAN_COMPLETED",
            Self::FirstFail { .. } => "FIRST_FAIL",
            Self::BudgetExhausted { .. } => "BUDGET_EXHAUSTED",
        }
    }
}

/// What a finished run consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub requests_observed: u32,
    pub max_total_requests: u32,
    pub request_bound_per_trial: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    /// Always zero.
    pub state_changes: u32,
    /// Always zero.
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// A trial in progress.
#[derive(Debug)]
pub struct TrialGuard {
    index: u32,
    requests: u32,
    bytes: usize,
}

impl TrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }
}

/// Run-wide accounting.
#[derive(Debug, Clone)]
pub struct TrialLedger {
    plan: TrialPlan,
    trials_started: u32,
    requests_observed: u32,
    output_bytes_used: usize,
    stopped: Option<StopReason>,
}

impl TrialLedger {
    pub fn may_start_trial(&self) -> bool {
        self.stopped.is_none() && self.trials_started < self.plan.trials
    }

    pub fn start_trial(&mut self) -> Result<TrialGuard> {
        if self.trials_started >= self.plan.trials {
            return Err(McpAuthSecurityError::BudgetExhausted(
                "the plan is complete".to_owned(),
            ));
        }
        let index = self.trials_started;
        self.trials_started += 1;
        Ok(TrialGuard {
            index,
            requests: 0,
            bytes: 0,
        })
    }

    /// Charge one observed request against both bounds.
    pub fn charge_request(&mut self, guard: &mut TrialGuard) -> Result<()> {
        if guard.requests + 1 > self.plan.max_requests_per_trial {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "trial {} observed more than {} requests",
                guard.index, self.plan.max_requests_per_trial
            )));
        }
        if self.requests_observed + 1 > crate::limits::HARD_MAX_TOTAL_REQUESTS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "the run observed more than {} requests in total",
                crate::limits::HARD_MAX_TOTAL_REQUESTS
            )));
        }
        guard.requests += 1;
        self.requests_observed += 1;
        Ok(())
    }

    /// Charge retained bytes against both bounds.
    pub fn charge_output(&mut self, guard: &mut TrialGuard, bytes: usize) -> Result<()> {
        if guard.bytes + bytes > crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "trial {} retained more than {} bytes",
                guard.index,
                crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL
            )));
        }
        if self.output_bytes_used + bytes > crate::limits::MAX_TOTAL_OUTPUT_BYTES {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "the run retained more than {} bytes in total",
                crate::limits::MAX_TOTAL_OUTPUT_BYTES
            )));
        }
        guard.bytes += bytes;
        self.output_bytes_used += bytes;
        Ok(())
    }

    /// Stop after the current trial, once its evidence is already collected.
    pub fn stop(&mut self, reason: StopReason) {
        if self.stopped.is_none() {
            self.stopped = Some(reason);
        }
    }

    pub fn stop_reason(&self) -> StopReason {
        self.stopped.clone().unwrap_or(StopReason::PlanCompleted)
    }

    pub fn trials_executed(&self) -> u32 {
        self.trials_started
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            trials_planned: self.plan.trials,
            trials_executed: self.trials_started,
            requests_observed: self.requests_observed,
            max_total_requests: crate::limits::HARD_MAX_TOTAL_REQUESTS,
            request_bound_per_trial: self.plan.max_requests_per_trial,
            output_bytes_used: self.output_bytes_used,
            max_total_output_bytes: crate::limits::MAX_TOTAL_OUTPUT_BYTES,
            state_changes: crate::limits::MAX_STATE_CHANGES,
            external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
            exhausted: matches!(self.stopped, Some(StopReason::BudgetExhausted { .. })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;

    #[test]
    fn a_plan_defaults_to_the_approved_maxima() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert_eq!(plan.trials, 3);
        assert_eq!(
            plan.max_requests_per_trial,
            crate::limits::HARD_MAX_REQUESTS_PER_TRIAL
        );
    }

    #[test]
    fn an_over_bound_trial_count_is_refused_rather_than_clamped() {
        // A clamped request runs as though it had asked for something
        // reasonable, and the operator never learns otherwise.
        let mut over = scenario();
        over.trials.count = crate::limits::HARD_MAX_TRIALS + 1;
        assert!(matches!(
            TrialPlan::from_scenario(&over).expect_err("refused"),
            McpAuthSecurityError::BudgetExhausted(_)
        ));
    }

    #[test]
    fn a_zero_trial_count_is_refused() {
        let mut none = scenario();
        none.trials.count = 0;
        assert!(TrialPlan::from_scenario(&none).is_err());
    }

    #[test]
    fn an_override_is_refused_above_the_crate_hard_maximum() {
        // Renamed. It used to be called
        // `an_override_may_narrow_but_never_widen_past_the_hard_bound`, which
        // claimed the narrowing guarantee while only ever checking the crate
        // ceiling. The guarantee it named is the test below.
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert!(plan
            .with_trial_override(Some(crate::limits::HARD_MAX_TRIALS + 1))
            .is_err());
    }

    #[test]
    fn an_override_may_narrow_what_a_scenario_approved() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert_eq!(plan.trials, 3, "the fixture scenario approves three trials");
        for requested in [1, 2, 3] {
            assert_eq!(
                plan.clone()
                    .with_trial_override(Some(requested))
                    .expect("narrowing is allowed")
                    .trials,
                requested
            );
        }
    }

    #[test]
    fn an_override_can_never_widen_what_a_scenario_approved() {
        // The false PASS this closes: `--trials 10` against a scenario approved
        // for 3 used to run ten times. Every one of those is under
        // HARD_MAX_TRIALS, and none of them was approved.
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert_eq!(plan.trials, 3);
        for requested in [4, 5, crate::limits::HARD_MAX_TRIALS] {
            let err = plan
                .clone()
                .with_trial_override(Some(requested))
                .expect_err("widening past the scenario must be refused");
            assert!(
                err.to_string().contains("approved"),
                "the refusal does not say what was exceeded: {err}"
            );
        }
    }

    #[test]
    fn a_zero_override_is_still_refused_alongside_the_new_bound() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert!(plan.with_trial_override(Some(0)).is_err());
    }

    #[test]
    fn clamping_to_an_available_source_only_reduces() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        assert_eq!(plan.clone().clamped_to_available(1).trials, 1);
        // A source offering more does not widen the plan.
        assert_eq!(plan.clamped_to_available(99).trials, 3);
    }

    #[test]
    fn run_wide_request_totals_do_not_reset_between_trials() {
        // The bug this prevents: a per-trial counter restarting each trial is
        // not a bound on the run.
        let plan = TrialPlan {
            trials: crate::limits::HARD_MAX_TRIALS,
            stop_on_first_fail: false,
            max_requests_per_trial: crate::limits::HARD_MAX_REQUESTS_PER_TRIAL,
        };
        let mut ledger = plan.open();
        let mut charged = 0u32;
        let mut exhausted = false;
        'outer: while ledger.may_start_trial() {
            let mut guard = ledger.start_trial().expect("starts");
            for _ in 0..crate::limits::HARD_MAX_REQUESTS_PER_TRIAL {
                if ledger.charge_request(&mut guard).is_err() {
                    exhausted = true;
                    break 'outer;
                }
                charged += 1;
            }
        }
        assert!(exhausted, "the run-wide total was never reached");
        assert_eq!(charged, crate::limits::HARD_MAX_TOTAL_REQUESTS);
    }

    #[test]
    fn the_per_trial_request_bound_is_enforced_too() {
        let plan = TrialPlan {
            trials: 1,
            stop_on_first_fail: false,
            max_requests_per_trial: 2,
        };
        let mut ledger = plan.open();
        let mut guard = ledger.start_trial().expect("starts");
        ledger.charge_request(&mut guard).expect("first");
        ledger.charge_request(&mut guard).expect("second");
        assert!(ledger.charge_request(&mut guard).is_err());
    }

    #[test]
    fn retained_bytes_are_bounded_per_trial_and_per_run() {
        let plan = TrialPlan {
            trials: 2,
            stop_on_first_fail: false,
            max_requests_per_trial: 1,
        };
        let mut ledger = plan.open();
        let mut guard = ledger.start_trial().expect("starts");
        assert!(ledger
            .charge_output(&mut guard, crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL + 1)
            .is_err());
    }

    #[test]
    fn a_plan_records_zero_state_changes_and_zero_egress() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        let snapshot = plan.open().snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn a_ledger_stops_offering_trials_once_the_plan_is_done() {
        let plan = TrialPlan {
            trials: 1,
            stop_on_first_fail: true,
            max_requests_per_trial: 1,
        };
        let mut ledger = plan.open();
        assert!(ledger.may_start_trial());
        ledger.start_trial().expect("starts");
        assert!(!ledger.may_start_trial());
        assert!(ledger.start_trial().is_err());
    }

    #[test]
    fn stopping_records_the_first_reason_rather_than_the_last() {
        let mut ledger = TrialPlan {
            trials: 2,
            stop_on_first_fail: true,
            max_requests_per_trial: 1,
        }
        .open();
        ledger.stop(StopReason::FirstFail { trial_index: 0 });
        ledger.stop(StopReason::BudgetExhausted {
            detail: "later".to_owned(),
        });
        assert_eq!(ledger.stop_reason().as_str(), "FIRST_FAIL");
    }
}
