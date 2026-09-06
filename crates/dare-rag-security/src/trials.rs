//! The bounded trial ledger.
//!
//! Two rules shape this module.
//!
//! **Over-limit is refused, never clamped.** A request past a hard bound could
//! be quietly reduced to something reasonable, and the run would then succeed
//! while the operator never learned their scenario was out of bounds. Refusing
//! makes the mistake visible at the moment it is made. Narrowing is always
//! allowed — a scenario may ask for less than the maximum, and often should.
//!
//! **Run totals never reset between trials.** A counter that restarts each
//! trial is not a bound on the run; ten trials of eight queries would then be
//! eighty queries against a stated ceiling of twenty-four. Per-trial state lives
//! on [`TrialGuard`] and is recreated each trial; run-wide state lives on
//! [`TrialLedger`] and is not.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{RagSecurityError, Result};
use crate::model::RagSecurityScenario;

/// A fixed, already-bounded execution plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_queries_per_trial: u32,
    pub max_total_queries: u32,
    pub max_results_per_query: u32,
    pub max_output_bytes_per_trial: usize,
    pub max_total_output_bytes: usize,
    pub max_duration_seconds: u64,
}

impl Default for TrialPlan {
    fn default() -> Self {
        Self {
            trials: crate::limits::DEFAULT_TRIALS,
            stop_on_first_fail: crate::limits::STOP_ON_FIRST_FAIL,
            max_queries_per_trial: crate::limits::HARD_MAX_QUERIES_PER_TRIAL,
            max_total_queries: crate::limits::HARD_MAX_TOTAL_QUERIES,
            max_results_per_query: crate::limits::HARD_MAX_RESULTS_PER_QUERY,
            max_output_bytes_per_trial: crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            max_total_output_bytes: crate::limits::MAX_TOTAL_OUTPUT_BYTES,
            max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        }
    }
}

impl TrialPlan {
    /// Bound a requested value, refusing anything above the hard maximum.
    ///
    /// The asymmetry is the whole point: `min` would silently accept an
    /// over-limit request and run something smaller than was asked for.
    fn bound(requested: Option<u32>, hard_max: u32, label: &str) -> Result<u32> {
        match requested {
            None => Ok(hard_max),
            Some(0) => Err(RagSecurityError::invalid(format!("{label} cannot be zero"))),
            Some(value) if value > hard_max => Err(RagSecurityError::BudgetExhausted(format!(
                "{label} of {value} exceeds the hard maximum of {hard_max}"
            ))),
            Some(value) => Ok(value),
        }
    }

    fn bound_bytes(requested: Option<usize>, hard_max: usize, label: &str) -> Result<usize> {
        match requested {
            None => Ok(hard_max),
            Some(0) => Err(RagSecurityError::invalid(format!("{label} cannot be zero"))),
            Some(value) if value > hard_max => Err(RagSecurityError::BudgetExhausted(format!(
                "{label} of {value} exceeds the hard maximum of {hard_max}"
            ))),
            Some(value) => Ok(value),
        }
    }

    /// Build a plan from a scenario's requested envelope.
    pub fn from_scenario(scenario: &RagSecurityScenario) -> Result<Self> {
        let safety = &scenario.safety;
        Ok(Self {
            trials: Self::bound(
                Some(scenario.trials.count),
                crate::limits::HARD_MAX_TRIALS,
                "trial count",
            )?,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_queries_per_trial: Self::bound(
                safety.max_queries_per_trial,
                crate::limits::HARD_MAX_QUERIES_PER_TRIAL,
                "queries per trial",
            )?,
            max_total_queries: Self::bound(
                safety.max_total_queries,
                crate::limits::HARD_MAX_TOTAL_QUERIES,
                "total queries",
            )?,
            max_results_per_query: Self::bound(
                safety.max_results_per_query,
                crate::limits::HARD_MAX_RESULTS_PER_QUERY,
                "results per query",
            )?,
            max_output_bytes_per_trial: Self::bound_bytes(
                safety.max_output_bytes,
                crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL,
                "output bytes per trial",
            )?,
            max_total_output_bytes: Self::bound_bytes(
                safety.max_total_output_bytes,
                crate::limits::MAX_TOTAL_OUTPUT_BYTES,
                "total output bytes",
            )?,
            max_duration_seconds: match safety.max_duration_seconds {
                None => crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
                Some(0) => return Err(RagSecurityError::invalid("trial duration cannot be zero")),
                Some(value) if value > crate::limits::MAX_DURATION_SECONDS_PER_TRIAL => {
                    return Err(RagSecurityError::BudgetExhausted(format!(
                        "trial duration of {value}s exceeds the hard maximum of {}s",
                        crate::limits::MAX_DURATION_SECONDS_PER_TRIAL
                    )))
                }
                Some(value) => value,
            },
        })
    }

    /// Apply an operator's `--trials` override.
    pub fn with_trial_override(mut self, trials: Option<u32>) -> Result<Self> {
        if let Some(requested) = trials {
            self.trials = Self::bound(
                Some(requested),
                crate::limits::HARD_MAX_TRIALS,
                "trial count",
            )?;
        }
        Ok(self)
    }

    /// Reduce the plan to what a bounded source can actually supply.
    ///
    /// Only ever lowers. A trace with three trials cannot be asked for ten;
    /// asking would end the run in a harness error that says nothing about the
    /// boundary under test.
    pub fn clamped_to_available(mut self, available: u32) -> Self {
        self.trials = self.trials.min(available.max(1));
        self
    }

    pub fn open(self) -> TrialLedger {
        TrialLedger {
            plan: self,
            trials_executed: 0,
            queries_charged: 0,
            output_bytes_used: 0,
            exhausted: false,
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

/// Snapshot of consumption, recorded into evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub queries_observed: u32,
    pub max_total_queries: u32,
    pub result_bound_per_query: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    /// Cycle 017 performs none. Recorded so the zero is evidenced.
    pub state_changes: u32,
    /// Cycle 017 performs none. Recorded so the zero is evidenced.
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// Tracks consumption against a fixed plan.
#[derive(Debug)]
pub struct TrialLedger {
    plan: TrialPlan,
    trials_executed: u32,
    /// Run-wide. Deliberately not reset by `start_trial`.
    queries_charged: u32,
    /// Run-wide. Deliberately not reset by `start_trial`.
    output_bytes_used: usize,
    exhausted: bool,
}

/// Per-trial state. Recreated each trial, which is what makes it per-trial.
#[derive(Debug)]
pub struct TrialGuard {
    index: u32,
    started: Instant,
    deadline: Duration,
    queries_this_trial: u32,
    bytes_this_trial: usize,
}

impl TrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Refuse to continue past the trial's time bound.
    pub fn check_deadline(&self) -> Result<()> {
        if self.started.elapsed() > self.deadline {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "trial {} exceeded its {}s bound",
                self.index,
                self.deadline.as_secs()
            )));
        }
        Ok(())
    }
}

impl TrialLedger {
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            trials_planned: self.plan.trials,
            trials_executed: self.trials_executed,
            queries_observed: self.queries_charged,
            max_total_queries: self.plan.max_total_queries,
            result_bound_per_query: self.plan.max_results_per_query,
            output_bytes_used: self.output_bytes_used,
            max_total_output_bytes: self.plan.max_total_output_bytes,
            state_changes: crate::limits::MAX_STATE_CHANGES,
            external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
            exhausted: self.exhausted,
        }
    }

    pub fn plan(&self) -> TrialPlan {
        self.plan
    }

    pub fn may_start_trial(&self) -> bool {
        !self.exhausted && self.trials_executed < self.plan.trials
    }

    /// Begin a trial, resetting only per-trial state.
    pub fn start_trial(&mut self) -> Result<TrialGuard> {
        if self.exhausted {
            return Err(RagSecurityError::BudgetExhausted(
                "the run budget is exhausted".to_owned(),
            ));
        }
        if self.trials_executed >= self.plan.trials {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "the plan allows {} trials",
                self.plan.trials
            )));
        }
        let index = self.trials_executed;
        self.trials_executed += 1;
        Ok(TrialGuard {
            index,
            started: Instant::now(),
            deadline: Duration::from_secs(self.plan.max_duration_seconds),
            queries_this_trial: 0,
            bytes_this_trial: 0,
        })
    }

    /// Charge one observed query against both the trial and the run.
    pub fn charge_query(&mut self, guard: &mut TrialGuard) -> Result<()> {
        if guard.queries_this_trial >= self.plan.max_queries_per_trial {
            self.exhausted = true;
            return Err(RagSecurityError::BudgetExhausted(format!(
                "trial {} reached its bound of {} queries",
                guard.index, self.plan.max_queries_per_trial
            )));
        }
        if self.queries_charged >= self.plan.max_total_queries {
            self.exhausted = true;
            return Err(RagSecurityError::BudgetExhausted(format!(
                "the run reached its bound of {} queries",
                self.plan.max_total_queries
            )));
        }
        guard.queries_this_trial += 1;
        self.queries_charged += 1;
        Ok(())
    }

    /// Charge retained bytes against both the trial and the run.
    pub fn charge_output(&mut self, guard: &mut TrialGuard, bytes: usize) -> Result<()> {
        if guard.bytes_this_trial + bytes > self.plan.max_output_bytes_per_trial {
            self.exhausted = true;
            return Err(RagSecurityError::BudgetExhausted(format!(
                "trial {} reached its bound of {} retained bytes",
                guard.index, self.plan.max_output_bytes_per_trial
            )));
        }
        if self.output_bytes_used + bytes > self.plan.max_total_output_bytes {
            self.exhausted = true;
            return Err(RagSecurityError::BudgetExhausted(format!(
                "the run reached its bound of {} retained bytes",
                self.plan.max_total_output_bytes
            )));
        }
        guard.bytes_this_trial += bytes;
        self.output_bytes_used += bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;

    #[test]
    fn a_plan_defaults_to_the_approved_maxima() {
        let plan = TrialPlan::default();
        assert_eq!(plan.trials, crate::limits::DEFAULT_TRIALS);
        assert_eq!(
            plan.max_total_queries,
            crate::limits::HARD_MAX_TOTAL_QUERIES
        );
        // The two zero bounds are compile-time constants, so a non-zero value
        // would not build rather than failing a test at run time.
        const { assert!(crate::limits::MAX_STATE_CHANGES == 0) };
        const { assert!(crate::limits::EXTERNAL_EGRESS_BYTES == 0) };
    }

    #[test]
    fn a_scenario_may_narrow_a_bound() {
        let mut scenario = scenario();
        scenario.safety.max_queries_per_trial = Some(2);
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        assert_eq!(plan.max_queries_per_trial, 2);
    }

    #[test]
    fn an_over_limit_request_is_refused_and_never_clamped_upward() {
        // The distinction that matters: clamping would run something smaller
        // than was asked for and report success.
        let mut over_queries = scenario();
        over_queries.safety.max_queries_per_trial =
            Some(crate::limits::HARD_MAX_QUERIES_PER_TRIAL + 1);
        let err = TrialPlan::from_scenario(&over_queries).expect_err("must be refused");
        assert!(matches!(err, RagSecurityError::BudgetExhausted(_)));

        let mut over_trials = scenario();
        over_trials.trials.count = crate::limits::HARD_MAX_TRIALS + 1;
        assert!(TrialPlan::from_scenario(&over_trials).is_err());
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_treated_as_unlimited() {
        let mut scenario = scenario();
        scenario.safety.max_results_per_query = Some(0);
        assert!(TrialPlan::from_scenario(&scenario).is_err());
    }

    #[test]
    fn a_trial_override_cannot_raise_the_hard_maximum() {
        let plan = TrialPlan::default();
        assert!(plan
            .with_trial_override(Some(crate::limits::HARD_MAX_TRIALS + 1))
            .is_err());
        assert_eq!(
            plan.with_trial_override(Some(2)).expect("narrows").trials,
            2
        );
    }

    #[test]
    fn clamping_to_an_available_source_only_ever_lowers() {
        let plan = TrialPlan {
            trials: 5,
            ..TrialPlan::default()
        };
        assert_eq!(plan.clamped_to_available(2).trials, 2);
        // A source claiming more capacity cannot raise the plan.
        assert_eq!(plan.clamped_to_available(50).trials, 5);
    }

    #[test]
    fn the_run_query_counter_never_resets_between_trials() {
        // The bug this prevents: ten trials of eight queries against a stated
        // run ceiling of twenty-four.
        let plan = TrialPlan {
            trials: 10,
            max_queries_per_trial: 8,
            max_total_queries: 5,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();

        let mut charged = 0;
        'outer: for _ in 0..10 {
            let Ok(mut guard) = ledger.start_trial() else {
                break;
            };
            for _ in 0..2 {
                if ledger.charge_query(&mut guard).is_err() {
                    break 'outer;
                }
                charged += 1;
            }
        }
        assert_eq!(charged, 5, "the run-wide bound was not enforced");
        assert!(ledger.snapshot().exhausted);
    }

    #[test]
    fn the_output_counter_is_also_run_wide() {
        let plan = TrialPlan {
            trials: 10,
            max_output_bytes_per_trial: 100,
            max_total_output_bytes: 150,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();

        let mut guard = ledger.start_trial().expect("first trial");
        ledger.charge_output(&mut guard, 100).expect("fits");

        let mut guard = ledger.start_trial().expect("second trial");
        // The per-trial allowance resets; the run-wide one does not.
        let err = ledger.charge_output(&mut guard, 100).expect_err("refused");
        assert!(err.to_string().contains("the run reached"));
    }

    #[test]
    fn a_plan_records_zero_state_changes_and_zero_egress() {
        let snapshot = TrialPlan::default().open().snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn a_ledger_stops_offering_trials_once_the_plan_is_done() {
        let plan = TrialPlan {
            trials: 2,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();
        assert!(ledger.may_start_trial());
        ledger.start_trial().expect("first");
        ledger.start_trial().expect("second");
        assert!(!ledger.may_start_trial());
        assert!(ledger.start_trial().is_err());
    }

    #[test]
    fn a_stop_reason_serializes_with_a_stable_tag() {
        assert_eq!(StopReason::PlanCompleted.as_str(), "PLAN_COMPLETED");
        let wire =
            serde_json::to_string(&StopReason::FirstFail { trial_index: 1 }).expect("serializes");
        assert!(wire.contains("\"reason\":\"FIRST_FAIL\""));
    }
}
