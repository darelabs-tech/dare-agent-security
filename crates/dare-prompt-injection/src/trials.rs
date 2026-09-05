//! Bounded trial policy.
//!
//! The trial plan is fixed *before* execution and the hard maxima are compiled
//! in. Scenario input and CLI input can both ask for less; neither can ask for
//! more. When a bound is reached the run stops — a budget is never widened to
//! accommodate the work in front of it, because that is exactly how a bounded
//! validator turns into an unbounded one.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{PromptInjectionError, Result};
use crate::limits;
use crate::model::PromptInjectionScenario;

/// A trial plan that has already been checked against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_output_bytes_per_trial: usize,
    pub max_total_output_bytes: usize,
    pub max_duration_seconds_per_trial: u64,
}

impl Default for TrialPlan {
    fn default() -> Self {
        Self {
            trials: limits::DEFAULT_TRIALS,
            stop_on_first_fail: limits::STOP_ON_FIRST_FAIL,
            max_output_bytes_per_trial: limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            max_total_output_bytes: limits::MAX_TOTAL_OUTPUT_BYTES,
            max_duration_seconds_per_trial: limits::MAX_DURATION_SECONDS_PER_TRIAL,
        }
    }
}

fn check_upper<T: PartialOrd + std::fmt::Display>(
    requested: T,
    hard_max: T,
    label: &str,
) -> Result<T> {
    if requested > hard_max {
        return Err(PromptInjectionError::refusal(format!(
            "{label} {requested} exceeds the Cycle 013 hard maximum {hard_max}; \
             approved bounds cannot be raised by input"
        )));
    }
    Ok(requested)
}

impl TrialPlan {
    /// Build a plan from an approved scenario, refusing any attempt to exceed
    /// an approved bound.
    pub fn from_scenario(scenario: &PromptInjectionScenario) -> Result<Self> {
        if !scenario.safety.local_only {
            return Err(PromptInjectionError::refusal(
                "scenario disabled local_only; Cycle 013 has no non-local execution path",
            ));
        }

        let trials = Self::check_trials(scenario.trials.count)?;
        let max_output_bytes_per_trial = check_upper(
            scenario
                .safety
                .max_output_bytes
                .unwrap_or(limits::MAX_OUTPUT_BYTES_PER_TRIAL),
            limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            "max_output_bytes",
        )?;
        let max_total_output_bytes = check_upper(
            scenario
                .safety
                .max_total_output_bytes
                .unwrap_or(limits::MAX_TOTAL_OUTPUT_BYTES),
            limits::MAX_TOTAL_OUTPUT_BYTES,
            "max_total_output_bytes",
        )?;
        let max_duration_seconds_per_trial = check_upper(
            scenario
                .safety
                .max_duration_seconds
                .unwrap_or(limits::MAX_DURATION_SECONDS_PER_TRIAL),
            limits::MAX_DURATION_SECONDS_PER_TRIAL,
            "max_duration_seconds",
        )?;

        Ok(Self {
            trials,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_output_bytes_per_trial,
            max_total_output_bytes,
            max_duration_seconds_per_trial,
        })
    }

    fn check_trials(requested: u32) -> Result<u32> {
        if requested == 0 {
            return Err(PromptInjectionError::invalid(
                "trial count must be at least 1",
            ));
        }
        check_upper(requested, limits::HARD_MAX_TRIALS, "trial count")
    }

    /// Apply an operator override, which is bounded by the same hard maximum.
    pub fn with_trial_override(mut self, requested: Option<u32>) -> Result<Self> {
        if let Some(count) = requested {
            self.trials = Self::check_trials(count)?;
        }
        Ok(self)
    }

    /// Open a ledger for this plan.
    pub fn open(self) -> TrialLedger {
        TrialLedger::new(self)
    }
}

/// Why a bounded run stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopReason {
    /// Every planned trial ran.
    PlanCompleted,
    /// A deterministic invariant violation stopped the remaining trials.
    FirstFail { trial_index: u32 },
    /// A hard bound was reached. The bound is never widened.
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
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    pub exhausted: bool,
}

/// Tracks consumption against a fixed plan.
#[derive(Debug)]
pub struct TrialLedger {
    plan: TrialPlan,
    trials_executed: u32,
    output_bytes_used: usize,
    exhausted: bool,
}

impl TrialLedger {
    fn new(plan: TrialPlan) -> Self {
        Self {
            plan,
            trials_executed: 0,
            output_bytes_used: 0,
            exhausted: false,
        }
    }

    pub fn plan(&self) -> TrialPlan {
        self.plan
    }

    pub fn trials_executed(&self) -> u32 {
        self.trials_executed
    }

    pub fn output_bytes_used(&self) -> usize {
        self.output_bytes_used
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            trials_planned: self.plan.trials,
            trials_executed: self.trials_executed,
            output_bytes_used: self.output_bytes_used,
            max_total_output_bytes: self.plan.max_total_output_bytes,
            exhausted: self.exhausted,
        }
    }

    /// True when another trial is permitted by the plan.
    pub fn may_start_trial(&self) -> bool {
        !self.exhausted && self.trials_executed < self.plan.trials
    }

    /// Begin a trial, returning its deadline guard.
    pub fn start_trial(&mut self) -> Result<TrialGuard> {
        if self.exhausted {
            return Err(PromptInjectionError::BudgetExhausted(
                "output budget already exhausted".to_owned(),
            ));
        }
        if self.trials_executed >= self.plan.trials {
            return Err(PromptInjectionError::BudgetExhausted(format!(
                "trial budget of {} exhausted",
                self.plan.trials
            )));
        }
        let index = self.trials_executed;
        self.trials_executed += 1;
        Ok(TrialGuard {
            index,
            started: Instant::now(),
            limit: Duration::from_secs(self.plan.max_duration_seconds_per_trial),
            trial_bytes: 0,
            max_trial_bytes: self.plan.max_output_bytes_per_trial,
        })
    }

    /// Charge retained observation bytes against the per-trial and total bounds.
    ///
    /// On exhaustion the ledger latches: the run stops rather than continuing
    /// with a widened allowance.
    pub fn charge_output(&mut self, guard: &mut TrialGuard, bytes: usize) -> Result<()> {
        let trial_total = guard.trial_bytes.saturating_add(bytes);
        if trial_total > guard.max_trial_bytes {
            self.exhausted = true;
            return Err(PromptInjectionError::BudgetExhausted(format!(
                "trial {} output exceeded {} bytes",
                guard.index, guard.max_trial_bytes
            )));
        }
        let run_total = self.output_bytes_used.saturating_add(bytes);
        if run_total > self.plan.max_total_output_bytes {
            self.exhausted = true;
            return Err(PromptInjectionError::BudgetExhausted(format!(
                "run output exceeded {} bytes",
                self.plan.max_total_output_bytes
            )));
        }
        guard.trial_bytes = trial_total;
        self.output_bytes_used = run_total;
        Ok(())
    }

    /// Mark the ledger exhausted without charging bytes (for example on timeout).
    pub fn mark_exhausted(&mut self) {
        self.exhausted = true;
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Per-trial guard carrying the deadline and the per-trial byte allowance.
#[derive(Debug)]
pub struct TrialGuard {
    index: u32,
    started: Instant,
    limit: Duration,
    trial_bytes: usize,
    max_trial_bytes: usize,
}

impl TrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn trial_bytes(&self) -> usize {
        self.trial_bytes
    }

    pub fn max_trial_bytes(&self) -> usize {
        self.max_trial_bytes
    }

    /// Refuse to continue past the per-trial deadline.
    pub fn check_deadline(&self) -> Result<()> {
        if self.started.elapsed() >= self.limit {
            return Err(PromptInjectionError::BudgetExhausted(format!(
                "trial {} exceeded {}s",
                self.index,
                self.limit.as_secs()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scenario_with(safety: serde_json::Value, trials: serde_json::Value) -> Result<TrialPlan> {
        let mut value = crate::schema::tests::valid_scenario();
        value["safety"] = safety;
        value["trials"] = trials;
        let scenario: PromptInjectionScenario = serde_json::from_value(value).unwrap();
        TrialPlan::from_scenario(&scenario)
    }

    fn default_scenario_plan() -> TrialPlan {
        scenario_with(
            json!({"local_only": true}),
            json!({"count": 3, "stop_on_first_fail": true}),
        )
        .unwrap()
    }

    #[test]
    fn approved_defaults_are_the_compiled_in_bounds() {
        let plan = TrialPlan::default();
        assert_eq!(plan.trials, 3);
        assert!(plan.stop_on_first_fail);
        assert_eq!(plan.max_output_bytes_per_trial, 16_384);
        assert_eq!(plan.max_total_output_bytes, 65_536);
        assert_eq!(plan.max_duration_seconds_per_trial, 30);
    }

    #[test]
    fn a_scenario_omitting_bounds_inherits_the_approved_maxima() {
        let plan = default_scenario_plan();
        assert_eq!(plan.trials, 3);
        assert_eq!(plan.max_output_bytes_per_trial, 16_384);
        assert_eq!(plan.max_total_output_bytes, 65_536);
        assert_eq!(plan.max_duration_seconds_per_trial, 30);
    }

    #[test]
    fn hard_max_trials_is_ten_and_boundaries_hold() {
        assert_eq!(
            scenario_with(json!({"local_only": true}), json!({"count": 10}))
                .unwrap()
                .trials,
            10
        );
        assert!(scenario_with(json!({"local_only": true}), json!({"count": 11})).is_err());
        assert!(scenario_with(json!({"local_only": true}), json!({"count": 0})).is_err());
        assert_eq!(
            scenario_with(json!({"local_only": true}), json!({"count": 1}))
                .unwrap()
                .trials,
            1
        );
    }

    #[test]
    fn a_scenario_cannot_raise_any_hard_bound() {
        for safety in [
            json!({"local_only": true, "max_output_bytes": 16385}),
            json!({"local_only": true, "max_total_output_bytes": 65537}),
            json!({"local_only": true, "max_duration_seconds": 31}),
            json!({"local_only": true, "max_output_bytes": 1048576}),
        ] {
            let err = scenario_with(safety.clone(), json!({"count": 3})).unwrap_err();
            assert!(err.is_refusal(), "{safety} must be refused");
            assert!(err.to_string().contains("cannot be raised by input"));
        }
    }

    #[test]
    fn a_scenario_may_request_less_than_the_maximum() {
        let plan = scenario_with(
            json!({"local_only": true, "max_output_bytes": 512, "max_total_output_bytes": 2048, "max_duration_seconds": 5}),
            json!({"count": 2}),
        )
        .unwrap();
        assert_eq!(plan.max_output_bytes_per_trial, 512);
        assert_eq!(plan.max_total_output_bytes, 2048);
        assert_eq!(plan.max_duration_seconds_per_trial, 5);
        assert_eq!(plan.trials, 2);
    }

    #[test]
    fn disabling_local_only_is_refused() {
        let mut value = crate::schema::tests::valid_scenario();
        value["safety"] = json!({"local_only": false});
        let scenario: PromptInjectionScenario = serde_json::from_value(value).unwrap();
        let err = TrialPlan::from_scenario(&scenario).unwrap_err();
        assert!(err.is_refusal());
    }

    #[test]
    fn an_operator_override_is_bounded_by_the_same_maximum() {
        let plan = default_scenario_plan();
        assert_eq!(plan.with_trial_override(Some(7)).unwrap().trials, 7);
        assert_eq!(plan.with_trial_override(Some(10)).unwrap().trials, 10);
        assert!(plan.with_trial_override(Some(11)).unwrap_err().is_refusal());
        assert!(plan.with_trial_override(Some(u32::MAX)).is_err());
        assert!(plan.with_trial_override(Some(0)).is_err());
        // No override keeps the scenario value.
        assert_eq!(plan.with_trial_override(None).unwrap().trials, 3);
    }

    #[test]
    fn the_ledger_stops_at_the_planned_trial_count() {
        let mut ledger = TrialPlan {
            trials: 2,
            ..TrialPlan::default()
        }
        .open();

        assert!(ledger.may_start_trial());
        let first = ledger.start_trial().unwrap();
        assert_eq!(first.index(), 0);
        let second = ledger.start_trial().unwrap();
        assert_eq!(second.index(), 1);

        assert!(!ledger.may_start_trial());
        let err = ledger.start_trial().unwrap_err();
        assert!(matches!(err, PromptInjectionError::BudgetExhausted(_)));
        assert_eq!(ledger.trials_executed(), 2);
    }

    #[test]
    fn per_trial_output_budget_stops_the_run_and_never_expands() {
        let mut ledger = TrialPlan {
            max_output_bytes_per_trial: 100,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().unwrap();

        ledger.charge_output(&mut guard, 60).unwrap();
        assert_eq!(guard.trial_bytes(), 60);

        let err = ledger.charge_output(&mut guard, 41).unwrap_err();
        assert!(matches!(err, PromptInjectionError::BudgetExhausted(_)));

        // The bound did not move and the ledger latched.
        assert_eq!(guard.max_trial_bytes(), 100);
        assert_eq!(guard.trial_bytes(), 60, "rejected bytes are not charged");
        assert!(ledger.is_exhausted());
        assert!(!ledger.may_start_trial());
    }

    #[test]
    fn total_output_budget_spans_trials() {
        let mut ledger = TrialPlan {
            trials: 5,
            max_output_bytes_per_trial: 100,
            max_total_output_bytes: 150,
            ..TrialPlan::default()
        }
        .open();

        let mut first = ledger.start_trial().unwrap();
        ledger.charge_output(&mut first, 100).unwrap();

        let mut second = ledger.start_trial().unwrap();
        ledger.charge_output(&mut second, 50).unwrap();
        assert_eq!(ledger.output_bytes_used(), 150);

        // One more byte crosses the run total even though the trial allowance
        // still has room.
        let err = ledger.charge_output(&mut second, 1).unwrap_err();
        assert!(matches!(err, PromptInjectionError::BudgetExhausted(_)));
        assert_eq!(ledger.output_bytes_used(), 150);
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn exact_boundary_is_allowed_and_one_over_is_not() {
        let mut ledger = TrialPlan {
            max_output_bytes_per_trial: 10,
            max_total_output_bytes: 10,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().unwrap();
        ledger
            .charge_output(&mut guard, 10)
            .expect("exact boundary");
        assert!(ledger.charge_output(&mut guard, 1).is_err());
    }

    #[test]
    fn charging_saturates_instead_of_overflowing() {
        let mut ledger = TrialPlan::default().open();
        let mut guard = ledger.start_trial().unwrap();
        let err = ledger.charge_output(&mut guard, usize::MAX).unwrap_err();
        assert!(matches!(err, PromptInjectionError::BudgetExhausted(_)));
    }

    #[test]
    fn a_deadline_guard_is_armed_from_the_plan() {
        let mut ledger = TrialPlan {
            max_duration_seconds_per_trial: 30,
            ..TrialPlan::default()
        }
        .open();
        let guard = ledger.start_trial().unwrap();
        // A fresh trial is inside its deadline.
        guard.check_deadline().expect("within deadline");

        let mut ledger = TrialPlan {
            max_duration_seconds_per_trial: 0,
            ..TrialPlan::default()
        }
        .open();
        let guard = ledger.start_trial().unwrap();
        // A zero-second allowance is already spent.
        assert!(guard.check_deadline().is_err());
    }

    #[test]
    fn snapshot_reports_consumption_for_evidence() {
        let mut ledger = TrialPlan {
            trials: 3,
            max_total_output_bytes: 1000,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().unwrap();
        ledger.charge_output(&mut guard, 42).unwrap();

        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.trials_planned, 3);
        assert_eq!(snapshot.trials_executed, 1);
        assert_eq!(snapshot.output_bytes_used, 42);
        assert_eq!(snapshot.max_total_output_bytes, 1000);
        assert!(!snapshot.exhausted);

        ledger.mark_exhausted();
        assert!(ledger.snapshot().exhausted);
    }

    #[test]
    fn stop_reasons_serialize_with_stable_tags() {
        assert_eq!(
            serde_json::to_value(StopReason::PlanCompleted).unwrap(),
            json!({"reason": "PLAN_COMPLETED"})
        );
        assert_eq!(
            serde_json::to_value(StopReason::FirstFail { trial_index: 1 }).unwrap(),
            json!({"reason": "FIRST_FAIL", "trial_index": 1})
        );
        assert_eq!(StopReason::PlanCompleted.as_str(), "PLAN_COMPLETED");
        assert_eq!(
            StopReason::BudgetExhausted {
                detail: "x".to_owned()
            }
            .as_str(),
            "BUDGET_EXHAUSTED"
        );
    }
}
