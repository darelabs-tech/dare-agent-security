//! Bounded trial, operation, decision and output policy.
//!
//! The plan is fixed *before* execution and the hard maxima are compiled in.
//! A scenario, a policy or a CLI flag can ask for less; none can ask for more,
//! and an over-limit request is **refused** rather than clamped down and quietly
//! accepted. When a bound is reached the run stops; a budget is never widened to
//! accommodate the work in front of it.
//!
//! Run totals are cumulative across trials by construction. [`TrialLedger`] owns
//! them and `start_trial` resets only the per-trial guard, so a run cannot
//! escape `hard_max_total_operations` by starting another trial.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{IdentitySecurityError, Result};
use crate::limits;
use crate::model::IdentitySecurityScenario;

/// A plan already checked against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_operations_per_trial: u32,
    pub max_total_operations: u32,
    pub max_authorization_decisions_per_trial: u32,
    pub max_delegation_depth: u32,
    pub max_output_bytes_per_trial: usize,
    pub max_total_output_bytes: usize,
    pub max_duration_seconds_per_trial: u64,
}

impl Default for TrialPlan {
    fn default() -> Self {
        Self {
            trials: limits::DEFAULT_TRIALS,
            stop_on_first_fail: limits::STOP_ON_FIRST_FAIL,
            max_operations_per_trial: limits::MAX_OPERATIONS_PER_TRIAL,
            max_total_operations: limits::HARD_MAX_TOTAL_OPERATIONS,
            max_authorization_decisions_per_trial: limits::MAX_AUTHORIZATION_DECISIONS_PER_TRIAL,
            max_delegation_depth: limits::HARD_MAX_DELEGATION_DEPTH,
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
        return Err(IdentitySecurityError::refusal(format!(
            "{label} {requested} exceeds the Cycle 015 hard maximum {hard_max}; approved bounds \
             cannot be raised by input"
        )));
    }
    Ok(requested)
}

/// Resolve one bound from an optional request.
///
/// The request is checked against the hard maximum on its own, so an over-limit
/// value is refused rather than silently reduced to the maximum. The approved
/// bound is then the tighter of the two.
fn bound<T: Copy + Ord + std::fmt::Display>(
    request: Option<T>,
    hard_max: T,
    label: &str,
) -> Result<T> {
    match request {
        Some(requested) => {
            check_upper(requested, hard_max, label)?;
            Ok(requested.min(hard_max))
        }
        None => Ok(hard_max),
    }
}

impl TrialPlan {
    /// Build a plan from an approved scenario, refusing over-limit requests.
    pub fn from_scenario(scenario: &IdentitySecurityScenario) -> Result<Self> {
        if !scenario.safety.local_only {
            return Err(IdentitySecurityError::refusal(
                "scenario disabled local_only; Cycle 015 has no non-local execution path",
            ));
        }

        Ok(Self {
            trials: Self::check_trials(scenario.trials.count)?,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_operations_per_trial: bound(
                scenario.safety.max_operations_per_trial,
                limits::MAX_OPERATIONS_PER_TRIAL,
                "max_operations_per_trial",
            )?,
            max_total_operations: bound(
                scenario.safety.max_total_operations,
                limits::HARD_MAX_TOTAL_OPERATIONS,
                "max_total_operations",
            )?,
            max_authorization_decisions_per_trial: bound(
                scenario.safety.max_authorization_decisions_per_trial,
                limits::MAX_AUTHORIZATION_DECISIONS_PER_TRIAL,
                "max_authorization_decisions_per_trial",
            )?,
            max_delegation_depth: bound(
                scenario.safety.max_delegation_depth,
                limits::HARD_MAX_DELEGATION_DEPTH,
                "max_delegation_depth",
            )?,
            max_output_bytes_per_trial: bound(
                scenario.safety.max_output_bytes,
                limits::MAX_OUTPUT_BYTES_PER_TRIAL,
                "max_output_bytes",
            )?,
            max_total_output_bytes: bound(
                scenario.safety.max_total_output_bytes,
                limits::MAX_TOTAL_OUTPUT_BYTES,
                "max_total_output_bytes",
            )?,
            max_duration_seconds_per_trial: bound(
                scenario.safety.max_duration_seconds,
                limits::MAX_DURATION_SECONDS_PER_TRIAL,
                "max_duration_seconds",
            )?,
        })
    }

    fn check_trials(requested: u32) -> Result<u32> {
        if requested == 0 {
            return Err(IdentitySecurityError::invalid(
                "trial count must be at least 1",
            ));
        }
        check_upper(requested, limits::HARD_MAX_TRIALS, "trial count")
    }

    /// Apply an operator override, bounded by the same hard maximum.
    pub fn with_trial_override(mut self, requested: Option<u32>) -> Result<Self> {
        if let Some(count) = requested {
            self.trials = Self::check_trials(count)?;
        }
        Ok(self)
    }

    /// Reduce the plan to at most `available` trials.
    ///
    /// Downward only, and deliberately so. A source that recorded three trials
    /// cannot supply four, and planning a fourth would end the run in a harness
    /// error that says nothing about the boundary under test. Raising the count
    /// stays impossible: this never increases `trials`.
    pub fn clamped_to_available(mut self, available: u32) -> Self {
        self.trials = self.trials.min(available.max(1));
        self
    }

    pub fn open(self) -> TrialLedger {
        TrialLedger::new(self)
    }
}

/// Why a bounded run stopped.
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
    pub operations_observed: u32,
    pub max_total_operations: u32,
    pub authorization_decisions_observed: u32,
    pub max_delegation_depth_observed: u32,
    pub delegation_depth_bound: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    /// Cycle 015 performs none. Recorded so the zero is evidenced.
    pub state_changes: u32,
    /// Cycle 015 performs none. Recorded so the zero is evidenced.
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// Tracks consumption against a fixed plan.
#[derive(Debug)]
pub struct TrialLedger {
    plan: TrialPlan,
    trials_executed: u32,
    total_operations: u32,
    total_decisions: u32,
    total_output_bytes: usize,
    max_depth_observed: u32,
    exhausted: bool,
}

impl TrialLedger {
    fn new(plan: TrialPlan) -> Self {
        Self {
            plan,
            trials_executed: 0,
            total_operations: 0,
            total_decisions: 0,
            total_output_bytes: 0,
            max_depth_observed: 0,
            exhausted: false,
        }
    }

    pub fn plan(&self) -> TrialPlan {
        self.plan
    }

    pub fn trials_executed(&self) -> u32 {
        self.trials_executed
    }

    pub fn total_operations(&self) -> u32 {
        self.total_operations
    }

    pub fn total_output_bytes(&self) -> usize {
        self.total_output_bytes
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            trials_planned: self.plan.trials,
            trials_executed: self.trials_executed,
            operations_observed: self.total_operations,
            max_total_operations: self.plan.max_total_operations,
            authorization_decisions_observed: self.total_decisions,
            max_delegation_depth_observed: self.max_depth_observed,
            delegation_depth_bound: self.plan.max_delegation_depth,
            output_bytes_used: self.total_output_bytes,
            max_total_output_bytes: self.plan.max_total_output_bytes,
            state_changes: limits::MAX_STATE_CHANGES,
            external_egress_bytes: limits::EXTERNAL_EGRESS_BYTES,
            exhausted: self.exhausted,
        }
    }

    pub fn may_start_trial(&self) -> bool {
        !self.exhausted && self.trials_executed < self.plan.trials
    }

    /// Begin a trial, returning its per-trial guard.
    pub fn start_trial(&mut self) -> Result<TrialGuard> {
        if self.exhausted {
            return Err(IdentitySecurityError::BudgetExhausted(
                "a run budget is already exhausted".to_owned(),
            ));
        }
        if self.trials_executed >= self.plan.trials {
            return Err(IdentitySecurityError::BudgetExhausted(format!(
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
            trial_operations: 0,
            max_trial_operations: self.plan.max_operations_per_trial,
            trial_decisions: 0,
            max_trial_decisions: self.plan.max_authorization_decisions_per_trial,
            trial_bytes: 0,
            max_trial_bytes: self.plan.max_output_bytes_per_trial,
        })
    }

    /// Charge one observed operation against both bounds.
    ///
    /// The run total is cumulative across trials and never resets.
    pub fn charge_operation(&mut self, guard: &mut TrialGuard) -> Result<()> {
        let next_trial = guard.trial_operations.saturating_add(1);
        if next_trial > guard.max_trial_operations {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "trial {} exceeded {} operations",
                guard.index, guard.max_trial_operations
            )));
        }
        let next_total = self.total_operations.saturating_add(1);
        if next_total > self.plan.max_total_operations {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "run exceeded {} total operations",
                self.plan.max_total_operations
            )));
        }
        guard.trial_operations = next_trial;
        self.total_operations = next_total;
        Ok(())
    }

    /// Charge one observed authorization decision.
    pub fn charge_decision(&mut self, guard: &mut TrialGuard) -> Result<()> {
        let next = guard.trial_decisions.saturating_add(1);
        if next > guard.max_trial_decisions {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "trial {} exceeded {} authorization decisions",
                guard.index, guard.max_trial_decisions
            )));
        }
        guard.trial_decisions = next;
        self.total_decisions = self.total_decisions.saturating_add(1);
        Ok(())
    }

    /// Record an observed delegation depth against the bound.
    pub fn charge_delegation_depth(&mut self, depth: u32) -> Result<()> {
        self.max_depth_observed = self.max_depth_observed.max(depth);
        if depth > self.plan.max_delegation_depth {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "observed delegation depth {depth} exceeded the bound {}",
                self.plan.max_delegation_depth
            )));
        }
        Ok(())
    }

    /// Charge retained observation bytes against the per-trial and run bounds.
    pub fn charge_output(&mut self, guard: &mut TrialGuard, bytes: usize) -> Result<()> {
        let trial_total = guard.trial_bytes.saturating_add(bytes);
        if trial_total > guard.max_trial_bytes {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "trial {} output exceeded {} bytes",
                guard.index, guard.max_trial_bytes
            )));
        }
        let run_total = self.total_output_bytes.saturating_add(bytes);
        if run_total > self.plan.max_total_output_bytes {
            self.exhausted = true;
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "run output exceeded {} bytes",
                self.plan.max_total_output_bytes
            )));
        }
        guard.trial_bytes = trial_total;
        self.total_output_bytes = run_total;
        Ok(())
    }

    pub fn mark_exhausted(&mut self) {
        self.exhausted = true;
    }
}

/// Per-trial guard carrying the deadline and per-trial allowances.
#[derive(Debug)]
pub struct TrialGuard {
    index: u32,
    started: Instant,
    limit: Duration,
    trial_operations: u32,
    max_trial_operations: u32,
    trial_decisions: u32,
    max_trial_decisions: u32,
    trial_bytes: usize,
    max_trial_bytes: usize,
}

impl TrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn trial_operations(&self) -> u32 {
        self.trial_operations
    }

    pub fn trial_decisions(&self) -> u32 {
        self.trial_decisions
    }

    /// Refuse to continue past the per-trial deadline.
    pub fn check_deadline(&self) -> Result<()> {
        if self.started.elapsed() >= self.limit {
            return Err(IdentitySecurityError::BudgetExhausted(format!(
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

    #[test]
    fn a_plan_can_be_reduced_to_what_a_source_can_supply_but_never_raised() {
        let plan = TrialPlan {
            trials: 3,
            ..TrialPlan::default()
        };
        assert_eq!(plan.clamped_to_available(1).trials, 1);
        assert_eq!(plan.clamped_to_available(3).trials, 3);
        // A source claiming more than the plan cannot raise it.
        assert_eq!(plan.clamped_to_available(9).trials, 3);
        assert_eq!(plan.clamped_to_available(999).trials, 3);
        // Zero available still leaves one trial to attempt and fail honestly,
        // rather than a plan of zero that would report nothing at all.
        assert_eq!(plan.clamped_to_available(0).trials, 1);
    }

    use serde_json::json;

    fn scenario_with(safety: serde_json::Value, trials: serde_json::Value) -> Result<TrialPlan> {
        let raw = include_str!("../tests/fixtures/scenario.json");
        let mut value: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        value["safety"] = safety;
        value["trials"] = trials;
        let scenario: IdentitySecurityScenario =
            serde_json::from_value(value).expect("scenario decodes");
        TrialPlan::from_scenario(&scenario)
    }

    #[test]
    fn approved_defaults_are_the_compiled_in_bounds() {
        let plan = TrialPlan::default();
        assert_eq!(plan.trials, 3);
        assert!(plan.stop_on_first_fail);
        assert_eq!(plan.max_operations_per_trial, 8);
        assert_eq!(plan.max_total_operations, 24);
        assert_eq!(plan.max_authorization_decisions_per_trial, 8);
        assert_eq!(plan.max_delegation_depth, 4);
        assert_eq!(plan.max_output_bytes_per_trial, 16_384);
        assert_eq!(plan.max_total_output_bytes, 65_536);
        assert_eq!(plan.max_duration_seconds_per_trial, 30);
    }

    #[test]
    fn hard_max_trials_is_ten_and_the_boundaries_hold() {
        assert_eq!(
            scenario_with(json!({"local_only": true}), json!({"count": 10}))
                .expect("plan")
                .trials,
            10
        );
        assert!(scenario_with(json!({"local_only": true}), json!({"count": 11})).is_err());
        assert!(scenario_with(json!({"local_only": true}), json!({"count": 0})).is_err());
    }

    #[test]
    fn a_scenario_cannot_raise_any_hard_bound() {
        for safety in [
            json!({"local_only": true, "max_operations_per_trial": 9}),
            json!({"local_only": true, "max_total_operations": 25}),
            json!({"local_only": true, "max_authorization_decisions_per_trial": 9}),
            json!({"local_only": true, "max_delegation_depth": 5}),
            json!({"local_only": true, "max_output_bytes": 16385}),
            json!({"local_only": true, "max_total_output_bytes": 65537}),
            json!({"local_only": true, "max_duration_seconds": 31}),
        ] {
            let err = scenario_with(safety.clone(), json!({"count": 3}))
                .expect_err(&format!("{safety} must be refused"));
            assert!(err.is_refusal(), "{safety}");
            assert!(err.to_string().contains("cannot be raised by input"));
        }
    }

    #[test]
    fn a_scenario_may_ask_for_less() {
        let plan = scenario_with(
            json!({"local_only": true, "max_operations_per_trial": 2, "max_delegation_depth": 1}),
            json!({"count": 2}),
        )
        .expect("plan");
        assert_eq!(plan.max_operations_per_trial, 2);
        assert_eq!(plan.max_delegation_depth, 1);
        assert_eq!(plan.trials, 2);
    }

    #[test]
    fn disabling_local_only_is_refused() {
        // The schema pins local_only to the constant true, so this is the
        // typed-layer backstop behind that.
        let raw = include_str!("../tests/fixtures/scenario.json");
        let mut value: serde_json::Value = serde_json::from_str(raw).expect("parses");
        value["safety"]["local_only"] = json!(false);
        let scenario: IdentitySecurityScenario =
            serde_json::from_value(value).expect("decodes at the typed layer");
        assert!(TrialPlan::from_scenario(&scenario)
            .expect_err("refused")
            .is_refusal());
    }

    #[test]
    fn an_operator_override_is_bounded_by_the_same_maximum() {
        let plan = TrialPlan::default();
        assert_eq!(plan.with_trial_override(Some(7)).expect("ok").trials, 7);
        assert_eq!(plan.with_trial_override(Some(10)).expect("ok").trials, 10);
        assert!(plan
            .with_trial_override(Some(11))
            .expect_err("refused")
            .is_refusal());
        assert!(plan.with_trial_override(Some(0)).is_err());
        assert_eq!(plan.with_trial_override(None).expect("ok").trials, 3);
    }

    #[test]
    fn the_ledger_stops_at_the_planned_trial_count() {
        let mut ledger = TrialPlan {
            trials: 2,
            ..TrialPlan::default()
        }
        .open();
        assert_eq!(ledger.start_trial().expect("first").index(), 0);
        assert_eq!(ledger.start_trial().expect("second").index(), 1);
        assert!(!ledger.may_start_trial());
        assert!(matches!(
            ledger.start_trial().expect_err("third"),
            IdentitySecurityError::BudgetExhausted(_)
        ));
    }

    #[test]
    fn the_total_operation_counter_never_resets_between_trials() {
        // The bypass this bound exists to prevent: several trials, each inside
        // its per-trial allowance, still hitting the run total.
        let mut ledger = TrialPlan {
            trials: 10,
            max_operations_per_trial: 2,
            max_total_operations: 5,
            ..TrialPlan::default()
        }
        .open();

        let mut charged = 0;
        let mut exhausted = false;
        for _ in 0..10 {
            let Ok(mut guard) = ledger.start_trial() else {
                break;
            };
            for _ in 0..2 {
                match ledger.charge_operation(&mut guard) {
                    Ok(()) => charged += 1,
                    Err(_) => {
                        exhausted = true;
                        break;
                    }
                }
            }
            if exhausted {
                break;
            }
        }

        assert!(exhausted, "the run total must eventually stop the run");
        assert_eq!(charged, 5, "exactly the run total was charged");
        assert_eq!(ledger.total_operations(), 5);
    }

    #[test]
    fn the_per_trial_operation_bound_stops_the_run() {
        let mut ledger = TrialPlan {
            max_operations_per_trial: 2,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().expect("trial");
        ledger.charge_operation(&mut guard).expect("first");
        ledger.charge_operation(&mut guard).expect("second");
        assert!(ledger.charge_operation(&mut guard).is_err());
        assert_eq!(
            guard.trial_operations(),
            2,
            "a rejected charge is not counted"
        );
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn the_decision_bound_is_enforced_per_trial() {
        let mut ledger = TrialPlan {
            max_authorization_decisions_per_trial: 2,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().expect("trial");
        ledger.charge_decision(&mut guard).expect("first");
        ledger.charge_decision(&mut guard).expect("second");
        assert!(ledger.charge_decision(&mut guard).is_err());
        assert_eq!(guard.trial_decisions(), 2);
    }

    #[test]
    fn delegation_depth_beyond_the_bound_stops_the_run() {
        let mut ledger = TrialPlan {
            max_delegation_depth: 2,
            ..TrialPlan::default()
        }
        .open();
        ledger.charge_delegation_depth(1).expect("one");
        ledger.charge_delegation_depth(2).expect("two");
        assert!(ledger.charge_delegation_depth(3).is_err());
        assert!(ledger.is_exhausted());
        // The deepest observed value is still recorded for evidence.
        assert_eq!(ledger.snapshot().max_delegation_depth_observed, 3);
        assert_eq!(ledger.snapshot().delegation_depth_bound, 2);
    }

    #[test]
    fn output_budgets_span_trials_and_never_widen() {
        let mut ledger = TrialPlan {
            trials: 5,
            max_output_bytes_per_trial: 100,
            max_total_output_bytes: 150,
            ..TrialPlan::default()
        }
        .open();

        let mut first = ledger.start_trial().expect("trial");
        ledger.charge_output(&mut first, 100).expect("first");
        let mut second = ledger.start_trial().expect("trial");
        ledger.charge_output(&mut second, 50).expect("second");
        assert_eq!(ledger.total_output_bytes(), 150);

        assert!(ledger.charge_output(&mut second, 1).is_err());
        assert_eq!(ledger.total_output_bytes(), 150);
    }

    #[test]
    fn exact_boundaries_are_allowed_and_one_over_is_not() {
        let mut ledger = TrialPlan {
            max_output_bytes_per_trial: 10,
            max_total_output_bytes: 10,
            ..TrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().expect("trial");
        ledger
            .charge_output(&mut guard, 10)
            .expect("exact boundary");
        assert!(ledger.charge_output(&mut guard, 1).is_err());
    }

    #[test]
    fn charging_saturates_instead_of_overflowing() {
        let mut ledger = TrialPlan::default().open();
        let mut guard = ledger.start_trial().expect("trial");
        assert!(ledger.charge_output(&mut guard, usize::MAX).is_err());
    }

    #[test]
    fn a_deadline_guard_is_armed_from_the_plan() {
        let mut ledger = TrialPlan::default().open();
        ledger
            .start_trial()
            .expect("trial")
            .check_deadline()
            .expect("fresh trial is inside its deadline");

        let mut ledger = TrialPlan {
            max_duration_seconds_per_trial: 0,
            ..TrialPlan::default()
        }
        .open();
        assert!(ledger
            .start_trial()
            .expect("trial")
            .check_deadline()
            .is_err());
    }

    #[test]
    fn the_snapshot_evidences_zero_state_change_and_zero_egress() {
        let snapshot = TrialPlan::default().open().snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn stop_reasons_serialize_with_stable_tags() {
        assert_eq!(
            serde_json::to_value(StopReason::PlanCompleted).expect("serializes"),
            json!({"reason": "PLAN_COMPLETED"})
        );
        assert_eq!(
            serde_json::to_value(StopReason::FirstFail { trial_index: 1 }).expect("serializes"),
            json!({"reason": "FIRST_FAIL", "trial_index": 1})
        );
        assert_eq!(
            StopReason::BudgetExhausted {
                detail: "x".to_owned()
            }
            .as_str(),
            "BUDGET_EXHAUSTED"
        );
    }
}
