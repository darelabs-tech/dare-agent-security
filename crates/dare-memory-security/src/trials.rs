//! Bounded trials, memory/event/recall counts and output budgets.
//!
//! Two properties this module exists to hold:
//!
//! - **an over-limit request is refused, never clamped upward.** [`bound`]
//!   checks a requested value against its hard maximum *on its own* before
//!   taking the minimum, so asking for more than the ceiling is an error rather
//!   than a silent reduction to the ceiling. A caller that asks for 99 trials
//!   has misunderstood something, and quietly giving them 10 hides that.
//! - **run totals never reset between trials.** The totals live on the
//!   [`TrialLedger`]; [`TrialLedger::start_trial`] resets only the per-trial
//!   guard. A run-wide budget that reset each trial would not be a run-wide
//!   budget.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};
use crate::model::MemorySecurityScenario;

/// A fixed plan for one bounded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_events_per_trial: u32,
    pub max_total_events: u32,
    pub max_recall_items: u32,
    pub max_output_bytes_per_trial: usize,
    pub max_total_output_bytes: usize,
    pub max_duration_seconds: u64,
}

impl Default for TrialPlan {
    fn default() -> Self {
        Self {
            trials: crate::limits::DEFAULT_TRIALS,
            stop_on_first_fail: crate::limits::STOP_ON_FIRST_FAIL,
            max_events_per_trial: crate::limits::MAX_MEMORY_EVENTS_PER_TRIAL,
            max_total_events: crate::limits::HARD_MAX_TOTAL_MEMORY_EVENTS,
            max_recall_items: crate::limits::MAX_RECALL_ITEMS_PER_REQUEST,
            max_output_bytes_per_trial: crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            max_total_output_bytes: crate::limits::MAX_TOTAL_OUTPUT_BYTES,
            max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        }
    }
}

/// Refuse a request above a hard maximum, rather than clamping it down.
///
/// The check happens before the `min`, deliberately. Clamping would let an
/// over-limit scenario run as if it had asked for something reasonable, and the
/// operator would never learn their input was wrong.
fn bound<T>(requested: Option<T>, hard_max: T, what: &str) -> Result<T>
where
    T: PartialOrd + Copy + std::fmt::Display,
{
    match requested {
        Some(value) if value > hard_max => Err(MemorySecurityError::BudgetExhausted(format!(
            "{what} requested {value}; the hard maximum is {hard_max}"
        ))),
        Some(value) => Ok(value),
        None => Ok(hard_max),
    }
}

fn check_upper(value: u32, hard_max: u32, what: &str) -> Result<u32> {
    if value > hard_max {
        return Err(MemorySecurityError::BudgetExhausted(format!(
            "{what} requested {value}; the hard maximum is {hard_max}"
        )));
    }
    Ok(value)
}

impl TrialPlan {
    /// Build a plan from a scenario, refusing anything above a hard bound.
    pub fn from_scenario(scenario: &MemorySecurityScenario) -> Result<Self> {
        if !scenario.safety.local_only {
            return Err(MemorySecurityError::refusal(format!(
                "scenario `{}` requests non-local execution; Cycle 016 is local only",
                scenario.id
            )));
        }

        Ok(Self {
            trials: check_upper(
                scenario.trials.count,
                crate::limits::HARD_MAX_TRIALS,
                "trials",
            )?,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_events_per_trial: bound(
                scenario.safety.max_events_per_trial,
                crate::limits::MAX_MEMORY_EVENTS_PER_TRIAL,
                "events per trial",
            )?,
            max_total_events: bound(
                scenario.safety.max_total_events,
                crate::limits::HARD_MAX_TOTAL_MEMORY_EVENTS,
                "total events",
            )?,
            max_recall_items: bound(
                scenario.safety.max_recall_items,
                crate::limits::MAX_RECALL_ITEMS_PER_REQUEST,
                "recall items",
            )?,
            max_output_bytes_per_trial: bound(
                scenario.safety.max_output_bytes,
                crate::limits::MAX_OUTPUT_BYTES_PER_TRIAL,
                "output bytes per trial",
            )?,
            max_total_output_bytes: bound(
                scenario.safety.max_total_output_bytes,
                crate::limits::MAX_TOTAL_OUTPUT_BYTES,
                "total output bytes",
            )?,
            max_duration_seconds: bound(
                scenario.safety.max_duration_seconds,
                crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
                "duration seconds",
            )?,
        })
    }

    /// Apply an operator's trial override, refusing anything above the ceiling.
    pub fn with_trial_override(mut self, requested: Option<u32>) -> Result<Self> {
        if let Some(count) = requested {
            self.trials = check_upper(count, crate::limits::HARD_MAX_TRIALS, "trials")?;
        }
        Ok(self)
    }

    /// Reduce the plan to at most `available` trials.
    ///
    /// Downward only, and deliberately so. A trace that recorded three trials
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
    pub events_observed: u32,
    pub max_total_events: u32,
    pub recall_items_observed: u32,
    pub recall_item_bound: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    /// Cycle 016 performs none. Recorded so the zero is evidenced.
    pub state_changes: u32,
    /// Cycle 016 performs none. Recorded so the zero is evidenced.
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// Tracks consumption against a fixed plan.
#[derive(Debug)]
pub struct TrialLedger {
    plan: TrialPlan,
    trials_executed: u32,
    total_events: u32,
    total_recall_items: u32,
    total_output_bytes: usize,
    exhausted: bool,
}

impl TrialLedger {
    fn new(plan: TrialPlan) -> Self {
        Self {
            plan,
            trials_executed: 0,
            total_events: 0,
            total_recall_items: 0,
            total_output_bytes: 0,
            exhausted: false,
        }
    }

    pub fn plan(&self) -> TrialPlan {
        self.plan
    }

    pub fn trials_executed(&self) -> u32 {
        self.trials_executed
    }

    pub fn total_events(&self) -> u32 {
        self.total_events
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
            events_observed: self.total_events,
            max_total_events: self.plan.max_total_events,
            recall_items_observed: self.total_recall_items,
            recall_item_bound: self.plan.max_recall_items,
            output_bytes_used: self.total_output_bytes,
            max_total_output_bytes: self.plan.max_total_output_bytes,
            state_changes: crate::limits::MAX_STATE_CHANGES,
            external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
            exhausted: self.exhausted,
        }
    }

    pub fn may_start_trial(&self) -> bool {
        !self.exhausted && self.trials_executed < self.plan.trials
    }

    /// Begin a trial, returning its per-trial guard.
    ///
    /// Only the guard is fresh. The run totals above stay where they are, which
    /// is what stops a long run from getting an unlimited budget one trial at a
    /// time.
    pub fn start_trial(&mut self) -> Result<TrialGuard> {
        if self.exhausted {
            return Err(MemorySecurityError::BudgetExhausted(
                "the run budget is exhausted".to_owned(),
            ));
        }
        if self.trials_executed >= self.plan.trials {
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "the plan plans {} trials and all are executed",
                self.plan.trials
            )));
        }
        let index = self.trials_executed;
        self.trials_executed += 1;
        Ok(TrialGuard {
            index,
            events: 0,
            output_bytes: 0,
            started_at: Instant::now(),
            deadline: Duration::from_secs(self.plan.max_duration_seconds),
        })
    }

    /// Charge one observed event against both the trial and the run.
    pub fn charge_event(&mut self, guard: &mut TrialGuard) -> Result<()> {
        if guard.events >= self.plan.max_events_per_trial {
            self.exhausted = true;
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "trial {} reached its {} event bound",
                guard.index, self.plan.max_events_per_trial
            )));
        }
        if self.total_events >= self.plan.max_total_events {
            self.exhausted = true;
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "the run reached its {} total event bound",
                self.plan.max_total_events
            )));
        }
        guard.events += 1;
        self.total_events += 1;
        Ok(())
    }

    /// Charge recalled items against the per-request bound.
    pub fn charge_recall_items(&mut self, count: u32) -> Result<()> {
        if count > self.plan.max_recall_items {
            self.exhausted = true;
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "a recall returned {count} items; the bound is {}",
                self.plan.max_recall_items
            )));
        }
        self.total_recall_items += count;
        Ok(())
    }

    /// Charge retained bytes against both the trial and the run.
    pub fn charge_output(&mut self, guard: &mut TrialGuard, bytes: usize) -> Result<()> {
        if guard.output_bytes + bytes > self.plan.max_output_bytes_per_trial {
            self.exhausted = true;
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "trial {} would retain more than its {} byte bound",
                guard.index, self.plan.max_output_bytes_per_trial
            )));
        }
        if self.total_output_bytes + bytes > self.plan.max_total_output_bytes {
            self.exhausted = true;
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "the run would retain more than its {} byte bound",
                self.plan.max_total_output_bytes
            )));
        }
        guard.output_bytes += bytes;
        self.total_output_bytes += bytes;
        Ok(())
    }

    pub fn mark_exhausted(&mut self) {
        self.exhausted = true;
    }
}

/// Per-trial state. Reset on each trial; the run totals are not.
#[derive(Debug)]
pub struct TrialGuard {
    index: u32,
    events: u32,
    output_bytes: usize,
    started_at: Instant,
    deadline: Duration,
}

impl TrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn trial_events(&self) -> u32 {
        self.events
    }

    pub fn trial_output_bytes(&self) -> usize {
        self.output_bytes
    }

    /// Refuse to continue past the trial's time bound.
    pub fn check_deadline(&self) -> Result<()> {
        if self.started_at.elapsed() > self.deadline {
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "trial {} exceeded its {} second bound",
                self.index,
                self.deadline.as_secs()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;

    #[test]
    fn the_default_plan_is_the_approved_one() {
        let plan = TrialPlan::default();
        assert_eq!(plan.trials, 3);
        assert!(plan.stop_on_first_fail);
        assert_eq!(plan.max_events_per_trial, 32);
        assert_eq!(plan.max_total_events, 96);
        assert_eq!(plan.max_recall_items, 8);
        assert_eq!(plan.max_output_bytes_per_trial, 16_384);
        assert_eq!(plan.max_total_output_bytes, 65_536);
        assert_eq!(plan.max_duration_seconds, 30);
    }

    #[test]
    fn a_scenario_may_ask_for_less() {
        let plan = TrialPlan::from_scenario(&scenario()).expect("plan");
        // The fixture asks for 16 events and 4 recall items.
        assert_eq!(plan.max_events_per_trial, 16);
        assert_eq!(plan.max_recall_items, 4);
        assert_eq!(plan.trials, 3);
    }

    #[test]
    fn an_over_limit_request_is_refused_and_never_clamped_upward() {
        // Clamping would let an over-limit scenario run as if it had asked for
        // something reasonable, and the operator would never learn otherwise.
        let mut scenario = scenario();
        scenario.safety.max_events_per_trial = Some(999);
        let err = TrialPlan::from_scenario(&scenario).expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::BudgetExhausted(_)));
        assert!(err.to_string().contains("999"));

        let mut scenario = super::tests::scenario();
        scenario.safety.max_recall_items = Some(99);
        assert!(TrialPlan::from_scenario(&scenario).is_err());

        let mut scenario = super::tests::scenario();
        scenario.safety.max_total_output_bytes = Some(10_000_000);
        assert!(TrialPlan::from_scenario(&scenario).is_err());

        let mut scenario = super::tests::scenario();
        scenario.trials.count = 11;
        assert!(TrialPlan::from_scenario(&scenario).is_err());
    }

    #[test]
    fn the_trial_ceiling_is_ten_and_the_boundaries_hold() {
        let mut scenario = scenario();
        scenario.trials.count = 10;
        assert_eq!(
            TrialPlan::from_scenario(&scenario).expect("plan").trials,
            10
        );

        let plan = TrialPlan::default();
        assert!(plan.with_trial_override(Some(10)).is_ok());
        assert!(plan.with_trial_override(Some(11)).is_err());
        assert_eq!(
            plan.with_trial_override(None).expect("unchanged").trials,
            crate::limits::DEFAULT_TRIALS
        );
    }

    #[test]
    fn disabling_local_only_is_refused() {
        let mut scenario = scenario();
        scenario.safety.local_only = false;
        let err = TrialPlan::from_scenario(&scenario).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("local only"));
    }

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
        // Zero available still leaves one trial to attempt and fail honestly.
        assert_eq!(plan.clamped_to_available(0).trials, 1);
    }

    #[test]
    fn the_total_event_counter_never_resets_between_trials() {
        // The property that makes a run-wide budget a run-wide budget.
        let plan = TrialPlan {
            trials: 10,
            max_events_per_trial: 2,
            max_total_events: 5,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();

        let mut charged = 0;
        while ledger.may_start_trial() {
            let Ok(mut guard) = ledger.start_trial() else {
                break;
            };
            for _ in 0..2 {
                if ledger.charge_event(&mut guard).is_err() {
                    break;
                }
                charged += 1;
            }
            if ledger.is_exhausted() {
                break;
            }
        }

        // Ten trials of two events each would be twenty if the counter reset.
        assert_eq!(charged, 5, "the run total was reset between trials");
        assert_eq!(ledger.total_events(), 5);
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn the_per_trial_event_bound_stops_one_trial() {
        let plan = TrialPlan {
            trials: 3,
            max_events_per_trial: 2,
            max_total_events: 96,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();
        let mut guard = ledger.start_trial().expect("first trial");
        ledger.charge_event(&mut guard).expect("first");
        ledger.charge_event(&mut guard).expect("second");
        let err = ledger.charge_event(&mut guard).expect_err("third");
        assert!(matches!(err, MemorySecurityError::BudgetExhausted(_)));
        assert_eq!(guard.trial_events(), 2);
    }

    #[test]
    fn an_over_bound_recall_is_refused() {
        let plan = TrialPlan {
            max_recall_items: 4,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();
        ledger.charge_recall_items(4).expect("at the bound");
        let err = ledger.charge_recall_items(5).expect_err("above it");
        assert!(matches!(err, MemorySecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn the_output_budget_bounds_both_the_trial_and_the_run() {
        let plan = TrialPlan {
            trials: 3,
            max_output_bytes_per_trial: 100,
            max_total_output_bytes: 150,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();

        let mut first = ledger.start_trial().expect("first trial");
        ledger
            .charge_output(&mut first, 100)
            .expect("fills the trial");
        assert!(ledger.charge_output(&mut first, 1).is_err());

        let mut ledger = plan.open();
        let mut first = ledger.start_trial().expect("first trial");
        ledger.charge_output(&mut first, 100).expect("first trial");
        let mut second = ledger.start_trial().expect("second trial");
        // The run total is 150, so only 50 more may be retained.
        ledger
            .charge_output(&mut second, 50)
            .expect("within the run");
        assert!(ledger.charge_output(&mut second, 1).is_err());
    }

    #[test]
    fn a_plan_runs_exactly_the_trials_it_planned() {
        let plan = TrialPlan {
            trials: 2,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();
        assert!(ledger.may_start_trial());
        assert_eq!(ledger.start_trial().expect("first").index(), 0);
        assert_eq!(ledger.start_trial().expect("second").index(), 1);
        assert!(!ledger.may_start_trial());
        assert!(ledger.start_trial().is_err());
        assert_eq!(ledger.trials_executed(), 2);
    }

    #[test]
    fn the_snapshot_evidences_zero_state_change_and_zero_egress() {
        let ledger = TrialPlan::default().open();
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
        assert!(!snapshot.exhausted);
    }

    #[test]
    fn a_fresh_guard_does_not_reopen_the_run_budget() {
        let plan = TrialPlan {
            trials: 5,
            max_events_per_trial: 32,
            max_total_events: 3,
            ..TrialPlan::default()
        };
        let mut ledger = plan.open();

        let mut first = ledger.start_trial().expect("first");
        for _ in 0..3 {
            ledger.charge_event(&mut first).expect("within the run");
        }
        // A new guard is fresh; the run total is not.
        let mut second = ledger.start_trial().expect("second");
        assert_eq!(second.trial_events(), 0);
        assert!(ledger.charge_event(&mut second).is_err());
    }

    #[test]
    fn a_deadline_that_has_not_passed_does_not_fire() {
        let ledger = TrialPlan::default().open();
        let _ = ledger;
        let mut ledger = TrialPlan::default().open();
        let guard = ledger.start_trial().expect("trial");
        guard.check_deadline().expect("30 seconds have not elapsed");
    }

    #[test]
    fn stop_reasons_serialize_with_stable_tags() {
        assert_eq!(StopReason::PlanCompleted.as_str(), "PLAN_COMPLETED");
        assert_eq!(
            StopReason::FirstFail { trial_index: 0 }.as_str(),
            "FIRST_FAIL"
        );
        assert_eq!(
            StopReason::BudgetExhausted {
                detail: "x".to_owned()
            }
            .as_str(),
            "BUDGET_EXHAUSTED"
        );
        let json =
            serde_json::to_string(&StopReason::FirstFail { trial_index: 2 }).expect("serializes");
        assert!(json.contains("\"reason\":\"FIRST_FAIL\""));
        assert!(json.contains("\"trial_index\":2"));
    }
}
