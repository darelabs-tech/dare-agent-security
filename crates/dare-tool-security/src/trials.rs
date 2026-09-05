//! Bounded trial, tool-request and chain-depth policy.
//!
//! The plan is fixed *before* execution and the hard maxima are compiled in.
//! Scenario, policy and CLI input can all ask for less; none can ask for more.
//! When a bound is reached the run stops — a budget is never widened to
//! accommodate the work in front of it.
//!
//! Total counters are cumulative across trials by construction. `TrialLedger`
//! owns them, and `start_trial` only resets the *per-trial* guard, so a run
//! cannot escape `hard_max_total_tool_requests` by starting a new trial.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ToolSecurityError};
use crate::limits;
use crate::model::ToolSecurityScenario;

/// A plan already checked against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTrialPlan {
    pub trials: u32,
    pub stop_on_first_fail: bool,
    pub max_tool_requests_per_trial: u32,
    pub max_total_tool_requests: u32,
    pub max_chain_depth: u32,
    pub max_output_bytes_per_trial: usize,
    pub max_total_output_bytes: usize,
    pub max_duration_seconds_per_trial: u64,
}

impl Default for ToolTrialPlan {
    fn default() -> Self {
        Self {
            trials: limits::DEFAULT_TRIALS,
            stop_on_first_fail: limits::STOP_ON_FIRST_FAIL,
            max_tool_requests_per_trial: limits::MAX_TOOL_REQUESTS_PER_TRIAL,
            max_total_tool_requests: limits::HARD_MAX_TOTAL_TOOL_REQUESTS,
            max_chain_depth: limits::HARD_MAX_CHAIN_DEPTH,
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
        return Err(ToolSecurityError::refusal(format!(
            "{label} {requested} exceeds the Cycle 014 hard maximum {hard_max}; \
             approved bounds cannot be raised by input"
        )));
    }
    Ok(requested)
}

/// Resolve one bound from two independent requests.
///
/// Each request is checked against the hard maximum on its own, so an
/// over-limit value is refused even when the *other* request happens to be
/// tighter. The approved bound is then the tightest of what remains. That is
/// the difference between refusing and silently clamping.
fn min_bound<T: Copy + Ord + std::fmt::Display>(
    scenario_request: Option<T>,
    policy_request: Option<T>,
    hard_max: T,
    label: &str,
) -> Result<T> {
    let mut bound = hard_max;
    for request in [scenario_request, policy_request].into_iter().flatten() {
        check_upper(request, hard_max, label)?;
        bound = bound.min(request);
    }
    Ok(bound)
}

impl ToolTrialPlan {
    /// Build a plan from an approved scenario, refusing over-limit requests.
    ///
    /// Both the scenario safety block and the policy invocation/chain blocks
    /// are consulted. Every stated value must fit inside the hard maximum on
    /// its own; the tightest surviving value becomes the bound.
    pub fn from_scenario(scenario: &ToolSecurityScenario) -> Result<Self> {
        if !scenario.safety.local_only {
            return Err(ToolSecurityError::refusal(
                "scenario disabled local_only; Cycle 014 has no non-local execution path",
            ));
        }

        let invocation = scenario.policy.invocation_policy;
        let chain = scenario.policy.chain_policy.as_ref();

        Ok(Self {
            trials: Self::check_trials(scenario.trials.count)?,
            stop_on_first_fail: scenario.trials.stop_on_first_fail,
            max_tool_requests_per_trial: min_bound(
                scenario.safety.max_tool_requests_per_trial,
                invocation.and_then(|policy| policy.max_requests_per_trial),
                limits::MAX_TOOL_REQUESTS_PER_TRIAL,
                "max_tool_requests_per_trial",
            )?,
            max_total_tool_requests: min_bound(
                scenario.safety.max_total_tool_requests,
                invocation.and_then(|policy| policy.max_total_requests),
                limits::HARD_MAX_TOTAL_TOOL_REQUESTS,
                "max_total_tool_requests",
            )?,
            max_chain_depth: min_bound(
                scenario.safety.max_chain_depth,
                chain.and_then(|policy| policy.max_chain_depth),
                limits::HARD_MAX_CHAIN_DEPTH,
                "max_chain_depth",
            )?,
            max_output_bytes_per_trial: min_bound(
                scenario.safety.max_output_bytes,
                None,
                limits::MAX_OUTPUT_BYTES_PER_TRIAL,
                "max_output_bytes",
            )?,
            max_total_output_bytes: min_bound(
                scenario.safety.max_total_output_bytes,
                None,
                limits::MAX_TOTAL_OUTPUT_BYTES,
                "max_total_output_bytes",
            )?,
            max_duration_seconds_per_trial: min_bound(
                scenario.safety.max_duration_seconds,
                None,
                limits::MAX_DURATION_SECONDS_PER_TRIAL,
                "max_duration_seconds",
            )?,
        })
    }

    fn check_trials(requested: u32) -> Result<u32> {
        if requested == 0 {
            return Err(ToolSecurityError::invalid("trial count must be at least 1"));
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

    pub fn open(self) -> ToolTrialLedger {
        ToolTrialLedger::new(self)
    }
}

/// Why a bounded run stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolStopReason {
    PlanCompleted,
    FirstFail { trial_index: u32 },
    BudgetExhausted { detail: String },
}

impl ToolStopReason {
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
pub struct ToolBudgetSnapshot {
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub tool_requests_observed: u32,
    pub max_total_tool_requests: u32,
    pub max_chain_depth_observed: u32,
    pub chain_depth_bound: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    /// Cycle 014 performs none. Recorded so the zero is evidenced.
    pub state_changes: u32,
    /// Cycle 014 performs none. Recorded so the zero is evidenced.
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// Tracks consumption against a fixed plan.
///
/// Total counters live here, never on the per-trial guard, so they cannot be
/// reset by starting another trial.
#[derive(Debug)]
pub struct ToolTrialLedger {
    plan: ToolTrialPlan,
    trials_executed: u32,
    total_tool_requests: u32,
    total_output_bytes: usize,
    max_chain_depth_observed: u32,
    exhausted: bool,
}

impl ToolTrialLedger {
    fn new(plan: ToolTrialPlan) -> Self {
        Self {
            plan,
            trials_executed: 0,
            total_tool_requests: 0,
            total_output_bytes: 0,
            max_chain_depth_observed: 0,
            exhausted: false,
        }
    }

    pub fn plan(&self) -> ToolTrialPlan {
        self.plan
    }

    pub fn trials_executed(&self) -> u32 {
        self.trials_executed
    }

    pub fn total_tool_requests(&self) -> u32 {
        self.total_tool_requests
    }

    pub fn total_output_bytes(&self) -> usize {
        self.total_output_bytes
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn snapshot(&self) -> ToolBudgetSnapshot {
        ToolBudgetSnapshot {
            trials_planned: self.plan.trials,
            trials_executed: self.trials_executed,
            tool_requests_observed: self.total_tool_requests,
            max_total_tool_requests: self.plan.max_total_tool_requests,
            max_chain_depth_observed: self.max_chain_depth_observed,
            chain_depth_bound: self.plan.max_chain_depth,
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
    pub fn start_trial(&mut self) -> Result<ToolTrialGuard> {
        if self.exhausted {
            return Err(ToolSecurityError::BudgetExhausted(
                "a run budget is already exhausted".to_owned(),
            ));
        }
        if self.trials_executed >= self.plan.trials {
            return Err(ToolSecurityError::BudgetExhausted(format!(
                "trial budget of {} exhausted",
                self.plan.trials
            )));
        }
        let index = self.trials_executed;
        self.trials_executed += 1;
        Ok(ToolTrialGuard {
            index,
            started: Instant::now(),
            limit: Duration::from_secs(self.plan.max_duration_seconds_per_trial),
            trial_requests: 0,
            max_trial_requests: self.plan.max_tool_requests_per_trial,
            trial_bytes: 0,
            max_trial_bytes: self.plan.max_output_bytes_per_trial,
        })
    }

    /// Charge one observed tool request against both bounds.
    ///
    /// The total is cumulative across trials and never resets.
    pub fn charge_tool_request(&mut self, guard: &mut ToolTrialGuard) -> Result<()> {
        let next_trial = guard.trial_requests.saturating_add(1);
        if next_trial > guard.max_trial_requests {
            self.exhausted = true;
            return Err(ToolSecurityError::BudgetExhausted(format!(
                "trial {} exceeded {} tool requests",
                guard.index, guard.max_trial_requests
            )));
        }
        let next_total = self.total_tool_requests.saturating_add(1);
        if next_total > self.plan.max_total_tool_requests {
            self.exhausted = true;
            return Err(ToolSecurityError::BudgetExhausted(format!(
                "run exceeded {} total tool requests",
                self.plan.max_total_tool_requests
            )));
        }
        guard.trial_requests = next_trial;
        self.total_tool_requests = next_total;
        Ok(())
    }

    /// Record an observed chain depth against the bound.
    pub fn charge_chain_depth(&mut self, depth: u32) -> Result<()> {
        self.max_chain_depth_observed = self.max_chain_depth_observed.max(depth);
        if depth > self.plan.max_chain_depth {
            self.exhausted = true;
            return Err(ToolSecurityError::BudgetExhausted(format!(
                "observed chain depth {depth} exceeded the bound {}",
                self.plan.max_chain_depth
            )));
        }
        Ok(())
    }

    /// Charge retained observation bytes against the per-trial and total bounds.
    pub fn charge_output(&mut self, guard: &mut ToolTrialGuard, bytes: usize) -> Result<()> {
        let trial_total = guard.trial_bytes.saturating_add(bytes);
        if trial_total > guard.max_trial_bytes {
            self.exhausted = true;
            return Err(ToolSecurityError::BudgetExhausted(format!(
                "trial {} output exceeded {} bytes",
                guard.index, guard.max_trial_bytes
            )));
        }
        let run_total = self.total_output_bytes.saturating_add(bytes);
        if run_total > self.plan.max_total_output_bytes {
            self.exhausted = true;
            return Err(ToolSecurityError::BudgetExhausted(format!(
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
pub struct ToolTrialGuard {
    index: u32,
    started: Instant,
    limit: Duration,
    trial_requests: u32,
    max_trial_requests: u32,
    trial_bytes: usize,
    max_trial_bytes: usize,
}

impl ToolTrialGuard {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn trial_requests(&self) -> u32 {
        self.trial_requests
    }

    pub fn max_trial_requests(&self) -> u32 {
        self.max_trial_requests
    }

    pub fn trial_bytes(&self) -> usize {
        self.trial_bytes
    }

    /// Refuse to continue past the per-trial deadline.
    pub fn check_deadline(&self) -> Result<()> {
        if self.started.elapsed() >= self.limit {
            return Err(ToolSecurityError::BudgetExhausted(format!(
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

    fn plan_from(safety: serde_json::Value, trials: serde_json::Value) -> Result<ToolTrialPlan> {
        let mut value = crate::schema::tests::valid_scenario();
        value["safety"] = safety;
        value["trials"] = trials;
        let scenario: ToolSecurityScenario = serde_json::from_value(value).unwrap();
        ToolTrialPlan::from_scenario(&scenario)
    }

    #[test]
    fn approved_defaults_are_the_compiled_in_bounds() {
        let plan = ToolTrialPlan::default();
        assert_eq!(plan.trials, 3);
        assert!(plan.stop_on_first_fail);
        assert_eq!(plan.max_tool_requests_per_trial, 8);
        assert_eq!(plan.max_total_tool_requests, 24);
        assert_eq!(plan.max_chain_depth, 3);
        assert_eq!(plan.max_output_bytes_per_trial, 16_384);
        assert_eq!(plan.max_total_output_bytes, 65_536);
        assert_eq!(plan.max_duration_seconds_per_trial, 30);
    }

    #[test]
    fn hard_max_trials_is_ten_and_boundaries_hold() {
        assert_eq!(
            plan_from(json!({"local_only": true}), json!({"count": 10}))
                .unwrap()
                .trials,
            10
        );
        assert!(plan_from(json!({"local_only": true}), json!({"count": 11})).is_err());
        assert!(plan_from(json!({"local_only": true}), json!({"count": 0})).is_err());
    }

    #[test]
    fn a_scenario_cannot_raise_any_hard_bound() {
        for safety in [
            json!({"local_only": true, "max_tool_requests_per_trial": 9}),
            json!({"local_only": true, "max_total_tool_requests": 25}),
            json!({"local_only": true, "max_chain_depth": 4}),
            json!({"local_only": true, "max_output_bytes": 16385}),
            json!({"local_only": true, "max_total_output_bytes": 65537}),
            json!({"local_only": true, "max_duration_seconds": 31}),
        ] {
            // Each value is refused on its own merits, even though the
            // approved policy already asks for something tighter. A tighter
            // neighbour must never launder an over-limit request into a clamp.
            let err = plan_from(safety.clone(), json!({"count": 3})).unwrap_err();
            assert!(err.is_refusal(), "{safety} must be refused");
            assert!(err.to_string().contains("cannot be raised by input"));
        }
    }

    #[test]
    fn the_tighter_of_scenario_and_policy_wins() {
        let mut value = crate::schema::tests::valid_scenario();
        // Policy asks for 4 per trial; scenario asks for 2.
        value["safety"] = json!({"local_only": true, "max_tool_requests_per_trial": 2});
        let scenario: ToolSecurityScenario = serde_json::from_value(value).unwrap();
        let plan = ToolTrialPlan::from_scenario(&scenario).unwrap();
        assert_eq!(plan.max_tool_requests_per_trial, 2);

        // And the policy's tighter chain depth of 2 wins over the default 3.
        assert_eq!(plan.max_chain_depth, 2);
    }

    #[test]
    fn disabling_local_only_is_refused() {
        let mut value = crate::schema::tests::valid_scenario();
        value["safety"] = json!({"local_only": false});
        let scenario: ToolSecurityScenario = serde_json::from_value(value).unwrap();
        assert!(ToolTrialPlan::from_scenario(&scenario)
            .unwrap_err()
            .is_refusal());
    }

    #[test]
    fn an_operator_override_is_bounded_by_the_same_maximum() {
        let plan = ToolTrialPlan::default();
        assert_eq!(plan.with_trial_override(Some(7)).unwrap().trials, 7);
        assert_eq!(plan.with_trial_override(Some(10)).unwrap().trials, 10);
        assert!(plan.with_trial_override(Some(11)).unwrap_err().is_refusal());
        assert!(plan.with_trial_override(Some(u32::MAX)).is_err());
        assert!(plan.with_trial_override(Some(0)).is_err());
        assert_eq!(plan.with_trial_override(None).unwrap().trials, 3);
    }

    #[test]
    fn the_ledger_stops_at_the_planned_trial_count() {
        let mut ledger = ToolTrialPlan {
            trials: 2,
            ..ToolTrialPlan::default()
        }
        .open();
        assert!(ledger.may_start_trial());
        assert_eq!(ledger.start_trial().unwrap().index(), 0);
        assert_eq!(ledger.start_trial().unwrap().index(), 1);
        assert!(!ledger.may_start_trial());
        assert!(matches!(
            ledger.start_trial().unwrap_err(),
            ToolSecurityError::BudgetExhausted(_)
        ));
    }

    #[test]
    fn per_trial_request_bound_stops_the_run() {
        let mut ledger = ToolTrialPlan {
            max_tool_requests_per_trial: 2,
            ..ToolTrialPlan::default()
        }
        .open();
        let mut guard = ledger.start_trial().unwrap();
        ledger.charge_tool_request(&mut guard).unwrap();
        ledger.charge_tool_request(&mut guard).unwrap();
        let err = ledger.charge_tool_request(&mut guard).unwrap_err();
        assert!(matches!(err, ToolSecurityError::BudgetExhausted(_)));
        assert_eq!(
            guard.trial_requests(),
            2,
            "rejected requests are not charged"
        );
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn the_total_request_counter_never_resets_between_trials() {
        // This is the bypass the bound exists to prevent: run several trials,
        // each within its per-trial allowance, and still hit the run total.
        let mut ledger = ToolTrialPlan {
            trials: 10,
            max_tool_requests_per_trial: 2,
            max_total_tool_requests: 5,
            ..ToolTrialPlan::default()
        }
        .open();

        let mut charged = 0;
        let mut exhausted = false;
        for _ in 0..10 {
            let Ok(mut guard) = ledger.start_trial() else {
                break;
            };
            for _ in 0..2 {
                match ledger.charge_tool_request(&mut guard) {
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
        assert_eq!(ledger.total_tool_requests(), 5);
        assert_eq!(ledger.snapshot().max_total_tool_requests, 5);
    }

    #[test]
    fn chain_depth_beyond_the_bound_stops_the_run() {
        let mut ledger = ToolTrialPlan {
            max_chain_depth: 2,
            ..ToolTrialPlan::default()
        }
        .open();
        ledger.charge_chain_depth(1).unwrap();
        ledger.charge_chain_depth(2).unwrap();
        let err = ledger.charge_chain_depth(3).unwrap_err();
        assert!(matches!(err, ToolSecurityError::BudgetExhausted(_)));
        assert!(ledger.is_exhausted());
        // The deepest observed value is still recorded for evidence.
        assert_eq!(ledger.snapshot().max_chain_depth_observed, 3);
        assert_eq!(ledger.snapshot().chain_depth_bound, 2);
    }

    #[test]
    fn output_budgets_span_trials_and_never_widen() {
        let mut ledger = ToolTrialPlan {
            trials: 5,
            max_output_bytes_per_trial: 100,
            max_total_output_bytes: 150,
            ..ToolTrialPlan::default()
        }
        .open();

        let mut first = ledger.start_trial().unwrap();
        ledger.charge_output(&mut first, 100).unwrap();
        let mut second = ledger.start_trial().unwrap();
        ledger.charge_output(&mut second, 50).unwrap();
        assert_eq!(ledger.total_output_bytes(), 150);

        let err = ledger.charge_output(&mut second, 1).unwrap_err();
        assert!(matches!(err, ToolSecurityError::BudgetExhausted(_)));
        assert_eq!(ledger.total_output_bytes(), 150);
        assert_eq!(ledger.snapshot().max_total_output_bytes, 150);
    }

    #[test]
    fn exact_boundaries_are_allowed_and_one_over_is_not() {
        let mut ledger = ToolTrialPlan {
            max_output_bytes_per_trial: 10,
            max_total_output_bytes: 10,
            ..ToolTrialPlan::default()
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
        let mut ledger = ToolTrialPlan::default().open();
        let mut guard = ledger.start_trial().unwrap();
        assert!(ledger.charge_output(&mut guard, usize::MAX).is_err());
    }

    #[test]
    fn a_deadline_guard_is_armed_from_the_plan() {
        let mut ledger = ToolTrialPlan::default().open();
        ledger
            .start_trial()
            .unwrap()
            .check_deadline()
            .expect("fresh");

        let mut ledger = ToolTrialPlan {
            max_duration_seconds_per_trial: 0,
            ..ToolTrialPlan::default()
        }
        .open();
        assert!(ledger.start_trial().unwrap().check_deadline().is_err());
    }

    #[test]
    fn the_snapshot_evidences_zero_state_change_and_zero_egress() {
        let ledger = ToolTrialPlan::default().open();
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn stopping_on_first_fail_does_not_hide_the_violations_already_observed() {
        // stop_on_first_fail is a budget control, not a reporting filter: the
        // trial that fails still reports every independently observed
        // violation, and the ledger still evidences what it consumed.
        use crate::invariant::evaluate;
        use crate::model::{OperationClass, ToolInvariantType};
        use crate::observation::{ToolObservationEvent, ToolRequested, ToolSelected};

        let scenario: ToolSecurityScenario =
            serde_json::from_value(crate::schema::tests::valid_scenario()).unwrap();
        let plan = ToolTrialPlan::from_scenario(&scenario).unwrap();
        assert!(plan.stop_on_first_fail);

        let mut ledger = plan.open();
        let mut guard = ledger.start_trial().unwrap();

        // Two independently unapproved tools inside one trial.
        let events = [
            ToolObservationEvent::ToolSelected(ToolSelected {
                tool_id: "ticket_delete".to_owned(),
                for_objective_id: None,
                tool_digest: None,
            }),
            ToolObservationEvent::ToolRequested(ToolRequested {
                tool_id: "ticket_export".to_owned(),
                operation_class: Some(OperationClass::Read),
                dispatched: false,
            }),
        ];
        for _ in &events {
            ledger.charge_tool_request(&mut guard).unwrap();
        }

        let outcome = evaluate(
            ToolInvariantType::ApprovedToolOnly,
            &scenario.objective,
            &scenario.policy,
            &events,
        );
        assert_eq!(outcome.verdict, crate::Verdict::Fail);
        assert_eq!(
            outcome.violations.len(),
            2,
            "one classification must never mask another"
        );

        let stop = ToolStopReason::FirstFail {
            trial_index: guard.index(),
        };
        assert_eq!(stop, ToolStopReason::FirstFail { trial_index: 0 });

        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.trials_planned, 3);
        assert_eq!(snapshot.trials_executed, 1, "later trials are not run");
        assert_eq!(snapshot.tool_requests_observed, 2, "and nothing is erased");
    }

    #[test]
    fn stop_reasons_serialize_with_stable_tags() {
        assert_eq!(
            serde_json::to_value(ToolStopReason::PlanCompleted).unwrap(),
            json!({"reason": "PLAN_COMPLETED"})
        );
        assert_eq!(
            serde_json::to_value(ToolStopReason::FirstFail { trial_index: 1 }).unwrap(),
            json!({"reason": "FIRST_FAIL", "trial_index": 1})
        );
        assert_eq!(
            ToolStopReason::BudgetExhausted {
                detail: "x".to_owned()
            }
            .as_str(),
            "BUDGET_EXHAUSTED"
        );
    }
}
