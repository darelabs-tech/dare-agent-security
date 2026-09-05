//! Local-synthetic adapter, gated by the Cycle 009 controlled substrate.
//!
//! No second executor is introduced. Observations still come from the Cycle 015
//! simulator; what this module adds is that every trial is first expressed as a
//! Cycle 009 `VectorStep` and pushed through the Cycle 009 controls:
//!
//! - `kill_switch::inspect_step` — refuses unexpected state change, external
//!   egress, target substitution, or a secret appearing in arguments;
//! - `budget_enforce::BudgetState` — refuses the next operation once a fixed
//!   bound would be crossed;
//! - the step's safety class is pinned to `SYNTHETIC_NOOP`.
//!
//! The step is read-only by construction: zero state changes, zero bytes
//! written, zero egress, no network method, and no target but the approved
//! synthetic one. An operation the reference agent "requests" against another
//! tenant's resource is recorded as an observation and is never carried out,
//! because no code path here could carry it out — the boundary crossing is
//! proven from declarations, never by touching anything.
//!
//! The step's arguments are identifiers only: scenario, principal role bindings
//! by id, trial index. No authority values, no credential metadata, no resource
//! content and no operation arguments travel into the control substrate.
//!
//! A triggered control is a *harness outcome*. It produces `ERROR` through the
//! normal harness-error channel; it never becomes a security verdict.

use std::cell::RefCell;

use dare_adversarial::{
    budget_enforce::BudgetState,
    kill_switch::{inspect_step, KillState},
    model::{ExecutionBudget, ExpectedDecision, ProofClass, VectorStep},
    AdversarialError,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{IdentitySecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawHarnessError, RawTrialOutput, TrialRequest};
use crate::observation::HarnessErrorKind;
use crate::simulated::SimulatedAdapter;

/// Cycle 009 budget for a Cycle 015 local-synthetic run.
///
/// State changes, bytes written and external egress are all zero, so an attempt
/// to mutate or exfiltrate is refused by the Cycle 009 policy rather than by a
/// Cycle 015 rule of its own.
pub fn synthetic_budget(trials: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "budget-identity-security-local-synthetic".to_owned(),
        max_operations: trials.max(1),
        max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        max_state_changes: crate::limits::MAX_STATE_CHANGES,
        max_bytes_read: crate::limits::MAX_TOTAL_OUTPUT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: crate::limits::HARD_MAX_DELEGATION_DEPTH,
    }
}

/// Kill-switch and budget state recorded into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityControlSnapshot {
    /// Kill-switch state after the last inspected step.
    pub kill_switch: String,
    /// Operations consumed against the Cycle 009 budget.
    pub operations: u32,
    /// State changes observed. Always zero for Cycle 015.
    pub state_changes: u32,
    /// External egress bytes observed. Always zero for Cycle 015.
    pub external_egress_bytes: u64,
}

/// Controlled local synthetic execution.
#[derive(Debug)]
pub struct LocalSyntheticAdapter {
    inner: SimulatedAdapter,
    target_id: String,
    budget: ExecutionBudget,
    state: RefCell<BudgetState>,
    control: RefCell<IdentityControlSnapshot>,
}

impl LocalSyntheticAdapter {
    /// Build an adapter approved for one synthetic target.
    ///
    /// The target is the scenario the run was approved for. The step names the
    /// scenario it is actually observing, so pointing an approved run at a
    /// different scenario is a target substitution the Cycle 009 kill switch
    /// catches — rather than something this module has to remember to check.
    pub fn new(target_id: impl Into<String>, trials: u32) -> Self {
        Self {
            inner: SimulatedAdapter::new(),
            target_id: target_id.into(),
            budget: synthetic_budget(trials),
            state: RefCell::new(BudgetState::default()),
            control: RefCell::new(IdentityControlSnapshot {
                kill_switch: "ARMED".to_owned(),
                operations: 0,
                state_changes: 0,
                external_egress_bytes: 0,
            }),
        }
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn budget(&self) -> &ExecutionBudget {
        &self.budget
    }

    /// Current kill-switch and budget state, for evidence.
    pub fn control_snapshot(&self) -> IdentityControlSnapshot {
        self.control.borrow().clone()
    }

    /// Build an adapter approved for exactly this scenario.
    pub fn for_scenario(scenario: &crate::model::IdentitySecurityScenario, trials: u32) -> Self {
        Self::new(scenario.id.clone(), trials)
    }

    /// Build the read-only synthetic step for one trial.
    fn step_for(&self, request: &TrialRequest<'_>) -> VectorStep {
        let bindings = &request.scenario.principals.bindings;
        VectorStep {
            method: "observe".to_owned(),
            capability: request.scenario.property.as_str().to_owned(),
            arguments: json!({
                "scenario_id": request.scenario.id,
                "trial_index": request.trial_index,
                "initiating_principal_id": bindings.initiating_principal_id,
                "effective_principal_id": bindings.effective_principal_id,
                "source_kind": request.scenario.source.kind.as_str(),
            }),
            safety_class: ProofClass::SyntheticNoop,
            synthetic_observation: ExpectedDecision::Inconclusive,
            bytes_read: 0,
            bytes_written: 0,
            state_changes: 0,
            external_egress_bytes: 0,
            retries: 0,
            // The scenario actually being observed, not the approved one: the
            // two are compared by the control, not asserted equal here.
            target_id: Some(request.scenario.id.clone()),
            identity_id: None,
            trigger: None,
        }
    }
}

impl HarnessAdapter for LocalSyntheticAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::LocalSynthetic
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        let step = self.step_for(request);

        // Cycle 009 kill switch first. A triggered control stops the trial and
        // becomes a harness condition, never a security verdict.
        match inspect_step(&step, &self.target_id) {
            Ok(KillState::NotTriggered) => {}
            Ok(other) => {
                self.control.borrow_mut().kill_switch = format!("{other:?}");
            }
            Err(AdversarialError::KillTriggered(reason)) => {
                self.control.borrow_mut().kill_switch = "TRIGGERED".to_owned();
                return Ok(RawTrialOutput {
                    harness_error: Some(RawHarnessError {
                        kind: HarnessErrorKind::KillSwitchTriggered,
                        detail: format!("Cycle 009 kill switch triggered: {reason}"),
                    }),
                    ..RawTrialOutput::default()
                });
            }
            Err(error) => {
                return Err(IdentitySecurityError::refusal(format!(
                    "Cycle 009 control refused the synthetic step: {error}"
                )))
            }
        }

        // Cycle 009 budget next: refuse the operation that would cross a bound.
        {
            let mut state = self.state.borrow_mut();
            if let Err(error) = state.check_next(&step, &self.budget) {
                self.control.borrow_mut().kill_switch = "BUDGET_STOP".to_owned();
                return Err(IdentitySecurityError::BudgetExhausted(error.to_string()));
            }
            state.consume(&step);
            let snapshot = state.snapshot.clone();
            let mut control = self.control.borrow_mut();
            control.kill_switch = "NOT_TRIGGERED".to_owned();
            control.operations = snapshot.operations;
            control.state_changes = snapshot.state_changes;
            control.external_egress_bytes = snapshot.external_egress_bytes;
        }

        self.inner.observe(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{normalize_checked, observed_operations, tests::scenario};
    use crate::invariant::evaluate;
    use crate::model::{IdentityInvariantType, ReferenceBehavior};
    use crate::observation::IdentityObservationEvent;
    use dare_adversarial::model::KillTrigger;
    use dare_security_evidence::Verdict;

    const TARGET: &str = "IDENTITY-LAB-001";

    fn adapter() -> LocalSyntheticAdapter {
        LocalSyntheticAdapter::new(TARGET, crate::limits::HARD_MAX_TRIALS)
    }

    #[test]
    fn the_synthetic_step_is_read_only_by_construction() {
        let scenario = scenario();
        let adapter = adapter();
        let step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        });
        assert_eq!(step.safety_class, ProofClass::SyntheticNoop);
        assert_eq!(step.state_changes, 0);
        assert_eq!(step.bytes_written, 0);
        assert_eq!(step.external_egress_bytes, 0);
        assert_eq!(step.retries, 0);
        assert_eq!(step.method, "observe");
        assert_eq!(step.target_id.as_deref(), Some(scenario.id.as_str()));
    }

    #[test]
    fn the_budget_pins_state_change_and_egress_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
        assert_eq!(budget.max_retries, 0);
        assert_eq!(
            budget.max_chain_depth,
            crate::limits::HARD_MAX_DELEGATION_DEPTH
        );
    }

    #[test]
    fn the_step_carries_identifiers_and_no_authority_or_credential_content() {
        let scenario = scenario();
        let adapter = adapter();
        let step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        });
        let text = serde_json::to_string(&step.arguments).expect("serializes");
        for forbidden in [
            "capability_labels",
            "authority",
            "credential",
            "resource_id",
            "constraint",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked into {text}");
        }
        // Refuse silently-empty arguments too: identifiers must be present.
        assert!(text.contains("user-7"));
    }

    #[test]
    fn a_controlled_run_produces_the_same_events_as_the_simulator() {
        // The controls gate the run; they do not alter what was observed.
        let scenario = scenario();
        let adapter = adapter();
        let request = TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        };
        let controlled = adapter.observe(&request).expect("observes");
        let plain = SimulatedAdapter::new().observe(&request).expect("observes");
        assert_eq!(controlled, plain);
        assert_eq!(adapter.mode(), HarnessMode::LocalSynthetic);
        assert!(adapter.mode().is_synthetic());
    }

    #[test]
    fn the_control_snapshot_records_zero_state_change_and_zero_egress() {
        let scenario = scenario();
        let adapter = adapter();
        adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");
        let snapshot = adapter.control_snapshot();
        assert_eq!(snapshot.kill_switch, "NOT_TRIGGERED");
        assert_eq!(snapshot.operations, 1);
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn the_budget_refuses_the_operation_that_would_cross_it() {
        let scenario = scenario();
        let adapter = LocalSyntheticAdapter::new(TARGET, 1);
        let request = TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        };
        adapter.observe(&request).expect("first trial is inside");
        let err = adapter
            .observe(&request)
            .expect_err("second must be refused");
        assert!(matches!(err, IdentitySecurityError::BudgetExhausted(_)));
        assert!(err.is_refusal());
        assert_eq!(adapter.control_snapshot().kill_switch, "BUDGET_STOP");
    }

    #[test]
    fn a_step_that_would_change_state_is_killed_and_becomes_error_not_fail() {
        // Proven through the Cycle 009 control itself rather than a local rule.
        let scenario = scenario();
        let adapter = adapter();
        let mut step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        });
        step.state_changes = 1;
        step.trigger = Some(KillTrigger::UnexpectedState);
        let outcome = inspect_step(&step, TARGET);
        assert!(
            matches!(outcome, Err(AdversarialError::KillTriggered(_)))
                || matches!(outcome, Ok(ref state) if *state != KillState::NotTriggered),
            "{outcome:?}"
        );
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_trips_the_kill_switch() {
        // Substituting the target is exactly what the Cycle 009 kill switch is
        // there to catch, and it must surface as ERROR rather than as a verdict
        // about the scenario that was never actually observed.
        let scenario = scenario();
        let adapter = LocalSyntheticAdapter::new("IDENTITY-LAB-024", 3);
        let raw = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("a triggered control is an outcome, not a panic");

        let error = raw
            .harness_error
            .as_ref()
            .expect("the substituted target must trigger the control");
        assert_eq!(error.kind, HarnessErrorKind::KillSwitchTriggered);
        assert!(error.detail.contains("unexpected target"));
        assert_eq!(adapter.control_snapshot().kill_switch, "TRIGGERED");
        // Nothing was observed, so nothing can be claimed.
        assert!(raw.principals.is_empty());
        assert!(raw.final_operations.is_empty());

        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        assert!(events[0].is_harness_error());
        for invariant in IdentityInvariantType::all() {
            assert_eq!(
                evaluate(invariant, &scenario, &events).verdict,
                Verdict::Error,
                "{}",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn an_adapter_built_for_a_scenario_is_approved_for_that_scenario() {
        let scenario = scenario();
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario, 3);
        assert_eq!(adapter.target_id(), scenario.id);
        adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("the approved scenario is observable");
        assert_eq!(adapter.control_snapshot().kill_switch, "NOT_TRIGGERED");
    }

    #[test]
    fn nothing_is_dispatched_even_for_a_denied_operation() {
        let mut scenario = scenario();
        scenario
            .lab
            .as_mut()
            .expect("the fixture declares a lab spec")
            .reference_behavior = ReferenceBehavior::DenyBypassed;

        let adapter = adapter();
        let raw = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        assert!(observed_operations(&events) > 0);
        for event in &events {
            if let IdentityObservationEvent::FinalOperation(observed)
            | IdentityObservationEvent::OperationRequest(observed) = event
            {
                assert!(!observed.dispatched);
            }
        }
        // The denied operation is observed and reported, not performed.
        assert_eq!(
            evaluate(IdentityInvariantType::DenyNotBypassed, &scenario, &events).verdict,
            Verdict::Fail
        );
        assert_eq!(adapter.control_snapshot().state_changes, 0);
    }
}
