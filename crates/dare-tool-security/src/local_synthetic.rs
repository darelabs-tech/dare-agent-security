//! Local-synthetic adapter, gated by the Cycle 009 controlled substrate.
//!
//! This adapter introduces no second executor. Observations still come from the
//! Cycle 014 simulator; what this module adds is that every trial is first
//! expressed as a Cycle 009 `VectorStep` and pushed through the Cycle 009
//! controls:
//!
//! - `kill_switch::inspect_step` — refuses unexpected state change, external
//!   egress, target substitution, or a secret appearing in arguments;
//! - `budget_enforce::BudgetState` — refuses the next operation once a fixed
//!   bound would be crossed;
//! - the step's safety class is pinned to `SYNTHETIC_NOOP`.
//!
//! The synthetic step is read-only by construction: zero state changes, zero
//! bytes written, zero egress, no network method and no target but the approved
//! synthetic one. A risky operation the reference agent "requests" — a delete,
//! a payment, a send, an external fetch — is recorded as an observation and is
//! never carried out, because there is no code path here that could carry it
//! out.
//!
//! A triggered control is a *harness outcome*. It produces ERROR through the
//! normal harness-error channel; it never becomes a security verdict, and it is
//! never read by a model.

use std::cell::RefCell;

use dare_adversarial::{
    budget_enforce::BudgetState,
    kill_switch::{inspect_step, KillState},
    model::{ExecutionBudget, ExpectedDecision, ProofClass, VectorStep},
    AdversarialError,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{Result, ToolSecurityError};
use crate::harness::{
    RawHarnessError, RawToolTrialOutput, ToolHarnessAdapter, ToolHarnessMode, ToolTrialRequest,
};
use crate::model::ToolLabSpec;
use crate::observation::HarnessErrorKind;
use crate::simulated::ToolSimulatedAdapter;

/// Cycle 009 budget for a Cycle 014 local-synthetic run.
///
/// State changes, bytes written and external egress are all zero, so an attempt
/// to mutate or exfiltrate is refused by the Cycle 009 policy rather than by a
/// Cycle 014 rule of its own.
pub fn synthetic_budget(trials: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "budget-tool-security-local-synthetic".to_owned(),
        max_operations: trials.max(1),
        max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        max_state_changes: crate::limits::MAX_STATE_CHANGES,
        max_bytes_read: crate::limits::MAX_TOTAL_OUTPUT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: crate::limits::HARD_MAX_CHAIN_DEPTH,
    }
}

/// Kill-switch and budget state recorded into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolControlSnapshot {
    /// Kill-switch state after the last inspected step.
    pub kill_switch: String,
    /// Operations consumed against the Cycle 009 budget.
    pub operations: u32,
    /// State changes observed. Always zero for Cycle 014.
    pub state_changes: u32,
    /// External egress bytes observed. Always zero for Cycle 014.
    pub external_egress_bytes: u64,
}

/// Controlled local synthetic execution.
#[derive(Debug)]
pub struct ToolLocalSyntheticAdapter {
    inner: ToolSimulatedAdapter,
    target_id: String,
    budget: ExecutionBudget,
    state: RefCell<BudgetState>,
    control: RefCell<ToolControlSnapshot>,
}

impl ToolLocalSyntheticAdapter {
    /// Build an adapter for an approved synthetic target.
    pub fn new(lab: ToolLabSpec, target_id: impl Into<String>, trials: u32) -> Self {
        Self {
            inner: ToolSimulatedAdapter::new(lab),
            target_id: target_id.into(),
            budget: synthetic_budget(trials),
            state: RefCell::new(BudgetState::default()),
            control: RefCell::new(ToolControlSnapshot {
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
    pub fn control_snapshot(&self) -> ToolControlSnapshot {
        self.control.borrow().clone()
    }

    /// Build the read-only synthetic step for one trial.
    ///
    /// It carries no state change, no bytes written, no egress, no network
    /// method and the `SyntheticNoop` safety class. Arguments are identifiers
    /// only — never tool output, never argument values, never a credential.
    fn step_for(&self, request: &ToolTrialRequest<'_>) -> VectorStep {
        VectorStep {
            method: "observe".to_owned(),
            capability: request.scenario.property.as_str().to_owned(),
            arguments: json!({
                "scenario_id": request.scenario.id,
                "surface_id": request.binding.surface_id,
                "policy_id": request.binding.policy_id,
                "trial_index": request.trial_index,
                "source_kind": request.scenario.source.kind.as_str(),
            }),
            safety_class: ProofClass::SyntheticNoop,
            synthetic_observation: ExpectedDecision::Inconclusive,
            bytes_read: 0,
            bytes_written: 0,
            state_changes: 0,
            external_egress_bytes: 0,
            retries: 0,
            target_id: Some(self.target_id.clone()),
            identity_id: None,
            trigger: None,
        }
    }
}

impl ToolHarnessAdapter for ToolLocalSyntheticAdapter {
    fn mode(&self) -> ToolHarnessMode {
        ToolHarnessMode::LocalSynthetic
    }

    fn observe(&self, request: &ToolTrialRequest<'_>) -> Result<RawToolTrialOutput> {
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
                return Ok(RawToolTrialOutput {
                    harness_error: Some(RawHarnessError {
                        kind: HarnessErrorKind::KillSwitchTriggered,
                        detail: format!("Cycle 009 kill switch triggered: {reason}"),
                    }),
                    ..RawToolTrialOutput::default()
                });
            }
            Err(error) => {
                return Err(ToolSecurityError::refusal(format!(
                    "Cycle 009 control refused the synthetic step: {error}"
                )))
            }
        }

        // Cycle 009 budget next: refuse the operation that would cross a bound.
        {
            let mut state = self.state.borrow_mut();
            if let Err(error) = state.check_next(&step, &self.budget) {
                self.control.borrow_mut().kill_switch = "BUDGET_STOP".to_owned();
                return Err(ToolSecurityError::BudgetExhausted(error.to_string()));
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
    use crate::canonical::ToolIdentityBinding;
    use crate::harness::{normalize_checked, tests::binding, tests::scenario};
    use crate::invariant::evaluate;
    use crate::model::{
        OperationClass, ReferenceBehavior, ToolInvariantType, ToolSecurityScenario,
    };
    use crate::observation::ToolObservationEvent;
    use crate::Verdict;
    use dare_adversarial::model::KillTrigger;

    const TARGET: &str = "synthetic-tool-security-lab";

    fn lab(behavior: ReferenceBehavior) -> ToolLabSpec {
        ToolLabSpec {
            reference_behavior: behavior,
            per_trial: std::collections::BTreeMap::new(),
            output_filler_bytes: None,
        }
    }

    fn adapter(behavior: ReferenceBehavior) -> ToolLocalSyntheticAdapter {
        ToolLocalSyntheticAdapter::new(lab(behavior), TARGET, 3)
    }

    fn request<'a>(
        trial_index: u32,
        scenario: &'a ToolSecurityScenario,
        binding: &'a ToolIdentityBinding,
    ) -> ToolTrialRequest<'a> {
        ToolTrialRequest {
            trial_index,
            scenario,
            binding,
            entry: None,
        }
    }

    #[test]
    fn the_mode_is_local_synthetic_and_marked_synthetic() {
        let adapter = adapter(ReferenceBehavior::Compliant);
        assert_eq!(adapter.mode(), ToolHarnessMode::LocalSynthetic);
        assert!(adapter.mode().is_synthetic());
    }

    #[test]
    fn the_cycle_009_budget_forbids_mutation_and_egress() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
        assert_eq!(budget.max_retries, 0);
        assert_eq!(budget.max_chain_depth, crate::limits::HARD_MAX_CHAIN_DEPTH);
    }

    #[test]
    fn the_synthetic_step_is_read_only_by_construction() {
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::Compliant);
        let step = adapter.step_for(&request(0, &scenario, &binding));

        assert_eq!(step.method, "observe");
        assert_eq!(step.safety_class, ProofClass::SyntheticNoop);
        assert_eq!(step.state_changes, 0);
        assert_eq!(step.bytes_written, 0);
        assert_eq!(step.external_egress_bytes, 0);
        assert_eq!(step.retries, 0);
        assert_eq!(step.target_id.as_deref(), Some(TARGET));
        assert_eq!(step.trigger, None);
    }

    #[test]
    fn a_risky_staged_request_never_becomes_a_step() {
        // The whole point of the boundary: a fixture may stage a DELETE
        // request, and it stays a recorded observation. The step that actually
        // runs is still a read-only no-op against the synthetic target.
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::DangerousArgumentRequested);

        let step = adapter.step_for(&request(0, &scenario, &binding));
        assert_eq!(step.method, "observe");
        assert_eq!(step.state_changes, 0);
        assert_eq!(step.external_egress_bytes, 0);

        let raw = adapter.observe(&request(0, &scenario, &binding)).unwrap();
        let events = normalize_checked(&raw, &binding).unwrap();
        let risky: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                ToolObservationEvent::ToolRequested(request) => request.operation_class,
                _ => None,
            })
            .filter(|class| {
                matches!(
                    class,
                    OperationClass::Delete
                        | OperationClass::Send
                        | OperationClass::Payment
                        | OperationClass::ExternalFetch
                        | OperationClass::PrivilegeChange
                )
            })
            .collect();
        assert!(!risky.is_empty(), "the fixture stages a risky request");

        // Observed, and deterministically failed — without ever happening.
        assert_eq!(
            evaluate(
                ToolInvariantType::DangerousArgumentNotRequested,
                &scenario.objective,
                &scenario.policy,
                &events
            )
            .verdict,
            Verdict::Fail
        );
        assert_eq!(adapter.control_snapshot().state_changes, 0);
        assert_eq!(adapter.control_snapshot().external_egress_bytes, 0);
    }

    #[test]
    fn a_triggered_kill_switch_is_a_harness_outcome_not_a_verdict() {
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::Compliant);

        // A step aimed at a different target is a substitution, which the
        // Cycle 009 control refuses.
        let mut step = adapter.step_for(&request(0, &scenario, &binding));
        step.target_id = Some("some-other-target".to_owned());
        assert!(inspect_step(&step, TARGET).is_err());

        // And the adapter surfaces such a refusal through the harness channel.
        let raw = RawToolTrialOutput {
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::KillSwitchTriggered,
                detail: "Cycle 009 kill switch triggered: target substitution".to_owned(),
            }),
            ..RawToolTrialOutput::default()
        };
        let events = normalize_checked(&raw, &binding).unwrap();
        for invariant in crate::invariant::supported_invariants() {
            assert_eq!(
                evaluate(invariant, &scenario.objective, &scenario.policy, &events).verdict,
                Verdict::Error,
                "{} must be ERROR when a control triggered",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn a_state_changing_or_egressing_step_is_refused_by_cycle_009() {
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::Compliant);
        let base = adapter.step_for(&request(0, &scenario, &binding));

        let mutating = VectorStep {
            state_changes: 1,
            ..base.clone()
        };
        assert!(inspect_step(&mutating, TARGET).is_err());

        let egressing = VectorStep {
            external_egress_bytes: 1,
            ..base.clone()
        };
        assert!(inspect_step(&egressing, TARGET).is_err());

        let triggered = VectorStep {
            trigger: Some(KillTrigger::UnexpectedState),
            ..base
        };
        assert!(inspect_step(&triggered, TARGET).is_err());
    }

    #[test]
    fn the_budget_stops_the_run_rather_than_widening() {
        let scenario = scenario();
        let binding = binding();
        let adapter = ToolLocalSyntheticAdapter::new(lab(ReferenceBehavior::Compliant), TARGET, 2);

        adapter.observe(&request(0, &scenario, &binding)).unwrap();
        adapter.observe(&request(1, &scenario, &binding)).unwrap();
        let err = adapter
            .observe(&request(2, &scenario, &binding))
            .unwrap_err();
        assert!(matches!(err, ToolSecurityError::BudgetExhausted(_)));
        assert_eq!(adapter.control_snapshot().kill_switch, "BUDGET_STOP");
        assert_eq!(adapter.control_snapshot().operations, 2);
    }

    #[test]
    fn control_state_is_recorded_for_evidence() {
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::Compliant);
        assert_eq!(adapter.control_snapshot().kill_switch, "ARMED");

        adapter.observe(&request(0, &scenario, &binding)).unwrap();
        let snapshot = adapter.control_snapshot();
        assert_eq!(snapshot.kill_switch, "NOT_TRIGGERED");
        assert_eq!(snapshot.operations, 1);
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn the_step_arguments_carry_identifiers_only() {
        // Cycle 009 refuses a secret in step arguments. Nothing observed —
        // no tool output, no argument value — is ever put there in the first
        // place, so the control has nothing to catch.
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter(ReferenceBehavior::Compliant);
        let step = adapter.step_for(&request(0, &scenario, &binding));
        let arguments = step.arguments.as_object().expect("object arguments");
        let mut keys: Vec<&str> = arguments.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "policy_id",
                "scenario_id",
                "source_kind",
                "surface_id",
                "trial_index"
            ]
        );
        assert!(inspect_step(&step, TARGET).is_ok());
    }

    #[test]
    fn local_synthetic_observations_match_the_simulator_it_wraps() {
        // No second executor: the controls gate the run, they do not produce a
        // different reality from the one the simulator staged.
        let scenario = scenario();
        let binding = binding();
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::UnapprovedToolSelected,
            ReferenceBehavior::NoRelevantObservation,
        ] {
            let gated = adapter(behavior)
                .observe(&request(0, &scenario, &binding))
                .unwrap();
            let plain = ToolSimulatedAdapter::new(lab(behavior))
                .observe(&request(0, &scenario, &binding))
                .unwrap();
            assert_eq!(gated, plain, "{} must be unchanged", behavior.as_str());
        }
    }
}
