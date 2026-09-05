//! Local-synthetic adapter, gated by the Cycle 009 controlled substrate.
//!
//! This adapter does not introduce a second executor. Every trial is expressed
//! as a Cycle 009 `VectorStep` and pushed through the Cycle 009 controls before
//! any observation is produced:
//!
//! - `kill_switch::inspect_step` — refuses unexpected state change, external
//!   egress, target substitution or a secret appearing in arguments;
//! - `budget_enforce::BudgetState` — refuses the next operation once a fixed
//!   bound would be crossed;
//! - the step's own safety class is pinned to `SYNTHETIC_NOOP`.
//!
//! The synthetic step is read-only by construction: zero state changes, zero
//! egress bytes, no network method. Actions the reference agent "requests" are
//! recorded as observations and are never carried out.

use dare_adversarial::{
    budget_enforce::BudgetState,
    kill_switch::{inspect_step, KillState},
    model::{ExecutionBudget, ExpectedDecision, ProofClass, VectorStep},
    AdversarialError,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{PromptInjectionError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawHarnessError, RawTrialOutput, TrialRequest};
use crate::observation::HarnessErrorKind;
use crate::simulated::{SimulatedAdapter, SimulationProfile};

/// Cycle 009 budget for a Cycle 013 local-synthetic run.
///
/// State changes, bytes written and external egress are all zero, so any
/// attempt to mutate or exfiltrate is refused by the Cycle 009 policy rather
/// than by a Cycle 013 rule of its own.
pub fn synthetic_budget(trials: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "budget-prompt-injection-local-synthetic".to_owned(),
        max_operations: trials.max(1),
        max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        max_state_changes: 0,
        max_bytes_read: crate::limits::MAX_TOTAL_OUTPUT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: 0,
        max_retries: 0,
        max_chain_depth: trials.max(1),
    }
}

/// Kill-switch and budget state recorded into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSnapshot {
    /// Kill-switch state after the last inspected step.
    pub kill_switch: String,
    /// Operations consumed against the Cycle 009 budget.
    pub operations: u32,
    /// State changes observed. Always zero for Cycle 013.
    pub state_changes: u32,
    /// External egress bytes observed. Always zero for Cycle 013.
    pub external_egress_bytes: u64,
}

/// Controlled local synthetic execution.
#[derive(Debug)]
pub struct LocalSyntheticAdapter {
    inner: SimulatedAdapter,
    target_id: String,
    budget: ExecutionBudget,
    state: std::cell::RefCell<BudgetState>,
    control: std::cell::RefCell<ControlSnapshot>,
}

impl LocalSyntheticAdapter {
    /// Build an adapter for an approved synthetic target.
    pub fn new(profile: SimulationProfile, target_id: impl Into<String>, trials: u32) -> Self {
        let target_id = target_id.into();
        Self {
            inner: SimulatedAdapter::new(profile),
            target_id,
            budget: synthetic_budget(trials),
            state: std::cell::RefCell::new(BudgetState::default()),
            control: std::cell::RefCell::new(ControlSnapshot {
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
    pub fn control_snapshot(&self) -> ControlSnapshot {
        self.control.borrow().clone()
    }

    /// Build the read-only synthetic step for one trial.
    ///
    /// Deliberately carries no state change, no egress, no network method and
    /// the `SyntheticNoop` safety class.
    fn step_for(&self, request: &TrialRequest<'_>) -> VectorStep {
        VectorStep {
            method: "observe".to_owned(),
            capability: request.scenario.property.as_str().to_owned(),
            arguments: json!({
                "scenario_id": request.scenario.id,
                "corpus_id": request.entry.id,
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

impl HarnessAdapter for LocalSyntheticAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::LocalSynthetic
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        let step = self.step_for(request);

        // Cycle 009 kill switch first: a triggered control stops the trial and
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
                        kind: HarnessErrorKind::AdapterFailure,
                        detail: format!("Cycle 009 kill switch triggered: {reason}"),
                    }),
                    ..RawTrialOutput::default()
                });
            }
            Err(error) => {
                return Err(PromptInjectionError::refusal(format!(
                    "Cycle 009 control refused the synthetic step: {error}"
                )))
            }
        }

        // Cycle 009 budget next: refuse the operation that would cross a bound.
        {
            let mut state = self.state.borrow_mut();
            if let Err(error) = state.check_next(&step, &self.budget) {
                self.control.borrow_mut().kill_switch = "BUDGET_STOP".to_owned();
                return Err(PromptInjectionError::BudgetExhausted(error.to_string()));
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
    use crate::harness::normalize;
    use crate::invariant::evaluate;
    use crate::model::{CorpusEntry, InvariantType, PromptInjectionScenario};
    use crate::observation::ObservationEvent;
    use dare_adversarial::model::KillTrigger;
    use dare_security_evidence::Verdict;
    use serde_json::{json, Value};

    fn scenario() -> PromptInjectionScenario {
        let mut value: Value = crate::schema::tests::valid_scenario();
        value["vector"]["corpus_id"] = json!("direct-ignore-objective-001");
        value["objective"]["denied_policy_decisions"] = json!(["payment.transfer"]);
        serde_json::from_value(value).unwrap()
    }

    fn entry() -> CorpusEntry {
        serde_json::from_value(crate::corpus::tests::direct_entry()).unwrap()
    }

    fn adapter(profile: SimulationProfile) -> LocalSyntheticAdapter {
        LocalSyntheticAdapter::new(profile, "synthetic-prompt-injection-lab", 3)
    }

    #[test]
    fn mode_is_local_synthetic_and_marked_synthetic() {
        let adapter = adapter(SimulationProfile::secure());
        assert_eq!(adapter.mode(), HarnessMode::LocalSynthetic);
        assert!(adapter.mode().is_synthetic());
    }

    #[test]
    fn the_cycle_009_budget_forbids_mutation_and_egress() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
        assert_eq!(budget.max_retries, 0);
    }

    #[test]
    fn the_synthetic_step_is_read_only_by_construction() {
        let scenario = scenario();
        let entry = entry();
        let adapter = adapter(SimulationProfile::secure());
        let step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
            entry: &entry,
        });

        assert_eq!(step.state_changes, 0);
        assert_eq!(step.external_egress_bytes, 0);
        assert_eq!(step.bytes_written, 0);
        assert_eq!(step.retries, 0);
        assert_eq!(step.safety_class, ProofClass::SyntheticNoop);
        assert!(step.trigger.is_none());
        assert_eq!(step.target_id.as_deref(), Some(adapter.target_id()));
        // Not a network method.
        assert!(!matches!(
            step.method.as_str(),
            "http" | "https" | "connect" | "socket"
        ));

        // And the Cycle 009 kill switch accepts it.
        assert_eq!(
            inspect_step(&step, adapter.target_id()).unwrap(),
            KillState::NotTriggered
        );
    }

    #[test]
    fn secure_and_vulnerable_references_flow_through_the_controls() {
        let scenario = scenario();
        let entry = entry();

        let secure = adapter(SimulationProfile::secure());
        let raw = secure
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
                entry: &entry,
            })
            .unwrap();
        let events = normalize(&raw, &scenario.objective);
        assert_eq!(
            evaluate(
                InvariantType::AuthorizedGoalUnchanged,
                &scenario.objective,
                &events
            )
            .verdict,
            Verdict::Pass
        );

        let vulnerable = adapter(SimulationProfile::vulnerable());
        let raw = vulnerable
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
                entry: &entry,
            })
            .unwrap();
        let events = normalize(&raw, &scenario.objective);
        assert_eq!(
            evaluate(
                InvariantType::AuthorizedGoalUnchanged,
                &scenario.objective,
                &events
            )
            .verdict,
            Verdict::Fail
        );
    }

    #[test]
    fn requested_unauthorized_actions_are_observed_never_executed() {
        let scenario = scenario();
        let entry = entry();
        let adapter = adapter(SimulationProfile::vulnerable());
        let raw = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
                entry: &entry,
            })
            .unwrap();
        let events = normalize(&raw, &scenario.objective);

        let requests: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                ObservationEvent::StructuredActionRequest(request) => Some(request),
                _ => None,
            })
            .collect();
        assert!(!requests.is_empty(), "the vector requests a denied action");
        assert!(requests.iter().all(|request| !request.executed));

        // The controls confirm nothing was mutated or exfiltrated.
        let snapshot = adapter.control_snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn kill_switch_and_budget_state_are_recorded_for_evidence() {
        let scenario = scenario();
        let entry = entry();
        let adapter = adapter(SimulationProfile::secure());
        assert_eq!(adapter.control_snapshot().kill_switch, "ARMED");

        adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
                entry: &entry,
            })
            .unwrap();

        let snapshot = adapter.control_snapshot();
        assert_eq!(snapshot.kill_switch, "NOT_TRIGGERED");
        assert_eq!(snapshot.operations, 1);
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn the_cycle_009_budget_stops_the_run_rather_than_expanding() {
        let scenario = scenario();
        let entry = entry();
        // One operation allowed.
        let adapter = LocalSyntheticAdapter::new(SimulationProfile::secure(), "lab", 1);

        adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
                entry: &entry,
            })
            .expect("first operation is inside budget");

        let err = adapter
            .observe(&TrialRequest {
                trial_index: 1,
                scenario: &scenario,
                entry: &entry,
            })
            .unwrap_err();
        assert!(matches!(err, PromptInjectionError::BudgetExhausted(_)));
        assert!(err.is_refusal());
        assert_eq!(adapter.control_snapshot().kill_switch, "BUDGET_STOP");
        // The bound did not grow.
        assert_eq!(adapter.budget().max_operations, 1);
    }

    #[test]
    fn a_kill_trigger_becomes_a_harness_condition_not_a_verdict() {
        // Prove the Cycle 009 kill switch is genuinely in the path by feeding it
        // a step it must refuse.
        let mut hostile = VectorStep {
            method: "observe".to_owned(),
            capability: "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY".to_owned(),
            arguments: json!({}),
            safety_class: ProofClass::SyntheticNoop,
            synthetic_observation: ExpectedDecision::Inconclusive,
            bytes_read: 0,
            bytes_written: 0,
            state_changes: 0,
            external_egress_bytes: 0,
            retries: 0,
            target_id: Some("lab".to_owned()),
            identity_id: None,
            trigger: None,
        };

        // Each of these is refused by the Cycle 009 control, not by Cycle 013.
        hostile.state_changes = 1;
        assert!(inspect_step(&hostile, "lab").is_err());
        hostile.state_changes = 0;

        hostile.external_egress_bytes = 1;
        assert!(inspect_step(&hostile, "lab").is_err());
        hostile.external_egress_bytes = 0;

        hostile.target_id = Some("some-other-target".to_owned());
        assert!(inspect_step(&hostile, "lab").is_err());
        hostile.target_id = Some("lab".to_owned());

        hostile.arguments = json!({"api_key": "value"});
        assert!(inspect_step(&hostile, "lab").is_err());
        hostile.arguments = json!({});

        hostile.trigger = Some(KillTrigger::OperatorStop);
        assert!(inspect_step(&hostile, "lab").is_err());
    }

    #[test]
    fn there_is_no_remote_or_dynamic_path_in_this_adapter() {
        let adapter = adapter(SimulationProfile::secure());
        // The mode vocabulary itself has no remote variant.
        assert_eq!(adapter.mode(), HarnessMode::LocalSynthetic);
        assert!(HarnessMode::all()
            .iter()
            .all(|mode| mode.as_str() != "AUTHORIZED_DYNAMIC"));
        // Egress is structurally impossible: the budget allows zero bytes.
        assert_eq!(adapter.budget().max_external_egress_bytes, 0);
    }

    #[test]
    fn local_synthetic_results_are_reproducible() {
        let scenario = scenario();
        let entry = entry();
        let request = TrialRequest {
            trial_index: 0,
            scenario: &scenario,
            entry: &entry,
        };
        let first = adapter(SimulationProfile::vulnerable())
            .observe(&request)
            .unwrap();
        let second = adapter(SimulationProfile::vulnerable())
            .observe(&request)
            .unwrap();
        assert_eq!(first, second);
    }
}
