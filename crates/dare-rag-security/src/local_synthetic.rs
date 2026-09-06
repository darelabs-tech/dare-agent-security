//! Local-synthetic adapter, gated by the Cycle 009 controlled substrate.
//!
//! No second executor is introduced. Observations still come from the Cycle 017
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
//! synthetic one. A document a scenario describes as leaked is *described*,
//! never fetched — the boundary crossing is proven from declarations rather
//! than by touching an index.
//!
//! The step's arguments are identifiers only: scenario, acting principal,
//! tenant, collections, trial index. No document content, no provenance detail
//! and no policy values travel into the control substrate.
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

use crate::error::{RagSecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawHarnessError, RawTrialOutput, TrialRequest};
use crate::model::RagSecurityScenario;
use crate::observation::HarnessErrorKind;
use crate::simulated::SimulatedAdapter;

/// Cycle 009 budget for a Cycle 017 local-synthetic run.
///
/// State changes, bytes written and external egress are all zero, so an attempt
/// to write to an index or exfiltrate a document is refused by the Cycle 009
/// policy rather than by a Cycle 017 rule of its own.
pub fn synthetic_budget(trials: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "budget-rag-security-local-synthetic".to_owned(),
        max_operations: trials.max(1),
        max_duration_seconds: crate::limits::MAX_DURATION_SECONDS_PER_TRIAL,
        max_state_changes: crate::limits::MAX_STATE_CHANGES,
        max_bytes_read: crate::limits::MAX_TOTAL_OUTPUT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: crate::limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: crate::limits::HARD_MAX_QUERIES_PER_TRIAL,
    }
}

/// Kill-switch and budget state recorded into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagControlSnapshot {
    /// Kill-switch state after the last inspected step.
    pub kill_switch: String,
    /// Operations consumed against the Cycle 009 budget.
    pub operations: u32,
    /// State changes observed. Always zero for Cycle 017.
    pub state_changes: u32,
    /// External egress bytes observed. Always zero for Cycle 017.
    pub external_egress_bytes: u64,
}

/// Controlled local synthetic execution.
#[derive(Debug)]
pub struct LocalSyntheticAdapter {
    inner: SimulatedAdapter,
    target_id: String,
    budget: ExecutionBudget,
    state: RefCell<BudgetState>,
    control: RefCell<RagControlSnapshot>,
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
            control: RefCell::new(RagControlSnapshot {
                kill_switch: "ARMED".to_owned(),
                operations: 0,
                state_changes: 0,
                external_egress_bytes: 0,
            }),
        }
    }

    /// Build an adapter approved for exactly this scenario.
    pub fn for_scenario(scenario: &RagSecurityScenario, trials: u32) -> Self {
        Self::new(scenario.id.clone(), trials)
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn budget(&self) -> &ExecutionBudget {
        &self.budget
    }

    /// Current kill-switch and budget state, for evidence.
    pub fn control_snapshot(&self) -> RagControlSnapshot {
        self.control.borrow().clone()
    }

    /// Build the read-only synthetic step for one trial.
    fn step_for(&self, request: &TrialRequest<'_>) -> VectorStep {
        let context = &request.scenario.context;
        VectorStep {
            method: "observe".to_owned(),
            capability: request.scenario.property.as_str().to_owned(),
            arguments: json!({
                "scenario_id": request.scenario.id,
                "trial_index": request.trial_index,
                "acting_principal_id": context.acting_principal_id,
                "tenant_id": context.tenant_id,
                "collection_ids": context.collection_ids,
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
                return Err(RagSecurityError::refusal(format!(
                    "Cycle 009 control refused the synthetic step: {error}"
                )))
            }
        }

        // Cycle 009 budget next: refuse the operation that would cross a bound.
        {
            let mut state = self.state.borrow_mut();
            if let Err(error) = state.check_next(&step, &self.budget) {
                self.control.borrow_mut().kill_switch = "BUDGET_STOP".to_owned();
                return Err(RagSecurityError::BudgetExhausted(error.to_string()));
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
    use crate::harness::tests::scenario;

    fn adapter(scenario: &RagSecurityScenario) -> LocalSyntheticAdapter {
        LocalSyntheticAdapter::for_scenario(scenario, crate::limits::HARD_MAX_TRIALS)
    }

    #[test]
    fn the_synthetic_step_is_read_only_by_construction() {
        // Not a runtime check: a step that could change state or send bytes
        // would have to be built differently, and there is no code path here
        // that builds one.
        let scenario = scenario();
        let adapter = adapter(&scenario);
        let step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        });

        assert_eq!(step.state_changes, 0);
        assert_eq!(step.bytes_written, 0);
        assert_eq!(step.external_egress_bytes, 0);
        assert_eq!(step.retries, 0);
        assert_eq!(step.safety_class, ProofClass::SyntheticNoop);
        assert_eq!(step.method, "observe");
    }

    #[test]
    fn the_step_carries_identifiers_and_never_document_content() {
        let scenario = scenario();
        let adapter = adapter(&scenario);
        let step = adapter.step_for(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        });
        let arguments = step.arguments.to_string();

        for identifier in ["scenario_id", "acting_principal_id", "tenant_id"] {
            assert!(arguments.contains(identifier), "{identifier} is missing");
        }
        // No excerpt, digest, classification or policy value travels into the
        // control substrate.
        for leaked in [
            "content_excerpt",
            "content_digest",
            "classification",
            "sha256:",
        ] {
            assert!(!arguments.contains(leaked), "{leaked} reached the control");
        }
    }

    #[test]
    fn the_budget_pins_state_changes_and_egress_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_bytes_written, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_retries, 0);
    }

    #[test]
    fn an_approved_run_observes_normally() {
        let scenario = scenario();
        let adapter = adapter(&scenario);
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");
        assert!(!output.result_sets.is_empty());
        assert!(output.harness_error.is_none());

        let control = adapter.control_snapshot();
        assert_eq!(control.kill_switch, "NOT_TRIGGERED");
        assert_eq!(control.state_changes, 0);
        assert_eq!(control.external_egress_bytes, 0);
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_trips_the_kill_switch() {
        // The substitution the Cycle 009 control exists to catch: the adapter
        // holds the approved target, the step names what is actually being
        // observed, and the control compares them.
        let approved = scenario();
        let adapter = adapter(&approved);

        let mut other = scenario();
        other.id = "RAG-LAB-SOMETHING-ELSE".to_owned();

        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &other,
            })
            .expect("returns a harness outcome rather than an error");

        let error = output.harness_error.expect("the control fired");
        assert_eq!(error.kind, HarnessErrorKind::KillSwitchTriggered);
        assert_eq!(adapter.control_snapshot().kill_switch, "TRIGGERED");
        // And it produced no observations at all.
        assert!(output.result_sets.is_empty());
    }

    #[test]
    fn a_triggered_control_is_a_harness_outcome_and_never_a_verdict() {
        let approved = scenario();
        let adapter = adapter(&approved);
        let mut other = scenario();
        other.id = "RAG-LAB-ELSEWHERE".to_owned();

        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &other,
            })
            .expect("harness outcome");
        let events = crate::harness::normalize_checked(&output, &other).expect("normalizes");

        // Every invariant reads this as ERROR, never as a finding.
        for invariant in crate::model::RagInvariantType::all() {
            let outcome = crate::invariant::evaluate(invariant, &other, &events);
            assert_eq!(outcome.verdict, dare_security_evidence::Verdict::Error);
            assert!(outcome.violations.is_empty());
        }
    }

    #[test]
    fn exhausting_the_budget_stops_the_run_rather_than_failing_it() {
        let scenario = scenario();
        // One operation only.
        let adapter = LocalSyntheticAdapter::new(scenario.id.clone(), 1);

        adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("first observation fits");

        let err = adapter
            .observe(&TrialRequest {
                trial_index: 1,
                scenario: &scenario,
            })
            .expect_err("the second is refused");
        assert!(matches!(err, RagSecurityError::BudgetExhausted(_)));
        assert_eq!(adapter.control_snapshot().kill_switch, "BUDGET_STOP");
    }

    #[test]
    fn a_leaked_document_is_described_and_never_fetched() {
        // The scenario describes a cross-tenant disclosure. Running it under
        // the controls produces observations and zero state change, zero
        // egress: the crossing is proven from declarations.
        let mut scenario = scenario();
        scenario.lab.as_mut().expect("lab").reference_behavior =
            crate::model::ReferenceBehavior::CrossTenantResult;

        let adapter = adapter(&scenario);
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");

        let control = adapter.control_snapshot();
        assert_eq!(control.state_changes, 0);
        assert_eq!(control.external_egress_bytes, 0);

        let serialized = serde_json::to_string(&output).expect("serializes");
        for marker in ["http://", "https://", "redis://", "pinecone", "qdrant"] {
            assert!(!serialized.contains(marker));
        }
    }
}
