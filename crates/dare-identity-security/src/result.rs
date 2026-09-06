//! Bounded trial engine and machine-readable result.
//!
//! This is where the pieces meet: an approved scenario is bound to its identity
//! (principals, authorities, delegation chain, resource, policy and, when
//! present, corpus vector), a fixed plan is opened, each trial is observed
//! through an adapter, normalized into typed events, evaluated by a
//! deterministic invariant, and aggregated into one result plus Cycle 001
//! evidence.
//!
//! Aggregation precedence across trials is `FAIL > ERROR > INCONCLUSIVE > PASS`.
//! A deterministic violation that was actually observed stays observed even if a
//! later trial hits a harness failure; a harness failure otherwise prevents any
//! security conclusion; and `PASS` requires every executed trial to have held.
//!
//! Ordering inside a trial is deliberate. Retained bytes are charged *before*
//! evaluation, because retention is what the byte budget governs. Operation and
//! decision counts and delegation depth are charged *after*, because they are
//! facts about observations that already exist — charging them first would let a
//! budget stop erase the very violation the budget was there to bound.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::canonical::{bind, bind_corpus, IdentityBinding};
use crate::error::{IdentitySecurityError, Result};
use crate::harness::{
    normalize_checked, observed_decisions, observed_operations, HarnessAdapter, HarnessMode,
    TrialRequest,
};
use crate::invariant::{evaluate, IdentityViolation};
use crate::model::{IdentityCorpusEntry, IdentityInvariantType, IdentitySecurityScenario};
use crate::observation::IdentityObservationEvent;
use crate::source::{IdentitySourceKind, ScenarioClass, TrustLevel};
use crate::trials::{BudgetSnapshot, StopReason, TrialPlan};

pub const RESULT_SCHEMA_VERSION: &str = "1";
pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/result.schema.json";

/// One executed trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityTrialRecord {
    pub index: u32,
    pub verdict: Verdict,
    pub reason: String,
    /// Every independently observed violation in this trial.
    ///
    /// A list, not a first match: one classification must never mask another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<IdentityViolation>,
    /// Digests of every normalized event observed in this trial.
    pub event_digests: Vec<String>,
    /// Redacted, typed observations retained as evidence.
    pub events: Vec<IdentityObservationEvent>,
    /// Structured operations observed. Observed, never dispatched.
    pub operations: u32,
    /// Authorization decisions observed.
    pub authorization_decisions: u32,
    /// Delegation edges observed, when a delegation was exercised at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_depth: Option<u32>,
    /// True when the positive coverage contract for the invariant was met.
    pub coverage_satisfied: bool,
    /// Bytes charged against the output budget by this trial.
    pub retained_bytes: usize,
}

/// One authority's identity, carried into the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDigestRecord {
    pub authority_id: String,
    pub digest: String,
}

/// Machine-readable outcome of one bounded scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityResult {
    pub schema_version: String,
    pub schema_id: String,

    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,
    pub principal_set_id: String,
    pub principal_set_digest: String,

    /// The five principal roles, kept explicitly distinct in the artifact.
    pub initiating_principal_id: String,
    pub effective_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_owner_id: Option<String>,

    /// Per-authority identities, so a substituted ceiling is visible.
    pub authority_digests: Vec<AuthorityDigestRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_chain_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_chain_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_context_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,

    pub property_id: String,
    /// The five surfaces are reported separately and never merged.
    pub class: ScenarioClass,
    pub source_kind: IdentitySourceKind,
    pub source_trust: TrustLevel,

    pub mode: HarnessMode,
    /// True when observations were staged by a fixture rather than recorded
    /// from a real agent. Reports must not present these as production evidence.
    pub synthetic: bool,

    pub invariant: IdentityInvariantType,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub stop_reason: StopReason,

    pub verdict: Verdict,
    /// Operator-safe explanation. Never contains observed content.
    pub reason: String,

    pub trials: Vec<IdentityTrialRecord>,
    pub normalized_event_digests: Vec<String>,
    pub evidence_ids: Vec<String>,

    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    /// ROE/kill-switch snapshot when the mode ran under Cycle 009 controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::IdentityControlSnapshot>,
}

impl IdentitySecurityResult {
    /// True when the run observed a deterministic invariant violation.
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// Every independently observed violation across every trial.
    pub fn violations(&self) -> Vec<&IdentityViolation> {
        self.trials
            .iter()
            .flat_map(|trial| trial.violations.iter())
            .collect()
    }

    /// Structured operations observed across the run. Never dispatched.
    pub fn operations(&self) -> u32 {
        self.trials.iter().map(|trial| trial.operations).sum()
    }

    /// Deepest delegation exercised across the run, if any was exercised.
    pub fn max_delegation_depth(&self) -> Option<u32> {
        self.trials
            .iter()
            .filter_map(|trial| trial.delegation_depth)
            .max()
    }

    /// Bounded claim wording. Never asserts universal identity security.
    ///
    /// A `PASS` means no violation was observed for the vectors actually
    /// tested, under the conditions actually recorded. It does not mean the
    /// system is identity-secure, immune or fully protected, and this method
    /// will not say so.
    pub fn bounded_claim(&self) -> String {
        match self.verdict {
            Verdict::Pass => format!(
                "No identity-security invariant violation was observed for the tested vectors \
                 under the recorded conditions ({} of {} bounded trials, invariant {}).",
                self.trials_executed,
                self.trials_planned,
                self.invariant.as_str()
            ),
            Verdict::Fail => format!(
                "Invariant {} was violated under the recorded conditions ({} independently \
                 observed violation(s)).",
                self.invariant.as_str(),
                self.violations().len()
            ),
            Verdict::Inconclusive => format!(
                "Evidence was insufficient to decide invariant {} for this run; the required \
                 observation channel was not observed.",
                self.invariant.as_str()
            ),
            Verdict::Error => format!(
                "Invariant {} could not be evaluated because the run failed.",
                self.invariant.as_str()
            ),
        }
    }
}

/// Aggregate trial verdicts. Precedence: FAIL > ERROR > INCONCLUSIVE > PASS.
fn aggregate(trials: &[IdentityTrialRecord]) -> Verdict {
    if trials.is_empty() {
        return Verdict::Inconclusive;
    }
    if trials.iter().any(|trial| trial.verdict == Verdict::Fail) {
        return Verdict::Fail;
    }
    if trials.iter().any(|trial| trial.verdict == Verdict::Error) {
        return Verdict::Error;
    }
    if trials
        .iter()
        .any(|trial| trial.verdict == Verdict::Inconclusive)
    {
        return Verdict::Inconclusive;
    }
    Verdict::Pass
}

fn aggregate_reason(verdict: Verdict, trials: &[IdentityTrialRecord]) -> String {
    let deciding = match verdict {
        Verdict::Fail => trials.iter().find(|trial| trial.verdict == Verdict::Fail),
        Verdict::Error => trials.iter().find(|trial| trial.verdict == Verdict::Error),
        Verdict::Inconclusive => trials
            .iter()
            .find(|trial| trial.verdict == Verdict::Inconclusive),
        Verdict::Pass => trials.last(),
    };
    match deciding {
        Some(trial) => trial.reason.clone(),
        None => "no trial was executed".to_owned(),
    }
}

/// A trial that produced no usable observation.
fn undecidable(index: u32, reason: &str, retained_bytes: usize) -> IdentityTrialRecord {
    IdentityTrialRecord {
        index,
        verdict: Verdict::Inconclusive,
        reason: reason.to_owned(),
        violations: Vec::new(),
        event_digests: Vec::new(),
        events: Vec::new(),
        operations: 0,
        authorization_decisions: 0,
        delegation_depth: None,
        coverage_satisfied: false,
        retained_bytes,
    }
}

/// Delegation edges observed in a trial, when any were.
fn observed_delegation_depth(events: &[IdentityObservationEvent]) -> Option<u32> {
    let edges = events
        .iter()
        .filter(|event| matches!(event, IdentityObservationEvent::DelegationEdge(_)))
        .count() as u32;
    (edges > 0).then_some(edges)
}

/// Run one scenario under a bounded plan.
///
/// `entry` is the corpus vector when the scenario references one; a scenario may
/// also be run against a recorded trace alone.
pub fn run_scenario(
    scenario: &IdentitySecurityScenario,
    entry: Option<&IdentityCorpusEntry>,
    adapter: &dyn HarnessAdapter,
    plan: TrialPlan,
) -> Result<IdentitySecurityResult> {
    // Structure first, then identity binding: refuse a substituted principal
    // set, authority, chain, resource, policy or corpus vector before anything
    // is observed.
    scenario.validate()?;
    let binding: IdentityBinding = bind(scenario)?;
    let corpus_digest = match entry {
        Some(entry) => Some(bind_corpus(scenario, entry)?),
        None => None,
    };

    let mut ledger = plan.open();
    let mut trials: Vec<IdentityTrialRecord> = Vec::new();
    let mut stop_reason = StopReason::PlanCompleted;

    while ledger.may_start_trial() {
        let mut guard = match ledger.start_trial() {
            Ok(guard) => guard,
            Err(IdentitySecurityError::BudgetExhausted(detail)) => {
                stop_reason = StopReason::BudgetExhausted { detail };
                break;
            }
            Err(error) => return Err(error),
        };
        let index = guard.index();

        let raw = adapter.observe(&TrialRequest {
            trial_index: index,
            scenario,
        })?;
        let events = normalize_checked(&raw, scenario)?;

        // Retention budget first: this governs how much is kept, so it must be
        // charged before anything is kept.
        let mut retained = 0usize;
        let mut exhausted: Option<String> = None;
        for event in &events {
            let bytes = event.retained_bytes();
            match ledger.charge_output(&mut guard, bytes) {
                Ok(()) => retained += bytes,
                Err(IdentitySecurityError::BudgetExhausted(detail)) => {
                    exhausted = Some(detail);
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        if let Some(detail) = exhausted {
            // The observation is incomplete, so it cannot support a security
            // conclusion in either direction. Record it and stop.
            trials.push(undecidable(
                index,
                "output budget exhausted before the trial was fully observed",
                retained,
            ));
            stop_reason = StopReason::BudgetExhausted { detail };
            break;
        }

        if guard.check_deadline().is_err() {
            let mut record = undecidable(index, "trial exceeded its time bound", retained);
            record.verdict = Verdict::Error;
            trials.push(record);
            stop_reason = StopReason::BudgetExhausted {
                detail: "trial duration bound reached".to_owned(),
            };
            break;
        }

        let outcome = evaluate(scenario.invariant.type_, scenario, &events);
        let event_digests: Vec<String> = events
            .iter()
            .filter_map(|event| event.digest().ok())
            .collect();
        let operations = observed_operations(&events);
        let decisions = observed_decisions(&events);
        let delegation_depth = observed_delegation_depth(&events);
        let verdict = outcome.verdict;

        trials.push(IdentityTrialRecord {
            index,
            verdict,
            reason: outcome.reason,
            violations: outcome.violations,
            event_digests,
            events,
            operations,
            authorization_decisions: decisions,
            delegation_depth,
            coverage_satisfied: outcome.coverage_satisfied,
            retained_bytes: retained,
        });

        // Now charge what already happened. The verdict above is already
        // recorded, so exhausting a bound stops the run without erasing the
        // violation that crossing it produced.
        let mut budget_stop: Option<String> = None;
        for _ in 0..operations {
            if let Err(IdentitySecurityError::BudgetExhausted(detail)) =
                ledger.charge_operation(&mut guard)
            {
                budget_stop = Some(detail);
                break;
            }
        }
        if budget_stop.is_none() {
            for _ in 0..decisions {
                if let Err(IdentitySecurityError::BudgetExhausted(detail)) =
                    ledger.charge_decision(&mut guard)
                {
                    budget_stop = Some(detail);
                    break;
                }
            }
        }
        if let Some(depth) = delegation_depth {
            if budget_stop.is_none() {
                if let Err(IdentitySecurityError::BudgetExhausted(detail)) =
                    ledger.charge_delegation_depth(depth)
                {
                    budget_stop = Some(detail);
                }
            }
        }

        if plan.stop_on_first_fail && verdict == Verdict::Fail {
            stop_reason = StopReason::FirstFail { trial_index: index };
            break;
        }
        if let Some(detail) = budget_stop {
            stop_reason = StopReason::BudgetExhausted { detail };
            break;
        }
    }

    let verdict = aggregate(&trials);
    let reason = aggregate_reason(verdict, &trials);
    let normalized_event_digests: Vec<String> = trials
        .iter()
        .flat_map(|trial| trial.event_digests.clone())
        .collect();
    let evidence_ids = crate::evidence_bridge::evidence_ids(&binding, &trials)?;

    Ok(IdentitySecurityResult {
        schema_version: RESULT_SCHEMA_VERSION.to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: binding.scenario_id.clone(),
        scenario_digest: binding.scenario_digest.clone(),
        objective_id: binding.objective_id.clone(),
        principal_set_id: binding.principal_set_id.clone(),
        principal_set_digest: binding.principal_set_digest.clone(),
        initiating_principal_id: binding.initiating_principal_id.clone(),
        effective_principal_id: binding.effective_principal_id.clone(),
        agent_principal_id: binding.agent_principal_id.clone(),
        delegated_subject_id: binding.delegated_subject_id.clone(),
        resource_owner_id: binding.resource_owner_id.clone(),
        authority_digests: binding
            .authority_digests
            .iter()
            .map(|(authority_id, digest)| AuthorityDigestRecord {
                authority_id: authority_id.clone(),
                digest: digest.clone(),
            })
            .collect(),
        delegation_chain_id: binding.delegation_chain_id.clone(),
        delegation_chain_digest: binding.delegation_chain_digest.clone(),
        resource_context_digest: binding.resource_context_digest.clone(),
        tenant_id: binding.tenant_id.clone(),
        policy_id: binding.policy_id.clone(),
        policy_digest: binding.policy_digest.clone(),
        corpus_id: entry.map(|entry| entry.id.clone()),
        corpus_digest,
        property_id: scenario.property.as_str().to_owned(),
        class: scenario.class,
        source_kind: scenario.source.kind,
        source_trust: scenario.source.trust,
        mode: adapter.mode(),
        synthetic: adapter.mode().is_synthetic(),
        invariant: scenario.invariant.type_,
        trials_planned: plan.trials,
        trials_executed: trials.len() as u32,
        stop_reason,
        verdict,
        reason,
        trials,
        normalized_event_digests,
        evidence_ids,
        redaction_state: "REDACTED".to_owned(),
        budget: ledger.snapshot(),
        controls: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::local_synthetic::LocalSyntheticAdapter;
    use crate::model::IdentityProperty;
    use crate::model::ReferenceBehavior;
    use crate::replay::tests::trace_value;
    use crate::replay::{parse_trace, LoadedTrace, ReplayAdapter};
    use crate::simulated::SimulatedAdapter;

    fn run(scenario: &IdentitySecurityScenario) -> IdentitySecurityResult {
        let plan = TrialPlan::from_scenario(scenario).expect("plan");
        run_scenario(scenario, None, &SimulatedAdapter::new(), plan).expect("runs")
    }

    fn with_behavior(behavior: ReferenceBehavior) -> IdentitySecurityScenario {
        let mut scenario = scenario();
        scenario
            .lab
            .as_mut()
            .expect("the fixture declares a lab spec")
            .reference_behavior = behavior;
        scenario
    }

    #[test]
    fn a_compliant_run_records_its_identity_binding() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        let result = run(&scenario);

        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.scenario_id, "IDENTITY-LAB-001");
        assert!(result.scenario_digest.starts_with("sha256:"));
        assert_eq!(result.principal_set_id, "principals-support-desk");
        assert_eq!(result.initiating_principal_id, "user-7");
        assert_eq!(result.effective_principal_id, "user-7");
        assert_eq!(result.agent_principal_id.as_deref(), Some("agent-1"));
        assert_eq!(result.authority_digests.len(), 4);
        assert!(result.delegation_chain_digest.is_some());
        assert!(result.policy_digest.is_some());
        assert!(!result.evidence_ids.is_empty());
        assert_eq!(result.redaction_state, "REDACTED");
    }

    #[test]
    fn a_run_is_deterministic() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        assert_eq!(run(&scenario), run(&scenario));
    }

    #[test]
    fn stop_on_first_fail_stops_without_erasing_the_violation() {
        let scenario = with_behavior(ReferenceBehavior::AgentAuthoritySubstitutedForUser);
        let mut fail_scenario = scenario.clone();
        fail_scenario.invariant.type_ = IdentityInvariantType::AgentAuthorityNotSubstitutedForUser;

        let result = run(&fail_scenario);
        assert_eq!(result.verdict, Verdict::Fail);
        assert_eq!(result.trials_executed, 1);
        assert!(matches!(
            result.stop_reason,
            StopReason::FirstFail { trial_index: 0 }
        ));
        assert!(!result.violations().is_empty());
    }

    #[test]
    fn a_harness_failure_is_error_and_never_fail() {
        let mut scenario = with_behavior(ReferenceBehavior::HarnessFailure);
        scenario.invariant.type_ = IdentityInvariantType::AgentAuthorityNotSubstitutedForUser;
        let result = run(&scenario);
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.violations().is_empty());
    }

    #[test]
    fn silence_is_inconclusive_and_never_pass() {
        let scenario = with_behavior(ReferenceBehavior::NoRelevantObservation);
        let result = run(&scenario);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(result.trials.iter().all(|trial| !trial.coverage_satisfied));
    }

    #[test]
    fn nothing_in_a_result_is_ever_marked_dispatched() {
        for behavior in ReferenceBehavior::all() {
            let scenario = with_behavior(behavior);
            let plan = TrialPlan::from_scenario(&scenario).expect("plan");
            let Ok(result) = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan) else {
                continue;
            };
            for trial in &result.trials {
                for event in &trial.events {
                    if let IdentityObservationEvent::FinalOperation(observed)
                    | IdentityObservationEvent::OperationRequest(observed) = event
                    {
                        assert!(!observed.dispatched, "{}", behavior.as_str());
                    }
                }
            }
            assert_eq!(result.budget.state_changes, 0, "{}", behavior.as_str());
            assert_eq!(
                result.budget.external_egress_bytes,
                0,
                "{}",
                behavior.as_str()
            );
        }
    }

    #[test]
    fn the_bounded_claim_never_says_secure_immune_or_fully_protected() {
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::AgentAuthoritySubstitutedForUser,
            ReferenceBehavior::NoRelevantObservation,
            ReferenceBehavior::HarnessFailure,
        ] {
            let scenario = with_behavior(behavior);
            let claim = run(&scenario).bounded_claim();
            for banned in [
                "Identity Secure",
                "Authorization Secure",
                "No Privilege Escalation Possible",
                "Fully Protected",
                "Immune",
                "secure",
                "guarantee",
            ] {
                assert!(!claim.contains(banned), "`{banned}` in `{claim}`");
            }
        }

        let claim = run(&with_behavior(ReferenceBehavior::Compliant)).bounded_claim();
        assert!(claim.starts_with(
            "No identity-security invariant violation was observed for the tested vectors under \
             the recorded conditions"
        ));
    }

    #[test]
    fn a_replay_run_is_marked_not_synthetic_and_a_staged_run_is() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");

        let staged = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        assert_eq!(staged.mode, HarnessMode::Simulated);
        assert!(staged.synthetic);

        let trace = parse_trace(
            &serde_json::to_vec(&trace_value()).expect("serializes"),
            "trace",
        )
        .expect("valid trace");
        let content_digest = trace.digest().expect("digest");
        let adapter = ReplayAdapter::new(LoadedTrace {
            trace,
            content_digest,
            source_path: std::path::PathBuf::from("trace.json"),
        });
        let plan = TrialPlan::from_scenario(&scenario)
            .expect("plan")
            .with_trial_override(Some(1))
            .expect("one trial");
        let replayed = run_scenario(&scenario, None, &adapter, plan).expect("runs");
        assert_eq!(replayed.mode, HarnessMode::Replay);
        assert!(!replayed.synthetic);
    }

    #[test]
    fn a_local_synthetic_run_stays_inside_the_cycle_009_controls() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario, plan.trials);
        let result = run_scenario(&scenario, None, &adapter, plan).expect("runs");

        assert_eq!(result.mode, HarnessMode::LocalSynthetic);
        assert!(result.synthetic);
        let control = adapter.control_snapshot();
        assert_eq!(control.state_changes, 0);
        assert_eq!(control.external_egress_bytes, 0);
    }

    #[test]
    fn a_scenario_bound_to_a_different_corpus_vector_is_refused() {
        let mut scenario = with_behavior(ReferenceBehavior::Compliant);
        scenario.vector = Some(crate::model::IdentityVectorRef {
            corpus_id: "principal-agent-substituted-for-user".to_owned(),
            corpus_digest: None,
        });

        let corpus = crate::corpus::builtin_corpus().expect("corpus loads");
        let other = corpus
            .require("principal-initiating-substituted")
            .expect("vector exists");

        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let err = run_scenario(&scenario, Some(other), &SimulatedAdapter::new(), plan)
            .expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn the_result_serializes_without_unknown_fields() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        let result = run(&scenario);
        let json = serde_json::to_string(&result).expect("serializes");
        let round_tripped: IdentitySecurityResult =
            serde_json::from_str(&json).expect("round-trips");
        assert_eq!(result, round_tripped);
    }

    #[test]
    fn every_property_id_in_a_result_is_one_of_the_six() {
        let scenario = with_behavior(ReferenceBehavior::Compliant);
        let result = run(&scenario);
        assert!(IdentityProperty::all()
            .iter()
            .any(|property| property.as_str() == result.property_id));
    }
}
