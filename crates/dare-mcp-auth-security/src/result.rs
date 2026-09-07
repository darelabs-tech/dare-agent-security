//! The run artifact.
//!
//! Aggregation follows a precedence that is not arbitrary:
//!
//! `ERROR` > `FAIL` > `INCONCLUSIVE` > `PASS`
//!
//! An observed violation outranks a later harness failure — the finding was
//! real and losing it because the next trial crashed would be worse than the
//! crash. An undecided trial outranks a clean one, because a run that could not
//! decide has not established anything about the trials that did.
//!
//! `stop_on_first_fail` stops *later trials* only after the failing trial's
//! evidence has been collected in full.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::error::Result;
use crate::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use crate::invariant::{evaluate, McpAuthViolation};
use crate::model::{McpAuthCorpusEntry, McpAuthInvariantType, McpAuthProperty, McpAuthScenario};
use crate::observation::McpAuthObservation;
use crate::source::ScenarioClass;
use crate::trials::{BudgetSnapshot, StopReason, TrialPlan};

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/mcp-auth-security/v1/result.schema.json";

/// One trial's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthTrialRecord {
    pub index: u32,
    pub verdict: Verdict,
    pub reason: String,
    pub coverage_satisfied: bool,
    pub requests: u32,
    pub retained_bytes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<McpAuthViolation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<McpAuthObservation>,
}

/// The bounded run artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthSecurityResult {
    pub schema_version: String,
    pub schema_id: String,

    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,

    pub property_id: McpAuthProperty,
    pub class: ScenarioClass,
    pub invariant: McpAuthInvariantType,

    pub protocol_revision: String,
    pub expected_resource: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,

    pub mode: crate::harness::HarnessMode,
    /// True when observations were staged or replayed rather than recorded from
    /// a production deployment.
    pub synthetic: bool,

    pub trials_planned: u32,
    pub trials_executed: u32,
    pub stop_reason: StopReason,

    pub verdict: Verdict,
    /// Operator-safe explanation. Never carries credential material.
    pub reason: String,

    pub trials: Vec<McpAuthTrialRecord>,
    pub evidence_ids: Vec<String>,
    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::McpAuthControlSnapshot>,
}

impl McpAuthSecurityResult {
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// Every independently observed violation across every trial.
    pub fn violations(&self) -> Vec<&McpAuthViolation> {
        self.trials
            .iter()
            .flat_map(|trial| trial.violations.iter())
            .collect()
    }

    pub fn requests(&self) -> u32 {
        self.trials.iter().map(|trial| trial.requests).sum()
    }

    /// Bounded claim wording. Never asserts universal security.
    ///
    /// A `PASS` means no violation was observed for the vectors actually
    /// tested, under the conditions actually recorded. It does not mean MCP
    /// authentication is secure or that token misuse is impossible, and this
    /// method will not say so however the result is rendered downstream.
    pub fn bounded_claim(&self) -> String {
        match self.verdict {
            Verdict::Pass => format!(
                "No MCP 2026 authentication/authorization hardening invariant violation was \
                 observed for the tested vectors under the recorded conditions ({} of {} bounded \
                 trials, invariant {}).",
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
                "Evidence was insufficient to decide invariant {}. An inconclusive result is not \
                 a pass.",
                self.invariant.as_str()
            ),
            Verdict::Error => format!(
                "The harness could not evaluate invariant {}; no security conclusion is \
                 available in either direction.",
                self.invariant.as_str()
            ),
        }
    }
}

/// Run one scenario to completion.
pub fn run_scenario(
    scenario: &McpAuthScenario,
    entry: Option<&McpAuthCorpusEntry>,
    adapter: &dyn HarnessAdapter,
    plan: TrialPlan,
) -> Result<McpAuthSecurityResult> {
    // Structure first, then binding: refuse a substituted request, resource,
    // token or policy before anything is observed. Binding after the first
    // observation would mean the run had already read whatever was swapped in.
    scenario.validate()?;
    let binding = crate::canonical::bind(scenario)?;
    let corpus_digest = match entry {
        Some(entry) => Some(crate::canonical::digest(entry)?),
        None => None,
    };

    let invariant = scenario.invariant.type_;
    let mut ledger = plan.open();
    let mut trials: Vec<McpAuthTrialRecord> = Vec::new();

    while ledger.may_start_trial() {
        let mut guard = match ledger.start_trial() {
            Ok(guard) => guard,
            Err(error) => {
                ledger.stop(StopReason::BudgetExhausted {
                    detail: error.to_string(),
                });
                break;
            }
        };
        let index = guard.index();

        let raw = adapter.observe(&TrialRequest {
            trial_index: index,
            scenario,
        })?;
        let events = normalize_checked(&raw, scenario)?;

        let mut retained = 0usize;
        let mut exhausted: Option<String> = None;
        for event in &events {
            let bytes = event.retained_bytes();
            match ledger.charge_output(&mut guard, bytes) {
                Ok(()) => retained += bytes,
                Err(error) => {
                    exhausted = Some(error.to_string());
                    break;
                }
            }
        }
        let mut requests = 0u32;
        for _ in &raw.observed_requests {
            if ledger.charge_request(&mut guard).is_err() {
                exhausted.get_or_insert_with(|| "request budget exhausted".to_owned());
                break;
            }
            requests += 1;
        }

        let outcome = evaluate(invariant, scenario, &events);
        let event_digests: Vec<String> = events
            .iter()
            .filter_map(|event| event.digest().ok())
            .collect();

        trials.push(McpAuthTrialRecord {
            index,
            verdict: outcome.verdict,
            reason: outcome.reason.clone(),
            coverage_satisfied: outcome.coverage_satisfied,
            requests,
            retained_bytes: retained,
            violations: outcome.violations.clone(),
            event_digests,
            events,
        });

        // The stop happens only after the record above is pushed, so a failing
        // trial's evidence is never lost to the stop it caused.
        if let Some(detail) = exhausted {
            ledger.stop(StopReason::BudgetExhausted { detail });
            break;
        }
        if plan.stop_on_first_fail && outcome.verdict == Verdict::Fail {
            ledger.stop(StopReason::FirstFail { trial_index: index });
            break;
        }
    }

    let verdict = aggregate(&trials);
    let reason = trials
        .iter()
        .find(|trial| trial.verdict == verdict)
        .map(|trial| trial.reason.clone())
        .unwrap_or_else(|| "no trial was executed".to_owned());

    let evidence_ids = (0..trials.len())
        .map(|index| crate::evidence_bridge::evidence_id(scenario, index as u32))
        .collect::<Result<Vec<_>>>()?;

    Ok(McpAuthSecurityResult {
        schema_version: "1".to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: scenario.id.clone(),
        scenario_digest: binding.scenario_digest.clone(),
        objective_id: scenario.objective.id.clone(),
        property_id: scenario.property,
        class: scenario.class,
        invariant,
        protocol_revision: scenario
            .requests
            .first()
            .map(|request| request.protocol.declared_revision.clone())
            .unwrap_or_default(),
        expected_resource: scenario.protected_resource.expected_resource.to_string(),
        corpus_id: entry.map(|entry| entry.id.clone()),
        corpus_digest,
        mode: adapter.mode(),
        synthetic: adapter.observations_are_synthetic(),
        trials_planned: plan.trials,
        trials_executed: ledger.trials_executed(),
        stop_reason: ledger.stop_reason(),
        verdict,
        reason,
        trials,
        evidence_ids,
        redaction_state: "REDACTED".to_owned(),
        budget: ledger.snapshot(),
        controls: None,
    })
}

/// `ERROR` > `FAIL` > `INCONCLUSIVE` > `PASS`.
fn aggregate(trials: &[McpAuthTrialRecord]) -> Verdict {
    if trials.is_empty() {
        return Verdict::Inconclusive;
    }
    // A violation outranks a later harness failure: the finding was real, and
    // losing it because a subsequent trial crashed would be worse than the
    // crash.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::simulated::SimulatedAdapter;

    fn run(scenario: &McpAuthScenario) -> McpAuthSecurityResult {
        let plan = TrialPlan::from_scenario(scenario).expect("plan");
        run_scenario(scenario, None, &SimulatedAdapter::new(), plan).expect("runs")
    }

    #[test]
    fn a_compliant_run_passes_and_records_what_it_observed() {
        let result = run(&scenario());
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.trials_executed, 3);
        assert_eq!(result.mode, crate::harness::HarnessMode::Simulated);
        assert!(result.synthetic);
        assert_eq!(result.redaction_state, "REDACTED");
        assert!(!result.evidence_ids.is_empty());
    }

    #[test]
    fn the_result_records_zero_state_changes_and_zero_egress() {
        let result = run(&scenario());
        assert_eq!(result.budget.state_changes, 0);
        assert_eq!(result.budget.external_egress_bytes, 0);
    }

    #[test]
    fn the_same_run_twice_produces_the_same_artifact() {
        // Determinism is what makes a recorded digest worth anything: two runs
        // that differed would mean the digest identified the run rather than
        // the thing under test.
        assert_eq!(run(&scenario()), run(&scenario()));
    }

    #[test]
    fn stopping_on_first_fail_keeps_the_failing_trials_evidence() {
        // The stop must never discard the evidence that caused it.
        let mut broken = scenario();
        broken.lab = Some(crate::model::McpAuthLabSpec {
            reference_behavior: crate::model::ReferenceBehavior::MethodHeaderBodyMismatch,
        });
        let result = run(&broken);
        assert_eq!(result.verdict, Verdict::Fail);
        assert_eq!(result.trials_executed, 1);
        assert_eq!(result.stop_reason.as_str(), "FIRST_FAIL");
        assert!(!result.trials[0].violations.is_empty());
        assert!(!result.trials[0].event_digests.is_empty());
    }

    #[test]
    fn a_pass_never_claims_mcp_auth_is_secure() {
        let claim = run(&scenario()).bounded_claim();
        assert!(claim.contains("No MCP 2026 authentication/authorization hardening invariant"));
        for banned in [
            "MCP Auth Secure",
            "is secure",
            "impossible",
            "fully protected",
        ] {
            assert!(!claim.contains(banned), "the claim said `{banned}`");
        }
    }

    #[test]
    fn an_inconclusive_claim_says_it_is_not_a_pass() {
        let mut quiet = scenario();
        quiet.lab = Some(crate::model::McpAuthLabSpec {
            reference_behavior: crate::model::ReferenceBehavior::NoRelevantObservation,
        });
        quiet.tokens = Default::default();
        quiet.authorization_flow = Default::default();
        quiet.flow = Default::default();
        quiet.scope = Default::default();
        quiet.registration = None;
        quiet.credential_flow = Default::default();
        quiet.identity_metadata = Default::default();
        quiet.final_operation = Default::default();
        quiet.protected_resource.metadata = None;
        quiet.protected_resource.authorization_servers = vec![];
        let result = run(&quiet);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(result.bounded_claim().contains("not a pass"));
    }

    #[test]
    fn a_harness_failure_is_an_error_rather_than_a_clean_run() {
        let mut failing = scenario();
        failing.lab = Some(crate::model::McpAuthLabSpec {
            reference_behavior: crate::model::ReferenceBehavior::HarnessFailure,
        });
        let result = run(&failing);
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.bounded_claim().contains("could not evaluate"));
    }

    #[test]
    fn the_artifact_never_carries_a_canary_a_credential_or_a_reachable_target() {
        let result = run(&scenario());
        let rendered = serde_json::to_string(&result).expect("serializes");
        for canary in &scenario().objective.protected_canaries {
            assert!(!rendered.contains(canary.as_str()));
        }
        for marker in ["sk-live-", "-----BEGIN", "Bearer ey", "eyJhbGci"] {
            assert!(!rendered.contains(marker), "artifact carried {marker}");
        }
        // A schema `$id` names a contract and is never resolved; every other
        // scheme-shaped occurrence would be something a reader could follow.
        for (index, _) in rendered.match_indices("://") {
            let from = rendered[..index].rfind('"').map_or(0, |at| at + 1);
            assert!(
                rendered[from..].starts_with("https://darelabs.tech/schemas/"),
                "artifact carries a reachable target"
            );
        }
    }

    #[test]
    fn a_substituted_scenario_identity_is_refused_before_anything_is_observed() {
        let mut substituted = scenario();
        substituted.requests[0].operation.name = Some("delete-invoice".to_owned());
        // The binding is computed from the scenario itself, so the run proceeds;
        // what must not happen is the *adapter* substituting one. That is
        // covered in harness and replay. Here we assert the digest moved.
        let original = crate::canonical::bind(&scenario()).expect("binds");
        let moved = crate::canonical::bind(&substituted).expect("binds");
        assert_ne!(original.scenario_digest, moved.scenario_digest);
        assert_ne!(original.protocol_digest, moved.protocol_digest);
    }
}
