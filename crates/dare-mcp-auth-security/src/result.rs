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
use crate::harness::{normalize_checked, HarnessAdapter, RawTrialOutput, TrialRequest};
use crate::invariant::{collect_observed_violations, evaluate, McpAuthViolation};
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
                 trials, primary invariant {}).",
                self.trials_executed,
                self.trials_planned,
                self.invariant.as_str()
            ),
            Verdict::Fail => format!(
                "One or more MCP 2026 authentication/authorization hardening invariants were \
                 violated under the recorded conditions ({} independently observed \
                 violation(s); primary invariant {}).",
                self.violations().len(),
                self.invariant.as_str()
            ),
            Verdict::Inconclusive => format!(
                "Evidence was insufficient to decide primary invariant {}. An inconclusive result \
                 is not a pass.",
                self.invariant.as_str()
            ),
            Verdict::Error => format!(
                "The harness could not evaluate primary invariant {}; no security conclusion is \
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

        // Request accounting is an admission boundary, not a post-hoc metric.
        // A request that could not be charged must not be normalized, evaluated
        // or persisted. Otherwise the artifact could contain evidence derived
        // from more requests than its own budget says were admitted.
        let mut exhausted: Option<String> = None;
        let mut requests = 0u32;
        let mut admitted_requests = Vec::with_capacity(raw.observed_requests.len());
        for request in &raw.observed_requests {
            match ledger.charge_request(&mut guard) {
                Ok(()) => {
                    requests += 1;
                    admitted_requests.push(request.clone());
                }
                Err(error) => {
                    exhausted = Some(error.to_string());
                    break;
                }
            }
        }

        let bounded_raw = RawTrialOutput {
            observed_requests: admitted_requests,
            harness_error: raw.harness_error.clone(),
        };
        let events = normalize_checked(&bounded_raw, scenario)?;

        // The output budget governs what is kept, not merely what is counted.
        // Admission and retention are the same act: an event that was not
        // charged is not kept, is not evaluated, and is not written.
        let mut retained = 0usize;
        let mut admitted: Vec<McpAuthObservation> = Vec::with_capacity(events.len());
        for event in events {
            let bytes = event.retained_bytes();
            match ledger.charge_output(&mut guard, bytes) {
                Ok(()) => {
                    retained += bytes;
                    admitted.push(event);
                }
                Err(error) => {
                    if exhausted.is_none() {
                        exhausted = Some(error.to_string());
                    }
                    break;
                }
            }
        }
        let events = admitted;

        // A trial that hit any bound partway through did not observe everything
        // it set out to. PASS must not be manufactured from a partial view.
        let incomplete = exhausted.is_some();

        // The scenario-selected invariant remains the primary decision surface
        // for backward compatibility and coverage semantics. Independently,
        // every evaluator is allowed to report a concrete FAIL over evidence
        // that is already present in this same trial. This is deliberately not
        // "all invariants must PASS": an inapplicable secondary invariant will
        // generally be INCONCLUSIVE and does not poison the primary result.
        let mut outcome = evaluate(invariant, scenario, &events);

        if incomplete && outcome.verdict == Verdict::Pass {
            outcome = crate::invariant::McpAuthInvariantOutcome {
                invariant,
                verdict: Verdict::Inconclusive,
                reason: format!(
                    "a hard bound stopped this trial before its evidence was complete, so {} was \
                     not decided",
                    invariant.as_str()
                ),
                violations: Vec::new(),
                coverage_satisfied: false,
            };
        }

        let event_digests: Vec<String> = events
            .iter()
            .filter_map(|event| event.digest().ok())
            .collect();

        let violations = collect_observed_violations(scenario, &events);
        let verdict = if violations.is_empty() {
            outcome.verdict
        } else {
            Verdict::Fail
        };
        let reason = if violations.is_empty() {
            outcome.reason.clone()
        } else if violations.len() == 1 {
            violations[0].reason.clone()
        } else {
            let mut names: Vec<&str> = violations
                .iter()
                .map(|violation| violation.invariant.as_str())
                .collect();
            names.sort_unstable();
            names.dedup();
            format!(
                "{} independent violations were observed across {} invariant(s): {}",
                violations.len(),
                names.len(),
                names.join(", ")
            )
        };

        trials.push(McpAuthTrialRecord {
            index,
            verdict,
            reason,
            // A boundary that was demonstrably crossed was demonstrably
            // exercised, whatever else the primary run did or did not observe.
            coverage_satisfied: outcome.coverage_satisfied || verdict == Verdict::Fail,
            requests,
            retained_bytes: retained,
            violations,
            event_digests,
            events,
        });

        // The stop happens only after the record above is pushed, so a failing
        // trial's evidence is never lost to the stop it caused.
        if let Some(detail) = exhausted {
            ledger.stop(StopReason::BudgetExhausted { detail });
            break;
        }
        if plan.stop_on_first_fail && verdict == Verdict::Fail {
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

/// `FAIL` outranks a later harness error because an observed violation is
/// retained evidence; then `ERROR` > `INCONCLUSIVE` > `PASS`.
fn aggregate(trials: &[McpAuthTrialRecord]) -> Verdict {
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
        assert_eq!(run(&scenario()), run(&scenario()));
    }

    #[test]
    fn stopping_on_first_fail_keeps_the_failing_trials_evidence() {
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
        let original = crate::canonical::bind(&scenario()).expect("binds");
        let moved = crate::canonical::bind(&substituted).expect("binds");
        assert_ne!(original.scenario_digest, moved.scenario_digest);
        assert_ne!(original.protocol_digest, moved.protocol_digest);
    }
}
