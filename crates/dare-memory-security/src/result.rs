//! Bounded run engine and machine-readable result.
//!
//! This is where the pieces meet. An approved scenario is bound to the identity
//! of everything it evaluates — store, per-item content, policy, context and,
//! when present, the corpus vector — a fixed plan is opened, each trial is
//! observed through an adapter, normalized into typed events, evaluated by a
//! deterministic invariant, and aggregated into one result.
//!
//! Aggregation precedence across trials is `FAIL > ERROR > INCONCLUSIVE > PASS`.
//! A violation that was actually observed stays observed even if a later trial
//! hits a harness failure; a harness failure otherwise prevents any security
//! conclusion; and `PASS` requires every executed trial to have held. Nothing
//! averages: three clean trials and one violation is a violation, because the
//! boundary either held every time or it did not hold.
//!
//! The ordering inside a trial is deliberate. Retained bytes are charged
//! *before* evaluation, since retention is exactly what the byte budget
//! governs. Event and recall-item counts are charged *after*, because they are
//! facts about observations that already exist — charging them first would let
//! a budget stop erase the very violation that crossing the budget produced.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::canonical::{bind, bind_corpus, MemoryBinding};
use crate::error::{MemorySecurityError, Result};
use crate::harness::{
    normalize_checked, observed_recall_items, HarnessAdapter, HarnessMode, TrialRequest,
};
use crate::invariant::{evaluate, MemoryViolation};
use crate::model::{
    MemoryCorpusEntry, MemoryInvariantType, MemoryProperty, MemorySecurityScenario,
};
use crate::observation::MemoryObservationEvent;
use crate::source::{MemorySourceKind, ScenarioClass, TrustLevel};
use crate::trials::{BudgetSnapshot, StopReason, TrialPlan};

pub const RESULT_SCHEMA_VERSION: &str = "1";
pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/result.schema.json";

/// One memory item's identity, carried into the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryItemDigestRecord {
    pub memory_id: String,
    /// Digest of the whole item record: id, owner, tenant, namespace, trust,
    /// lifecycle and content digest together.
    pub item_digest: String,
    /// Digest of the content alone. A substitution moves this and leaves the
    /// item's identity untouched, so the two are recorded separately.
    pub content_digest: String,
}

/// One executed trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrialRecord {
    pub index: u32,
    pub verdict: Verdict,
    pub reason: String,
    /// Every independently observed violation in this trial.
    ///
    /// A list, not a first match: one finding must never mask another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<MemoryViolation>,
    /// Digests of every normalized event observed in this trial.
    pub event_digests: Vec<String>,
    /// Redacted, typed observations retained as evidence.
    pub events: Vec<MemoryObservationEvent>,
    /// Memory items returned by recalls in this trial. Read, never written.
    pub recall_items: u32,
    /// True when the positive coverage contract for the invariant was met.
    pub coverage_satisfied: bool,
    /// Bytes charged against the output budget by this trial.
    pub retained_bytes: usize,
}

/// Machine-readable outcome of one bounded scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityResult {
    pub schema_version: String,
    pub schema_id: String,

    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,

    pub store_id: String,
    pub store_digest: String,
    /// Per-item identities, so a single substituted item is visible rather than
    /// hidden inside one store-wide digest.
    pub item_digests: Vec<MemoryItemDigestRecord>,

    pub context_id: String,
    pub context_digest: String,
    /// The three isolation axes, kept explicitly distinct in the artifact.
    pub acting_principal_id: String,
    pub tenant_id: String,
    pub namespace_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,

    pub property_id: MemoryProperty,
    /// The five surfaces are reported separately and never merged.
    pub class: ScenarioClass,
    pub source_kind: MemorySourceKind,
    pub source_trust: TrustLevel,

    pub mode: HarnessMode,
    /// True when observations were staged by a fixture rather than recorded
    /// from a real agent. Reports must not present these as production evidence.
    pub synthetic: bool,

    pub invariant: MemoryInvariantType,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub stop_reason: StopReason,

    pub verdict: Verdict,
    /// Operator-safe explanation. Never contains observed content.
    pub reason: String,

    pub trials: Vec<MemoryTrialRecord>,
    pub normalized_event_digests: Vec<String>,
    pub evidence_ids: Vec<String>,

    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    /// Kill-switch and budget snapshot when the run went through Cycle 009
    /// controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::MemoryControlSnapshot>,
}

impl MemorySecurityResult {
    /// True when the run observed a deterministic invariant violation.
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// Every independently observed violation across every trial.
    pub fn violations(&self) -> Vec<&MemoryViolation> {
        self.trials
            .iter()
            .flat_map(|trial| trial.violations.iter())
            .collect()
    }

    /// Memory items recalled across the run. Read, never written.
    pub fn recall_items(&self) -> u32 {
        self.trials.iter().map(|trial| trial.recall_items).sum()
    }

    /// Bounded claim wording. Never asserts universal memory security.
    ///
    /// A `PASS` means no violation was observed for the vectors actually
    /// tested, under the conditions actually recorded. It does not mean memory
    /// is secure, that poisoning is impossible, or that the system is fully
    /// protected, and this method will not say so however the result is
    /// rendered downstream.
    pub fn bounded_claim(&self) -> String {
        match self.verdict {
            Verdict::Pass => format!(
                "No memory-security invariant violation was observed for the tested vectors \
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
fn aggregate(trials: &[MemoryTrialRecord]) -> Verdict {
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

fn aggregate_reason(verdict: Verdict, trials: &[MemoryTrialRecord]) -> String {
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
fn undecidable(index: u32, reason: &str, retained_bytes: usize) -> MemoryTrialRecord {
    MemoryTrialRecord {
        index,
        verdict: Verdict::Inconclusive,
        reason: reason.to_owned(),
        violations: Vec::new(),
        event_digests: Vec::new(),
        events: Vec::new(),
        recall_items: 0,
        coverage_satisfied: false,
        retained_bytes,
    }
}

/// Run one scenario under a bounded plan.
///
/// `entry` is the corpus vector when the scenario references one; a scenario
/// may also be run against a recorded trace alone.
pub fn run_scenario(
    scenario: &MemorySecurityScenario,
    entry: Option<&MemoryCorpusEntry>,
    adapter: &dyn HarnessAdapter,
    plan: TrialPlan,
) -> Result<MemorySecurityResult> {
    // Structure first, then binding: refuse a substituted store, policy,
    // context or corpus vector before anything is observed. Binding after the
    // first observation would mean the run had already read whatever was
    // swapped in.
    scenario.validate()?;
    let binding: MemoryBinding = bind(scenario)?;
    let corpus_digest = match entry {
        Some(entry) => Some(bind_corpus(scenario, entry)?),
        None => None,
    };

    let mut ledger = plan.open();
    let mut trials: Vec<MemoryTrialRecord> = Vec::new();
    let mut stop_reason = StopReason::PlanCompleted;

    while ledger.may_start_trial() {
        let mut guard = match ledger.start_trial() {
            Ok(guard) => guard,
            Err(MemorySecurityError::BudgetExhausted(detail)) => {
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

        // Retention budget first: this governs how much is kept, so it is
        // charged before anything is kept.
        let mut retained = 0usize;
        let mut exhausted: Option<String> = None;
        for event in &events {
            let bytes = event.retained_bytes();
            match ledger.charge_output(&mut guard, bytes) {
                Ok(()) => retained += bytes,
                Err(MemorySecurityError::BudgetExhausted(detail)) => {
                    exhausted = Some(detail);
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        if let Some(detail) = exhausted {
            // The observation is incomplete, so it cannot support a security
            // conclusion in either direction. Record that and stop.
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
        let recall_items = observed_recall_items(&events);
        let verdict = outcome.verdict;

        trials.push(MemoryTrialRecord {
            index,
            verdict,
            reason: outcome.reason,
            violations: outcome.violations,
            event_digests,
            events: events.clone(),
            recall_items,
            coverage_satisfied: outcome.coverage_satisfied,
            retained_bytes: retained,
        });

        // Now charge what already happened. The verdict above is recorded, so
        // exhausting a bound stops the run without erasing the violation that
        // crossing it produced.
        let mut budget_stop: Option<String> = None;
        for _ in 0..events.len() {
            if let Err(MemorySecurityError::BudgetExhausted(detail)) =
                ledger.charge_event(&mut guard)
            {
                budget_stop = Some(detail);
                break;
            }
        }
        if budget_stop.is_none() {
            if let Err(MemorySecurityError::BudgetExhausted(detail)) =
                ledger.charge_recall_items(recall_items)
            {
                budget_stop = Some(detail);
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

    let item_digests = binding
        .item_digests
        .iter()
        .zip(binding.content_digests.iter())
        .map(
            |((memory_id, item_digest), (_, content_digest))| MemoryItemDigestRecord {
                memory_id: memory_id.clone(),
                item_digest: item_digest.clone(),
                content_digest: content_digest.clone(),
            },
        )
        .collect();

    Ok(MemorySecurityResult {
        schema_version: RESULT_SCHEMA_VERSION.to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: binding.scenario_id.clone(),
        scenario_digest: binding.scenario_digest.clone(),
        objective_id: binding.objective_id.clone(),
        store_id: binding.store_id.clone(),
        store_digest: binding.store_digest.clone(),
        item_digests,
        context_id: binding.context_id.clone(),
        context_digest: binding.context_digest.clone(),
        acting_principal_id: binding.acting_principal_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        namespace_id: binding.namespace_id.clone(),
        policy_id: binding.policy_id.clone(),
        policy_digest: binding.policy_digest.clone(),
        corpus_id: entry.map(|entry| entry.id.clone()),
        corpus_digest,
        property_id: scenario.property,
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
    use crate::model::ReferenceBehavior;
    use crate::simulated::SimulatedAdapter;

    fn run(scenario: &MemorySecurityScenario) -> MemorySecurityResult {
        let plan = TrialPlan::from_scenario(scenario).expect("plan");
        run_scenario(scenario, None, &SimulatedAdapter::new(), plan).expect("runs")
    }

    fn with_behavior(behavior: ReferenceBehavior) -> MemorySecurityScenario {
        let mut scenario = scenario();
        scenario
            .lab
            .as_mut()
            .expect("the fixture declares a lab spec")
            .reference_behavior = behavior;
        scenario
    }

    /// A scenario staging `behavior` and judged by the invariant that behavior
    /// actually bears on.
    ///
    /// Pairing them matters: staging a trust promotion while judging provenance
    /// would produce a PASS that says nothing about either.
    fn with_matched_behavior(
        behavior: ReferenceBehavior,
        invariant: MemoryInvariantType,
    ) -> MemorySecurityScenario {
        let mut scenario = with_behavior(behavior);
        scenario.invariant.type_ = invariant;
        scenario
    }

    #[test]
    fn a_compliant_run_passes_and_records_what_it_observed() {
        let result = run(&scenario());
        assert_eq!(result.verdict, Verdict::Pass);
        assert!(result.trials_executed > 0);
        assert!(!result.normalized_event_digests.is_empty());
        assert!(result.trials.iter().all(|trial| trial.coverage_satisfied));
    }

    #[test]
    fn a_pass_never_claims_memory_is_secure() {
        let result = run(&scenario());
        let claim = result.bounded_claim();
        for banned in [
            "Memory Secure",
            "Poisoning Impossible",
            "No Memory Poisoning",
            "Fully Protected",
        ] {
            assert!(!claim.contains(banned), "{claim}");
        }
        assert!(claim.contains("for the tested vectors under the recorded conditions"));
    }

    #[test]
    fn one_violated_trial_decides_the_run() {
        // Nothing averages. Three clean trials and one violation is a
        // violation: the boundary either held every time or it did not hold.
        let result = run(&with_matched_behavior(
            ReferenceBehavior::TrustPromoted,
            MemoryInvariantType::UntrustedMemoryNotPromotedToAuthority,
        ));
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(!result.violations().is_empty());
        assert!(matches!(result.stop_reason, StopReason::FirstFail { .. }));
    }

    #[test]
    fn a_harness_failure_is_an_error_rather_than_a_clean_run() {
        let result = run(&with_behavior(ReferenceBehavior::HarnessFailure));
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.violations().is_empty());
    }

    #[test]
    fn an_unobserved_channel_is_inconclusive_rather_than_a_pass() {
        let mut scenario = with_behavior(ReferenceBehavior::NoRelevantObservation);
        scenario.invariant.type_ = MemoryInvariantType::MemoryTenantBoundaryPreserved;
        let result = run(&scenario);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(result.trials.iter().all(|trial| !trial.coverage_satisfied));
    }

    #[test]
    fn the_result_records_zero_state_changes_and_zero_egress() {
        // Recorded rather than assumed: an artifact that simply omitted them
        // would leave a reader to take the claim on trust.
        let result = run(&scenario());
        assert_eq!(result.budget.state_changes, 0);
        assert_eq!(result.budget.external_egress_bytes, 0);
        assert!(result.synthetic);
    }

    #[test]
    fn every_memory_item_keeps_a_separate_identity_and_content_digest() {
        // A substitution moves content and leaves identity alone. One combined
        // digest would show that something changed without showing what.
        let result = run(&scenario());
        assert_eq!(result.item_digests.len(), result.item_digests.len());
        assert!(!result.item_digests.is_empty());
        for record in &result.item_digests {
            assert!(record.item_digest.starts_with("sha256:"));
            assert!(record.content_digest.starts_with("sha256:"));
            assert_ne!(record.item_digest, record.content_digest);
        }
    }

    #[test]
    fn a_substituted_store_changes_the_recorded_binding() {
        let baseline = run(&scenario());

        let mut swapped = scenario();
        swapped.store.items[0].content_digest =
            crate::canonical::content_digest("something else entirely");
        let after = run(&swapped);

        assert_ne!(baseline.store_digest, after.store_digest);
        assert_ne!(
            baseline.item_digests[0].content_digest,
            after.item_digests[0].content_digest
        );
        // The scenario digest moves too, so a swapped store cannot be passed
        // off as the approved one.
        assert_ne!(baseline.scenario_digest, after.scenario_digest);
    }

    #[test]
    fn a_run_yields_one_evidence_id_per_executed_trial() {
        let result = run(&scenario());
        assert_eq!(result.evidence_ids.len(), result.trials.len());

        let unique: std::collections::BTreeSet<&String> = result.evidence_ids.iter().collect();
        assert_eq!(unique.len(), result.evidence_ids.len(), "ids repeat");
    }

    #[test]
    fn the_same_run_twice_produces_the_same_artifact() {
        // Determinism is what makes a digest worth recording.
        let first = run(&scenario());
        let second = run(&scenario());
        assert_eq!(
            serde_json::to_string(&first).expect("serializes"),
            serde_json::to_string(&second).expect("serializes")
        );
    }

    #[test]
    fn the_artifact_never_carries_a_canary_or_a_credential() {
        for behavior in ReferenceBehavior::all() {
            let mut scenario = with_behavior(behavior);
            // Protected-field influence needs the invariant that reads it.
            if behavior == ReferenceBehavior::ProtectedFieldPopulated {
                scenario.invariant.type_ =
                    MemoryInvariantType::ProtectedFieldNotDerivedFromPoisonedMemory;
            }
            let plan = TrialPlan::from_scenario(&scenario).expect("plan");
            let Ok(result) = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan) else {
                continue;
            };
            let serialized = serde_json::to_string(&result).expect("serializes");
            for canary in &scenario.objective.protected_canaries {
                assert!(!serialized.contains(canary.as_str()), "{behavior:?}");
            }
            for marker in ["sk-live-", "-----BEGIN", "Bearer ey"] {
                assert!(!serialized.contains(marker), "{behavior:?}");
            }
        }
    }

    #[test]
    fn a_scenario_pinning_the_wrong_corpus_digest_is_refused() {
        let mut scenario = scenario();
        scenario.vector = Some(crate::model::MemoryVectorRef {
            corpus_id: "memory-security-v1".to_owned(),
            corpus_digest: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            ),
        });
        let entry = crate::corpus::builtin_corpus()
            .expect("corpus loads")
            .entries[0]
            .clone();
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");

        let err = run_scenario(&scenario, Some(&entry), &SimulatedAdapter::new(), plan)
            .expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::DigestMismatch(_)));
    }
}
