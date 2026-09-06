//! Bounded run engine and machine-readable result.
//!
//! This is where the pieces meet. An approved scenario is bound to the identity
//! of everything it evaluates — corpus, per-document content, policy, context
//! and, when present, the corpus vector — a fixed plan is opened, each trial is
//! observed through an adapter, normalized into typed events, evaluated by a
//! deterministic invariant, and aggregated into one result.
//!
//! Aggregation precedence across trials is `FAIL > ERROR > INCONCLUSIVE > PASS`.
//! Nothing averages: three clean trials and one violation is a violation,
//! because the boundary either held every time or it did not hold.
//!
//! The ordering inside a trial is deliberate. Retained bytes are charged
//! *before* evaluation, since retention is exactly what the byte budget
//! governs. Query counts are charged *after*, because they are facts about
//! observations that already exist — charging them first would let a budget
//! stop erase the very violation that crossing the budget produced.
//!
//! `stop_on_first_fail` stops *later* trials. It never truncates the current
//! one: the trial's verdict and every violation it produced are recorded before
//! the run ends, so stopping early cannot lose evidence already collected.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::canonical::{bind, bind_corpus, RagBinding};
use crate::error::{RagSecurityError, Result};
use crate::harness::{
    normalize_checked, observed_query_count, observed_result_count, HarnessAdapter, HarnessMode,
    TrialRequest,
};
use crate::invariant::{evaluate, RagViolation};
use crate::model::{RagCorpusEntry, RagInvariantType, RagProperty, RagSecurityScenario};
use crate::observation::RagObservationEvent;
use crate::source::{RetrievalSourceKind, ScenarioClass, TrustLevel};
use crate::trials::{BudgetSnapshot, StopReason, TrialPlan};

pub const RESULT_SCHEMA_VERSION: &str = "1";
pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/result.schema.json";

/// One document's identity, carried into the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagDocumentDigestRecord {
    pub document_id: String,
    /// Digest of the whole document record: id, owner, tenant, collection,
    /// classification, trust and content digest together.
    pub document_digest: String,
    /// Digest of the content alone. A substitution moves this and leaves the
    /// document's identity untouched, so the two are recorded separately.
    pub content_digest: String,
}

/// One chunk's identity, carried into the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagChunkDigestRecord {
    pub chunk_id: String,
    pub chunk_digest: String,
}

/// One executed trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagTrialRecord {
    pub index: u32,
    pub verdict: Verdict,
    pub reason: String,
    /// Every independently observed violation in this trial.
    ///
    /// A list, not a first match: one result can breach tenant, ACL, provenance
    /// and protected-document policy at once, and reporting the first would
    /// understate what was seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<RagViolation>,
    /// Digests of every normalized event observed in this trial.
    pub event_digests: Vec<String>,
    /// Redacted, typed observations retained as evidence.
    pub events: Vec<RagObservationEvent>,
    /// Queries issued in this trial.
    pub queries: u32,
    /// Results returned in this trial. Read from an index, never written to one.
    pub results: u32,
    /// True when the positive coverage contract for the invariant was met.
    pub coverage_satisfied: bool,
    /// Bytes charged against the output budget by this trial.
    pub retained_bytes: usize,
}

/// Machine-readable outcome of one bounded scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityResult {
    pub schema_version: String,
    pub schema_id: String,

    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,

    pub store_id: String,
    pub store_digest: String,
    /// Per-document identities, so a single substituted document is visible
    /// rather than hidden inside one corpus-wide digest.
    pub document_digests: Vec<RagDocumentDigestRecord>,
    /// Per-chunk identities, so a swapped chunk is visible too.
    pub chunk_digests: Vec<RagChunkDigestRecord>,

    pub context_id: String,
    pub context_digest: String,
    /// The isolation axes, kept explicitly distinct in the artifact.
    pub acting_principal_id: String,
    pub tenant_id: String,
    pub collection_ids: Vec<String>,

    pub policy_id: String,
    pub policy_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,

    pub property_id: RagProperty,
    /// The six surfaces are reported separately and never merged.
    pub class: ScenarioClass,
    pub source_kind: RetrievalSourceKind,
    pub source_trust: TrustLevel,

    pub mode: HarnessMode,
    /// True when observations were staged or replayed from a synthetic source
    /// rather than recorded from a production retriever. Reports must not
    /// present these as production evidence.
    pub synthetic: bool,

    pub invariant: RagInvariantType,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub stop_reason: StopReason,

    pub verdict: Verdict,
    /// Operator-safe explanation. Never contains retrieved content.
    pub reason: String,

    pub trials: Vec<RagTrialRecord>,
    pub normalized_event_digests: Vec<String>,
    pub evidence_ids: Vec<String>,

    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    /// Kill-switch and budget snapshot when the run went through Cycle 009
    /// controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::RagControlSnapshot>,
}

impl RagSecurityResult {
    /// True when the run observed a deterministic invariant violation.
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// Every independently observed violation across every trial.
    pub fn violations(&self) -> Vec<&RagViolation> {
        self.trials
            .iter()
            .flat_map(|trial| trial.violations.iter())
            .collect()
    }

    /// Queries issued across the run.
    pub fn queries(&self) -> u32 {
        self.trials.iter().map(|trial| trial.queries).sum()
    }

    /// Results returned across the run.
    pub fn results(&self) -> u32 {
        self.trials.iter().map(|trial| trial.results).sum()
    }

    /// Bounded claim wording. Never asserts universal retrieval security.
    ///
    /// A `PASS` means no violation was observed for the vectors actually
    /// tested, under the conditions actually recorded. It does not mean
    /// retrieval is secure, that leakage is impossible, or that a vector
    /// database is safe, and this method will not say so however the result is
    /// rendered downstream.
    pub fn bounded_claim(&self) -> String {
        match self.verdict {
            Verdict::Pass => format!(
                "No RAG/retrieval-security invariant violation was observed for the tested \
                 vectors under the recorded conditions ({} of {} bounded trials, invariant {}).",
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
fn aggregate(trials: &[RagTrialRecord]) -> Verdict {
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

fn aggregate_reason(verdict: Verdict, trials: &[RagTrialRecord]) -> String {
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
fn undecidable(index: u32, reason: &str, retained_bytes: usize) -> RagTrialRecord {
    RagTrialRecord {
        index,
        verdict: Verdict::Inconclusive,
        reason: reason.to_owned(),
        violations: Vec::new(),
        event_digests: Vec::new(),
        events: Vec::new(),
        queries: 0,
        results: 0,
        coverage_satisfied: false,
        retained_bytes,
    }
}

/// Run one scenario under a bounded plan.
pub fn run_scenario(
    scenario: &RagSecurityScenario,
    entry: Option<&RagCorpusEntry>,
    adapter: &dyn HarnessAdapter,
    plan: TrialPlan,
) -> Result<RagSecurityResult> {
    // Structure first, then binding: refuse a substituted corpus, document,
    // policy, context or corpus vector before anything is observed. Binding
    // after the first observation would mean the run had already read whatever
    // was swapped in.
    scenario.validate()?;
    let binding: RagBinding = bind(scenario)?;
    let corpus_digest = match entry {
        Some(entry) => Some(bind_corpus(scenario, entry)?),
        None => None,
    };

    let mut ledger = plan.open();
    let mut trials: Vec<RagTrialRecord> = Vec::new();
    let mut stop_reason = StopReason::PlanCompleted;

    while ledger.may_start_trial() {
        let mut guard = match ledger.start_trial() {
            Ok(guard) => guard,
            Err(RagSecurityError::BudgetExhausted(detail)) => {
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
                Err(RagSecurityError::BudgetExhausted(detail)) => {
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
        let queries = observed_query_count(&events);
        let results = observed_result_count(&events);
        let verdict = outcome.verdict;

        // The trial's evidence is recorded *before* any stop decision, so
        // stopping early cannot lose what this trial already established.
        trials.push(RagTrialRecord {
            index,
            verdict,
            reason: outcome.reason,
            violations: outcome.violations,
            event_digests,
            events,
            queries,
            results,
            coverage_satisfied: outcome.coverage_satisfied,
            retained_bytes: retained,
        });

        // Now charge what already happened. The verdict above is recorded, so
        // exhausting a bound stops the run without erasing the violation that
        // crossing it produced.
        let mut budget_stop: Option<String> = None;
        for _ in 0..queries {
            if let Err(RagSecurityError::BudgetExhausted(detail)) = ledger.charge_query(&mut guard)
            {
                budget_stop = Some(detail);
                break;
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

    let document_digests = binding
        .document_digests
        .iter()
        .zip(binding.content_digests.iter())
        .map(
            |((document_id, document_digest), (_, content_digest))| RagDocumentDigestRecord {
                document_id: document_id.clone(),
                document_digest: document_digest.clone(),
                content_digest: content_digest.clone(),
            },
        )
        .collect();

    let chunk_digests = binding
        .chunk_digests
        .iter()
        .map(|(chunk_id, chunk_digest)| RagChunkDigestRecord {
            chunk_id: chunk_id.clone(),
            chunk_digest: chunk_digest.clone(),
        })
        .collect();

    Ok(RagSecurityResult {
        schema_version: RESULT_SCHEMA_VERSION.to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: binding.scenario_id.clone(),
        scenario_digest: binding.scenario_digest.clone(),
        objective_id: binding.objective_id.clone(),
        store_id: binding.store_id.clone(),
        store_digest: binding.store_digest.clone(),
        document_digests,
        chunk_digests,
        context_id: binding.context_id.clone(),
        context_digest: binding.context_digest.clone(),
        acting_principal_id: binding.acting_principal_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        collection_ids: binding.collection_ids.clone(),
        policy_id: binding.policy_id.clone(),
        policy_digest: binding.policy_digest.clone(),
        corpus_id: entry.map(|entry| entry.id.clone()),
        corpus_digest,
        property_id: scenario.property,
        class: scenario.class,
        source_kind: scenario.source.kind,
        source_trust: scenario.source.trust,
        mode: adapter.mode(),
        synthetic: adapter.observations_are_synthetic(),
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

    fn run(scenario: &RagSecurityScenario) -> RagSecurityResult {
        let plan = TrialPlan::from_scenario(scenario).expect("plan");
        run_scenario(scenario, None, &SimulatedAdapter::new(), plan).expect("runs")
    }

    /// A scenario staging `behavior` and judged by the invariant that behaviour
    /// actually bears on.
    ///
    /// Pairing them matters: staging a tenant crossing while judging provenance
    /// would produce a verdict that says nothing about either.
    fn with_matched_behavior(
        behavior: ReferenceBehavior,
        invariant: RagInvariantType,
    ) -> RagSecurityScenario {
        let mut scenario = scenario();
        scenario.lab.as_mut().expect("lab").reference_behavior = behavior;
        scenario.invariant.type_ = invariant;
        scenario
    }

    #[test]
    fn a_compliant_run_passes_and_records_what_it_observed() {
        let result = run(&scenario());
        assert_eq!(result.verdict, Verdict::Pass, "{}", result.reason);
        assert!(result.trials_executed > 0);
        assert!(!result.normalized_event_digests.is_empty());
        assert!(result.trials.iter().all(|trial| trial.coverage_satisfied));
    }

    #[test]
    fn a_pass_never_claims_retrieval_is_secure() {
        let claim = run(&scenario()).bounded_claim();
        for banned in [
            "RAG Secure",
            "Vector Database Secure",
            "No Leakage Possible",
            "Fully Protected",
            "No Retrieval Attack Possible",
        ] {
            assert!(!claim.contains(banned), "{claim}");
        }
        assert!(claim.contains("for the tested vectors under the recorded conditions"));
    }

    #[test]
    fn one_violated_trial_decides_the_run() {
        // Nothing averages. Three clean trials and one violation is a
        // violation: the boundary either held every time or it did not.
        let result = run(&with_matched_behavior(
            ReferenceBehavior::CrossTenantResult,
            RagInvariantType::RetrievalTenantBoundaryPreserved,
        ));
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(!result.violations().is_empty());
        assert!(matches!(result.stop_reason, StopReason::FirstFail { .. }));
    }

    #[test]
    fn stopping_on_first_fail_keeps_the_failing_trials_evidence() {
        // The rule that matters: stop_on_first_fail ends later trials, never
        // the current one. Its verdict and violations are already recorded.
        let result = run(&with_matched_behavior(
            ReferenceBehavior::CrossTenantResult,
            RagInvariantType::RetrievalTenantBoundaryPreserved,
        ));
        let failing = result
            .trials
            .iter()
            .find(|trial| trial.verdict == Verdict::Fail)
            .expect("a failing trial was recorded");
        assert!(!failing.violations.is_empty());
        assert!(!failing.events.is_empty());
        assert!(!failing.event_digests.is_empty());
    }

    #[test]
    fn a_harness_failure_is_an_error_rather_than_a_clean_run() {
        let result = run(&with_matched_behavior(
            ReferenceBehavior::HarnessFailure,
            RagInvariantType::RetrievalTenantBoundaryPreserved,
        ));
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.violations().is_empty());
    }

    #[test]
    fn an_unobserved_channel_is_inconclusive_rather_than_a_pass() {
        let result = run(&with_matched_behavior(
            ReferenceBehavior::NoRelevantObservation,
            RagInvariantType::RetrievalTenantBoundaryPreserved,
        ));
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
    fn every_document_keeps_a_separate_identity_and_content_digest() {
        // A substitution moves content and leaves identity alone. One combined
        // digest would show that something changed without showing what.
        let result = run(&scenario());
        assert!(!result.document_digests.is_empty());
        for record in &result.document_digests {
            assert!(record.document_digest.starts_with("sha256:"));
            assert!(record.content_digest.starts_with("sha256:"));
            assert_ne!(record.document_digest, record.content_digest);
        }
        assert!(!result.chunk_digests.is_empty());
    }

    #[test]
    fn a_substituted_document_changes_the_recorded_binding() {
        let baseline = run(&scenario());

        let mut swapped = scenario();
        swapped.store.documents[0].content_digest =
            crate::canonical::content_digest("something else entirely");
        let after = run(&swapped);

        assert_ne!(baseline.store_digest, after.store_digest);
        assert_ne!(
            baseline.document_digests[0].content_digest,
            after.document_digests[0].content_digest
        );
        // The scenario digest moves too, so a swapped corpus cannot be passed
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
    fn the_artifact_never_carries_a_canary_a_credential_or_an_endpoint() {
        for behavior in ReferenceBehavior::all() {
            let mut scenario = scenario();
            scenario.lab.as_mut().expect("lab").reference_behavior = behavior;
            let plan = TrialPlan::from_scenario(&scenario).expect("plan");
            let Ok(result) = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan) else {
                continue;
            };
            let serialized = serde_json::to_string(&result).expect("serializes");
            for canary in &scenario.objective.protected_canaries {
                assert!(!serialized.contains(canary.as_str()), "{behavior:?}");
            }
            for marker in [
                "sk-live-",
                "-----BEGIN",
                "Bearer ey",
                "http://",
                "redis://",
                "postgresql://",
                "example.invalid",
            ] {
                assert!(!serialized.contains(marker), "{behavior:?}: {marker}");
            }

            // The artifact does carry `https://` — in its own schema
            // identifiers, which name a contract and are never resolved. Every
            // one of them must be a DARE schema id and nothing else.
            for occurrence in serialized.match_indices("https://") {
                let tail = &serialized[occurrence.0..];
                assert!(
                    tail.starts_with("https://darelabs.tech/schemas/"),
                    "{behavior:?}: the artifact carries a non-schema URL"
                );
            }
        }
    }

    #[test]
    fn a_scenario_pinning_the_wrong_corpus_digest_is_refused() {
        let mut scenario = scenario();
        scenario.vector = Some(crate::model::RagVectorRef {
            corpus_id: "rag-security-v1".to_owned(),
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
        assert!(matches!(err, RagSecurityError::DigestMismatch(_)));
    }
}
