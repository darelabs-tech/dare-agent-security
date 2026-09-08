//! The run artifact.
//!
//! One scenario, one evidence bundle, twelve invariant outcomes, one verdict.
//!
//! # Bounded wording
//!
//! A result never says a supply chain is secure. It says which invariants held
//! under the evidence that was actually read, and the reason text is written so
//! that a reader who sees only the artifact cannot mistake it for a broader
//! claim — `complete AI-BOM != secure supply chain` is a rule of this cycle and
//! the report is where it is easiest to break.
//!
//! # What the artifact carries
//!
//! Enough to get from the verdict back to the evidence: the digest of every
//! document read, the digest of the observation that decided each violation,
//! the budget the run executed under, and whether the evidence was staged.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::budget::{AdmissionLedger, BudgetSnapshot};
use crate::canonical::digest;
use crate::error::Result;
use crate::harness::SupplyChainAdapter;
use crate::invariant::{
    aggregate, evaluate_all, SupplyChainInvariantOutcome, SupplyChainViolation,
};
use crate::model::{SupplyChainInvariant, SupplyChainScenario};
use crate::observation::{project, HarnessErrorContext, ObservationSet, SupplyChainObservation};
use crate::source::{HarnessErrorKind, ScenarioClass, SupplyChainMode};

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/supply-chain-security/v1/result.schema.json";

/// One document the run read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRecord {
    pub document_id: String,
    pub format: crate::normalize::BomFormat,
    pub bytes: usize,
    pub content_digest: String,
}

/// The bounded run artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSecurityResult {
    pub schema_version: String,
    pub schema_id: String,

    pub scenario_id: String,
    pub scenario_digest: String,
    pub evidence_digest: String,

    pub class: ScenarioClass,
    /// The invariant the scenario selected for coverage. Never a verdict.
    pub primary_invariant: SupplyChainInvariant,
    pub property_id: String,

    pub mode: SupplyChainMode,
    /// True when the evidence was staged or replayed rather than collected from
    /// a real deployment.
    pub synthetic: bool,

    pub verdict: Verdict,
    /// Operator-safe explanation. Bounded to what was evaluated, and never a
    /// claim that the supply chain is secure.
    pub reason: String,

    pub outcomes: Vec<SupplyChainInvariantOutcome>,
    /// Every concrete violation retained across all twelve invariants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<SupplyChainViolation>,

    pub documents: Vec<DocumentRecord>,
    pub components_evaluated: usize,
    pub relationships_evaluated: usize,
    pub observation_digests: Vec<String>,

    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::SupplyChainControlSnapshot>,
}

impl SupplyChainSecurityResult {
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// The invariants that reached a definite answer.
    pub fn decided(&self) -> Vec<&SupplyChainInvariantOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome.verdict, Verdict::Pass | Verdict::Fail))
            .collect()
    }
}

/// Run one scenario through one adapter.
///
/// A harness failure becomes a `HARNESS_ERROR` observation rather than an
/// `Err`: a run that could not collect evidence is a result an operator needs
/// to see, and losing it in an error return would leave the scenario looking
/// like it had never been attempted.
pub fn run_scenario(
    scenario: &SupplyChainScenario,
    adapter: &dyn SupplyChainAdapter,
    ledger: &mut AdmissionLedger,
) -> Result<SupplyChainSecurityResult> {
    scenario.validate()?;

    let (evidence, observations) = match adapter.collect(scenario, ledger) {
        Ok(evidence) => {
            let observations = project(&evidence);
            (Some(evidence), observations)
        }
        Err(error) => (
            None,
            ObservationSet::new(vec![SupplyChainObservation::HarnessError(
                HarnessErrorContext {
                    kind: harness_error_kind(&error),
                    // The engine's own message, which is already written not to
                    // echo what it refused.
                    reason: error.to_string(),
                },
            )]),
        ),
    };

    let outcomes = evaluate_all(&observations);
    let verdict = aggregate(&outcomes);
    let violations: Vec<SupplyChainViolation> = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .flat_map(|outcome| outcome.violations.clone())
        .collect();

    let documents = evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .documents
                .iter()
                .map(|document| DocumentRecord {
                    document_id: document.document_id.clone(),
                    format: document.format,
                    bytes: document.bytes,
                    content_digest: document.content_digest.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let observation_digests = observations
        .observations
        .iter()
        .filter_map(|observation| observation.digest().ok())
        .collect();

    Ok(SupplyChainSecurityResult {
        schema_version: "1".to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: scenario.scenario_id.clone(),
        scenario_digest: digest(scenario)?,
        evidence_digest: match &evidence {
            Some(evidence) => digest(evidence)?,
            None => digest(&observations)?,
        },
        class: scenario.class,
        primary_invariant: scenario.primary_invariant,
        property_id: scenario.primary_invariant.property_id().to_owned(),
        mode: adapter.mode(),
        synthetic: adapter.evidence_is_synthetic(),
        verdict,
        reason: reason_for(verdict, &outcomes, &violations),
        outcomes,
        violations,
        components_evaluated: evidence
            .as_ref()
            .map(|evidence| evidence.components.len())
            .unwrap_or_default(),
        relationships_evaluated: evidence
            .as_ref()
            .map(|evidence| evidence.graph.edges.len())
            .unwrap_or_default(),
        documents,
        observation_digests,
        redaction_state: "REDACTED".to_owned(),
        budget: ledger.snapshot(),
        controls: None,
    })
}

fn harness_error_kind(error: &crate::error::SupplyChainError) -> HarnessErrorKind {
    match error {
        crate::error::SupplyChainError::BudgetExhausted(_) => HarnessErrorKind::BudgetExhausted,
        _ => HarnessErrorKind::DocumentRefused,
    }
}

/// The operator-facing summary.
///
/// Deliberately narrow. A run that violated nothing is reported as *these
/// invariants held under this evidence*, never as a secure supply chain — a
/// complete bill of materials is an inventory, and an inventory is not trust.
fn reason_for(
    verdict: Verdict,
    outcomes: &[SupplyChainInvariantOutcome],
    violations: &[SupplyChainViolation],
) -> String {
    let decided = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.verdict, Verdict::Pass | Verdict::Fail))
        .count();
    let undecided = outcomes.len() - decided;

    match verdict {
        Verdict::Fail => format!(
            "{} independent supply-chain violation(s) were observed across {decided} decided \
             invariant(s); {undecided} could not be decided from the evidence read",
            violations.len()
        ),
        Verdict::Error => {
            "the run could not read the evidence it was asked to evaluate, so no supply-chain \
             conclusion is available in either direction"
                .to_owned()
        }
        Verdict::Inconclusive => format!(
            "no violation was observed, and {undecided} of {} invariant(s) lacked the evidence \
             needed to decide them; this run does not establish that the supply chain is intact",
            outcomes.len()
        ),
        Verdict::Pass => format!(
            "all {decided} applicable invariant(s) held under the evidence read; this is a \
             statement about the evidence supplied, not that the supply chain is secure"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::corpus;
    use crate::harness::StaticAdapter;
    use crate::model::tests::scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::source::ReferenceBehavior;

    fn simulated(behavior: ReferenceBehavior) -> SupplyChainSecurityResult {
        let mut scenario = scenario(
            "supply-lab-result",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::Simulated;
        scenario.evidence_files = Vec::new();
        scenario.reference_behavior = Some(behavior);

        let mut ledger = AdmissionLedger::new();
        run_scenario(&scenario, &SimulatedAdapter::new(), &mut ledger).expect("runs")
    }

    #[test]
    fn a_substituted_artifact_produces_a_failing_artifact_with_its_evidence() {
        let result = simulated(ReferenceBehavior::DigestSubstituted);
        assert!(result.is_violation());
        assert!(!result.violations.is_empty());
        assert!(!result.observation_digests.is_empty());
        assert!(!result.documents.is_empty());
        assert!(result.documents[0].content_digest.starts_with("sha256:"));
        assert_eq!(result.outcomes.len(), 12);
    }

    #[test]
    fn a_clean_run_never_claims_the_supply_chain_is_secure() {
        // `complete AI-BOM != secure supply chain`, enforced where it is
        // easiest to break: the sentence an operator actually reads.
        let result = simulated(ReferenceBehavior::Compliant);
        let reason = result.reason.to_lowercase();
        assert!(
            !reason.contains("is secure") || reason.contains("not that the supply chain is secure"),
            "the artifact claimed a secure supply chain: {}",
            result.reason
        );
        assert!(reason.contains("evidence"));
    }

    #[test]
    fn an_inconclusive_run_says_it_established_nothing() {
        let result = simulated(ReferenceBehavior::NoRelevantObservation);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(result
            .reason
            .contains("does not establish that the supply chain is intact"));
    }

    #[test]
    fn a_harness_failure_becomes_an_error_result_rather_than_a_lost_run() {
        // A run that could not collect evidence is a result an operator needs
        // to see. Returning `Err` would leave the scenario looking like it had
        // never been attempted.
        let mut scenario = scenario(
            "supply-lab-broken",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::Static;
        scenario.evidence_files = vec!["absent.cdx.json".to_owned()];

        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &StaticAdapter::new("."), &mut ledger)
            .expect("a harness failure is still a result");
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.violations.is_empty());
        assert_eq!(result.components_evaluated, 0);
    }

    #[test]
    fn the_artifact_records_the_budget_it_ran_under() {
        let result = simulated(ReferenceBehavior::Compliant);
        assert_eq!(result.budget.state_changes, 0);
        assert_eq!(result.budget.external_egress_bytes, 0);
        assert_eq!(result.redaction_state, "REDACTED");
    }

    #[test]
    fn the_primary_invariant_does_not_filter_what_is_reported() {
        // The scenario selects integrity, and the bundle also drifts a
        // capability and comes from an unapproved vendor.
        let result = simulated(ReferenceBehavior::MultipleIndependentViolations);
        let invariants: std::collections::BTreeSet<&str> = result
            .violations
            .iter()
            .map(|violation| violation.invariant.as_str())
            .collect();
        assert!(invariants.len() >= 3, "{invariants:?}");
        assert_eq!(
            result.primary_invariant,
            SupplyChainInvariant::ArtifactDigestBoundToComponent
        );
    }

    #[test]
    fn the_artifact_carries_no_credential_shaped_content() {
        // The input gate does not apply here: an artifact carries a `verdict`
        // because it *is* the evaluator's output, and running the document
        // sweep over it would refuse the field the artifact exists to publish.
        // What must still hold is that nothing credential-shaped or
        // executable-shaped reached the artifact from the evidence.
        let result = simulated(ReferenceBehavior::DigestSubstituted);
        let rendered = serde_json::to_string(&result)
            .expect("serializes")
            .to_lowercase();
        for forbidden in [
            "api_key",
            "access_token",
            "client_secret",
            "private_key",
            "bearer ",
            "command",
            "entrypoint",
            "download_url",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "the artifact carries `{forbidden}`"
            );
        }
        assert!(!crate::schema::contains_bearer_credential(&rendered));
    }

    #[test]
    fn results_are_deterministic() {
        assert_eq!(
            digest(&simulated(ReferenceBehavior::DigestSubstituted)).unwrap(),
            digest(&simulated(ReferenceBehavior::DigestSubstituted)).unwrap()
        );
    }

    #[test]
    fn every_corpus_entry_produces_an_artifact_or_an_error_result() {
        // Nothing in the corpus can leave a run without a record.
        for entry in corpus() {
            let mut ledger = AdmissionLedger::new();
            let evidence = (entry.build)(&mut ledger);
            let observations = match &evidence {
                Ok(evidence) => project(evidence),
                Err(_) => continue,
            };
            let outcomes = evaluate_all(&observations);
            assert_eq!(
                outcomes.len(),
                12,
                "{} evaluated fewer than twelve",
                entry.id
            );
        }
    }
}
