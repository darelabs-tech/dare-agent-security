//! The run artifact.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::budget::{AdmissionLedger, BudgetSnapshot};
use crate::canonical::digest;
use crate::error::Result;
use crate::harness::SupplyChainAdapter;
use crate::invariant::{aggregate, evaluate_all, SupplyChainInvariantOutcome, SupplyChainViolation};
use crate::model::{SupplyChainInvariant, SupplyChainScenario};
use crate::observation::{project, HarnessErrorContext, ObservationSet, SupplyChainObservation};
use crate::source::{HarnessErrorKind, ScenarioClass, SupplyChainMode};

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/supply-chain-security/v1/result.schema.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRecord {
    pub document_id: String,
    pub format: crate::normalize::BomFormat,
    pub bytes: usize,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSecurityResult {
    pub schema_version: String,
    pub schema_id: String,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub evidence_digest: String,
    pub class: ScenarioClass,
    pub primary_invariant: SupplyChainInvariant,
    pub property_id: String,
    pub mode: SupplyChainMode,
    pub synthetic: bool,
    pub verdict: Verdict,
    pub reason: String,
    pub outcomes: Vec<SupplyChainInvariantOutcome>,
    #[serde(default)]
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

    pub fn decided(&self) -> Vec<&SupplyChainInvariantOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome.verdict, Verdict::Pass | Verdict::Fail))
            .collect()
    }
}

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
        components_evaluated: evidence.as_ref().map(|e| e.components.len()).unwrap_or_default(),
        relationships_evaluated: evidence.as_ref().map(|e| e.graph.edges.len()).unwrap_or_default(),
        documents,
        observation_digests,
        redaction_state: "REDACTED".to_owned(),
        budget: ledger.snapshot(),
        // Capture the adapter's real control state after collection. This is
        // especially important for a kill switch that may have tripped.
        controls: adapter.control_snapshot(),
    })
}

fn harness_error_kind(error: &crate::error::SupplyChainError) -> HarnessErrorKind {
    match error {
        crate::error::SupplyChainError::BudgetExhausted(_) => HarnessErrorKind::BudgetExhausted,
        _ => HarnessErrorKind::DocumentRefused,
    }
}

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
            "{} independent supply-chain violation(s) were observed across {decided} decided invariant(s); {undecided} could not be decided from the evidence read",
            violations.len()
        ),
        Verdict::Error => "the run could not read the evidence it was asked to evaluate, so no supply-chain conclusion is available in either direction".to_owned(),
        Verdict::Inconclusive => format!(
            "no violation was observed, and {undecided} of {} invariant(s) lacked the evidence needed to decide them; this run does not establish that the supply chain is intact",
            outcomes.len()
        ),
        Verdict::Pass => format!(
            "all {decided} applicable invariant(s) held under the evidence read; this is a statement about the evidence supplied, not that the supply chain is secure"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_synthetic::LocalSyntheticAdapter;
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
    fn a_substituted_artifact_produces_a_failing_artifact() {
        let result = simulated(ReferenceBehavior::DigestSubstituted);
        assert!(result.is_violation());
        assert!(!result.violations.is_empty());
        assert_eq!(result.outcomes.len(), 12);
    }

    #[test]
    fn local_synthetic_result_persists_the_control_snapshot() {
        let mut scenario = scenario(
            "supply-lab-controls",
            SupplyChainInvariant::ComponentIdentityUnambiguous,
        );
        scenario.mode = SupplyChainMode::LocalSynthetic;
        scenario.evidence_files = Vec::new();
        scenario.reference_behavior = Some(ReferenceBehavior::Compliant);
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &adapter, &mut ledger).expect("runs");
        let controls = result.controls.expect("control snapshot");
        assert_eq!(controls.state_changes, 0);
        assert_eq!(controls.external_egress_bytes, 0);
        assert!(!controls.kill_switch_triggered);
    }

    #[test]
    fn a_clean_run_never_claims_the_supply_chain_is_secure() {
        let result = simulated(ReferenceBehavior::Compliant);
        assert!(result.reason.contains("evidence"));
        assert!(!result.reason.eq_ignore_ascii_case("supply chain is secure"));
    }
}
