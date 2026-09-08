//! Local-synthetic collection, gated through the Cycle 009 controls.

use std::cell::Cell;

use dare_adversarial::model::ExecutionBudget;
use serde::{Deserialize, Serialize};

use crate::budget::AdmissionLedger;
use crate::error::{Result, SupplyChainError};
use crate::harness::SupplyChainAdapter;
use crate::limits;
use crate::model::SupplyChainScenario;
use crate::normalize::{BomFormat, EvidenceBuilder, SupplyChainEvidence};
use crate::source::{ReferenceBehavior, SupplyChainMode};

pub fn synthetic_budget(documents: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "supply-chain-security-synthetic".to_owned(),
        max_operations: documents.max(1),
        max_duration_seconds: 30,
        max_state_changes: limits::MAX_STATE_CHANGES,
        max_bytes_read: limits::HARD_MAX_BOM_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: 1,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainControlSnapshot {
    pub target_scenario_id: String,
    pub max_documents: u32,
    pub state_changes: u32,
    pub external_egress_bytes: u64,
    pub bytes_written: u64,
    pub kill_switch_triggered: bool,
}

#[derive(Debug, Clone)]
pub struct LocalSyntheticAdapter {
    target_scenario_id: String,
    kill_switch_triggered: Cell<bool>,
}

impl LocalSyntheticAdapter {
    pub fn new(target_scenario_id: impl Into<String>) -> Self {
        Self {
            target_scenario_id: target_scenario_id.into(),
            kill_switch_triggered: Cell::new(false),
        }
    }

    pub fn for_scenario(scenario: &SupplyChainScenario) -> Self {
        Self::new(scenario.scenario_id.clone())
    }

    pub fn snapshot(&self) -> SupplyChainControlSnapshot {
        let budget = synthetic_budget(1);
        SupplyChainControlSnapshot {
            target_scenario_id: self.target_scenario_id.clone(),
            max_documents: budget.max_operations,
            state_changes: budget.max_state_changes,
            external_egress_bytes: budget.max_external_egress_bytes,
            bytes_written: budget.max_bytes_written,
            kill_switch_triggered: self.kill_switch_triggered.get(),
        }
    }
}

impl SupplyChainAdapter for LocalSyntheticAdapter {
    fn mode(&self) -> SupplyChainMode {
        SupplyChainMode::LocalSynthetic
    }

    fn control_snapshot(&self) -> Option<SupplyChainControlSnapshot> {
        Some(self.snapshot())
    }

    fn collect(
        &self,
        scenario: &SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence> {
        scenario.validate()?;
        if scenario.scenario_id != self.target_scenario_id {
            self.kill_switch_triggered.set(true);
            return Err(SupplyChainError::refusal(format!(
                "the local-synthetic run was approved for `{}` and was pointed at another scenario",
                self.target_scenario_id
            )));
        }
        let behavior = scenario.reference_behavior.ok_or_else(|| {
            SupplyChainError::invalid(format!(
                "scenario `{}` runs in LOCAL_SYNTHETIC mode without naming a reference behaviour, so there is no document to generate",
                scenario.scenario_id
            ))
        })?;

        let document = generate_cyclonedx(behavior);
        let imported = crate::cyclonedx::import(&document, ledger)?;

        EvidenceBuilder::new()
            .with_document(&scenario.scenario_id, BomFormat::CycloneDx, &document)
            .with_import(imported.components, imported.graph)
            .build(ledger)
    }
}

pub fn generate_cyclonedx(behavior: ReferenceBehavior) -> Vec<u8> {
    let sha_a = "a".repeat(64);
    let sha_b = "b".repeat(64);

    let mut components = vec![serde_json::json!({
        "type": "library",
        "bom-ref": "react",
        "name": "react",
        "version": "1.0.0",
        "hashes": [{ "alg": "SHA-256", "content": sha_a }],
        "purl": "pkg:npm/react@1.0.0"
    })];

    match behavior {
        ReferenceBehavior::AmbiguousDuplicateIdentity => {
            components.push(serde_json::json!({
                "type": "library",
                "bom-ref": "react-mirror",
                "name": "react",
                "version": "1.0.0",
                "hashes": [{ "alg": "SHA-256", "content": sha_a }]
            }));
        }
        ReferenceBehavior::DigestSubstituted => {
            components[0]["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sha_b }]);
        }
        ReferenceBehavior::MutableReferenceUsedAsIdentity => {
            components.push(serde_json::json!({
                "type": "container",
                "bom-ref": "api-image",
                "name": "api-image",
                "version": "latest"
            }));
        }
        _ => {}
    }

    serde_json::to_vec(&serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": components
    }))
    .expect("a generated document serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::scenario;
    use crate::model::SupplyChainInvariant;

    fn synthetic_scenario(behavior: ReferenceBehavior) -> SupplyChainScenario {
        let mut scenario = scenario(
            "supply-lab-synthetic",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::LocalSynthetic;
        scenario.evidence_files = Vec::new();
        scenario.reference_behavior = Some(behavior);
        scenario
    }

    #[test]
    fn the_budget_pins_state_changes_egress_and_writes_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
    }

    #[test]
    fn control_snapshot_is_exposed_through_the_adapter_contract() {
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario);
        let snapshot = adapter.control_snapshot().expect("snapshot");
        assert_eq!(snapshot.target_scenario_id, scenario.scenario_id);
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_records_the_kill_switch() {
        let adapter = LocalSyntheticAdapter::new("supply-lab-elsewhere");
        let mut ledger = AdmissionLedger::new();
        assert!(adapter
            .collect(
                &synthetic_scenario(ReferenceBehavior::Compliant),
                &mut ledger,
            )
            .is_err());
        assert!(adapter.snapshot().kill_switch_triggered);
    }

    #[test]
    fn generation_is_deterministic() {
        for behavior in ReferenceBehavior::all() {
            assert_eq!(generate_cyclonedx(behavior), generate_cyclonedx(behavior));
        }
    }
}

#[cfg(test)]
mod cycle019_pre_review_tests {
    use super::*;
    use crate::invariant::{collect_observed_violations, evaluate};
    use crate::model::tests::scenario;
    use crate::model::SupplyChainInvariant;
    use crate::observation::project;
    use crate::schema::assert_no_hostile_fields;
    use dare_security_evidence::Verdict;

    fn synthetic_scenario(behavior: ReferenceBehavior) -> SupplyChainScenario {
        let mut scenario = scenario(
            "supply-lab-synthetic",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::LocalSynthetic;
        scenario.evidence_files = Vec::new();
        scenario.reference_behavior = Some(behavior);
        scenario
    }

    #[test]
    fn the_budget_pins_state_changes_egress_and_writes_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
    }

    #[test]
    fn a_generated_document_goes_through_the_real_importer() {
        // The point of this adapter. A bundle assembled in memory proves the
        // evaluators work; only a generated document proves the importer does.
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");

        assert_eq!(evidence.components.len(), 1);
        assert_eq!(evidence.components[0].component_id, "react");
        assert_eq!(evidence.documents.len(), 1);
        assert_eq!(evidence.documents[0].format, BomFormat::CycloneDx);
    }

    #[test]
    fn a_generated_substitution_is_seen_through_the_importer() {
        let scenario = synthetic_scenario(ReferenceBehavior::AmbiguousDuplicateIdentity);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");

        let outcome = evaluate(
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            &project(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_trips_the_kill_switch() {
        // The allocation would still look correct in every record, because the
        // record names the scenario the run was approved for.
        let adapter = LocalSyntheticAdapter::new("supply-lab-elsewhere");
        let mut ledger = AdmissionLedger::new();
        let error = adapter
            .collect(
                &synthetic_scenario(ReferenceBehavior::Compliant),
                &mut ledger,
            )
            .expect_err("must refuse");
        assert!(error.is_refusal());
    }

    #[test]
    fn generation_is_deterministic() {
        // A report's document digest is reproducible, so a changed digest means
        // a changed generator rather than a changed run.
        for behavior in ReferenceBehavior::all() {
            assert_eq!(
                generate_cyclonedx(behavior),
                generate_cyclonedx(behavior),
                "{behavior:?} generated two different documents"
            );
        }
    }

    #[test]
    fn no_generated_document_carries_a_hostile_field() {
        // The generator is inside the trust boundary, and a generator that
        // emitted a credential-shaped or fetch-shaped field would be teaching
        // the corpus that such fields are normal.
        for behavior in ReferenceBehavior::all() {
            let raw = generate_cyclonedx(behavior);
            let value: serde_json::Value = serde_json::from_slice(&raw).expect("parses");
            assert_no_hostile_fields(&value, "a generated document")
                .unwrap_or_else(|error| panic!("{behavior:?} generated {error}"));
        }
    }

    #[test]
    fn a_generated_document_carries_a_coordinate_and_nothing_fetches_it() {
        // Real documents carry purls, and refusing them would refuse every real
        // document. The boundary is that nothing resolves one, not that none
        // appears.
        let raw = generate_cyclonedx(ReferenceBehavior::Compliant);
        let text = String::from_utf8(raw).expect("utf-8");
        assert!(text.contains("pkg:npm/react@1.0.0"));
        assert!(!text.contains("http"));
    }

    #[test]
    fn a_synthetic_scenario_without_a_behaviour_is_refused() {
        let mut plain = synthetic_scenario(ReferenceBehavior::Compliant);
        plain.reference_behavior = None;
        let mut ledger = AdmissionLedger::new();
        assert!(LocalSyntheticAdapter::for_scenario(&plain)
            .collect(&plain, &mut ledger)
            .is_err());
    }

    #[test]
    fn the_snapshot_records_what_the_controls_allowed() {
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let snapshot = LocalSyntheticAdapter::for_scenario(&scenario).snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
        assert_eq!(snapshot.bytes_written, 0);
        assert!(!snapshot.kill_switch_triggered);
        assert_eq!(snapshot.target_scenario_id, "supply-lab-synthetic");
    }

    #[test]
    fn synthetic_evidence_is_marked_synthetic() {
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario);
        assert!(adapter.evidence_is_synthetic());
        assert_eq!(adapter.mode(), SupplyChainMode::LocalSynthetic);
    }

    #[test]
    fn a_generated_bundle_carries_no_approval_of_its_own() {
        // A generator that also produced the manifest would be approving the
        // components it invented, and every synthetic run would agree with
        // itself.
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");
        assert!(evidence.manifest.is_empty());
        assert!(collect_observed_violations(&project(&evidence)).is_empty());
    }
}
