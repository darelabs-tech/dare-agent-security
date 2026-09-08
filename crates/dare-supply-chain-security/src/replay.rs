//! The replay adapter: a previously captured bundle, re-evaluated locally.
//!
//! A capture supplies evidence, never approval. The recorded manifest is
//! discarded and a separate local manifest is applied. Replay also binds the
//! complete declared component scope: partial overlap is not proof that the
//! recording is of the same system.

use serde::{Deserialize, Serialize};

use crate::budget::AdmissionLedger;
use crate::error::{Result, SupplyChainError};
use crate::harness::SupplyChainAdapter;
use crate::manifest::DareManifest;
use crate::model::SupplyChainScenario;
use crate::normalize::SupplyChainEvidence;
use crate::source::SupplyChainMode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainCapture {
    pub schema_version: String,
    pub capture_id: String,
    pub scenario_id: String,
    pub mode: SupplyChainMode,
    pub synthetic: bool,
    pub evidence: SupplyChainEvidence,
}

impl SupplyChainCapture {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "1" {
            return Err(SupplyChainError::schema(format!(
                "capture schema version `{}` is not supported",
                self.schema_version
            )));
        }
        if self.mode != SupplyChainMode::Replay {
            return Err(SupplyChainError::refusal(
                "a capture declared a mode other than REPLAY; a recording cannot ask to be run as something else".to_owned(),
            ));
        }
        if !self.synthetic {
            return Err(SupplyChainError::refusal(
                "a capture declared itself non-synthetic; a recording is a recording, and a report must not present one as production evidence".to_owned(),
            ));
        }
        self.evidence.validate()
    }
}

pub struct ReplayAdapter {
    capture: SupplyChainCapture,
    local_manifest: DareManifest,
}

impl ReplayAdapter {
    pub fn new(capture: SupplyChainCapture, local_manifest: DareManifest) -> Self {
        Self { capture, local_manifest }
    }
}

impl SupplyChainAdapter for ReplayAdapter {
    fn mode(&self) -> SupplyChainMode {
        SupplyChainMode::Replay
    }

    fn collect(
        &self,
        scenario: &SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence> {
        scenario.validate()?;
        self.capture.validate()?;
        self.local_manifest.validate()?;

        if self.capture.scenario_id != scenario.scenario_id {
            return Err(SupplyChainError::BindingMismatch(format!(
                "the capture was taken under scenario `{}` and is being replayed under `{}`",
                self.capture.scenario_id, scenario.scenario_id
            )));
        }

        let mut evidence = self.capture.evidence.clone();
        evidence.manifest = DareManifest::default();

        if !self.local_manifest.declared_component_ids.is_empty() {
            let recorded: std::collections::BTreeSet<String> = evidence
                .components
                .iter()
                .map(|component| component.component_id.clone())
                .collect();
            let declared = &self.local_manifest.declared_component_ids;

            // Exact declared-scope binding. The prior partial-overlap rule
            // accepted {A,X,Y} under a policy declaring {A,B,C}; one shared row
            // is identity coincidence, not semantic equivalence.
            if &recorded != declared {
                return Err(SupplyChainError::BindingMismatch(
                    "the capture component set does not exactly match the component scope declared by the local replay policy".to_owned(),
                ));
            }
        }

        // Rebuild with the external run-wide ledger. This performs component,
        // relationship and per-component record admission exactly once.
        let mut builder = crate::normalize::EvidenceBuilder::new()
            .with_import(evidence.components.clone(), evidence.graph.clone())
            .with_provenance(evidence.provenance.clone())
            .with_attestations(evidence.attestations.clone());
        for document in &evidence.documents {
            builder = builder.with_recorded_document(document.clone());
        }
        builder.with_manifest(self.local_manifest.clone()).build(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::tests::{component, digest};
    use crate::manifest::ApprovedComponent;
    use crate::model::tests::scenario;
    use crate::model::SupplyChainInvariant;
    use crate::normalize::{BomFormat, EvidenceBuilder};
    use crate::observation::project;
    use crate::relationship::RelationshipGraph;
    use crate::source::ComponentType;
    use dare_security_evidence::Verdict;
    use std::collections::BTreeSet;

    fn captured(manifest: DareManifest) -> SupplyChainCapture {
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_document("bom-1", BomFormat::CycloneDx, b"{}")
            .with_import(vec![component("react", ComponentType::Package)], RelationshipGraph::new())
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");
        SupplyChainCapture {
            schema_version: "1".to_owned(),
            capture_id: "capture-1".to_owned(),
            scenario_id: "supply-lab-replay".to_owned(),
            mode: SupplyChainMode::Replay,
            synthetic: true,
            evidence,
        }
    }

    fn replay_scenario() -> SupplyChainScenario {
        let mut scenario = scenario(
            "supply-lab-replay",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::Replay;
        scenario.evidence_files = Vec::new();
        scenario
    }

    fn approving(seed: &str) -> DareManifest {
        DareManifest {
            schema_version: "1".to_owned(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(),
                name: None,
                version: None,
                digests: BTreeSet::from([digest(seed)]),
            }]),
            declared_component_ids: BTreeSet::from(["react".to_owned()]),
            ..Default::default()
        }
    }

    #[test]
    fn a_capture_replays_under_the_local_policy() {
        let mut ledger = AdmissionLedger::new();
        let evidence = ReplayAdapter::new(captured(DareManifest::default()), approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .expect("replays");
        let outcome = crate::invariant::evaluate(
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            &project(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Pass);
        assert_eq!(ledger.snapshot().components_admitted, 1);
    }

    #[test]
    fn a_recorded_manifest_cannot_approve_its_own_components() {
        let capture = captured(approving("a"));
        let mut ledger = AdmissionLedger::new();
        let evidence = ReplayAdapter::new(capture, approving("b"))
            .collect(&replay_scenario(), &mut ledger)
            .expect("replays");
        assert_eq!(evidence.manifest, approving("b"));
        assert_eq!(
            crate::invariant::evaluate(
                SupplyChainInvariant::ArtifactDigestBoundToComponent,
                &project(&evidence),
            )
            .verdict,
            Verdict::Fail
        );
    }

    #[test]
    fn partial_component_overlap_is_refused() {
        let mut policy = approving("a");
        policy.declared_component_ids.insert("required-service".to_owned());
        let mut ledger = AdmissionLedger::new();
        let error = ReplayAdapter::new(captured(DareManifest::default()), policy)
            .collect(&replay_scenario(), &mut ledger)
            .expect_err("partial overlap must be refused");
        assert!(error.to_string().contains("does not exactly match"));
    }

    #[test]
    fn extra_recorded_components_are_refused_without_an_explicit_subset_policy() {
        let mut capture = captured(DareManifest::default());
        capture.evidence.components.push(component("extra", ComponentType::Package));
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_of_another_scenario_is_refused() {
        let mut capture = captured(DareManifest::default());
        capture.scenario_id = "supply-lab-elsewhere".to_owned();
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }
}
