//! The replay adapter: a previously captured bundle, re-evaluated locally.
//!
//! # The thing a recording must not bring with it
//!
//! A capture records what a system contained. It must not also record what was
//! approved — and this is the Cycle 017 lesson in this cycle's vocabulary.
//!
//! A recorded bundle can carry a manifest. If replay accepted it, whoever
//! produced the capture would be supplying both the evidence and the policy it
//! is judged against, and a recording could approve its own components,
//! builders and signers. Every invariant that compares observation against
//! approval would then compare a capture against itself.
//!
//! [`ReplayAdapter`] therefore **discards** the recorded manifest and applies a
//! local one supplied beside it. `a_recorded_manifest_cannot_approve_its_own
//! _components` asserts it.
//!
//! # Semantic binding
//!
//! Matching a scenario id is identity, not evidence. A capture is bound to the
//! run by what it *describes*: its semantic keys must match the ones the
//! scenario's expectation names, so a capture of a different system cannot be
//! replayed under this scenario's approvals.

use serde::{Deserialize, Serialize};

use crate::budget::AdmissionLedger;
use crate::error::{Result, SupplyChainError};
use crate::harness::SupplyChainAdapter;
use crate::manifest::DareManifest;
use crate::model::SupplyChainScenario;
use crate::normalize::SupplyChainEvidence;
use crate::source::SupplyChainMode;

/// A captured evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainCapture {
    pub schema_version: String,
    pub capture_id: String,
    /// The scenario the capture was taken under. Identity, never authority.
    pub scenario_id: String,
    /// Always `REPLAY`. A recording cannot ask to be run any other way.
    pub mode: SupplyChainMode,
    /// Always `true`. A capture cannot claim to be production evidence.
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
                "a capture declared a mode other than REPLAY; a recording cannot ask to be run \
                 as something else"
                    .to_owned(),
            ));
        }
        if !self.synthetic {
            return Err(SupplyChainError::refusal(
                "a capture declared itself non-synthetic; a recording is a recording, and a \
                 report must not present one as production evidence"
                    .to_owned(),
            ));
        }
        self.evidence.validate()
    }
}

/// Re-evaluate a captured bundle under a local policy.
pub struct ReplayAdapter {
    capture: SupplyChainCapture,
    local_manifest: DareManifest,
}

impl ReplayAdapter {
    /// The manifest is a separate argument on purpose: it is the one input the
    /// capture may not supply.
    pub fn new(capture: SupplyChainCapture, local_manifest: DareManifest) -> Self {
        Self {
            capture,
            local_manifest,
        }
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

        // The recorded manifest is discarded rather than merged. Merging would
        // let the capture add approvals the local policy never granted, which
        // is the same thing as the capture approving itself.
        evidence.manifest = DareManifest::default();

        // Semantic binding: the capture must describe the system the local
        // policy is about. A capture of a different deployment replayed under
        // these approvals would report on components nobody here runs.
        if !self.local_manifest.declared_component_ids.is_empty() {
            let recorded: std::collections::BTreeSet<&String> = evidence
                .components
                .iter()
                .map(|component| &component.component_id)
                .collect();
            let unmatched: Vec<&String> = self
                .local_manifest
                .declared_component_ids
                .iter()
                .filter(|declared| !recorded.contains(declared))
                .collect();
            if unmatched.len() == self.local_manifest.declared_component_ids.len() {
                return Err(SupplyChainError::BindingMismatch(
                    "the capture describes none of the components the local policy declares, so \
                     it is a recording of a different system"
                        .to_owned(),
                ));
            }
        }

        // Re-admitted rather than trusted. A capture is a file like any other
        // and can have grown past a bound since it was taken.
        for _ in &evidence.components {
            ledger.admit_component()?;
        }
        for _ in &evidence.graph.edges {
            ledger.admit_relationship()?;
        }

        let mut builder = crate::normalize::EvidenceBuilder::new()
            .with_import(evidence.components.clone(), evidence.graph.clone())
            .with_provenance(evidence.provenance.clone())
            .with_attestations(evidence.attestations.clone());
        for document in &evidence.documents {
            builder = builder.with_recorded_document(document.clone());
        }
        builder
            .with_manifest(self.local_manifest.clone())
            .build(&mut AdmissionLedger::new())
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
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
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
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);
    }

    #[test]
    fn a_recorded_manifest_cannot_approve_its_own_components() {
        // The capture approves the artifact it recorded; the local policy
        // approves a different one. If the recorded manifest survived, the
        // substitution would pass.
        let capture = captured(approving("a"));
        let mut ledger = AdmissionLedger::new();
        let evidence = ReplayAdapter::new(capture, approving("b"))
            .collect(&replay_scenario(), &mut ledger)
            .expect("replays");

        assert_eq!(
            evidence.manifest,
            approving("b"),
            "the recorded manifest survived replay"
        );
        let outcome = crate::invariant::evaluate(
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            &project(&evidence),
        );
        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "a capture approved its own components"
        );
    }

    #[test]
    fn a_capture_of_another_scenario_is_refused() {
        // Identity, checked because replaying a capture under someone else's
        // approvals reports on a system nobody ran.
        let mut capture = captured(DareManifest::default());
        capture.scenario_id = "supply-lab-elsewhere".to_owned();
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_describing_a_different_system_is_refused() {
        // Semantic binding. The scenario id can match while the recording is of
        // something else entirely.
        let mut policy = approving("a");
        policy.declared_component_ids = BTreeSet::from(["some-other-service".to_owned()]);

        let mut ledger = AdmissionLedger::new();
        let error = ReplayAdapter::new(captured(DareManifest::default()), policy)
            .collect(&replay_scenario(), &mut ledger)
            .expect_err("must be refused");
        assert!(error.to_string().contains("different system"));
    }

    #[test]
    fn a_capture_cannot_declare_itself_production_evidence() {
        let mut capture = captured(DareManifest::default());
        capture.synthetic = false;
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_cannot_ask_to_be_run_in_another_mode() {
        let mut capture = captured(DareManifest::default());
        capture.mode = SupplyChainMode::Static;
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, approving("a"))
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_cannot_carry_a_verdict() {
        let mut value =
            serde_json::to_value(captured(DareManifest::default())).expect("serializes");
        value
            .as_object_mut()
            .expect("an object")
            .insert("expected_verdict".to_owned(), serde_json::json!("PASS"));
        assert!(serde_json::from_value::<SupplyChainCapture>(value).is_err());
    }

    #[test]
    fn replayed_evidence_is_still_synthetic() {
        // A replayed observation is a recording, and a report must not present
        // it as something observed in production now.
        assert!(
            ReplayAdapter::new(captured(DareManifest::default()), approving("a"))
                .evidence_is_synthetic()
        );
    }
}
