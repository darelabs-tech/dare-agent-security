//! The simulated adapter: an evidence bundle constructed in memory.
//!
//! Every bundle it produces comes from a [`ReferenceBehavior`] — a *behaviour*,
//! never a verdict. `DIGEST_SUBSTITUTED` says the recorded digest is not the
//! approved one; it does not say the run should FAIL, and nothing in this file
//! decides that. The evaluator reads the constructed evidence exactly as it
//! reads an imported document, and reaches its own conclusion.
//!
//! That separation is what makes the paired corpus worth having. If the staging
//! function also declared the expected outcome, every pair would test whether
//! the fixture author and the evaluator agreed about a label, rather than
//! whether the evaluator can see a substitution.

use std::collections::{BTreeMap, BTreeSet};

use crate::attestation::AttestationRecord;
use crate::budget::AdmissionLedger;
use crate::capability::projection;
use crate::component::{ArtifactDigest, Component, SupplierClaim};
use crate::error::{Result, SupplyChainError};
use crate::harness::SupplyChainAdapter;
use crate::manifest::{
    ApprovedComponent, DareManifest, ExpectedEdge, ExpectedLineage, TrustPolicy,
};
use crate::model::SupplyChainScenario;
use crate::normalize::{BomFormat, EvidenceBuilder, SupplyChainEvidence};
use crate::provenance::ProvenanceRecord;
use crate::relationship::{RelationType, Relationship, RelationshipGraph};
use crate::source::{
    ComponentType, DigestAlgorithm, EvidenceSource, ObservationKind, ReferenceBehavior,
    SupplyChainMode, VerificationStatus,
};

/// Construct an evidence bundle from a reference behaviour.
pub struct SimulatedAdapter;

impl SimulatedAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SimulatedAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyChainAdapter for SimulatedAdapter {
    fn mode(&self) -> SupplyChainMode {
        SupplyChainMode::Simulated
    }

    fn collect(
        &self,
        scenario: &SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence> {
        scenario.validate()?;
        let behavior = scenario.reference_behavior.ok_or_else(|| {
            SupplyChainError::invalid(format!(
                "scenario `{}` runs in SIMULATED mode without naming a reference behaviour, so \
                 there is nothing to construct",
                scenario.scenario_id
            ))
        })?;
        stage(behavior, ledger)
    }
}

/// Build the bundle one reference behaviour describes.
///
/// Public so the corpus can stage a bundle without going through an adapter,
/// and so a test can assert what a behaviour produces rather than what a run
/// concluded about it.
pub fn stage(
    behavior: ReferenceBehavior,
    ledger: &mut AdmissionLedger,
) -> Result<SupplyChainEvidence> {
    use ReferenceBehavior as B;

    if behavior == B::HarnessFailure {
        // The adapter fails, so the run reports ERROR rather than a security
        // conclusion. A staged harness failure that quietly produced a clean
        // bundle would test the opposite of what it is for.
        return Err(SupplyChainError::refusal(
            "the staged harness could not assemble an evidence bundle".to_owned(),
        ));
    }

    let mut components = vec![package("react", "1.0.0", "a", Some("acme"))];
    let mut graph = RelationshipGraph::new();
    let mut provenance = vec![provenance_for("react", "a", "builder-ci")];
    let mut attestations = vec![attestation_for("react", "a", "signer-release")];
    let mut manifest = baseline_manifest();
    let mut undeclared: BTreeSet<String> = BTreeSet::new();

    match behavior {
        B::Compliant | B::HarnessFailure => {}

        B::AmbiguousDuplicateIdentity => {
            // The same artifact under a second id: a policy approving one
            // leaves the other unapproved while a reader sees it as covered.
            let mut mirror = package("react-mirror", "1.0.0", "a", Some("acme"));
            mirror.name = "react".to_owned();
            components.push(mirror);
        }

        B::DigestSubstituted => {
            components[0].digests = BTreeSet::from([sha256("b")]);
        }

        B::MutableReferenceUsedAsIdentity => {
            let mut image = package("api-image", "latest", "a", Some("acme"));
            image.component_type = ComponentType::ContainerImage;
            image.digests.clear();
            components.push(image);
        }

        B::SourceSubstituted => {
            components[0].supplier.supplier_id = Some("unknown-vendor".to_owned());
        }

        B::ProvenanceSubjectMismatch => {
            provenance[0].subject_digests = BTreeSet::from([sha256("b")]);
        }

        B::UnauthorizedBuilder => {
            provenance[0].builder_id = Some("builder-unknown".to_owned());
        }

        B::AttestationSubjectMismatch => {
            attestations[0].subject_digests = BTreeSet::from([sha256("b")]);
        }

        B::UnapprovedSigner => {
            attestations[0].signer_id = Some("signer-unknown".to_owned());
        }

        B::UnexpectedDependencyEdge => {
            components.push(package("app", "1.0.0", "c", Some("acme")));
            components.push(package("left-pad", "1.0.0", "d", Some("acme")));
            manifest.expected_edges = BTreeSet::from([expected_edge("app", "react")]);
            graph.insert(observed_edge("app", "react", RelationType::DependsOn))?;
            graph.insert(observed_edge("app", "left-pad", RelationType::DependsOn))?;
        }

        B::MissingExpectedDependencyEdge => {
            components.push(package("app", "1.0.0", "c", Some("acme")));
            // Something else is observed, so the graph is comparable and the
            // approved edge is visibly absent rather than the graph being empty.
            components.push(package("left-pad", "1.0.0", "d", Some("acme")));
            manifest.expected_edges = BTreeSet::from([expected_edge("app", "react")]);
            graph.insert(observed_edge("app", "left-pad", RelationType::DependsOn))?;
        }

        B::CapabilityDrifted => {
            let mut tool = package("file-tool", "1.0.0", "e", Some("acme"));
            tool.component_type = ComponentType::Tool;
            tool.capabilities = Some(projection(&["read-file"], &["read-file", "write-file"]));
            components.push(tool);
        }

        B::BaseModelSubstituted => {
            components.push(model("planner-model", "c"));
            components.push(model("base-attacker", "b"));
            components.push(model("base-approved", "a"));
            graph.insert(observed_edge(
                "planner-model",
                "base-attacker",
                RelationType::FineTunedFrom,
            ))?;
            manifest.expected_lineage = BTreeSet::from([expected_lineage("base-approved", "a")]);
        }

        B::DatasetSubstituted => {
            let mut dataset = package("training-corpus", "1.0.0", "b", Some("acme"));
            dataset.component_type = ComponentType::Dataset;
            components.push(dataset);
            components.push(model("planner-model", "c"));
            graph.insert(observed_edge(
                "planner-model",
                "training-corpus",
                RelationType::TrainedFrom,
            ))?;
            manifest
                .approved_components
                .insert(approved("training-corpus", "a"));
        }

        B::UndeclaredExternalComponent => {
            // Something arrived that the deployment never declared. An engine
            // that only checked named origins would report nothing about a
            // component that came from nowhere.
            let mut arrival = package("partner-agent", "1.0.0", "f", None);
            arrival.component_type = ComponentType::ExternalAgent;
            components.push(arrival);
            undeclared.insert("partner-agent".to_owned());
        }

        B::MultipleIndependentViolations => {
            // Three boundaries at once, so a run that reports only the first
            // understates what it saw.
            components[0].digests = BTreeSet::from([sha256("b")]);
            components[0].supplier.supplier_id = Some("unknown-vendor".to_owned());
            let mut tool = package("file-tool", "1.0.0", "e", Some("acme"));
            tool.component_type = ComponentType::Tool;
            tool.capabilities = Some(projection(&["read-file"], &["read-file", "write-file"]));
            components.push(tool);
        }

        B::NoRelevantObservation => {
            // A bundle with nothing to decide on. A service API is a running
            // endpoint rather than bytes, so no digest is owed for it, and no
            // approval, provenance or attestation evidence accompanies it. The
            // run must report INCONCLUSIVE rather than finding nothing to
            // disagree with and calling that a clean supply chain.
            components = vec![package("billing-api", "1.0.0", "a", None)];
            components[0].component_type = ComponentType::ServiceApi;
            components[0].digests.clear();
            provenance.clear();
            attestations.clear();
            manifest = DareManifest::default();
        }
    }

    // Everything observed is declared, except what a behaviour deliberately
    // leaves out. Declaring the undeclared component would erase the finding
    // the behaviour exists to stage.
    if !manifest.is_empty() {
        manifest.declared_component_ids = components
            .iter()
            .map(|component| component.component_id.clone())
            .filter(|id| !undeclared.contains(id))
            .collect();
    }

    EvidenceBuilder::new()
        .with_document("staged-bom", BomFormat::CycloneDx, b"{\"staged\":true}")
        .with_import(components, graph)
        .with_provenance(provenance)
        .with_attestations(attestations)
        .with_manifest(manifest)
        .build(ledger)
}

fn sha256(seed: &str) -> ArtifactDigest {
    ArtifactDigest {
        algorithm: DigestAlgorithm::Sha256,
        value: seed.repeat(64),
    }
}

fn package(id: &str, version: &str, digest_seed: &str, supplier: Option<&str>) -> Component {
    Component {
        component_id: id.to_owned(),
        component_type: ComponentType::Package,
        name: id.to_owned(),
        version: Some(version.to_owned()),
        digests: BTreeSet::from([sha256(digest_seed)]),
        identifiers: BTreeSet::new(),
        supplier: SupplierClaim {
            supplier_id: supplier.map(ToOwned::to_owned),
            ..Default::default()
        },
        source_trust: None,
        capabilities: None,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
        metadata: BTreeMap::new(),
    }
}

fn model(id: &str, digest_seed: &str) -> Component {
    let mut component = package(id, "1.0.0", digest_seed, Some("acme"));
    component.component_type = ComponentType::Model;
    component
}

fn observed_edge(source: &str, target: &str, relation: RelationType) -> Relationship {
    Relationship {
        source_id: source.to_owned(),
        target_id: target.to_owned(),
        relation,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
    }
}

fn expected_edge(source: &str, target: &str) -> ExpectedEdge {
    ExpectedEdge {
        source_id: source.to_owned(),
        target_id: target.to_owned(),
        relation: RelationType::DependsOn,
    }
}

fn expected_lineage(base_id: &str, base_seed: &str) -> ExpectedLineage {
    ExpectedLineage {
        component_id: "planner-model".to_owned(),
        base_component_id: base_id.to_owned(),
        base_digests: BTreeSet::from([sha256(base_seed)]),
    }
}

fn approved(id: &str, digest_seed: &str) -> ApprovedComponent {
    ApprovedComponent {
        component_id: id.to_owned(),
        name: None,
        version: None,
        digests: BTreeSet::from([sha256(digest_seed)]),
    }
}

fn provenance_for(subject: &str, digest_seed: &str, builder: &str) -> ProvenanceRecord {
    ProvenanceRecord {
        provenance_id: format!("prov-{subject}"),
        subject_component_id: subject.to_owned(),
        subject_digests: BTreeSet::from([sha256(digest_seed)]),
        builder_id: Some(builder.to_owned()),
        invocation_id: Some("run-1".to_owned()),
        source_material_ids: BTreeSet::new(),
        evidence_source: EvidenceSource::LocalProvenance,
    }
}

fn attestation_for(subject: &str, digest_seed: &str, signer: &str) -> AttestationRecord {
    AttestationRecord {
        attestation_id: format!("att-{subject}"),
        subject_component_id: subject.to_owned(),
        subject_digests: BTreeSet::from([sha256(digest_seed)]),
        predicate_type: Some("slsa-provenance".to_owned()),
        signer_id: Some(signer.to_owned()),
        verification_status: VerificationStatus::Valid,
        evidence_source: EvidenceSource::LocalAttestation,
    }
}

fn baseline_manifest() -> DareManifest {
    DareManifest {
        schema_version: "1".to_owned(),
        manifest_id: Some("staged-manifest".to_owned()),
        trust_policy: TrustPolicy {
            approved_suppliers: BTreeSet::from(["acme".to_owned()]),
            approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
            approved_signers: BTreeSet::from(["signer-release".to_owned()]),
            ..Default::default()
        },
        approved_components: BTreeSet::from([approved("react", "a")]),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::{aggregate, collect_observed_violations, evaluate_all};
    use crate::model::tests::scenario;
    use crate::model::SupplyChainInvariant;
    use crate::observation::project;
    use dare_security_evidence::Verdict;

    fn staged(behavior: ReferenceBehavior) -> SupplyChainEvidence {
        let mut ledger = AdmissionLedger::new();
        stage(behavior, &mut ledger).expect("stages")
    }

    #[test]
    fn the_compliant_behaviour_produces_no_violation_at_all() {
        // The control. If this failed, every vulnerable fixture would be
        // agreeing with a broken baseline rather than demonstrating a
        // difference.
        let violations =
            collect_observed_violations(&project(&staged(ReferenceBehavior::Compliant)));
        assert!(violations.is_empty(), "{violations:#?}");
    }

    #[test]
    fn every_reference_behaviour_stages_and_only_the_harness_failure_refuses() {
        // A behaviour that could not be staged would silently drop a corpus
        // entry while the count still looked right.
        for behavior in ReferenceBehavior::all() {
            let mut ledger = AdmissionLedger::new();
            let staged = stage(behavior, &mut ledger);
            if behavior == ReferenceBehavior::HarnessFailure {
                assert!(staged.is_err(), "the staged harness failure succeeded");
            } else {
                staged.unwrap_or_else(|error| panic!("{behavior:?} could not be staged: {error}"));
            }
        }
    }

    #[test]
    fn each_vulnerable_behaviour_is_seen_by_the_invariant_it_targets() {
        use ReferenceBehavior as B;
        use SupplyChainInvariant as I;

        for (behavior, expected) in [
            (
                B::AmbiguousDuplicateIdentity,
                I::ComponentIdentityUnambiguous,
            ),
            (B::DigestSubstituted, I::ArtifactDigestBoundToComponent),
            (
                B::MutableReferenceUsedAsIdentity,
                I::MutableReferenceNotUsedAsImmutableIdentity,
            ),
            (B::SourceSubstituted, I::ComponentSourceTrustPreserved),
            (
                B::UndeclaredExternalComponent,
                I::ComponentSourceTrustPreserved,
            ),
            (
                B::ProvenanceSubjectMismatch,
                I::ProvenanceSubjectAndBuilderBound,
            ),
            (B::UnauthorizedBuilder, I::ProvenanceSubjectAndBuilderBound),
            (
                B::AttestationSubjectMismatch,
                I::AttestationSubjectDigestPreserved,
            ),
            (B::UnapprovedSigner, I::AttestationSubjectDigestPreserved),
            (
                B::UnexpectedDependencyEdge,
                I::DependencyEdgeIntegrityPreserved,
            ),
            (
                B::MissingExpectedDependencyEdge,
                I::DependencyEdgeIntegrityPreserved,
            ),
            (B::CapabilityDrifted, I::ExternalCapabilityDriftNotObserved),
            (B::BaseModelSubstituted, I::ModelLineagePreserved),
            (B::DatasetSubstituted, I::DatasetProvenancePreserved),
        ] {
            let outcome = crate::invariant::evaluate(expected, &project(&staged(behavior)));
            assert_eq!(
                outcome.verdict,
                Verdict::Fail,
                "{behavior:?} was not seen by {}: {}",
                expected.as_str(),
                outcome.reason
            );
        }
    }

    #[test]
    fn a_run_with_nothing_to_decide_on_is_inconclusive_rather_than_clean() {
        // The failure mode the coverage contracts exist for: an engine that
        // finds nothing to disagree with must not call that a clean supply
        // chain.
        let observations = project(&staged(ReferenceBehavior::NoRelevantObservation));
        assert!(
            collect_observed_violations(&observations).is_empty(),
            "{:#?}",
            collect_observed_violations(&observations)
        );
        assert_eq!(
            aggregate(&evaluate_all(&observations)),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn the_staged_harness_failure_cannot_quietly_produce_a_clean_bundle() {
        let mut ledger = AdmissionLedger::new();
        assert!(stage(ReferenceBehavior::HarnessFailure, &mut ledger).is_err());
    }

    #[test]
    fn the_multi_violation_behaviour_retains_every_independent_finding() {
        let violations = collect_observed_violations(&project(&staged(
            ReferenceBehavior::MultipleIndependentViolations,
        )));
        let invariants: BTreeSet<&str> = violations
            .iter()
            .map(|violation| violation.invariant.as_str())
            .collect();
        assert!(invariants.contains("ARTIFACT_DIGEST_BOUND_TO_COMPONENT"));
        assert!(invariants.contains("COMPONENT_SOURCE_TRUST_PRESERVED"));
        assert!(invariants.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
    }

    #[test]
    fn staging_is_deterministic() {
        let left = crate::canonical::digest(&staged(ReferenceBehavior::DigestSubstituted)).unwrap();
        let right =
            crate::canonical::digest(&staged(ReferenceBehavior::DigestSubstituted)).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn the_staged_bundle_carries_no_expected_outcome() {
        // A behaviour is a behaviour. If staging also declared the outcome,
        // every pair would test whether the fixture author and the evaluator
        // agreed about a label.
        let rendered = serde_json::to_string(&staged(ReferenceBehavior::DigestSubstituted))
            .expect("serializes")
            .to_lowercase();
        for absent in ["expected", "verdict", "should_fail", "is_secure"] {
            assert!(
                !rendered.contains(absent),
                "the staged bundle carries `{absent}`"
            );
        }
    }

    #[test]
    fn a_simulated_scenario_without_a_behaviour_is_refused() {
        // There would be nothing to construct, and returning an empty bundle
        // would report INCONCLUSIVE for a fixture that was simply misconfigured.
        let mut plain = scenario(
            "supply-lab-sim",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        plain.mode = SupplyChainMode::Simulated;
        plain.reference_behavior = None;
        plain.evidence_files = Vec::new();

        let mut ledger = AdmissionLedger::new();
        assert!(SimulatedAdapter::new()
            .collect(&plain, &mut ledger)
            .is_err());
    }

    #[test]
    fn a_compliant_run_passes_on_the_invariants_that_apply_to_it() {
        // The compliant bundle carries no dependency edges, no model and no
        // dataset, so four invariants have no subject in it. Those are marked
        // inapplicable rather than undecided, and the aggregate is PASS.
        //
        // Counting them as undecided would make a clean result unreachable for
        // any system that does not contain one of everything, and an operator
        // who never sees PASS stops reading the difference between PASS and
        // INCONCLUSIVE.
        let compliant = evaluate_all(&project(&staged(ReferenceBehavior::Compliant)));
        assert!(compliant
            .iter()
            .all(|outcome| outcome.verdict != Verdict::Fail));

        let inapplicable: Vec<&str> = compliant
            .iter()
            .filter(|outcome| !outcome.applicable)
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert!(
            inapplicable.contains(&"MODEL_LINEAGE_PRESERVED"),
            "a bundle with no model was asked about model lineage: {inapplicable:?}"
        );
        assert_eq!(aggregate(&compliant), Verdict::Pass);

        assert_eq!(
            aggregate(&evaluate_all(&project(&staged(
                ReferenceBehavior::DigestSubstituted
            )))),
            Verdict::Fail
        );
    }

    #[test]
    fn simulated_evidence_is_synthetic() {
        assert!(SimulatedAdapter::new().evidence_is_synthetic());
        assert_eq!(SimulatedAdapter::new().mode(), SupplyChainMode::Simulated);
    }
}
