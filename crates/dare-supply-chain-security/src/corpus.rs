//! The SUPPLY-LAB corpus.
//!
//! Forty entries, each describing one vector: which dimension it exercises,
//! which invariant it is built to be judged against, and how the evidence is
//! staged.
//!
//! # What an entry records, and what it cannot
//!
//! An entry records a **class** — control, attack, refusal or gap — and never a
//! verdict. There is no `expected_verdict` field, no `expected_findings`, no
//! `is_secure`. An entry that could state its own outcome would make the
//! evaluator ceremonial, and the corpus would test whether the fixture author
//! and the engine agreed about a label.
//!
//! The expectation lives in the *harness contract* instead, asserted once for
//! every entry of a class: every attack must be seen by its invariant, every
//! control must not be, every refusal must be refused before anything is
//! evaluated, and every gap must be undecidable rather than passing.
//!
//! # Why controls are half the corpus
//!
//! A corpus of attacks alone lets an over-strict engine look perfect. An engine
//! that reported FAIL for everything would score 100% against attacks and be
//! useless — worse than useless, because an operator would learn to ignore it.
//! Sixteen of the forty entries are controls or gaps for exactly that reason.

use crate::attestation::AttestationRecord;
use crate::budget::AdmissionLedger;
use crate::capability::projection;
use crate::component::{ArtifactDigest, Component, SupplierClaim};
use crate::error::Result;
use crate::manifest::{
    ApprovedComponent, DareManifest, ExpectedEdge, ExpectedLineage, TrustPolicy,
};
use crate::model::SupplyChainInvariant;
use crate::normalize::{BomFormat, EvidenceBuilder, SupplyChainEvidence};
use crate::provenance::ProvenanceRecord;
use crate::relationship::{RelationType, Relationship, RelationshipGraph};
use crate::simulated::stage;
use crate::source::{
    ComponentType, DigestAlgorithm, EvidenceSource, ObservationKind, ReferenceBehavior,
    ScenarioClass, VerificationStatus,
};
use std::collections::{BTreeMap, BTreeSet};

/// What a corpus entry is for.
///
/// A description of the vector, never of the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyLabClass {
    /// Legitimate activity the engine must not report.
    Control,
    /// A boundary crossing the engine must see.
    Attack,
    /// Input the engine must refuse before evaluating anything.
    Refusal,
    /// Evidence too thin to decide on, which must not pass.
    Gap,
}

impl SupplyLabClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "CONTROL",
            Self::Attack => "ATTACK",
            Self::Refusal => "REFUSAL",
            Self::Gap => "GAP",
        }
    }
}

/// One corpus entry.
pub struct SupplyLabEntry {
    pub id: &'static str,
    pub dimension: ScenarioClass,
    pub class: SupplyLabClass,
    /// The invariant this entry is built to be judged against.
    ///
    /// A coverage selector. Every other invariant is still evaluated, and a
    /// concrete failure of one of them is still retained.
    pub invariant: SupplyChainInvariant,
    pub description: &'static str,
    pub build: fn(&mut AdmissionLedger) -> Result<SupplyChainEvidence>,
}

/// The forty SUPPLY-LAB entries, in DESIGN section 26 order.
pub fn corpus() -> Vec<SupplyLabEntry> {
    use ScenarioClass as D;
    use SupplyChainInvariant as I;
    use SupplyLabClass as C;

    vec![
        entry(
            "SUPPLY-LAB-001",
            D::ComponentIdentity,
            C::Control,
            I::ComponentIdentityUnambiguous,
            "every component resolves to one canonical identity",
            compliant,
        ),
        entry(
            "SUPPLY-LAB-002",
            D::ComponentIdentity,
            C::Attack,
            I::ComponentIdentityUnambiguous,
            "one artifact appears under two canonical ids",
            ambiguous_identity,
        ),
        entry(
            "SUPPLY-LAB-003",
            D::ArtifactIntegrity,
            C::Control,
            I::ArtifactDigestBoundToComponent,
            "the observed digest is the approved digest",
            compliant,
        ),
        entry(
            "SUPPLY-LAB-004",
            D::ArtifactIntegrity,
            C::Attack,
            I::ArtifactDigestBoundToComponent,
            "the artifact was substituted under an approved identity",
            digest_substituted,
        ),
        entry(
            "SUPPLY-LAB-005",
            D::ComponentIdentity,
            C::Control,
            I::MutableReferenceNotUsedAsImmutableIdentity,
            "a floating tag beside an immutable digest is pinned by the digest",
            mutable_reference_with_digest,
        ),
        entry(
            "SUPPLY-LAB-006",
            D::ComponentIdentity,
            C::Attack,
            I::MutableReferenceNotUsedAsImmutableIdentity,
            "a floating tag is the only thing identifying an artifact",
            mutable_reference_as_identity,
        ),
        entry(
            "SUPPLY-LAB-007",
            D::SourceTrust,
            C::Control,
            I::ComponentSourceTrustPreserved,
            "the component came from a supplier local policy approved",
            compliant,
        ),
        entry(
            "SUPPLY-LAB-008",
            D::SourceTrust,
            C::Attack,
            I::ComponentSourceTrustPreserved,
            "the component came from a supplier nobody approved",
            source_substituted,
        ),
        entry(
            "SUPPLY-LAB-009",
            D::ProvenanceBinding,
            C::Control,
            I::ProvenanceSubjectAndBuilderBound,
            "provenance binds the subject artifact and names an approved builder",
            compliant,
        ),
        entry(
            "SUPPLY-LAB-010",
            D::ProvenanceBinding,
            C::Attack,
            I::ProvenanceSubjectAndBuilderBound,
            "provenance names the component and describes a different artifact",
            provenance_subject_mismatch,
        ),
        entry(
            "SUPPLY-LAB-011",
            D::ProvenanceBinding,
            C::Attack,
            I::ProvenanceSubjectAndBuilderBound,
            "provenance names a builder local policy does not approve",
            unauthorized_builder,
        ),
        entry(
            "SUPPLY-LAB-012",
            D::ProvenanceBinding,
            C::Gap,
            I::ComponentProvenanceSufficient,
            "no provenance evidence was collected at all",
            provenance_absent,
        ),
        entry(
            "SUPPLY-LAB-013",
            D::AttestationBinding,
            C::Control,
            I::AttestationSubjectDigestPreserved,
            "the attestation binds this artifact's digest and an approved signer",
            compliant,
        ),
        entry(
            "SUPPLY-LAB-014",
            D::AttestationBinding,
            C::Attack,
            I::AttestationSubjectDigestPreserved,
            "the attestation names the component and binds another artifact's digest",
            attestation_subject_mismatch,
        ),
        entry(
            "SUPPLY-LAB-015",
            D::AttestationBinding,
            C::Attack,
            I::AttestationSubjectDigestPreserved,
            "a locally valid signature by a signer nobody approved",
            unapproved_signer,
        ),
        entry(
            "SUPPLY-LAB-016",
            D::DependencyIntegrity,
            C::Control,
            I::DependencyEdgeIntegrityPreserved,
            "declared and observed dependency edges agree",
            dependency_agreeing,
        ),
        entry(
            "SUPPLY-LAB-017",
            D::DependencyIntegrity,
            C::Attack,
            I::DependencyEdgeIntegrityPreserved,
            "a dependency edge nobody declared was observed",
            dependency_inserted,
        ),
        entry(
            "SUPPLY-LAB-018",
            D::DependencyIntegrity,
            C::Attack,
            I::DependencyEdgeIntegrityPreserved,
            "a declared dependency edge was not observed",
            dependency_missing,
        ),
        entry(
            "SUPPLY-LAB-019",
            D::DependencyIntegrity,
            C::Refusal,
            I::DependencyEdgeIntegrityPreserved,
            "an edge names a component nothing inventoried",
            dangling_edge,
        ),
        entry(
            "SUPPLY-LAB-020",
            D::CapabilityDrift,
            C::Control,
            I::ExternalCapabilityDriftNotObserved,
            "the observed capability set is the approved one",
            capability_unchanged,
        ),
        entry(
            "SUPPLY-LAB-021",
            D::CapabilityDrift,
            C::Attack,
            I::ExternalCapabilityDriftNotObserved,
            "a component gained a capability since approval",
            capability_drifted,
        ),
        entry(
            "SUPPLY-LAB-022",
            D::CapabilityDrift,
            C::Gap,
            I::ExternalCapabilityDriftNotObserved,
            "only one side of the capability comparison exists",
            capability_one_sided,
        ),
        entry(
            "SUPPLY-LAB-023",
            D::ModelLineage,
            C::Control,
            I::ModelLineagePreserved,
            "the model derives from the approved base and its approved build",
            lineage_agreeing,
        ),
        entry(
            "SUPPLY-LAB-024",
            D::ModelLineage,
            C::Attack,
            I::ModelLineagePreserved,
            "the base model was substituted while the model's name stayed the same",
            lineage_substituted,
        ),
        entry(
            "SUPPLY-LAB-025",
            D::ModelLineage,
            C::Gap,
            I::ModelLineagePreserved,
            "no lineage edge was recorded for a model under an approved expectation",
            lineage_absent,
        ),
        entry(
            "SUPPLY-LAB-026",
            D::DatasetProvenance,
            C::Control,
            I::DatasetProvenancePreserved,
            "the training dataset is the approved one",
            dataset_agreeing,
        ),
        entry(
            "SUPPLY-LAB-027",
            D::DatasetProvenance,
            C::Attack,
            I::DatasetProvenancePreserved,
            "the training dataset was substituted under an approved identity",
            dataset_substituted,
        ),
        entry(
            "SUPPLY-LAB-028",
            D::ProvenanceBinding,
            C::Control,
            I::ComponentProvenanceSufficient,
            "an MCP server carries the same provenance evidence a package does",
            agentic_component_provenance,
        ),
        entry(
            "SUPPLY-LAB-029",
            D::SourceTrust,
            C::Attack,
            I::ComponentSourceTrustPreserved,
            "a component is present that the deployment never declared",
            undeclared_external_component,
        ),
        entry(
            "SUPPLY-LAB-030",
            D::BomCompleteness,
            C::Control,
            I::ComponentIdentityUnambiguous,
            "a CycloneDX 1.7 document normalizes into the internal model",
            cyclonedx_import,
        ),
        entry(
            "SUPPLY-LAB-031",
            D::BomCompleteness,
            C::Control,
            I::ComponentIdentityUnambiguous,
            "an SPDX 3.0.1 document normalizes into the same internal model",
            spdx_import,
        ),
        entry(
            "SUPPLY-LAB-032",
            D::BomCompleteness,
            C::Control,
            I::ComponentIdentityUnambiguous,
            "the SPDX half of the cross-format equivalence pair",
            spdx_equivalent_import,
        ),
        entry(
            "SUPPLY-LAB-033",
            D::BomCompleteness,
            C::Refusal,
            I::BomRequiredEvidencePresent,
            "a bill of materials declaring an unsupported specification version",
            unsupported_spec_version,
        ),
        entry(
            "SUPPLY-LAB-034",
            D::BomCompleteness,
            C::Refusal,
            I::BomRequiredEvidencePresent,
            "a document carrying a credential-shaped field",
            hostile_credential_field,
        ),
        entry(
            "SUPPLY-LAB-035",
            D::BomCompleteness,
            C::Refusal,
            I::BomRequiredEvidencePresent,
            "a document with more components than the hard maximum",
            oversized_component_set,
        ),
        entry(
            "SUPPLY-LAB-036",
            D::BomCompleteness,
            C::Attack,
            I::ArtifactDigestBoundToComponent,
            "three independent boundaries crossed in one bundle",
            multiple_violations,
        ),
        entry(
            "SUPPLY-LAB-037",
            D::BomCompleteness,
            C::Control,
            I::ComponentIdentityUnambiguous,
            "a document omitting optional metadata the selected invariant does not need",
            benign_metadata_omissions,
        ),
        entry(
            "SUPPLY-LAB-038",
            D::ComponentIdentity,
            C::Attack,
            I::ComponentIdentityUnambiguous,
            "two documents that each look consistent and collide once merged",
            cross_document_identity_conflict,
        ),
        entry(
            "SUPPLY-LAB-039",
            D::ArtifactIntegrity,
            C::Refusal,
            I::ArtifactDigestBoundToComponent,
            "a digest whose length does not match its algorithm",
            malformed_digest,
        ),
        entry(
            "SUPPLY-LAB-040",
            D::DependencyIntegrity,
            C::Control,
            I::DependencyEdgeIntegrityPreserved,
            "the same dependency edge recorded twice stays one edge",
            duplicate_edge_deduplicated,
        ),
    ]
}

fn entry(
    id: &'static str,
    dimension: ScenarioClass,
    class: SupplyLabClass,
    invariant: SupplyChainInvariant,
    description: &'static str,
    build: fn(&mut AdmissionLedger) -> Result<SupplyChainEvidence>,
) -> SupplyLabEntry {
    SupplyLabEntry {
        id,
        dimension,
        class,
        invariant,
        description,
        build,
    }
}

// --- staged bundles --------------------------------------------------------

fn compliant(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::Compliant, ledger)
}

fn ambiguous_identity(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::AmbiguousDuplicateIdentity, ledger)
}

fn digest_substituted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::DigestSubstituted, ledger)
}

fn mutable_reference_as_identity(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::MutableReferenceUsedAsIdentity, ledger)
}

fn source_substituted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::SourceSubstituted, ledger)
}

fn provenance_subject_mismatch(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::ProvenanceSubjectMismatch, ledger)
}

fn unauthorized_builder(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::UnauthorizedBuilder, ledger)
}

fn attestation_subject_mismatch(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::AttestationSubjectMismatch, ledger)
}

fn unapproved_signer(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::UnapprovedSigner, ledger)
}

fn dependency_inserted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::UnexpectedDependencyEdge, ledger)
}

fn dependency_missing(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::MissingExpectedDependencyEdge, ledger)
}

fn capability_drifted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::CapabilityDrifted, ledger)
}

fn lineage_substituted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::BaseModelSubstituted, ledger)
}

fn dataset_substituted(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::DatasetSubstituted, ledger)
}

fn undeclared_external_component(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::UndeclaredExternalComponent, ledger)
}

fn multiple_violations(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    stage(ReferenceBehavior::MultipleIndependentViolations, ledger)
}

// --- bundles this corpus builds itself -------------------------------------

fn sha256(seed: &str) -> ArtifactDigest {
    ArtifactDigest {
        algorithm: DigestAlgorithm::Sha256,
        value: seed.repeat(64),
    }
}

fn component_of(id: &str, kind: ComponentType, version: &str, seed: Option<&str>) -> Component {
    Component {
        component_id: id.to_owned(),
        component_type: kind,
        name: id.to_owned(),
        version: Some(version.to_owned()),
        digests: seed
            .map(|seed| BTreeSet::from([sha256(seed)]))
            .unwrap_or_default(),
        identifiers: BTreeSet::new(),
        supplier: SupplierClaim {
            supplier_id: Some("acme".to_owned()),
            ..Default::default()
        },
        source_trust: None,
        capabilities: None,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
        metadata: BTreeMap::new(),
    }
}

fn edge_of(source: &str, target: &str, relation: RelationType) -> Relationship {
    Relationship {
        source_id: source.to_owned(),
        target_id: target.to_owned(),
        relation,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
    }
}

fn policy() -> TrustPolicy {
    TrustPolicy {
        approved_suppliers: BTreeSet::from(["acme".to_owned()]),
        approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
        approved_signers: BTreeSet::from(["signer-release".to_owned()]),
        ..Default::default()
    }
}

fn manifest_of(components: &[Component]) -> DareManifest {
    DareManifest {
        schema_version: "1".to_owned(),
        trust_policy: policy(),
        declared_component_ids: components
            .iter()
            .map(|component| component.component_id.clone())
            .collect(),
        ..Default::default()
    }
}

fn build(
    components: Vec<Component>,
    graph: RelationshipGraph,
    manifest: DareManifest,
    provenance: Vec<ProvenanceRecord>,
    attestations: Vec<AttestationRecord>,
    ledger: &mut AdmissionLedger,
) -> Result<SupplyChainEvidence> {
    EvidenceBuilder::new()
        .with_document("supply-lab-bom", BomFormat::CycloneDx, b"{\"staged\":true}")
        .with_import(components, graph)
        .with_provenance(provenance)
        .with_attestations(attestations)
        .with_manifest(manifest)
        .build(ledger)
}

fn mutable_reference_with_digest(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // The control for entry 006. A `latest` tag is a naming convention; the
    // digest beside it is the identity, and reporting this would teach an
    // operator to skip the finding that matters.
    let image = component_of(
        "api-image",
        ComponentType::ContainerImage,
        "latest",
        Some("a"),
    );
    let components = vec![image];
    let manifest = manifest_of(&components);
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        Vec::new(),
        Vec::new(),
        ledger,
    )
}

fn provenance_absent(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // No provenance evidence of any kind. Distinct from provenance that exists
    // and names somebody else, which is a finding rather than a gap.
    let components = vec![component_of(
        "react",
        ComponentType::Package,
        "1.0.0",
        Some("a"),
    )];
    let manifest = manifest_of(&components);
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        Vec::new(),
        Vec::new(),
        ledger,
    )
}

fn dependency_agreeing(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let components = vec![
        component_of("app", ComponentType::Package, "1.0.0", Some("c")),
        component_of("react", ComponentType::Package, "1.0.0", Some("a")),
    ];
    let mut graph = RelationshipGraph::new();
    graph.insert(edge_of("app", "react", RelationType::DependsOn))?;
    let mut manifest = manifest_of(&components);
    manifest.expected_edges = BTreeSet::from([ExpectedEdge {
        source_id: "app".to_owned(),
        target_id: "react".to_owned(),
        relation: RelationType::DependsOn,
    }]);
    build(components, graph, manifest, Vec::new(), Vec::new(), ledger)
}

fn dangling_edge(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // An edge to something nobody inventoried is a dependency on a component
    // the bill of materials never described, which is the thing an inventory
    // exists to prevent.
    let components = vec![component_of(
        "app",
        ComponentType::Package,
        "1.0.0",
        Some("c"),
    )];
    let mut graph = RelationshipGraph::new();
    graph.insert(edge_of("app", "nowhere", RelationType::DependsOn))?;
    let manifest = manifest_of(&components);
    build(components, graph, manifest, Vec::new(), Vec::new(), ledger)
}

fn tool_with(approved: &[&str], observed: &[&str]) -> Component {
    let mut tool = component_of("file-tool", ComponentType::Tool, "1.0.0", Some("e"));
    tool.capabilities = Some(projection(approved, observed));
    tool
}

fn capability_unchanged(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let components = vec![tool_with(&["read-file"], &["read-file"])];
    let manifest = manifest_of(&components);
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        Vec::new(),
        Vec::new(),
        ledger,
    )
}

fn capability_one_sided(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // Observed capabilities with nothing approved. One side describes what
    // exists, and a difference needs two.
    let components = vec![tool_with(&[], &["read-file", "write-file"])];
    let manifest = manifest_of(&components);
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        Vec::new(),
        Vec::new(),
        ledger,
    )
}

fn lineage_bundle(base_seed: &str, ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let components = vec![
        component_of("planner-model", ComponentType::Model, "1.0.0", Some("c")),
        component_of(
            "base-approved",
            ComponentType::Model,
            "1.0.0",
            Some(base_seed),
        ),
    ];
    let mut graph = RelationshipGraph::new();
    graph.insert(edge_of(
        "planner-model",
        "base-approved",
        RelationType::FineTunedFrom,
    ))?;
    let mut manifest = manifest_of(&components);
    manifest.expected_lineage = BTreeSet::from([ExpectedLineage {
        component_id: "planner-model".to_owned(),
        base_component_id: "base-approved".to_owned(),
        base_digests: BTreeSet::from([sha256("a")]),
    }]);
    build(components, graph, manifest, Vec::new(), Vec::new(), ledger)
}

fn lineage_agreeing(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    lineage_bundle("a", ledger)
}

fn lineage_absent(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // An approved expectation and no observed lineage edge. The engine has
    // nothing to compare, and answering "matches" would answer a question
    // nobody asked.
    let components = vec![component_of(
        "planner-model",
        ComponentType::Model,
        "1.0.0",
        Some("c"),
    )];
    let mut manifest = manifest_of(&components);
    manifest.expected_lineage = BTreeSet::from([ExpectedLineage {
        component_id: "planner-model".to_owned(),
        base_component_id: "base-approved".to_owned(),
        base_digests: BTreeSet::from([sha256("a")]),
    }]);
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        Vec::new(),
        Vec::new(),
        ledger,
    )
}

fn dataset_agreeing(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let components = vec![
        component_of(
            "training-corpus",
            ComponentType::Dataset,
            "1.0.0",
            Some("a"),
        ),
        component_of("planner-model", ComponentType::Model, "1.0.0", Some("c")),
    ];
    let mut graph = RelationshipGraph::new();
    graph.insert(edge_of(
        "planner-model",
        "training-corpus",
        RelationType::TrainedFrom,
    ))?;
    let mut manifest = manifest_of(&components);
    manifest.approved_components = BTreeSet::from([ApprovedComponent {
        component_id: "training-corpus".to_owned(),
        name: None,
        version: None,
        digests: BTreeSet::from([sha256("a")]),
    }]);
    build(components, graph, manifest, Vec::new(), Vec::new(), ledger)
}

fn agentic_component_provenance(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // An MCP server is a supply-chain component like any other: the same
    // provenance and attestation machinery covers it, and no parallel model
    // exists for it.
    let components = vec![component_of(
        "filesystem-mcp",
        ComponentType::McpServer,
        "1.0.0",
        Some("a"),
    )];
    let manifest = manifest_of(&components);
    let provenance = vec![ProvenanceRecord {
        provenance_id: "prov-mcp".to_owned(),
        subject_component_id: "filesystem-mcp".to_owned(),
        subject_digests: BTreeSet::from([sha256("a")]),
        builder_id: Some("builder-ci".to_owned()),
        invocation_id: Some("run-1".to_owned()),
        source_material_ids: BTreeSet::new(),
        evidence_source: EvidenceSource::LocalProvenance,
    }];
    let attestations = vec![AttestationRecord {
        attestation_id: "att-mcp".to_owned(),
        subject_component_id: "filesystem-mcp".to_owned(),
        subject_digests: BTreeSet::from([sha256("a")]),
        predicate_type: Some("slsa-provenance".to_owned()),
        signer_id: Some("signer-release".to_owned()),
        verification_status: VerificationStatus::Valid,
        evidence_source: EvidenceSource::LocalAttestation,
    }];
    build(
        components,
        RelationshipGraph::new(),
        manifest,
        provenance,
        attestations,
        ledger,
    )
}

fn duplicate_edge_deduplicated(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // The same edge from two documents. It must stay one edge, or an agreeing
    // dependency would read as a duplicate and the graph would grow with every
    // document describing it.
    let components = vec![
        component_of("app", ComponentType::Package, "1.0.0", Some("c")),
        component_of("react", ComponentType::Package, "1.0.0", Some("a")),
    ];
    let mut graph = RelationshipGraph::new();
    graph.insert(edge_of("app", "react", RelationType::DependsOn))?;
    graph.insert(edge_of("app", "react", RelationType::DependsOn))?;
    let mut manifest = manifest_of(&components);
    manifest.expected_edges = BTreeSet::from([ExpectedEdge {
        source_id: "app".to_owned(),
        target_id: "react".to_owned(),
        relation: RelationType::DependsOn,
    }]);
    build(components, graph, manifest, Vec::new(), Vec::new(), ledger)
}

// --- bundles that go through a real importer -------------------------------

fn cyclonedx_bytes(spec_version: &str, digest: &str, extra: Option<serde_json::Value>) -> Vec<u8> {
    let mut component = serde_json::json!({
        "type": "library",
        "bom-ref": "react",
        "name": "react",
        "version": "1.0.0",
        "hashes": [{ "alg": "SHA-256", "content": digest }],
        "purl": "pkg:npm/react@1.0.0"
    });
    if let Some(extra) = extra {
        for (key, value) in extra.as_object().expect("an object") {
            component[key] = value.clone();
        }
    }
    serde_json::to_vec(&serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "components": [component]
    }))
    .expect("serializes")
}

fn spdx_bytes() -> Vec<u8> {
    let sha = "a".repeat(64);
    serde_json::to_vec(&serde_json::json!({
        "spdxVersion": "SPDX-3.0",
        "specVersion": "3.0.1",
        "@graph": [{
            "type": "software_Package",
            "spdxId": "react",
            "name": "react",
            "software_packageVersion": "1.0.0",
            "verifiedUsing": [{ "algorithm": "sha256", "hashValue": sha }]
        }]
    }))
    .expect("serializes")
}

fn import_cyclonedx(raw: &[u8], ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let imported = crate::cyclonedx::import(raw, ledger)?;
    EvidenceBuilder::new()
        .with_document("supply-lab-cdx", BomFormat::CycloneDx, raw)
        .with_import(imported.components, imported.graph)
        .build(ledger)
}

fn cyclonedx_import(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    import_cyclonedx(&cyclonedx_bytes("1.7", &"a".repeat(64), None), ledger)
}

fn spdx_import(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let raw = spdx_bytes();
    let imported = crate::spdx::import(&raw, ledger)?;
    EvidenceBuilder::new()
        .with_document("supply-lab-spdx", BomFormat::Spdx, &raw)
        .with_import(imported.components, imported.graph)
        .build(ledger)
}

fn spdx_equivalent_import(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    spdx_import(ledger)
}

fn unsupported_spec_version(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    import_cyclonedx(&cyclonedx_bytes("1.4", &"a".repeat(64), None), ledger)
}

fn hostile_credential_field(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    import_cyclonedx(
        &cyclonedx_bytes(
            "1.7",
            &"a".repeat(64),
            Some(serde_json::json!({ "api_key": "not-a-real-key" })),
        ),
        ledger,
    )
}

fn malformed_digest(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // A SHA-256 value of the wrong length. A digest nobody can compare is a
    // field that looks like integrity evidence and is not.
    import_cyclonedx(&cyclonedx_bytes("1.7", "abc123", None), ledger)
}

fn oversized_component_set(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    let sha = "a".repeat(64);
    let components: Vec<serde_json::Value> = (0..=crate::limits::HARD_MAX_COMPONENTS)
        .map(|index| {
            serde_json::json!({
                "type": "library",
                "bom-ref": format!("component-{index}"),
                "name": format!("component-{index}"),
                "version": "1.0.0",
                "hashes": [{ "alg": "SHA-256", "content": sha }]
            })
        })
        .collect();
    let raw = serde_json::to_vec(&serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": components
    }))
    .expect("serializes");
    import_cyclonedx(&raw, ledger)
}

fn benign_metadata_omissions(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // No supplier, no purl, no version. None of it is needed to decide whether
    // identities are unambiguous, and an engine that reported it would be
    // reporting incompleteness as insecurity.
    let raw = serde_json::to_vec(&serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [{
            "type": "library",
            "bom-ref": "react",
            "name": "react",
            "hashes": [{ "alg": "SHA-256", "content": "a".repeat(64) }]
        }]
    }))
    .expect("serializes");
    import_cyclonedx(&raw, ledger)
}

fn cross_document_identity_conflict(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    // Each document is internally consistent. The collision exists only once
    // they are merged, which is why validation runs on the assembled bundle.
    let first = component_of("react", ComponentType::Package, "1.0.0", Some("a"));
    let mut second = component_of("react-mirror", ComponentType::Package, "1.0.0", Some("a"));
    second.name = "react".to_owned();
    EvidenceBuilder::new()
        .with_document(
            "supply-lab-first",
            BomFormat::CycloneDx,
            b"{\"first\":true}",
        )
        .with_import(vec![first], RelationshipGraph::new())
        .with_document("supply-lab-second", BomFormat::Spdx, b"{\"second\":true}")
        .with_import(vec![second], RelationshipGraph::new())
        .build(ledger)
}

/// An adapter that stages one corpus entry by id.
///
/// The bridge between a scenario naming `SUPPLY-LAB-004` and the builder that
/// stages it. Lookup is by id and nothing else: a scenario naming an entry the
/// corpus does not contain is refused rather than running as though it had
/// named nothing, which would report a clean verdict for a vector nobody
/// exercised.
pub struct CorpusAdapter;

impl crate::harness::SupplyChainAdapter for CorpusAdapter {
    fn mode(&self) -> crate::source::SupplyChainMode {
        crate::source::SupplyChainMode::Simulated
    }

    fn collect(
        &self,
        scenario: &crate::model::SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence> {
        let entries = corpus();
        let entry = entries
            .iter()
            .find(|entry| entry.id == scenario.scenario_id)
            .ok_or_else(|| {
                crate::error::SupplyChainError::invalid(format!(
                    "the corpus contains no entry `{}`",
                    scenario.scenario_id
                ))
            })?;
        (entry.build)(ledger)
    }
}

/// Build the scenario one corpus entry describes.
///
/// The scenario carries no outcome, exactly as a hand-written one would not:
/// `class` and `primary_invariant` say which surface and which question, and
/// the evaluator decides the rest.
pub fn scenario_for(entry: &SupplyLabEntry) -> crate::model::SupplyChainScenario {
    crate::model::SupplyChainScenario {
        scenario_id: entry.id.to_owned(),
        class: entry.dimension,
        mode: crate::source::SupplyChainMode::Simulated,
        primary_invariant: entry.invariant,
        evidence_files: Vec::new(),
        reference_behavior: None,
        description: entry.description.to_owned(),
    }
}

/// Find one entry by id.
pub fn entry_by_id(id: &str) -> Option<SupplyLabEntry> {
    corpus().into_iter().find(|entry| entry.id == id)
}

/// The CycloneDX half of the cross-format equivalence pair.
///
/// Public so the equivalence test can compare the two halves without going
/// through a corpus entry, which would compare a bundle with itself.
pub fn cyclonedx_equivalence_half(ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
    cyclonedx_import(ledger)
}
