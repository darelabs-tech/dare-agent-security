//! The normalized observation model.
//!
//! Closed, typed, and carrying no verdict. An adapter reports what it saw; it
//! never reports what that means. There is deliberately no `Verdict` variant,
//! no `Violation` variant and no `expected_outcome` field — an adapter able to
//! emit one would be deciding the result, and the evaluator would be reduced to
//! transcribing whatever the fixture author wrote.
//!
//! # Why observations exist at all, given the evidence bundle already does
//!
//! [`crate::normalize::SupplyChainEvidence`] is what was *imported*.
//! Observations are what a run *saw*, and the difference is the whole basis for
//! `INCONCLUSIVE`: an evaluator asks whether a channel is present, and a
//! channel that no evidence supported is simply absent from the set. A missing
//! channel is then a gap the evaluator can report, rather than a `false` it
//! would have to interpret.
//!
//! This is why [`project`] emits nothing for a component with no digests
//! instead of emitting a digest context saying `has_digest: false`. The second
//! shape reads as an answer; the first is honestly the absence of one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attestation::{self, AttestationAssessment};
use crate::canonical::digest;
use crate::capability::{self, DriftAssessment};
use crate::component::Component;
use crate::dataset::{self, DatasetAssessment};
use crate::error::Result;
use crate::identity::{is_mutable_reference, resolve_identity, IdentityStrength};
use crate::model_lineage::{self, LineageAssessment};
use crate::normalize::{BomFormat, SupplyChainEvidence};
use crate::provenance::{self, ProvenanceAssessment};
use crate::relationship::Relationship;
use crate::source::{
    ComponentType, DigestAlgorithm, EvidenceSource, HarnessErrorKind, ObservationKind, TrustClass,
};

/// The observation channels an invariant may require.
///
/// Closed. An unknown wire value fails to decode rather than becoming an
/// unrecognized channel that every coverage contract would silently ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationChannel {
    BomDocumentContext,
    ComponentContext,
    ComponentDigestContext,
    SourceTrustContext,
    ProvenanceContext,
    AttestationContext,
    RelationshipContext,
    CapabilityContext,
    ModelLineageContext,
    DatasetProvenanceContext,
    DeclaredObservedComponentContext,
    HarnessError,
}

impl ObservationChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BomDocumentContext => "BOM_DOCUMENT_CONTEXT",
            Self::ComponentContext => "COMPONENT_CONTEXT",
            Self::ComponentDigestContext => "COMPONENT_DIGEST_CONTEXT",
            Self::SourceTrustContext => "SOURCE_TRUST_CONTEXT",
            Self::ProvenanceContext => "PROVENANCE_CONTEXT",
            Self::AttestationContext => "ATTESTATION_CONTEXT",
            Self::RelationshipContext => "RELATIONSHIP_CONTEXT",
            Self::CapabilityContext => "CAPABILITY_CONTEXT",
            Self::ModelLineageContext => "MODEL_LINEAGE_CONTEXT",
            Self::DatasetProvenanceContext => "DATASET_PROVENANCE_CONTEXT",
            Self::DeclaredObservedComponentContext => "DECLARED_OBSERVED_COMPONENT_CONTEXT",
            Self::HarnessError => "HARNESS_ERROR",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::BomDocumentContext,
            Self::ComponentContext,
            Self::ComponentDigestContext,
            Self::SourceTrustContext,
            Self::ProvenanceContext,
            Self::AttestationContext,
            Self::RelationshipContext,
            Self::CapabilityContext,
            Self::ModelLineageContext,
            Self::DatasetProvenanceContext,
            Self::DeclaredObservedComponentContext,
            Self::HarnessError,
        ]
    }
}

/// One imported bill-of-materials document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomDocumentContext {
    pub document_id: String,
    pub format: BomFormat,
    pub bytes: usize,
    pub content_digest: String,
}

/// One component, as identity rather than as inventory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentContext {
    pub component_id: String,
    pub component_type: ComponentType,
    pub name: String,
    pub version: Option<String>,
    pub observation: ObservationKind,
    pub evidence_source: EvidenceSource,
    pub identity_strength: IdentityStrength,
    /// Format-independent, so the same component from two documents is one
    /// identity.
    pub semantic_key: String,
    /// Whether the version this component is pinned by can move under it.
    pub uses_mutable_reference: bool,
    /// Whether an immutable artifact digest is expected for this class.
    pub expects_immutable_artifact: bool,
}

/// The integrity evidence recorded for one component.
///
/// Emitted only when at least one digest exists. A component with no digest
/// produces no digest context, which is what lets the evaluator say the
/// question was undecidable rather than answered `false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDigestContext {
    pub component_id: String,
    pub algorithms: BTreeSet<DigestAlgorithm>,
    pub digest_count: usize,
    /// Whether the manifest approved a digest for this component, and whether
    /// an observed digest matches it. `None` when either side named none.
    pub approved_digest_bound: Option<bool>,
}

/// What is known about where a component came from, and what policy says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustContext {
    pub component_id: String,
    pub source_id: Option<String>,
    pub supplier_id: Option<String>,
    pub publisher_id: Option<String>,
    /// The class a local approval established, if one did. A BOM claim never
    /// reaches this field.
    pub trust_class: Option<TrustClass>,
    /// Whether a local policy exists at all. An absent policy is a gap, not a
    /// denial.
    pub policy_present: bool,
    /// Whether every present origin claim is approved by its corresponding
    /// local policy set. `None` when no claim was made or no policy exists.
    pub policy_approves_origin: Option<bool>,
}

/// The provenance bindings for one component, plus what policy says about every
/// builder the matching provenance records name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceContext {
    pub assessment: ProvenanceAssessment,
    pub policy_present: bool,
    /// Compatibility summary for a single representative builder. Security
    /// decisions use the complete approved/unapproved sets below.
    pub builder_approved: Option<bool>,
    pub approved_builder_ids: BTreeSet<String>,
    pub unapproved_builder_ids: BTreeSet<String>,
}

/// The attestation bindings for one component, plus signer approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationContext {
    pub assessment: AttestationAssessment,
    pub policy_present: bool,
    /// Signers a local policy approved.
    pub approved_signer_ids: BTreeSet<String>,
    /// Signers it did not. Named rather than counted, because "an unapproved
    /// signer attested this" is only actionable if the operator learns which.
    pub unapproved_signer_ids: BTreeSet<String>,
}

/// The dependency graph as declared, as observed, and where the two differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipContext {
    pub declared_edge_count: usize,
    pub observed_edge_count: usize,
    pub agreed_edge_count: usize,
    /// Observed edges nothing declared — an inserted dependency.
    pub undeclared_edge_keys: Vec<String>,
    /// Declared edges nothing observed — a missing dependency.
    pub unobserved_edge_keys: Vec<String>,
    /// Whether both sides exist, so the comparison can be made at all.
    pub comparable: bool,
}

/// Capability drift for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityContext {
    pub assessment: DriftAssessment,
}

/// Model lineage for one model component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelLineageContext {
    pub assessment: LineageAssessment,
}

/// Dataset provenance for one dataset component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetProvenanceContext {
    pub assessment: DatasetAssessment,
}

/// The declared inventory against the observed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredObservedContext {
    pub declared_only_ids: Vec<String>,
    pub observed_only_ids: Vec<String>,
    pub agreed_ids: Vec<String>,
    pub comparable: bool,
}

/// Why a run could not observe.
///
/// Not a finding. A harness that failed produces no security conclusion in
/// either direction, and an evaluator that read this as evidence of a problem
/// would turn every broken adapter into a vulnerability report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessErrorContext {
    pub kind: HarnessErrorKind,
    /// Operator-facing, and never an echo of refused input.
    pub reason: String,
}

/// One normalized observation.
///
/// The closed set. Note what is missing: there is no `Verdict`, `Violation`,
/// `Finding` or `ExpectedOutcome` variant, and no variant carries a field
/// shaped like one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub enum SupplyChainObservation {
    BomDocumentContext(BomDocumentContext),
    ComponentContext(ComponentContext),
    ComponentDigestContext(ComponentDigestContext),
    SourceTrustContext(SourceTrustContext),
    ProvenanceContext(ProvenanceContext),
    AttestationContext(AttestationContext),
    RelationshipContext(RelationshipContext),
    CapabilityContext(CapabilityContext),
    ModelLineageContext(ModelLineageContext),
    DatasetProvenanceContext(DatasetProvenanceContext),
    DeclaredObservedComponentContext(DeclaredObservedContext),
    HarnessError(HarnessErrorContext),
}

impl SupplyChainObservation {
    pub fn channel(&self) -> ObservationChannel {
        match self {
            Self::BomDocumentContext(_) => ObservationChannel::BomDocumentContext,
            Self::ComponentContext(_) => ObservationChannel::ComponentContext,
            Self::ComponentDigestContext(_) => ObservationChannel::ComponentDigestContext,
            Self::SourceTrustContext(_) => ObservationChannel::SourceTrustContext,
            Self::ProvenanceContext(_) => ObservationChannel::ProvenanceContext,
            Self::AttestationContext(_) => ObservationChannel::AttestationContext,
            Self::RelationshipContext(_) => ObservationChannel::RelationshipContext,
            Self::CapabilityContext(_) => ObservationChannel::CapabilityContext,
            Self::ModelLineageContext(_) => ObservationChannel::ModelLineageContext,
            Self::DatasetProvenanceContext(_) => ObservationChannel::DatasetProvenanceContext,
            Self::DeclaredObservedComponentContext(_) => {
                ObservationChannel::DeclaredObservedComponentContext
            }
            Self::HarnessError(_) => ObservationChannel::HarnessError,
        }
    }

    /// The component this observation is about, where it is about one.
    pub fn component_id(&self) -> Option<&str> {
        match self {
            Self::ComponentContext(context) => Some(&context.component_id),
            Self::ComponentDigestContext(context) => Some(&context.component_id),
            Self::SourceTrustContext(context) => Some(&context.component_id),
            Self::ProvenanceContext(context) => Some(&context.assessment.component_id),
            Self::AttestationContext(context) => Some(&context.assessment.component_id),
            Self::CapabilityContext(context) => Some(&context.assessment.component_id),
            Self::ModelLineageContext(context) => Some(&context.assessment.component_id),
            Self::DatasetProvenanceContext(context) => Some(&context.assessment.component_id),
            Self::BomDocumentContext(_)
            | Self::RelationshipContext(_)
            | Self::DeclaredObservedComponentContext(_)
            | Self::HarnessError(_) => None,
        }
    }

    /// A stable digest of this observation, for citation as deciding evidence.
    ///
    /// A finding with no deciding evidence is an assertion rather than a
    /// finding: an operator has to be able to get from the verdict back to
    /// what was seen.
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

/// Everything one run observed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSet {
    #[serde(default)]
    pub observations: Vec<SupplyChainObservation>,
}

impl ObservationSet {
    pub fn new(observations: Vec<SupplyChainObservation>) -> Self {
        Self { observations }
    }

    /// The channels this run actually produced.
    pub fn channels(&self) -> BTreeSet<ObservationChannel> {
        self.observations
            .iter()
            .map(SupplyChainObservation::channel)
            .collect()
    }

    pub fn has_channel(&self, channel: ObservationChannel) -> bool {
        self.observations
            .iter()
            .any(|observation| observation.channel() == channel)
    }

    /// Whether the run failed to observe.
    pub fn has_harness_error(&self) -> bool {
        self.has_channel(ObservationChannel::HarnessError)
    }

    /// Observations about one component, in the order they were produced.
    pub fn for_component<'a>(
        &'a self,
        component_id: &'a str,
    ) -> impl Iterator<Item = &'a SupplyChainObservation> {
        self.observations
            .iter()
            .filter(move |observation| observation.component_id() == Some(component_id))
    }
}

/// Project an evidence bundle into normalized observations.
///
/// Deterministic and total: the same bundle always produces the same
/// observations in the same order. Components are visited in the order the
/// bundle holds them, and every collection inside an observation is ordered,
/// so two runs over the same evidence digest identically.
pub fn project(evidence: &SupplyChainEvidence) -> ObservationSet {
    let mut observations = Vec::new();
    let policy = &evidence.manifest.trust_policy;
    let policy_present = !policy.is_empty();

    for document in &evidence.documents {
        observations.push(SupplyChainObservation::BomDocumentContext(
            BomDocumentContext {
                document_id: document.document_id.clone(),
                format: document.format,
                bytes: document.bytes,
                content_digest: document.content_digest.clone(),
            },
        ));
    }

    for component in &evidence.components {
        observations.push(SupplyChainObservation::ComponentContext(component_context(
            component,
        )));

        // Emitted only when a digest exists. "No digest" is the absence of an
        // answer, and a context saying `has_digest: false` would read as one.
        if !component.digests.is_empty() {
            observations.push(SupplyChainObservation::ComponentDigestContext(
                digest_context(component, evidence),
            ));
        }

        if !component.supplier.is_empty() || component.source_trust.is_some() {
            observations.push(SupplyChainObservation::SourceTrustContext(
                source_trust_context(component, evidence, policy_present),
            ));
        }

        if !evidence.provenance.is_empty() {
            let assessment = provenance::assess(component, &evidence.provenance);
            let builder_approved = assessment
                .builder_id
                .as_ref()
                .filter(|_| policy_present)
                .map(|builder| policy.approves_builder(builder));
            let (approved_builder_ids, unapproved_builder_ids) = if policy_present {
                assessment
                    .builder_ids
                    .iter()
                    .cloned()
                    .partition(|builder| policy.approves_builder(builder))
            } else {
                (BTreeSet::new(), BTreeSet::new())
            };
            observations.push(SupplyChainObservation::ProvenanceContext(
                ProvenanceContext {
                    assessment,
                    policy_present,
                    builder_approved,
                    approved_builder_ids,
                    unapproved_builder_ids,
                },
            ));
        }

        if !evidence.attestations.is_empty() {
            let assessment = attestation::assess(component, &evidence.attestations);
            let (approved_signer_ids, unapproved_signer_ids) = if policy_present {
                assessment
                    .signer_ids
                    .iter()
                    .cloned()
                    .partition(|signer| policy.approves_signer(signer))
            } else {
                (BTreeSet::new(), BTreeSet::new())
            };
            observations.push(SupplyChainObservation::AttestationContext(
                AttestationContext {
                    assessment,
                    policy_present,
                    approved_signer_ids,
                    unapproved_signer_ids,
                },
            ));
        }

        if component.capabilities.is_some()
            || evidence
                .manifest
                .approved_capabilities
                .contains_key(&component.component_id)
        {
            observations.push(SupplyChainObservation::CapabilityContext(
                CapabilityContext {
                    assessment: capability::assess(component, &evidence.manifest),
                },
            ));
        }

        if component.component_type.expects_lineage() {
            observations.push(SupplyChainObservation::ModelLineageContext(
                ModelLineageContext {
                    assessment: model_lineage::assess(component, evidence, &evidence.manifest),
                },
            ));
        }

        if component.component_type == ComponentType::Dataset {
            observations.push(SupplyChainObservation::DatasetProvenanceContext(
                DatasetProvenanceContext {
                    assessment: dataset::assess(component, evidence, &evidence.manifest),
                },
            ));
        }
    }

    if !evidence.graph.edges.is_empty() {
        observations.push(SupplyChainObservation::RelationshipContext(
            relationship_context(evidence),
        ));
    }

    if !evidence.manifest.declared_component_ids.is_empty() || !evidence.components.is_empty() {
        observations.push(SupplyChainObservation::DeclaredObservedComponentContext(
            declared_observed_context(evidence),
        ));
    }

    ObservationSet::new(observations)
}

fn component_context(component: &Component) -> ComponentContext {
    let identity = resolve_identity(component);
    ComponentContext {
        component_id: component.component_id.clone(),
        component_type: component.component_type,
        name: component.name.clone(),
        version: component.version.clone(),
        observation: component.observation,
        evidence_source: component.evidence_source,
        identity_strength: identity.strength,
        semantic_key: identity.semantic_key,
        uses_mutable_reference: component
            .version
            .as_deref()
            .is_some_and(is_mutable_reference),
        expects_immutable_artifact: component.component_type.expects_immutable_artifact(),
    }
}

fn digest_context(component: &Component, evidence: &SupplyChainEvidence) -> ComponentDigestContext {
    let approved_digest_bound = evidence
        .manifest
        .approved(&component.component_id)
        .and_then(|approved| {
            if approved.digests.is_empty() {
                return None;
            }
            Some(
                approved
                    .digests
                    .intersection(&component.digests)
                    .next()
                    .is_some(),
            )
        });

    ComponentDigestContext {
        component_id: component.component_id.clone(),
        algorithms: component
            .digests
            .iter()
            .map(|digest| digest.algorithm)
            .collect(),
        digest_count: component.digests.len(),
        approved_digest_bound,
    }
}

fn source_trust_context(
    component: &Component,
    evidence: &SupplyChainEvidence,
    policy_present: bool,
) -> SourceTrustContext {
    let claim = &component.supplier;
    let policy_approves_origin = policy_present.then(|| {
        evidence.manifest.trust_policy.approves_origin(
            claim.source_id.as_deref(),
            claim.supplier_id.as_deref(),
            claim.publisher_id.as_deref(),
        )
    });

    SourceTrustContext {
        component_id: component.component_id.clone(),
        source_id: claim.source_id.clone(),
        supplier_id: claim.supplier_id.clone(),
        publisher_id: claim.publisher_id.clone(),
        trust_class: component
            .source_trust
            .as_ref()
            .map(|assessment| assessment.trust),
        policy_present,
        policy_approves_origin: policy_approves_origin.flatten(),
    }
}

fn relationship_context(evidence: &SupplyChainEvidence) -> RelationshipContext {
    let graph = &evidence.graph;
    let count = |kind: ObservationKind| {
        graph
            .edges
            .iter()
            .filter(|edge| edge.observation == kind)
            .count()
    };
    let agreed = count(ObservationKind::DeclaredAndObserved);

    RelationshipContext {
        declared_edge_count: count(ObservationKind::Declared) + agreed,
        observed_edge_count: count(ObservationKind::Observed) + agreed,
        agreed_edge_count: agreed,
        undeclared_edge_keys: graph
            .undeclared_dependencies()
            .into_iter()
            .map(Relationship::edge_key)
            .collect(),
        unobserved_edge_keys: graph
            .unobserved_dependencies()
            .into_iter()
            .map(Relationship::edge_key)
            .collect(),
        comparable: graph.is_comparable(),
    }
}

fn declared_observed_context(evidence: &SupplyChainEvidence) -> DeclaredObservedContext {
    let declared = &evidence.manifest.declared_component_ids;
    let observed: BTreeSet<&String> = evidence
        .components
        .iter()
        .filter(|component| component.observation != ObservationKind::Declared)
        .map(|component| &component.component_id)
        .collect();

    let mut declared_only_ids = Vec::new();
    let mut agreed_ids = Vec::new();
    for id in declared {
        if observed.contains(id) {
            agreed_ids.push(id.clone());
        } else {
            declared_only_ids.push(id.clone());
        }
    }
    let observed_only_ids = observed
        .iter()
        .filter(|id| !declared.contains(**id))
        .map(|id| (*id).clone())
        .collect();

    DeclaredObservedContext {
        declared_only_ids,
        observed_only_ids,
        agreed_ids,
        comparable: evidence.has_declared_and_observed(),
    }
}

/// Group observations by component id, for evaluators that walk per component.
pub fn by_component(set: &ObservationSet) -> BTreeMap<&str, Vec<&SupplyChainObservation>> {
    let mut grouped: BTreeMap<&str, Vec<&SupplyChainObservation>> = BTreeMap::new();
    for observation in &set.observations {
        if let Some(component_id) = observation.component_id() {
            grouped.entry(component_id).or_default().push(observation);
        }
    }
    grouped
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::capability::projection;
    use crate::component::tests::{component, digest as artifact_digest};
    use crate::manifest::{ApprovedComponent, DareManifest, TrustPolicy};
    use crate::normalize::EvidenceBuilder;
    use crate::provenance::tests::record;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use std::collections::BTreeMap;

    pub(crate) fn evidence_of(
        components: Vec<Component>,
        graph: RelationshipGraph,
        manifest: DareManifest,
    ) -> SupplyChainEvidence {
        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_import(components, graph)
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn the_channel_set_is_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = ObservationChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        assert_eq!(names.len(), ObservationChannel::all().len());
        for channel in ObservationChannel::all() {
            assert_eq!(
                channel.as_str(),
                channel.as_str().to_uppercase(),
                "a channel token is not screaming snake case"
            );
        }
        assert!(
            serde_json::from_str::<ObservationChannel>("\"SOME_NEW_CONTEXT\"").is_err(),
            "an unknown channel decoded"
        );
    }

    #[test]
    fn the_twelve_design_channels_are_all_present() {
        let names: BTreeSet<&str> = ObservationChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        for required in [
            "BOM_DOCUMENT_CONTEXT",
            "COMPONENT_CONTEXT",
            "COMPONENT_DIGEST_CONTEXT",
            "SOURCE_TRUST_CONTEXT",
            "PROVENANCE_CONTEXT",
            "ATTESTATION_CONTEXT",
            "RELATIONSHIP_CONTEXT",
            "CAPABILITY_CONTEXT",
            "MODEL_LINEAGE_CONTEXT",
            "DATASET_PROVENANCE_CONTEXT",
            "DECLARED_OBSERVED_COMPONENT_CONTEXT",
            "HARNESS_ERROR",
        ] {
            assert!(names.contains(required), "{required} is missing");
        }
    }

    #[test]
    fn an_observation_cannot_carry_a_verdict() {
        for hostile in [
            serde_json::json!({ "channel": "COMPONENT_CONTEXT", "verdict": "PASS" }),
            serde_json::json!({ "channel": "HARNESS_ERROR", "kind": "ADAPTER_FAILURE",
                                "reason": "x", "is_secure": false }),
            serde_json::json!({ "channel": "VERDICT", "verdict": "FAIL" }),
            serde_json::json!({ "channel": "VIOLATION", "invariant": "X" }),
        ] {
            assert!(
                serde_json::from_value::<SupplyChainObservation>(hostile).is_err(),
                "an observation carrying a verdict decoded"
            );
        }
    }

    #[test]
    fn a_component_with_no_digest_produces_no_digest_context() {
        let mut bare = component("react", ComponentType::Package);
        bare.digests.clear();
        let set = project(&evidence_of(
            vec![bare],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ComponentContext));
        assert!(!set.has_channel(ObservationChannel::ComponentDigestContext));
    }

    #[test]
    fn a_component_with_a_digest_produces_one() {
        let set = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ComponentDigestContext));
    }

    #[test]
    fn an_approved_digest_that_matches_is_recorded_as_bound() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(),
                name: None,
                version: None,
                digests: BTreeSet::from([artifact_digest("a")]),
            }]),
            ..Default::default()
        };
        let set = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            manifest,
        ));

        let bound = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ComponentDigestContext(context) => {
                    Some(context.approved_digest_bound)
                }
                _ => None,
            });
        assert_eq!(bound, Some(Some(true)));
    }

    #[test]
    fn an_unapproved_signer_is_named_rather_than_counted() {
        let mut ledger = AdmissionLedger::new();
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_signers: BTreeSet::from(["signer-release".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
            .with_attestations(vec![{
                let mut record = crate::attestation::tests::attestation("att-1", "react");
                record.signer_id = Some("signer-unknown".to_owned());
                record
            }])
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::AttestationContext(context) => Some(context),
                _ => None,
            })
            .expect("an attestation context");
        assert!(context.unapproved_signer_ids.contains("signer-unknown"));
        assert!(context.approved_signer_ids.is_empty());
    }

    #[test]
    fn every_provenance_builder_is_classified_independently() {
        let mut ledger = AdmissionLedger::new();
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut second = record("prov-2", "react");
        second.builder_id = Some("builder-unknown".to_owned());
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
            .with_provenance(vec![record("prov-1", "react"), second])
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ProvenanceContext(context) => Some(context),
                _ => None,
            })
            .expect("a provenance context");
        assert!(context.approved_builder_ids.contains("builder-ci"));
        assert!(context.unapproved_builder_ids.contains("builder-unknown"));
    }

    #[test]
    fn an_absent_policy_leaves_signer_and_builder_approval_unanswered() {
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
            .with_provenance(vec![record("prov-1", "react")])
            .build(&mut ledger)
            .expect("builds");

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ProvenanceContext(context) => Some(context),
                _ => None,
            })
            .expect("a provenance context");
        assert!(!context.policy_present);
        assert_eq!(context.builder_approved, None);
        assert!(context.approved_builder_ids.is_empty());
        assert!(context.unapproved_builder_ids.is_empty());
    }

    #[test]
    fn a_mutable_version_is_recorded_on_the_component_context() {
        let mut floating = component("api-image", ComponentType::ContainerImage);
        floating.version = Some("latest".to_owned());
        let set = project(&evidence_of(
            vec![floating],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ComponentContext(context) => Some(context),
                _ => None,
            })
            .expect("a component context");
        assert!(context.uses_mutable_reference);
        assert!(context.expects_immutable_artifact);
    }

    #[test]
    fn declared_and_observed_edges_are_counted_separately_from_where_they_agree() {
        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "app",
                "react",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ))
            .expect("valid");
        let evidence = evidence_of(
            vec![
                component("app", ComponentType::Package),
                component("react", ComponentType::Package),
            ],
            graph,
            DareManifest::default(),
        );

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::RelationshipContext(context) => Some(context),
                _ => None,
            })
            .expect("a relationship context");
        assert_eq!(context.observed_edge_count, 1);
        assert_eq!(context.declared_edge_count, 0);
        assert_eq!(context.undeclared_edge_keys.len(), 1);
        assert!(!context.comparable, "one side alone compared as two");
    }

    #[test]
    fn capability_context_appears_when_either_side_supplies_capabilities() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_capabilities: BTreeMap::from([(
                "file-tool".to_owned(),
                BTreeSet::from(["read-file".to_owned()]),
            )]),
            ..Default::default()
        };
        let set = project(&evidence_of(
            vec![component("file-tool", ComponentType::Tool)],
            RelationshipGraph::new(),
            manifest,
        ));
        assert!(set.has_channel(ObservationChannel::CapabilityContext));

        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(projection(&["read-file"], &["read-file"]));
        let set = project(&evidence_of(
            vec![tool],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::CapabilityContext));
    }

    #[test]
    fn lineage_and_dataset_contexts_follow_the_component_class() {
        let set = project(&evidence_of(
            vec![
                component("planner-model", ComponentType::Model),
                component("corpus", ComponentType::Dataset),
                component("react", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ModelLineageContext));
        assert!(set.has_channel(ObservationChannel::DatasetProvenanceContext));

        let lineage_subjects: Vec<&str> = set
            .observations
            .iter()
            .filter(|observation| observation.channel() == ObservationChannel::ModelLineageContext)
            .filter_map(SupplyChainObservation::component_id)
            .collect();
        assert_eq!(lineage_subjects, vec!["planner-model"]);
    }

    #[test]
    fn projection_is_deterministic() {
        let build = || {
            evidence_of(
                vec![
                    component("react", ComponentType::Package),
                    component("planner-model", ComponentType::Model),
                ],
                RelationshipGraph::new(),
                DareManifest::default(),
            )
        };
        let left = project(&build());
        let right = project(&build());
        assert_eq!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn every_observation_digests_and_the_digests_differ() {
        let set = project(&evidence_of(
            vec![
                component("react", ComponentType::Package),
                component("vue", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let digests: BTreeSet<String> = set
            .observations
            .iter()
            .map(|observation| observation.digest().expect("digests"))
            .collect();
        assert_eq!(digests.len(), set.observations.len());
    }

    #[test]
    fn a_harness_error_is_a_channel_and_not_a_finding() {
        let set = ObservationSet::new(vec![SupplyChainObservation::HarnessError(
            HarnessErrorContext {
                kind: HarnessErrorKind::AdapterFailure,
                reason: "the adapter could not read the local evidence directory".to_owned(),
            },
        )]);
        assert!(set.has_harness_error());
        let rendered = serde_json::to_string(&set)
            .expect("serializes")
            .to_lowercase();
        for absent in ["violation", "verdict", "finding", "insecure"] {
            assert!(
                !rendered.contains(absent),
                "a harness error reads as `{absent}`"
            );
        }
    }

    #[test]
    fn observations_can_be_grouped_by_component() {
        let set = project(&evidence_of(
            vec![
                component("react", ComponentType::Package),
                component("vue", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let grouped = by_component(&set);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("react"));
        assert_eq!(set.for_component("react").count(), grouped["react"].len());
    }
}

#[cfg(test)]
pub(crate) mod cycle019_pre_review_tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::capability::projection;
    use crate::component::tests::{component, digest as artifact_digest};
    use crate::manifest::{ApprovedComponent, DareManifest, TrustPolicy};
    use crate::normalize::EvidenceBuilder;
    use crate::provenance::tests::record;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use std::collections::BTreeMap;

    pub(crate) fn evidence_of(
        components: Vec<Component>,
        graph: RelationshipGraph,
        manifest: DareManifest,
    ) -> SupplyChainEvidence {
        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_import(components, graph)
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn the_channel_set_is_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = ObservationChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        assert_eq!(names.len(), ObservationChannel::all().len());
        for channel in ObservationChannel::all() {
            assert_eq!(
                channel.as_str(),
                channel.as_str().to_uppercase(),
                "a channel token is not screaming snake case"
            );
        }
        assert!(
            serde_json::from_str::<ObservationChannel>("\"SOME_NEW_CONTEXT\"").is_err(),
            "an unknown channel decoded"
        );
    }

    #[test]
    fn the_twelve_design_channels_are_all_present() {
        // The list is fixed by DESIGN section 18. A channel quietly dropped
        // here would silently satisfy every coverage contract that required it.
        let names: BTreeSet<&str> = ObservationChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        for required in [
            "BOM_DOCUMENT_CONTEXT",
            "COMPONENT_CONTEXT",
            "COMPONENT_DIGEST_CONTEXT",
            "SOURCE_TRUST_CONTEXT",
            "PROVENANCE_CONTEXT",
            "ATTESTATION_CONTEXT",
            "RELATIONSHIP_CONTEXT",
            "CAPABILITY_CONTEXT",
            "MODEL_LINEAGE_CONTEXT",
            "DATASET_PROVENANCE_CONTEXT",
            "DECLARED_OBSERVED_COMPONENT_CONTEXT",
            "HARNESS_ERROR",
        ] {
            assert!(names.contains(required), "{required} is missing");
        }
    }

    #[test]
    fn an_observation_cannot_carry_a_verdict() {
        // The authority boundary, structural rather than checked. An adapter
        // that could emit a verdict would decide the outcome and reduce the
        // evaluator to transcribing it.
        for hostile in [
            serde_json::json!({ "channel": "COMPONENT_CONTEXT", "verdict": "PASS" }),
            serde_json::json!({ "channel": "HARNESS_ERROR", "kind": "ADAPTER_FAILURE",
                                "reason": "x", "is_secure": false }),
            serde_json::json!({ "channel": "VERDICT", "verdict": "FAIL" }),
            serde_json::json!({ "channel": "VIOLATION", "invariant": "X" }),
        ] {
            assert!(
                serde_json::from_value::<SupplyChainObservation>(hostile).is_err(),
                "an observation carrying a verdict decoded"
            );
        }
    }

    #[test]
    fn a_component_with_no_digest_produces_no_digest_context() {
        // The basis for INCONCLUSIVE. A context saying `has_digest: false`
        // reads as an answer; an absent channel is honestly the absence of one.
        let mut bare = component("react", ComponentType::Package);
        bare.digests.clear();
        let set = project(&evidence_of(
            vec![bare],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ComponentContext));
        assert!(!set.has_channel(ObservationChannel::ComponentDigestContext));
    }

    #[test]
    fn a_component_with_a_digest_produces_one() {
        let set = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ComponentDigestContext));
    }

    #[test]
    fn an_approved_digest_that_matches_is_recorded_as_bound() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(),
                name: None,
                version: None,
                digests: BTreeSet::from([artifact_digest("a")]),
            }]),
            ..Default::default()
        };
        let set = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            manifest,
        ));

        let bound = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ComponentDigestContext(context) => {
                    Some(context.approved_digest_bound)
                }
                _ => None,
            });
        assert_eq!(bound, Some(Some(true)));
    }

    #[test]
    fn an_unapproved_signer_is_named_rather_than_counted() {
        // "An unapproved signer attested this" is only actionable if the
        // operator learns which one.
        let mut ledger = AdmissionLedger::new();
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_signers: BTreeSet::from(["signer-release".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
            .with_attestations(vec![{
                let mut record = crate::attestation::tests::attestation("att-1", "react");
                record.signer_id = Some("signer-unknown".to_owned());
                record
            }])
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::AttestationContext(context) => Some(context),
                _ => None,
            })
            .expect("an attestation context");
        assert!(context.unapproved_signer_ids.contains("signer-unknown"));
        assert!(context.approved_signer_ids.is_empty());
    }

    #[test]
    fn an_absent_policy_leaves_signer_and_builder_approval_unanswered() {
        // Not `false`. With no policy nobody asked the question, and answering
        // it would make every component a finding.
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new(),
            )
            .with_provenance(vec![record("prov-1", "react")])
            .build(&mut ledger)
            .expect("builds");

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ProvenanceContext(context) => Some(context),
                _ => None,
            })
            .expect("a provenance context");
        assert!(!context.policy_present);
        assert_eq!(context.builder_approved, None);
    }

    #[test]
    fn a_mutable_version_is_recorded_on_the_component_context() {
        let mut floating = component("api-image", ComponentType::ContainerImage);
        floating.version = Some("latest".to_owned());
        let set = project(&evidence_of(
            vec![floating],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::ComponentContext(context) => Some(context),
                _ => None,
            })
            .expect("a component context");
        assert!(context.uses_mutable_reference);
        assert!(context.expects_immutable_artifact);
    }

    #[test]
    fn declared_and_observed_edges_are_counted_separately_from_where_they_agree() {
        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "app",
                "react",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ))
            .expect("valid");
        let evidence = evidence_of(
            vec![
                component("app", ComponentType::Package),
                component("react", ComponentType::Package),
            ],
            graph,
            DareManifest::default(),
        );

        let set = project(&evidence);
        let context = set
            .observations
            .iter()
            .find_map(|observation| match observation {
                SupplyChainObservation::RelationshipContext(context) => Some(context),
                _ => None,
            })
            .expect("a relationship context");
        assert_eq!(context.observed_edge_count, 1);
        assert_eq!(context.declared_edge_count, 0);
        assert_eq!(context.undeclared_edge_keys.len(), 1);
        assert!(!context.comparable, "one side alone compared as two");
    }

    #[test]
    fn capability_context_appears_when_either_side_supplies_capabilities() {
        // Including when only the manifest does: a component that dropped its
        // capability projection entirely must not make drift unobservable.
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_capabilities: BTreeMap::from([(
                "file-tool".to_owned(),
                BTreeSet::from(["read-file".to_owned()]),
            )]),
            ..Default::default()
        };
        let set = project(&evidence_of(
            vec![component("file-tool", ComponentType::Tool)],
            RelationshipGraph::new(),
            manifest,
        ));
        assert!(set.has_channel(ObservationChannel::CapabilityContext));

        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(projection(&["read-file"], &["read-file"]));
        let set = project(&evidence_of(
            vec![tool],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::CapabilityContext));
    }

    #[test]
    fn lineage_and_dataset_contexts_follow_the_component_class() {
        let set = project(&evidence_of(
            vec![
                component("planner-model", ComponentType::Model),
                component("corpus", ComponentType::Dataset),
                component("react", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        assert!(set.has_channel(ObservationChannel::ModelLineageContext));
        assert!(set.has_channel(ObservationChannel::DatasetProvenanceContext));

        // A package has neither lineage nor dataset provenance, and emitting
        // an empty context for it would make every package undecidable on two
        // invariants that do not apply to it.
        let lineage_subjects: Vec<&str> = set
            .observations
            .iter()
            .filter(|observation| observation.channel() == ObservationChannel::ModelLineageContext)
            .filter_map(SupplyChainObservation::component_id)
            .collect();
        assert_eq!(lineage_subjects, vec!["planner-model"]);
    }

    #[test]
    fn projection_is_deterministic() {
        // Two runs over the same evidence must digest identically, or a report
        // would differ from itself between runs.
        let build = || {
            evidence_of(
                vec![
                    component("react", ComponentType::Package),
                    component("planner-model", ComponentType::Model),
                ],
                RelationshipGraph::new(),
                DareManifest::default(),
            )
        };
        let left = project(&build());
        let right = project(&build());
        assert_eq!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn every_observation_digests_and_the_digests_differ() {
        // Deciding-evidence citation is only useful if two different
        // observations cite differently.
        let set = project(&evidence_of(
            vec![
                component("react", ComponentType::Package),
                component("vue", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let digests: BTreeSet<String> = set
            .observations
            .iter()
            .map(|observation| observation.digest().expect("digests"))
            .collect();
        assert_eq!(digests.len(), set.observations.len());
    }

    #[test]
    fn a_harness_error_is_a_channel_and_not_a_finding() {
        let set = ObservationSet::new(vec![SupplyChainObservation::HarnessError(
            HarnessErrorContext {
                kind: HarnessErrorKind::AdapterFailure,
                reason: "the adapter could not read the local evidence directory".to_owned(),
            },
        )]);
        assert!(set.has_harness_error());
        let rendered = serde_json::to_string(&set)
            .expect("serializes")
            .to_lowercase();
        for absent in ["violation", "verdict", "finding", "insecure"] {
            assert!(
                !rendered.contains(absent),
                "a harness error reads as `{absent}`"
            );
        }
    }

    #[test]
    fn observations_can_be_grouped_by_component() {
        let set = project(&evidence_of(
            vec![
                component("react", ComponentType::Package),
                component("vue", ComponentType::Package),
            ],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let grouped = by_component(&set);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("react"));
        assert_eq!(set.for_component("react").count(), grouped["react"].len());
    }
}
