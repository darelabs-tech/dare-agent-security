//! Format-independent normalization, and the evidence bundle everything else
//! reads.
//!
//! Two documents describing the same system in different vocabularies must
//! reach the same components and the same edges. That is what makes supporting
//! two formats worth anything: a security question gets one answer regardless
//! of which tool produced the evidence.
//!
//! **Equivalence is semantic, never structural.** Comparing normalized JSON
//! would compare parsers — field order, optional keys, which importer happened
//! to populate `metadata`. What is compared is the set of semantic keys, which
//! `identity.rs` builds from what a component *is* rather than from which
//! document described it.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationRecord;
use crate::budget::AdmissionLedger;
use crate::component::Component;
use crate::error::{Result, SupplyChainError};
use crate::identity::{assert_no_collisions, resolve_identity};
use crate::manifest::DareManifest;
use crate::provenance::ProvenanceRecord;
use crate::relationship::{Relationship, RelationshipGraph};
use crate::source::{EvidenceSource, ObservationKind};

/// Which format a document was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BomFormat {
    CycloneDx,
    Spdx,
    Dare,
}

impl BomFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CycloneDx => "CYCLONEDX",
            Self::Spdx => "SPDX",
            Self::Dare => "DARE",
        }
    }
}

/// A record that a document was read, and what it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomDocumentRef {
    pub document_id: String,
    pub format: BomFormat,
    pub bytes: usize,
    /// A digest of the raw document, so a substituted input is visible in the
    /// artifact rather than only in whoever ran it.
    pub content_digest: String,
}

/// Everything the evaluators read.
///
/// Assembled once, then treated as immutable. An evaluator that could mutate
/// the evidence it judges would make findings depend on evaluation order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainEvidence {
    #[serde(default)]
    pub documents: Vec<BomDocumentRef>,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub graph: RelationshipGraph,
    #[serde(default)]
    pub provenance: Vec<ProvenanceRecord>,
    #[serde(default)]
    pub attestations: Vec<AttestationRecord>,
    #[serde(default, skip_serializing_if = "DareManifest::is_empty")]
    pub manifest: DareManifest,
}

impl SupplyChainEvidence {
    /// Find a component by its canonical id.
    pub fn component(&self, component_id: &str) -> Option<&Component> {
        self.components
            .iter()
            .find(|component| component.component_id == component_id)
    }

    /// The set of semantic keys this evidence describes.
    ///
    /// The comparison surface for cross-format equivalence.
    pub fn semantic_keys(&self) -> BTreeSet<String> {
        self.components
            .iter()
            .map(|component| resolve_identity(component).semantic_key)
            .collect()
    }

    /// Edge keys, ignoring which format supplied them.
    pub fn edge_keys(&self) -> BTreeSet<String> {
        self.graph
            .edges
            .iter()
            .map(Relationship::edge_key)
            .collect()
    }

    /// Whether this evidence and another describe the same system.
    ///
    /// Semantic, not structural: two documents may differ in every optional
    /// field and still describe the same components and relationships.
    pub fn describes_same_system_as(&self, other: &Self) -> bool {
        self.semantic_keys() == other.semantic_keys() && self.edge_keys() == other.edge_keys()
    }

    /// Validate the assembled evidence as a whole.
    ///
    /// The checks that only make sense once everything is present: identities
    /// must be unambiguous across documents, edges must not dangle, and the
    /// graph must be bounded.
    pub fn validate(&self) -> Result<()> {
        for component in &self.components {
            component.validate()?;
        }
        for record in &self.provenance {
            record.validate()?;
        }
        for record in &self.attestations {
            record.validate()?;
        }
        self.manifest.validate()?;

        assert_no_collisions(&self.components)?;
        self.graph.assert_no_dangling(&self.components)?;
        self.graph.assert_bounded_depth()?;
        Ok(())
    }

    /// Whether both declared and observed component sets exist.
    ///
    /// Without both, the evidence describes what was expected or what was
    /// found, and the declared/observed comparison has nothing to compare.
    pub fn has_declared_and_observed(&self) -> bool {
        !self.manifest.declared_component_ids.is_empty()
            && self
                .components
                .iter()
                .any(|component| component.observation != ObservationKind::Declared)
    }

    /// Components observed that the manifest never declared.
    pub fn undeclared_components(&self) -> Vec<&Component> {
        if self.manifest.declared_component_ids.is_empty() {
            return Vec::new();
        }
        self.components
            .iter()
            .filter(|component| {
                !self
                    .manifest
                    .declared_component_ids
                    .contains(&component.component_id)
            })
            .collect()
    }
}

/// Merge imported documents, a manifest and local records into one bundle.
///
/// Merging is where duplicate identities become visible, so `validate` runs at
/// the end rather than per document: a collision between two documents cannot
/// be seen from inside either one.
pub struct EvidenceBuilder {
    evidence: SupplyChainEvidence,
    seen_ids: BTreeMap<String, EvidenceSource>,
}

impl Default for EvidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceBuilder {
    pub fn new() -> Self {
        Self {
            evidence: SupplyChainEvidence::default(),
            seen_ids: BTreeMap::new(),
        }
    }

    /// Record that a document was read.
    pub fn with_document(mut self, document_id: &str, format: BomFormat, raw: &[u8]) -> Self {
        self.evidence.documents.push(BomDocumentRef {
            document_id: document_id.to_owned(),
            format,
            bytes: raw.len(),
            content_digest: crate::canonical::digest_bytes(raw),
        });
        self
    }

    /// Add components and edges from one import.
    ///
    /// A component already present under the same id from another document is
    /// merged rather than duplicated: two documents describing one component is
    /// the normal case, and a duplicate row would make the identity resolver
    /// report an ambiguity that does not exist.
    pub fn with_import(mut self, components: Vec<Component>, graph: RelationshipGraph) -> Self {
        for component in components {
            match self.seen_ids.get(&component.component_id) {
                Some(_) => {
                    if let Some(existing) = self
                        .evidence
                        .components
                        .iter_mut()
                        .find(|candidate| candidate.component_id == component.component_id)
                    {
                        merge_into(existing, component);
                    }
                }
                None => {
                    self.seen_ids
                        .insert(component.component_id.clone(), component.evidence_source);
                    self.evidence.components.push(component);
                }
            }
        }
        for edge in graph.edges {
            self.evidence.graph.edges.insert(edge);
        }
        self
    }

    /// Apply a DARE manifest: approvals, expectations and declared components.
    ///
    /// This is the only step that can raise a component's trust class, and it
    /// is the only one that may: approval lives in a local policy.
    pub fn with_manifest(mut self, manifest: DareManifest) -> Self {
        // Expected edges enter the graph as *declared*, which is what makes the
        // declared/observed comparison possible at all.
        for expected in &manifest.expected_edges {
            self.evidence.graph.edges.insert(Relationship {
                source_id: expected.source_id.clone(),
                target_id: expected.target_id.clone(),
                relation: expected.relation,
                observation: ObservationKind::Declared,
                evidence_source: EvidenceSource::DareManifest,
            });
        }

        // An edge that is both declared and observed collapses into one
        // `DeclaredAndObserved` entry, so the comparison reports agreement
        // rather than two half-findings.
        collapse_declared_and_observed(&mut self.evidence.graph);

        self.evidence.manifest = manifest;
        self
    }

    pub fn with_provenance(mut self, records: Vec<ProvenanceRecord>) -> Self {
        self.evidence.provenance.extend(records);
        self
    }

    pub fn with_attestations(mut self, records: Vec<AttestationRecord>) -> Self {
        self.evidence.attestations.extend(records);
        self
    }

    /// Finish, admitting the assembled objects and validating the whole.
    pub fn build(self, ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
        let evidence = self.evidence;

        // Admission before persistence, once more: the merged set can exceed a
        // bound that no single document did.
        for _ in &evidence.components {
            ledger.admit_component()?;
        }
        for _ in &evidence.graph.edges {
            ledger.admit_relationship()?;
        }

        evidence.validate()?;
        Ok(evidence)
    }
}

/// Merge a second description of one component into the first.
///
/// Union of evidence, never replacement. A second document that omits a digest
/// the first supplied must not remove it: the union is what is known about the
/// component, and dropping evidence because one source was quieter would turn a
/// complete picture into a partial one.
fn merge_into(existing: &mut Component, incoming: Component) {
    existing.digests.extend(incoming.digests);
    existing.identifiers.extend(incoming.identifiers);
    if existing.version.is_none() {
        existing.version = incoming.version;
    }
    if existing.supplier.supplier_id.is_none() {
        existing.supplier.supplier_id = incoming.supplier.supplier_id;
    }
    if existing.supplier.publisher_id.is_none() {
        existing.supplier.publisher_id = incoming.supplier.publisher_id;
    }
    if existing.supplier.builder_id.is_none() {
        existing.supplier.builder_id = incoming.supplier.builder_id;
    }
    if existing.supplier.signer_id.is_none() {
        existing.supplier.signer_id = incoming.supplier.signer_id;
    }
    if existing.supplier.source_id.is_none() {
        existing.supplier.source_id = incoming.supplier.source_id;
    }
    existing.metadata.extend(incoming.metadata);
}

/// Collapse edges present as both declared and observed into one entry.
fn collapse_declared_and_observed(graph: &mut RelationshipGraph) {
    let declared: BTreeSet<String> = graph
        .edges
        .iter()
        .filter(|edge| edge.observation == ObservationKind::Declared)
        .map(Relationship::edge_key)
        .collect();
    let observed: BTreeSet<String> = graph
        .edges
        .iter()
        .filter(|edge| edge.observation == ObservationKind::Observed)
        .map(Relationship::edge_key)
        .collect();

    let both: BTreeSet<&String> = declared.intersection(&observed).collect();
    if both.is_empty() {
        return;
    }

    let mut collapsed = BTreeSet::new();
    for edge in std::mem::take(&mut graph.edges) {
        if both.contains(&edge.edge_key()) {
            if edge.observation == ObservationKind::Declared {
                collapsed.insert(Relationship {
                    observation: ObservationKind::DeclaredAndObserved,
                    ..edge
                });
            }
            // The observed twin is dropped; the collapsed entry carries both.
            continue;
        }
        collapsed.insert(edge);
    }
    graph.edges = collapsed;
}

/// Assert two evidence bundles describe the same system.
pub fn assert_equivalent(left: &SupplyChainEvidence, right: &SupplyChainEvidence) -> Result<()> {
    if left.semantic_keys() != right.semantic_keys() {
        return Err(SupplyChainError::BindingMismatch(
            "the two documents describe different component sets".to_owned(),
        ));
    }
    if left.edge_keys() != right.edge_keys() {
        return Err(SupplyChainError::BindingMismatch(
            "the two documents describe different relationships".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::component;
    use crate::manifest::{ExpectedEdge, TrustPolicy};
    use crate::relationship::RelationType;
    use crate::source::ComponentType;

    fn import_cyclonedx() -> SupplyChainEvidence {
        let raw = serde_json::to_vec(&crate::cyclonedx::tests::document()).expect("serializes");
        let mut ledger = AdmissionLedger::new();
        let imported = crate::cyclonedx::import(&raw, &mut ledger).expect("imports");
        EvidenceBuilder::new()
            .with_document("cdx", BomFormat::CycloneDx, &raw)
            .with_import(imported.components, imported.graph)
            .build(&mut ledger)
            .expect("builds")
    }

    fn import_spdx() -> SupplyChainEvidence {
        let raw = serde_json::to_vec(&crate::spdx::tests::document()).expect("serializes");
        let mut ledger = AdmissionLedger::new();
        let imported = crate::spdx::import(&raw, &mut ledger).expect("imports");
        EvidenceBuilder::new()
            .with_document("spdx", BomFormat::Spdx, &raw)
            .with_import(imported.components, imported.graph)
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn equivalent_cyclonedx_and_spdx_documents_normalize_equivalently() {
        // The claim two formats are for. Both fixtures describe the same
        // system: an agent depending on react 18.3.1 with one sha256 digest.
        let cyclonedx = import_cyclonedx();
        let spdx = import_spdx();

        assert!(
            cyclonedx.describes_same_system_as(&spdx),
            "cyclonedx keys {:?} spdx keys {:?}",
            cyclonedx.semantic_keys(),
            spdx.semantic_keys()
        );
        assert_equivalent(&cyclonedx, &spdx).expect("equivalent");
    }

    #[test]
    fn equivalence_is_semantic_rather_than_structural() {
        // The two bundles differ in every structural way — evidence source,
        // document id, content digest — and are still equivalent. A test
        // comparing serialized JSON would compare parsers instead.
        let cyclonedx = import_cyclonedx();
        let spdx = import_spdx();

        assert_ne!(
            serde_json::to_value(&cyclonedx).unwrap(),
            serde_json::to_value(&spdx).unwrap(),
            "the fixtures were structurally identical, so the test proves nothing"
        );
        assert!(cyclonedx.describes_same_system_as(&spdx));
    }

    #[test]
    fn a_different_digest_makes_two_documents_inequivalent() {
        // The control: equivalence must be able to fail, or it says nothing.
        let cyclonedx = import_cyclonedx();
        let mut altered = crate::spdx::tests::document();
        altered["@graph"][0]["verifiedUsing"] =
            serde_json::json!([{ "algorithm": "sha256", "hashValue": "b".repeat(64) }]);
        let raw = serde_json::to_vec(&altered).expect("serializes");
        let mut ledger = AdmissionLedger::new();
        let imported = crate::spdx::import(&raw, &mut ledger).expect("imports");
        let spdx = EvidenceBuilder::new()
            .with_import(imported.components, imported.graph)
            .build(&mut ledger)
            .expect("builds");

        assert!(!cyclonedx.describes_same_system_as(&spdx));
        assert!(assert_equivalent(&cyclonedx, &spdx).is_err());
    }

    #[test]
    fn two_documents_describing_one_component_merge_rather_than_duplicate() {
        // A duplicate row would make the identity resolver report an ambiguity
        // that does not exist, on the most ordinary input there is.
        let mut with_digest = component("react", ComponentType::Package);
        with_digest.evidence_source = EvidenceSource::CycloneDx;

        let mut without_digest = component("react", ComponentType::Package);
        without_digest.evidence_source = EvidenceSource::Spdx;
        without_digest.digests.clear();
        without_digest.supplier.publisher_id = Some("acme".to_owned());

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![with_digest], RelationshipGraph::new())
            .with_import(vec![without_digest], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");

        assert_eq!(evidence.components.len(), 1);
        let merged = &evidence.components[0];
        // Union, not replacement: the quieter document did not remove the
        // digest the first supplied.
        assert_eq!(merged.digests.len(), 1);
        assert_eq!(merged.supplier.publisher_id.as_deref(), Some("acme"));
    }

    #[test]
    fn an_expected_edge_and_an_observed_one_collapse_into_agreement() {
        // Otherwise the same dependency reads as both "declared and never
        // observed" and "observed and never declared" — two findings about one
        // agreement.
        let raw = serde_json::to_vec(&crate::cyclonedx::tests::document()).expect("serializes");
        let mut ledger = AdmissionLedger::new();
        let imported = crate::cyclonedx::import(&raw, &mut ledger).expect("imports");

        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            expected_edges: BTreeSet::from([ExpectedEdge {
                source_id: "app".to_owned(),
                target_id: "react".to_owned(),
                relation: RelationType::DependsOn,
            }]),
            ..Default::default()
        };

        let evidence = EvidenceBuilder::new()
            .with_import(imported.components, imported.graph)
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        assert_eq!(evidence.graph.edges.len(), 1);
        let edge = evidence.graph.edges.iter().next().expect("one edge");
        assert_eq!(edge.observation, ObservationKind::DeclaredAndObserved);
        assert!(evidence.graph.undeclared_dependencies().is_empty());
        assert!(evidence.graph.unobserved_dependencies().is_empty());
    }

    #[test]
    fn an_expected_edge_with_no_observation_stays_declared() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            expected_edges: BTreeSet::from([ExpectedEdge {
                source_id: "app".to_owned(),
                target_id: "lodash".to_owned(),
                relation: RelationType::DependsOn,
            }]),
            ..Default::default()
        };
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("app", ComponentType::Agent), {
                    let mut lodash = component("lodash", ComponentType::Package);
                    lodash.digests.clear();
                    lodash
                }],
                RelationshipGraph::new(),
            )
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        assert_eq!(evidence.graph.unobserved_dependencies().len(), 1);
    }

    #[test]
    fn a_component_nobody_declared_is_reported_as_undeclared() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            declared_component_ids: BTreeSet::from(["app".to_owned()]),
            ..Default::default()
        };
        let mut ledger = AdmissionLedger::new();
        let mut telemetry = component("telemetry", ComponentType::Package);
        telemetry.digests.clear();

        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![component("app", ComponentType::Agent), telemetry],
                RelationshipGraph::new(),
            )
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let undeclared = evidence.undeclared_components();
        assert_eq!(undeclared.len(), 1);
        assert_eq!(undeclared[0].component_id, "telemetry");
        assert!(evidence.has_declared_and_observed());
    }

    #[test]
    fn with_no_manifest_nothing_is_undeclared() {
        // Without a declared set there is nothing to be undeclared against.
        // Reporting every component would be a finding about the absence of a
        // manifest, dressed as a finding about the components.
        let evidence = import_cyclonedx();
        assert!(evidence.undeclared_components().is_empty());
        assert!(!evidence.has_declared_and_observed());
    }

    #[test]
    fn a_collision_between_two_documents_is_caught_at_merge_time() {
        // It cannot be seen from inside either document, which is why
        // `validate` runs on the assembled bundle rather than per import.
        let first = component("react", ComponentType::Package);
        let mut second = component("react-duplicate", ComponentType::Package);
        second.name = "react".to_owned();

        let mut ledger = AdmissionLedger::new();
        let result = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger);

        assert!(result.is_err(), "one artifact under two ids was admitted");
    }

    #[test]
    fn the_bundle_records_a_digest_of_every_document_it_read() {
        // So a substituted input is visible in the artifact rather than only to
        // whoever ran it.
        let evidence = import_cyclonedx();
        assert_eq!(evidence.documents.len(), 1);
        let document = &evidence.documents[0];
        assert_eq!(document.format, BomFormat::CycloneDx);
        assert!(document.content_digest.starts_with("sha256:"));
        assert!(document.bytes > 0);
    }

    #[test]
    fn a_manifest_can_raise_trust_and_a_document_cannot() {
        // The asymmetry the whole trust model rests on, checked end to end.
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_suppliers: BTreeSet::from(["acme".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(manifest
            .trust_policy
            .approves_origin(None, Some("acme"), None)
            .expect("a claim was present"));

        // And the imported components still carry no trust of their own.
        let evidence = import_cyclonedx();
        for component in &evidence.components {
            assert!(component.source_trust.is_none());
        }
    }
}
