//! Format-independent normalization, and the evidence bundle everything else reads.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationRecord;
use crate::budget::AdmissionLedger;
use crate::component::Component;
use crate::error::{Result, SupplyChainError};
use crate::identity::{find_collisions, resolve_identity, IdentityCollision};
use crate::manifest::DareManifest;
use crate::provenance::ProvenanceRecord;
use crate::relationship::{Relationship, RelationshipGraph};
use crate::source::{EvidenceSource, ObservationKind};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomDocumentRef {
    pub document_id: String,
    pub format: BomFormat,
    pub bytes: usize,
    pub content_digest: String,
}

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
    pub fn component(&self, component_id: &str) -> Option<&Component> {
        self.components.iter().find(|component| component.component_id == component_id)
    }

    pub fn semantic_keys(&self) -> BTreeSet<String> {
        self.components.iter().map(|component| resolve_identity(component).semantic_key).collect()
    }

    pub fn edge_keys(&self) -> BTreeSet<String> {
        self.graph.edges.iter().map(Relationship::edge_key).collect()
    }

    pub fn describes_same_system_as(&self, other: &Self) -> bool {
        self.semantic_keys() == other.semantic_keys() && self.edge_keys() == other.edge_keys()
    }

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

        let mut provenance_counts: BTreeMap<&str, u32> = BTreeMap::new();
        for record in &self.provenance {
            let count = provenance_counts.entry(&record.subject_component_id).or_default();
            *count += 1;
            if *count > crate::limits::HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT {
                return Err(SupplyChainError::BudgetExhausted(
                    "a component carries more provenance records than the hard maximum".to_owned(),
                ));
            }
        }
        let mut attestation_counts: BTreeMap<&str, u32> = BTreeMap::new();
        for record in &self.attestations {
            let count = attestation_counts.entry(&record.subject_component_id).or_default();
            *count += 1;
            if *count > crate::limits::HARD_MAX_ATTESTATIONS_PER_COMPONENT {
                return Err(SupplyChainError::BudgetExhausted(
                    "a component carries more attestations than the hard maximum".to_owned(),
                ));
            }
        }

        self.graph.assert_no_dangling(&self.components)?;
        self.graph.assert_bounded_depth()?;
        Ok(())
    }

    pub fn identity_collisions(&self) -> Vec<IdentityCollision> {
        find_collisions(&self.components)
    }

    pub fn has_declared_and_observed(&self) -> bool {
        !self.manifest.declared_component_ids.is_empty()
            && self.components.iter().any(|component| component.observation != ObservationKind::Declared)
    }

    pub fn undeclared_components(&self) -> Vec<&Component> {
        if self.manifest.declared_component_ids.is_empty() {
            return Vec::new();
        }
        self.components
            .iter()
            .filter(|component| !self.manifest.declared_component_ids.contains(&component.component_id))
            .collect()
    }
}

pub struct EvidenceBuilder {
    evidence: SupplyChainEvidence,
    seen_ids: BTreeMap<String, EvidenceSource>,
}

impl Default for EvidenceBuilder {
    fn default() -> Self { Self::new() }
}

impl EvidenceBuilder {
    pub fn new() -> Self {
        Self { evidence: SupplyChainEvidence::default(), seen_ids: BTreeMap::new() }
    }

    pub fn with_recorded_document(mut self, document: BomDocumentRef) -> Self {
        self.evidence.documents.push(document);
        self
    }

    pub fn with_document(mut self, document_id: &str, format: BomFormat, raw: &[u8]) -> Self {
        self.evidence.documents.push(BomDocumentRef {
            document_id: document_id.to_owned(),
            format,
            bytes: raw.len(),
            content_digest: crate::canonical::digest_bytes(raw),
        });
        self
    }

    /// Complementary descriptions of one component may merge; contradictory
    /// descriptions must survive as separate rows so the evaluator can see the
    /// conflict. In particular, two different digests for the same algorithm,
    /// or conflicting origin claims, are never unioned into one apparently
    /// acceptable component.
    pub fn with_import(mut self, components: Vec<Component>, graph: RelationshipGraph) -> Self {
        for component in components {
            match self.seen_ids.get(&component.component_id) {
                Some(_) => {
                    if let Some(existing_index) = self
                        .evidence
                        .components
                        .iter()
                        .position(|candidate| candidate.component_id == component.component_id)
                    {
                        if descriptions_conflict(&self.evidence.components[existing_index], &component) {
                            self.evidence.components.push(component);
                        } else {
                            merge_into(&mut self.evidence.components[existing_index], component);
                        }
                    }
                }
                None => {
                    self.seen_ids.insert(component.component_id.clone(), component.evidence_source);
                    self.evidence.components.push(component);
                }
            }
        }
        for edge in graph.edges {
            self.evidence.graph.edges.insert(edge);
        }
        self
    }

    pub fn with_manifest(mut self, manifest: DareManifest) -> Self {
        for expected in &manifest.expected_edges {
            self.evidence.graph.edges.insert(Relationship {
                source_id: expected.source_id.clone(),
                target_id: expected.target_id.clone(),
                relation: expected.relation,
                observation: ObservationKind::Declared,
                evidence_source: EvidenceSource::DareManifest,
            });
        }
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

    pub fn build(self, ledger: &mut AdmissionLedger) -> Result<SupplyChainEvidence> {
        let evidence = self.evidence;
        for _ in &evidence.components { ledger.admit_component()?; }
        for _ in &evidence.graph.edges { ledger.admit_relationship()?; }
        evidence.validate()?;
        Ok(evidence)
    }
}

fn descriptions_conflict(existing: &Component, incoming: &Component) -> bool {
    if existing.component_type != incoming.component_type || existing.name != incoming.name {
        return true;
    }
    if matches!((&existing.version, &incoming.version), (Some(a), Some(b)) if a != b) {
        return true;
    }

    // Different algorithms can complement one another (sha256 + sha512). For a
    // shared algorithm, however, two non-empty different value sets describe
    // different bytes and must not be unioned.
    for algorithm in crate::source::DigestAlgorithm::all() {
        let left: BTreeSet<&str> = existing
            .digests
            .iter()
            .filter(|digest| digest.algorithm == algorithm)
            .map(|digest| digest.value.as_str())
            .collect();
        let right: BTreeSet<&str> = incoming
            .digests
            .iter()
            .filter(|digest| digest.algorithm == algorithm)
            .map(|digest| digest.value.as_str())
            .collect();
        if !left.is_empty() && !right.is_empty() && left != right {
            return true;
        }
    }

    let origin_conflicts = [
        (&existing.supplier.source_id, &incoming.supplier.source_id),
        (&existing.supplier.supplier_id, &incoming.supplier.supplier_id),
        (&existing.supplier.publisher_id, &incoming.supplier.publisher_id),
        (&existing.supplier.builder_id, &incoming.supplier.builder_id),
        (&existing.supplier.signer_id, &incoming.supplier.signer_id),
    ];
    origin_conflicts
        .iter()
        .any(|(left, right)| matches!((left, right), (Some(a), Some(b)) if a != b))
}

fn merge_into(existing: &mut Component, incoming: Component) {
    existing.digests.extend(incoming.digests);
    existing.identifiers.extend(incoming.identifiers);
    if existing.version.is_none() { existing.version = incoming.version; }
    if existing.supplier.supplier_id.is_none() { existing.supplier.supplier_id = incoming.supplier.supplier_id; }
    if existing.supplier.publisher_id.is_none() { existing.supplier.publisher_id = incoming.supplier.publisher_id; }
    if existing.supplier.builder_id.is_none() { existing.supplier.builder_id = incoming.supplier.builder_id; }
    if existing.supplier.signer_id.is_none() { existing.supplier.signer_id = incoming.supplier.signer_id; }
    if existing.supplier.source_id.is_none() { existing.supplier.source_id = incoming.supplier.source_id; }
    existing.metadata.extend(incoming.metadata);
}

fn collapse_declared_and_observed(graph: &mut RelationshipGraph) {
    let declared: BTreeSet<String> = graph.edges.iter()
        .filter(|edge| edge.observation == ObservationKind::Declared)
        .map(Relationship::edge_key).collect();
    let observed: BTreeSet<String> = graph.edges.iter()
        .filter(|edge| edge.observation == ObservationKind::Observed)
        .map(Relationship::edge_key).collect();
    let both: BTreeSet<&String> = declared.intersection(&observed).collect();
    if both.is_empty() { return; }
    let mut collapsed = BTreeSet::new();
    for edge in std::mem::take(&mut graph.edges) {
        if both.contains(&edge.edge_key()) {
            if edge.observation == ObservationKind::Declared {
                collapsed.insert(Relationship { observation: ObservationKind::DeclaredAndObserved, ..edge });
            }
            continue;
        }
        collapsed.insert(edge);
    }
    graph.edges = collapsed;
}

pub fn assert_equivalent(left: &SupplyChainEvidence, right: &SupplyChainEvidence) -> Result<()> {
    if left.semantic_keys() != right.semantic_keys() {
        return Err(SupplyChainError::BindingMismatch("the two documents describe different component sets".to_owned()));
    }
    if left.edge_keys() != right.edge_keys() {
        return Err(SupplyChainError::BindingMismatch("the two documents describe different relationships".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::{component, digest};
    use crate::source::ComponentType;

    #[test]
    fn complementary_same_id_descriptions_merge() {
        let mut first = component("react", ComponentType::Package);
        first.supplier.supplier_id = Some("acme".to_owned());
        let mut second = component("react", ComponentType::Package);
        second.digests.clear();
        second.supplier = Default::default();
        second.evidence_source = EvidenceSource::Spdx;
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        assert_eq!(evidence.components.len(), 1);
        assert_eq!(evidence.components[0].digests.len(), 1);
    }

    #[test]
    fn conflicting_same_id_digest_descriptions_are_retained() {
        let first = component("react", ComponentType::Package);
        let mut second = component("react", ComponentType::Package);
        second.digests = BTreeSet::from([digest("b")]);
        second.evidence_source = EvidenceSource::Spdx;
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        assert_eq!(evidence.components.len(), 2);
        assert!(!evidence.identity_collisions().is_empty());
    }

    #[test]
    fn conflicting_origin_claims_are_retained() {
        let mut first = component("react", ComponentType::Package);
        first.supplier.source_id = Some("registry-approved".to_owned());
        let mut second = first.clone();
        second.supplier.source_id = Some("registry-evil".to_owned());
        second.evidence_source = EvidenceSource::Spdx;
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        assert_eq!(evidence.components.len(), 2);
    }

    #[test]
    fn provenance_and_attestation_counts_are_bounded_per_component() {
        use crate::attestation::tests::attestation;
        use crate::provenance::tests::record;
        let mut ledger = AdmissionLedger::new();
        let too_many_provenance: Vec<_> = (0..=crate::limits::HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT)
            .map(|i| record(&format!("prov-{i}"), "react")).collect();
        assert!(EvidenceBuilder::new()
            .with_import(vec![component("react", ComponentType::Package)], RelationshipGraph::new())
            .with_provenance(too_many_provenance)
            .build(&mut ledger)
            .is_err());

        let mut ledger = AdmissionLedger::new();
        let too_many_attestations: Vec<_> = (0..=crate::limits::HARD_MAX_ATTESTATIONS_PER_COMPONENT)
            .map(|i| attestation(&format!("att-{i}"), "react")).collect();
        assert!(EvidenceBuilder::new()
            .with_import(vec![component("react", ComponentType::Package)], RelationshipGraph::new())
            .with_attestations(too_many_attestations)
            .build(&mut ledger)
            .is_err());
    }
}
