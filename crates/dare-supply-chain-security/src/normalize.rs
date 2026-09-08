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
        self.components
            .iter()
            .find(|component| component.component_id == component_id)
    }

    pub fn semantic_keys(&self) -> BTreeSet<String> {
        self.components
            .iter()
            .map(|component| resolve_identity(component).semantic_key)
            .collect()
    }

    pub fn edge_keys(&self) -> BTreeSet<String> {
        self.graph
            .edges
            .iter()
            .map(Relationship::edge_key)
            .collect()
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
            let count = provenance_counts
                .entry(&record.subject_component_id)
                .or_default();
            *count += 1;
            if *count > crate::limits::HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT {
                return Err(SupplyChainError::BudgetExhausted(
                    "a component carries more provenance records than the hard maximum".to_owned(),
                ));
            }
        }
        let mut attestation_counts: BTreeMap<&str, u32> = BTreeMap::new();
        for record in &self.attestations {
            let count = attestation_counts
                .entry(&record.subject_component_id)
                .or_default();
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
            && self
                .components
                .iter()
                .any(|component| component.observation != ObservationKind::Declared)
    }

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
                        if descriptions_conflict(
                            &self.evidence.components[existing_index],
                            &component,
                        ) {
                            self.evidence.components.push(component);
                        } else {
                            merge_into(&mut self.evidence.components[existing_index], component);
                        }
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
        (
            &existing.supplier.supplier_id,
            &incoming.supplier.supplier_id,
        ),
        (
            &existing.supplier.publisher_id,
            &incoming.supplier.publisher_id,
        ),
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
            continue;
        }
        collapsed.insert(edge);
    }
    graph.edges = collapsed;
}

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
        let too_many_provenance: Vec<_> = (0
            ..=crate::limits::HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT)
            .map(|i| record(&format!("prov-{i}"), "react"))
            .collect();
        assert!(EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new()
            )
            .with_provenance(too_many_provenance)
            .build(&mut ledger)
            .is_err());

        let mut ledger = AdmissionLedger::new();
        let too_many_attestations: Vec<_> = (0
            ..=crate::limits::HARD_MAX_ATTESTATIONS_PER_COMPONENT)
            .map(|i| attestation(&format!("att-{i}"), "react"))
            .collect();
        assert!(EvidenceBuilder::new()
            .with_import(
                vec![component("react", ComponentType::Package)],
                RelationshipGraph::new()
            )
            .with_attestations(too_many_attestations)
            .build(&mut ledger)
            .is_err());
    }
}

#[cfg(test)]
pub(crate) mod cycle019_pre_review_tests {
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
    fn a_collision_between_two_documents_is_visible_at_merge_time() {
        // It cannot be seen from inside either document, which is why the
        // bundle is assembled before anything looks for it.
        //
        // It is reported rather than refused. One artifact under two canonical
        // ids is the finding `COMPONENT_IDENTITY_UNAMBIGUOUS` exists for, and
        // refusing the bundle would hand an operator a run that could not
        // observe instead of the ambiguity it observed perfectly well.
        let first = component("react", ComponentType::Package);
        let mut second = component("react-duplicate", ComponentType::Package);
        second.name = "react".to_owned();

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("an ambiguous bundle is evaluated, not refused");

        let collisions = evidence.identity_collisions();
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].component_id, "react-duplicate");
        assert_eq!(collisions[0].conflicting_component_id, "react");
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
