//! Dataset provenance, bounded to supply-chain scope.
//!
//! A dataset is a component: it has an identity, it has bytes, it came from
//! somewhere, and a model was trained on it. Those four are supply-chain
//! questions and this module answers them.
//!
//! # What this module deliberately does not do
//!
//! No privacy analysis, no PII detection, no copyright or licence assessment,
//! no fairness or bias evaluation. Those are real questions about datasets and
//! none of them is a supply-chain question. Answering them here would mean this
//! cycle asserting things about data it never reads — the engine sees a
//! dataset's *identity and digest*, never its contents, and could not evaluate
//! bias if it wanted to.
//!
//! The boundary is enforced structurally: there is no field in the model where
//! such a finding could be recorded, and
//! `the_dataset_model_has_nowhere_to_record_a_privacy_finding` asserts it.

use serde::{Deserialize, Serialize};

use crate::component::Component;
use crate::manifest::DareManifest;
use crate::normalize::SupplyChainEvidence;
use crate::source::ComponentType;

/// What the evidence says about one dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetAssessment {
    pub component_id: String,
    /// Whether the manifest approved a dataset under this id.
    pub approved: bool,
    /// Whether the observed digest matches an approved one.
    ///
    /// `None` when either side recorded none.
    pub digest_bound: Option<bool>,
    /// Models that record training on this dataset.
    pub consuming_model_ids: Vec<String>,
    /// Whether the dataset records a source or supplier at all.
    pub has_origin_claim: bool,
}

impl DatasetAssessment {
    /// Whether there is enough on both sides to decide anything.
    pub fn is_decidable(&self) -> bool {
        self.approved && self.digest_bound.is_some()
    }
}

/// Assess one dataset component.
pub fn assess(
    component: &Component,
    evidence: &SupplyChainEvidence,
    manifest: &DareManifest,
) -> DatasetAssessment {
    let approved_entry = manifest.approved(&component.component_id);

    let digest_bound = approved_entry.and_then(|approved| {
        if approved.digests.is_empty() || component.digests.is_empty() {
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

    // Which models were trained on this dataset. Recorded because a substituted
    // dataset matters in proportion to what consumed it, and a finding that
    // names the models is actionable in a way that one naming only the dataset
    // is not.
    let consuming_model_ids = evidence
        .graph
        .edges
        .iter()
        .filter(|edge| {
            edge.relation.is_lineage()
                && edge.target_id == component.component_id
                && evidence
                    .component(&edge.source_id)
                    .is_some_and(|source| source.component_type.expects_lineage())
        })
        .map(|edge| edge.source_id.clone())
        .collect();

    DatasetAssessment {
        component_id: component.component_id.clone(),
        approved: approved_entry.is_some(),
        digest_bound,
        consuming_model_ids,
        has_origin_claim: !component.supplier.is_empty(),
    }
}

/// Every dataset component in the evidence.
pub fn datasets(evidence: &SupplyChainEvidence) -> Vec<&Component> {
    evidence
        .components
        .iter()
        .filter(|component| component.component_type == ComponentType::Dataset)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::component::tests::{component, digest};
    use crate::manifest::ApprovedComponent;
    use crate::normalize::EvidenceBuilder;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use crate::source::ObservationKind;
    use std::collections::BTreeSet;

    fn evidence(dataset_digest: &str) -> SupplyChainEvidence {
        let mut dataset = component("training-corpus", ComponentType::Dataset);
        dataset.digests = BTreeSet::from([digest(dataset_digest)]);
        dataset.supplier.supplier_id = Some("acme-data".to_owned());

        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([digest("c")]);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner-model",
                "training-corpus",
                RelationType::TrainedFrom,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_import(vec![dataset, model], graph)
            .build(&mut ledger)
            .expect("builds")
    }

    fn manifest_approving(digest_seed: &str) -> DareManifest {
        DareManifest {
            schema_version: "1".to_owned(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "training-corpus".to_owned(),
                name: Some("training-corpus".to_owned()),
                version: None,
                digests: BTreeSet::from([digest(digest_seed)]),
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn an_approved_dataset_with_a_matching_digest_binds() {
        let evidence = evidence("a");
        let manifest = manifest_approving("a");
        let dataset = evidence.component("training-corpus").expect("present");

        let assessment = assess(dataset, &evidence, &manifest);
        assert!(assessment.approved);
        assert_eq!(assessment.digest_bound, Some(true));
        assert!(assessment.is_decidable());
        assert!(assessment.has_origin_claim);
    }

    #[test]
    fn a_substituted_dataset_does_not_bind() {
        let evidence = evidence("b");
        let manifest = manifest_approving("a");
        let dataset = evidence.component("training-corpus").expect("present");

        assert_eq!(
            assess(dataset, &evidence, &manifest).digest_bound,
            Some(false)
        );
    }

    #[test]
    fn the_assessment_names_the_models_that_consumed_the_dataset() {
        // A substituted dataset matters in proportion to what trained on it, and
        // a finding naming the models is actionable in a way one naming only
        // the dataset is not.
        let evidence = evidence("a");
        let dataset = evidence.component("training-corpus").expect("present");
        let assessment = assess(dataset, &evidence, &manifest_approving("a"));
        assert_eq!(assessment.consuming_model_ids, vec!["planner-model"]);
    }

    #[test]
    fn a_dataset_nobody_approved_is_undecidable_rather_than_wrong() {
        let evidence = evidence("a");
        let dataset = evidence.component("training-corpus").expect("present");
        let assessment = assess(dataset, &evidence, &DareManifest::default());
        assert!(!assessment.approved);
        assert!(!assessment.is_decidable());
        assert_eq!(assessment.digest_bound, None);
    }

    #[test]
    fn an_approval_with_no_digest_leaves_integrity_undecided() {
        // Approving a dataset by name says which dataset was meant. It does not
        // say which bytes, and treating it as if it did would let any content
        // under the approved name pass.
        let evidence = evidence("a");
        let mut manifest = manifest_approving("a");
        let mut approved: Vec<_> = manifest.approved_components.into_iter().collect();
        approved[0].digests.clear();
        manifest.approved_components = approved.into_iter().collect();

        let dataset = evidence.component("training-corpus").expect("present");
        let assessment = assess(dataset, &evidence, &manifest);
        assert!(assessment.approved);
        assert_eq!(assessment.digest_bound, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn datasets_are_selected_by_class_rather_than_by_name() {
        let evidence = evidence("a");
        let found = datasets(&evidence);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].component_id, "training-corpus");
    }

    #[test]
    fn the_dataset_model_has_nowhere_to_record_a_privacy_finding() {
        // The scope boundary, enforced structurally. Privacy, PII, copyright,
        // licence, fairness and bias are real questions about datasets and none
        // is a supply-chain question. This engine sees a dataset's identity and
        // digest and never its contents, so it could not evaluate bias if it
        // wanted to — and a field that invited the attempt would be a promise
        // the engine cannot keep.
        let rendered = serde_json::to_string(&DatasetAssessment {
            component_id: "training-corpus".to_owned(),
            approved: true,
            digest_bound: Some(true),
            consuming_model_ids: Vec::new(),
            has_origin_claim: true,
        })
        .expect("serializes");

        for absent in [
            "pii",
            "privacy",
            "copyright",
            "licence",
            "license",
            "bias",
            "fairness",
        ] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "the assessment carries a `{absent}` field"
            );
        }

        for hostile in ["pii_detected", "license_conflict", "bias_score"] {
            let value = serde_json::json!({
                "component_id": "d", "approved": true, "digest_bound": null,
                "consuming_model_ids": [], "has_origin_claim": false,
                hostile: true
            });
            assert!(serde_json::from_value::<DatasetAssessment>(value).is_err());
        }
    }
}
