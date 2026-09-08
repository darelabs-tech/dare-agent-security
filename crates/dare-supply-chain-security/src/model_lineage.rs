//! Model lineage.
//!
//! ```text
//! model name != base-model lineage
//! ```
//!
//! A model called `llama-3-8b-finetuned` tells you what somebody named it. It
//! does not tell you what it was fine-tuned *from*, and a substituted base
//! model keeps the name unchanged — which is exactly why the property exists
//! and why the expectation is expressed as a component id rather than a name.
//!
//! Lineage is read from typed edges (`TRAINED_FROM`, `FINE_TUNED_FROM`,
//! `BUILT_FROM`) between component identities, and compared against what a
//! local manifest approved.

use serde::{Deserialize, Serialize};

use crate::component::Component;
use crate::manifest::DareManifest;
use crate::normalize::SupplyChainEvidence;

/// What the evidence says about one model's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageAssessment {
    pub component_id: String,
    /// The base the manifest approved, if it named one.
    pub expected_base_id: Option<String>,
    /// The bases the graph actually records.
    pub observed_base_ids: Vec<String>,
    /// Whether the observed base digests match the approved ones.
    ///
    /// `None` when either side recorded no digest — a name-level agreement is
    /// not a digest-level one, and collapsing them would let a substituted
    /// build of the right base pass.
    pub base_digest_bound: Option<bool>,
}

impl LineageAssessment {
    /// Whether both sides exist, so the comparison can be made at all.
    pub fn is_decidable(&self) -> bool {
        self.expected_base_id.is_some() && !self.observed_base_ids.is_empty()
    }

    /// Whether the observed lineage includes the approved base.
    ///
    /// `None` when undecidable. A model may legitimately derive from several
    /// bases; the approved one being among them is agreement.
    pub fn base_matches(&self) -> Option<bool> {
        let expected = self.expected_base_id.as_ref()?;
        if self.observed_base_ids.is_empty() {
            return None;
        }
        Some(self.observed_base_ids.contains(expected))
    }
}

/// Assess the lineage of one model component.
pub fn assess(
    component: &Component,
    evidence: &SupplyChainEvidence,
    manifest: &DareManifest,
) -> LineageAssessment {
    let expected = manifest.lineage_for(&component.component_id);

    let observed_base_ids: Vec<String> = evidence
        .graph
        .lineage_of(&component.component_id)
        .into_iter()
        .map(|edge| edge.target_id.clone())
        .collect();

    // Digest binding is checked against the *approved base's* digests, not
    // against the observed base component's own record. A substituted base
    // that reused the approved id would otherwise carry its own digests and
    // agree with itself.
    let base_digest_bound = expected.and_then(|expected| {
        if expected.base_digests.is_empty() {
            return None;
        }
        let observed_component = observed_base_ids
            .iter()
            .filter_map(|id| evidence.component(id))
            .find(|candidate| candidate.component_id == expected.base_component_id)?;
        if observed_component.digests.is_empty() {
            return None;
        }
        Some(
            expected
                .base_digests
                .intersection(&observed_component.digests)
                .next()
                .is_some(),
        )
    });

    LineageAssessment {
        component_id: component.component_id.clone(),
        expected_base_id: expected.map(|expected| expected.base_component_id.clone()),
        observed_base_ids,
        base_digest_bound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::component::tests::{component, digest};
    use crate::manifest::ExpectedLineage;
    use crate::normalize::EvidenceBuilder;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use crate::source::{ComponentType, ObservationKind};
    use std::collections::BTreeSet;

    fn evidence_with(base_id: &str, base_digest: &str) -> SupplyChainEvidence {
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([digest("c")]);
        let mut base = component(base_id, ComponentType::Model);
        base.digests = BTreeSet::from([digest(base_digest)]);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner-model",
                base_id,
                RelationType::FineTunedFrom,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_import(vec![model, base], graph)
            .build(&mut ledger)
            .expect("builds")
    }

    fn manifest_expecting(base_id: &str, base_digest: &str) -> DareManifest {
        DareManifest {
            schema_version: "1".to_owned(),
            expected_lineage: BTreeSet::from([ExpectedLineage {
                component_id: "planner-model".to_owned(),
                base_component_id: base_id.to_owned(),
                base_digests: BTreeSet::from([digest(base_digest)]),
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn an_approved_base_that_is_observed_matches() {
        let evidence = evidence_with("base-model", "a");
        let manifest = manifest_expecting("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &manifest);
        assert!(assessment.is_decidable());
        assert_eq!(assessment.base_matches(), Some(true));
        assert_eq!(assessment.base_digest_bound, Some(true));
    }

    #[test]
    fn a_substituted_base_model_does_not_match() {
        // The finding the property exists for. The model's own name is
        // unchanged; only what it derives from moved.
        let evidence = evidence_with("base-model-attacker", "b");
        let manifest = manifest_expecting("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &manifest);
        assert!(assessment.is_decidable());
        assert_eq!(assessment.base_matches(), Some(false));
    }

    #[test]
    fn the_right_base_with_the_wrong_digest_is_still_a_substitution() {
        // Name-level agreement is not digest-level agreement. A rebuilt base
        // under the approved id would otherwise pass, which is the same
        // substitution one level down.
        let evidence = evidence_with("base-model", "b");
        let manifest = manifest_expecting("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &manifest);
        assert_eq!(assessment.base_matches(), Some(true));
        assert_eq!(
            assessment.base_digest_bound,
            Some(false),
            "a rebuilt base under the approved id compared as the approved base"
        );
    }

    #[test]
    fn missing_lineage_evidence_is_undecidable_rather_than_a_match() {
        // No observed lineage edge at all. The engine has nothing to compare,
        // and answering "matches" would be answering a question nobody asked.
        let mut ledger = AdmissionLedger::new();
        let model = component("planner-model", ComponentType::Model);
        let evidence = EvidenceBuilder::new()
            .with_import(vec![model], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        let manifest = manifest_expecting("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &manifest);
        assert!(!assessment.is_decidable());
        assert_eq!(assessment.base_matches(), None);
    }

    #[test]
    fn a_missing_expectation_is_also_undecidable() {
        // Lineage observed and nothing approved. The engine can see what the
        // model derives from and has no basis to call it right or wrong.
        let evidence = evidence_with("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &DareManifest::default());
        assert!(!assessment.is_decidable());
        assert_eq!(assessment.base_matches(), None);
        assert!(!assessment.observed_base_ids.is_empty());
    }

    #[test]
    fn a_model_may_derive_from_several_bases() {
        // Merged models are real. The approved base being among the observed
        // ones is agreement; requiring it to be the only one would report a
        // finding on a legitimate architecture.
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([digest("c")]);
        let mut first = component("base-model", ComponentType::Model);
        first.digests = BTreeSet::from([digest("a")]);
        let mut second = component("base-other", ComponentType::Model);
        second.digests = BTreeSet::from([digest("b")]);

        let mut graph = RelationshipGraph::new();
        for base in ["base-model", "base-other"] {
            graph
                .insert(edge(
                    "planner-model",
                    base,
                    RelationType::TrainedFrom,
                    ObservationKind::Observed,
                ))
                .expect("valid");
        }

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![model, first, second], graph)
            .build(&mut ledger)
            .expect("builds");
        let manifest = manifest_expecting("base-model", "a");
        let model = evidence.component("planner-model").expect("present");

        assert_eq!(
            assess(model, &evidence, &manifest).base_matches(),
            Some(true)
        );
    }

    #[test]
    fn a_dependency_edge_is_not_lineage() {
        // A model depending on a package is not derived from it, and reading
        // dependency edges as lineage would make every model's lineage the
        // whole graph.
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([digest("c")]);
        let package = component("numpy", ComponentType::Package);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner-model",
                "numpy",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![model, package], graph)
            .build(&mut ledger)
            .expect("builds");
        let model = evidence.component("planner-model").expect("present");

        let assessment = assess(model, &evidence, &manifest_expecting("base-model", "a"));
        assert!(assessment.observed_base_ids.is_empty());
    }
}
