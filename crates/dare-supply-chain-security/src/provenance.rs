//! Local provenance evidence, and the three bindings it must satisfy.
//!
//! ```text
//! digest presence     != provenance
//! provenance presence != trusted provenance
//! ```
//!
//! A digest says what an artifact *is*. Provenance says where it came from and
//! who built it — a different question with a different answer, and a component
//! can have a perfect digest and no provenance at all.
//!
//! The second distinction is the one that costs more. A provenance record is a
//! claim by whoever wrote it. `provenance_present == true` establishes nothing;
//! what establishes something is three independent bindings:
//!
//! 1. the record's **subject** is the component being assessed;
//! 2. the subject's **digest** is the artifact's digest;
//! 3. the **builder** is one a local policy approved.
//!
//! Each can hold while another fails. A record with the right subject, the
//! wrong digest and an approved builder is provenance for a different build of
//! the same component, and reporting it as satisfied would be reporting the
//! substitution as the thing it substituted for.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::component::{ArtifactDigest, Component};
use crate::error::{Result, SupplyChainError};
use crate::limits;
use crate::source::EvidenceSource;

/// One local provenance record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub provenance_id: String,
    /// The component this record claims to be about.
    pub subject_component_id: String,
    /// The digests the record says the subject has.
    #[serde(default)]
    pub subject_digests: BTreeSet<ArtifactDigest>,
    /// The builder identity the record names. A claim, not an approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    /// Build invocation or environment identifiers, as bounded metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    /// Source material the record references.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub source_material_ids: BTreeSet<String>,
    pub evidence_source: EvidenceSource,
}

impl ProvenanceRecord {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.provenance_id, "provenance id")?;
        assert_safe_identifier(&self.subject_component_id, "provenance subject")?;
        if let Some(builder) = &self.builder_id {
            assert_safe_identifier(builder, "builder id")?;
        }
        if let Some(invocation) = &self.invocation_id {
            assert_safe_identifier(invocation, "invocation id")?;
        }
        for material in &self.source_material_ids {
            assert_safe_identifier(material, "source material id")?;
        }
        for digest in &self.subject_digests {
            digest.validate()?;
        }
        if self.subject_digests.len() as u32 > limits::HARD_MAX_HASHES_PER_COMPONENT {
            return Err(SupplyChainError::BudgetExhausted(format!(
                "provenance `{}` names more subject digests than the hard maximum",
                self.provenance_id
            )));
        }
        Ok(())
    }

    /// Whether this record's subject is the component under assessment.
    ///
    /// The first binding, and the one an engine is most likely to skip: a
    /// provenance record found *near* a component is not a record *about* it.
    pub fn binds_subject(&self, component: &Component) -> bool {
        self.subject_component_id == component.component_id
    }

    /// Whether the subject digest matches the artifact's digest.
    ///
    /// Three answers. `None` means one side recorded no digest, so there is
    /// nothing to compare — distinct from "compared and differed", which is a
    /// substitution.
    pub fn binds_digest(&self, component: &Component) -> Option<bool> {
        if self.subject_digests.is_empty() || component.digests.is_empty() {
            return None;
        }
        Some(
            self.subject_digests
                .intersection(&component.digests)
                .next()
                .is_some(),
        )
    }
}

/// The provenance bindings for one component, evaluated together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceAssessment {
    pub component_id: String,
    /// Records naming this component as their subject.
    pub matching_provenance_ids: Vec<String>,
    /// Matching records that bind a different artifact digest.
    ///
    /// Kept explicitly so one correct provenance record cannot erase another
    /// record that describes a different build of the same component.
    pub misbound_provenance_ids: Vec<String>,
    /// Records that exist for other components and were not applied here.
    pub unbound_provenance_ids: Vec<String>,
    /// Whether all comparable matching records agree with the artifact.
    /// `Some(false)` wins over `Some(true)`: contradictory provenance is a
    /// contradiction, not agreement by majority or by best case.
    pub digest_bound: Option<bool>,
    /// A deterministic representative builder retained for compatibility with
    /// earlier artifacts. Security decisions must use `builder_ids` instead.
    pub builder_id: Option<String>,
    /// Every builder named by matching provenance records.
    pub builder_ids: BTreeSet<String>,
}

impl ProvenanceAssessment {
    /// Whether any provenance at all was found for this component.
    pub fn has_provenance(&self) -> bool {
        !self.matching_provenance_ids.is_empty()
    }
}

/// Assess the provenance available for one component.
pub fn assess(component: &Component, records: &[ProvenanceRecord]) -> ProvenanceAssessment {
    let mut matching = Vec::new();
    let mut misbound = Vec::new();
    let mut unbound = Vec::new();
    let mut saw_digest_match = false;
    let mut saw_digest_mismatch = false;
    let mut builder_ids = BTreeSet::new();

    for record in records {
        if !record.binds_subject(component) {
            unbound.push(record.provenance_id.clone());
            continue;
        }
        matching.push(record.provenance_id.clone());

        match record.binds_digest(component) {
            Some(true) => saw_digest_match = true,
            Some(false) => {
                saw_digest_mismatch = true;
                misbound.push(record.provenance_id.clone());
            }
            None => {}
        }
        if let Some(builder) = &record.builder_id {
            builder_ids.insert(builder.clone());
        }
    }

    let digest_bound = if saw_digest_mismatch {
        Some(false)
    } else if saw_digest_match {
        Some(true)
    } else {
        None
    };
    let builder_id = builder_ids.iter().next().cloned();

    ProvenanceAssessment {
        component_id: component.component_id.clone(),
        matching_provenance_ids: matching,
        misbound_provenance_ids: misbound,
        unbound_provenance_ids: unbound,
        digest_bound,
        builder_id,
        builder_ids,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::{component, digest};
    use crate::source::ComponentType;

    pub(crate) fn record(id: &str, subject: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            provenance_id: id.to_owned(),
            subject_component_id: subject.to_owned(),
            subject_digests: BTreeSet::from([digest("a")]),
            builder_id: Some("builder-ci".to_owned()),
            invocation_id: Some("run-1".to_owned()),
            source_material_ids: BTreeSet::new(),
            evidence_source: EvidenceSource::LocalProvenance,
        }
    }

    #[test]
    fn the_fixture_record_validates() {
        record("prov-1", "react").validate().expect("valid");
    }

    #[test]
    fn a_record_about_another_component_does_not_bind() {
        // A provenance record found near a component is not a record about it.
        let component = component("react", ComponentType::Package);
        let elsewhere = record("prov-1", "vue");
        assert!(!elsewhere.binds_subject(&component));

        let assessment = assess(&component, &[elsewhere]);
        assert!(!assessment.has_provenance());
        assert_eq!(assessment.unbound_provenance_ids, vec!["prov-1"]);
    }

    #[test]
    fn a_record_with_the_right_subject_binds() {
        let component = component("react", ComponentType::Package);
        let assessment = assess(&component, &[record("prov-1", "react")]);
        assert!(assessment.has_provenance());
        assert_eq!(assessment.digest_bound, Some(true));
        assert_eq!(assessment.builder_id.as_deref(), Some("builder-ci"));
        assert!(assessment.builder_ids.contains("builder-ci"));
    }

    #[test]
    fn a_record_naming_a_different_digest_is_provenance_for_a_different_build() {
        // The subject is right and the artifact is not. Reporting this as
        // satisfied would report the substitution as the thing it substituted
        // for.
        let component = component("react", ComponentType::Package);
        let mut wrong = record("prov-1", "react");
        wrong.subject_digests = BTreeSet::from([digest("b")]);

        assert_eq!(wrong.binds_digest(&component), Some(false));
        let assessment = assess(&component, &[wrong]);
        assert_eq!(assessment.digest_bound, Some(false));
        assert_eq!(assessment.misbound_provenance_ids, vec!["prov-1"]);
    }

    #[test]
    fn an_absent_digest_on_either_side_answers_nothing() {
        // Three answers, not two. "Nothing to compare" and "compared and
        // differed" are different situations and the evaluator treats them
        // differently.
        let component = component("react", ComponentType::Package);
        let mut no_subject_digest = record("prov-1", "react");
        no_subject_digest.subject_digests.clear();
        assert_eq!(no_subject_digest.binds_digest(&component), None);

        let mut no_artifact_digest = component.clone();
        no_artifact_digest.digests.clear();
        assert_eq!(
            record("prov-1", "react").binds_digest(&no_artifact_digest),
            None
        );
    }

    #[test]
    fn the_three_bindings_are_independent() {
        // Each can hold while another fails, which is why they are three
        // questions rather than one boolean.
        let component = component("react", ComponentType::Package);

        // Right subject, wrong digest, builder present.
        let mut wrong_digest = record("prov-1", "react");
        wrong_digest.subject_digests = BTreeSet::from([digest("b")]);
        let assessment = assess(&component, &[wrong_digest]);
        assert!(assessment.has_provenance());
        assert_eq!(assessment.digest_bound, Some(false));
        assert!(assessment.builder_id.is_some());

        // Right subject, right digest, no builder at all.
        let mut no_builder = record("prov-2", "react");
        no_builder.builder_id = None;
        let assessment = assess(&component, &[no_builder]);
        assert_eq!(assessment.digest_bound, Some(true));
        assert!(assessment.builder_id.is_none());
        assert!(assessment.builder_ids.is_empty());
    }

    #[test]
    fn several_records_for_one_component_agree_if_weaker_records_do_not_contradict() {
        // A record that cannot compare does not erase a stronger one. This is
        // different from a record that compares and disagrees, which must fail.
        let component = component("react", ComponentType::Package);
        let mut weak = record("prov-weak", "react");
        weak.subject_digests.clear();
        let strong = record("prov-strong", "react");

        let assessment = assess(&component, &[weak, strong]);
        assert_eq!(assessment.digest_bound, Some(true));
        assert_eq!(assessment.matching_provenance_ids.len(), 2);
        assert!(assessment.misbound_provenance_ids.is_empty());
    }

    #[test]
    fn a_conflicting_record_cannot_be_hidden_by_a_matching_one() {
        let component = component("react", ComponentType::Package);
        let good = record("prov-good", "react");
        let mut bad = record("prov-bad", "react");
        bad.subject_digests = BTreeSet::from([digest("b")]);

        let assessment = assess(&component, &[good, bad]);
        assert_eq!(assessment.digest_bound, Some(false));
        assert_eq!(assessment.misbound_provenance_ids, vec!["prov-bad"]);
    }

    #[test]
    fn every_named_builder_is_retained_for_policy_evaluation() {
        let component = component("react", ComponentType::Package);
        let good = record("prov-good", "react");
        let mut second = record("prov-second", "react");
        second.builder_id = Some("builder-secondary".to_owned());

        let assessment = assess(&component, &[good, second]);
        assert_eq!(assessment.builder_ids.len(), 2);
        assert!(assessment.builder_ids.contains("builder-ci"));
        assert!(assessment.builder_ids.contains("builder-secondary"));
    }

    #[test]
    fn provenance_presence_carries_no_trust_field() {
        // Structural: there is nowhere in this model to record that a
        // provenance record is trusted. Trust comes from the policy, and a
        // record that could assert it would make the policy decorative.
        let hostile = serde_json::json!({
            "provenance_id": "prov-1",
            "subject_component_id": "react",
            "evidence_source": "LOCAL_PROVENANCE",
            "trusted": true
        });
        assert!(serde_json::from_value::<ProvenanceRecord>(hostile).is_err());
    }

    #[test]
    fn a_hostile_provenance_identifier_is_refused() {
        let mut hostile = record("prov-1", "react");
        hostile.builder_id = Some("builder\u{202E}evil".to_owned());
        assert!(hostile.validate().is_err());
    }
}
