//! The twelve invariants, the scenarios that stage them, and the property
//! mapping that keeps coverage honest.
//!
//! # Twelve, and exactly twelve
//!
//! DESIGN section 19 fixes the list. A thirteenth invariant added during
//! execution would change what the cycle claims to have proved without anyone
//! reviewing the claim, and `the_registry_holds_exactly_the_twelve_approved_invariants`
//! fails if the count moves.
//!
//! # Why two invariants can share a property
//!
//! Invariants 1 and 7 both map to `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`,
//! and 3 and 5 both map to `COMPONENT_IDENTITY`. They are separate invariants
//! because they fail for separate reasons — a component with no provenance at
//! all is a different finding from one whose provenance names the wrong
//! builder — but they answer the same question a reader of the property asked.
//! Splitting the property would have made the registry describe the engine's
//! internals rather than the risk.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{Result, SupplyChainError};
use crate::source::{ReferenceBehavior, ScenarioClass, SupplyChainMode};

/// The risk family every property in this cycle belongs to.
///
/// Frozen by Cycle 012. This cycle adds properties to it and creates no second
/// family.
pub const RISK_FAMILY: &str = "AGENTIC_SUPPLY_CHAIN";

/// The property namespace. There is deliberately no `AGENT.SUPPLY.*`.
pub const PROPERTY_PREFIX: &str = "AGENT.SUPPLY_CHAIN.";

/// One deterministic invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupplyChainInvariant {
    /// 1. A component that needs provenance has it, bound to itself.
    ComponentProvenanceSufficient,
    /// 2. No externally supplied component gained a capability since approval.
    ExternalCapabilityDriftNotObserved,
    /// 3. No two artifacts claim one identity, and no artifact claims two.
    ComponentIdentityUnambiguous,
    /// 4. The artifact digest is bound to the component that was approved.
    ArtifactDigestBoundToComponent,
    /// 5. A tag or range is not being relied on as immutable identity.
    MutableReferenceNotUsedAsImmutableIdentity,
    /// 6. The component came from a source local policy approved.
    ComponentSourceTrustPreserved,
    /// 7. Provenance binds its subject, and names an approved builder.
    ProvenanceSubjectAndBuilderBound,
    /// 8. The attestation's subject digest is this artifact's digest.
    AttestationSubjectDigestPreserved,
    /// 9. Declared and observed dependency edges agree.
    DependencyEdgeIntegrityPreserved,
    /// 10. The model derives from the approved base.
    ModelLineagePreserved,
    /// 11. The dataset is the approved one.
    DatasetProvenancePreserved,
    /// 12. The evidence a component's class requires is present.
    BomRequiredEvidencePresent,
}

impl SupplyChainInvariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentProvenanceSufficient => "COMPONENT_PROVENANCE_SUFFICIENT",
            Self::ExternalCapabilityDriftNotObserved => "EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED",
            Self::ComponentIdentityUnambiguous => "COMPONENT_IDENTITY_UNAMBIGUOUS",
            Self::ArtifactDigestBoundToComponent => "ARTIFACT_DIGEST_BOUND_TO_COMPONENT",
            Self::MutableReferenceNotUsedAsImmutableIdentity => {
                "MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY"
            }
            Self::ComponentSourceTrustPreserved => "COMPONENT_SOURCE_TRUST_PRESERVED",
            Self::ProvenanceSubjectAndBuilderBound => "PROVENANCE_SUBJECT_AND_BUILDER_BOUND",
            Self::AttestationSubjectDigestPreserved => "ATTESTATION_SUBJECT_DIGEST_PRESERVED",
            Self::DependencyEdgeIntegrityPreserved => "DEPENDENCY_EDGE_INTEGRITY_PRESERVED",
            Self::ModelLineagePreserved => "MODEL_LINEAGE_PRESERVED",
            Self::DatasetProvenancePreserved => "DATASET_PROVENANCE_PRESERVED",
            Self::BomRequiredEvidencePresent => "BOM_REQUIRED_EVIDENCE_PRESENT",
        }
    }

    /// The twelve, in the order DESIGN section 19 fixes them.
    pub fn all() -> [Self; 12] {
        [
            Self::ComponentProvenanceSufficient,
            Self::ExternalCapabilityDriftNotObserved,
            Self::ComponentIdentityUnambiguous,
            Self::ArtifactDigestBoundToComponent,
            Self::MutableReferenceNotUsedAsImmutableIdentity,
            Self::ComponentSourceTrustPreserved,
            Self::ProvenanceSubjectAndBuilderBound,
            Self::AttestationSubjectDigestPreserved,
            Self::DependencyEdgeIntegrityPreserved,
            Self::ModelLineagePreserved,
            Self::DatasetProvenancePreserved,
            Self::BomRequiredEvidencePresent,
        ]
    }

    /// The registry property this invariant reports under.
    ///
    /// The mapping is fixed by DESIGN section 19 and is many-to-one: two
    /// invariants may share a property because they answer one question for
    /// different reasons.
    pub fn property_id(self) -> &'static str {
        match self {
            Self::ComponentProvenanceSufficient | Self::ProvenanceSubjectAndBuilderBound => {
                "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE"
            }
            Self::ExternalCapabilityDriftNotObserved => "AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT",
            Self::ComponentIdentityUnambiguous
            | Self::MutableReferenceNotUsedAsImmutableIdentity => {
                "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY"
            }
            Self::ArtifactDigestBoundToComponent => "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
            Self::ComponentSourceTrustPreserved => "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
            Self::AttestationSubjectDigestPreserved => "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
            Self::DependencyEdgeIntegrityPreserved => "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
            Self::ModelLineagePreserved => "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
            Self::DatasetProvenancePreserved => "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
            Self::BomRequiredEvidencePresent => "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
        }
    }

    /// The ten distinct properties the twelve invariants report under.
    pub fn properties() -> BTreeSet<&'static str> {
        Self::all()
            .iter()
            .map(|invariant| invariant.property_id())
            .collect()
    }
}

/// A local scenario that stages evidence for evaluation.
///
/// Note what it cannot say. There is no `expected_verdict`, no
/// `expected_findings`, no `is_secure`, no `should_fail` and no evaluator
/// override — the evaluator is the only verdict authority, and a scenario able
/// to state an outcome would turn every paired fixture into a test of the
/// fixture author.
///
/// There is also no executable hook: no command, no script path, no callback.
/// A scenario describes evidence; it does not run anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainScenario {
    pub scenario_id: String,
    pub class: ScenarioClass,
    pub mode: SupplyChainMode,
    /// The invariant this scenario is built to exercise.
    ///
    /// A coverage selector, never a verdict. Every applicable invariant is
    /// still evaluated, and a concrete failure of another one is retained.
    pub primary_invariant: SupplyChainInvariant,
    /// Local evidence files this scenario reads, relative to the corpus root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_files: Vec<String>,
    /// How a synthetic harness should behave, where one is staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_behavior: Option<ReferenceBehavior>,
    /// What the scenario is for, in operator terms.
    pub description: String,
}

impl SupplyChainScenario {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.scenario_id, "scenario id")?;
        if self.description.trim().is_empty() {
            return Err(SupplyChainError::invalid(format!(
                "scenario `{}` has no description; a fixture nobody can explain is a fixture \
                 nobody can review",
                self.scenario_id
            )));
        }
        for file in &self.evidence_files {
            assert_safe_identifier(file, "evidence file")?;
        }
        Ok(())
    }

    /// Whether this scenario stages a synthetic harness.
    pub fn is_synthetic(&self) -> bool {
        self.mode == SupplyChainMode::LocalSynthetic
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn scenario(id: &str, invariant: SupplyChainInvariant) -> SupplyChainScenario {
        SupplyChainScenario {
            scenario_id: id.to_owned(),
            class: ScenarioClass::ComponentIdentity,
            mode: SupplyChainMode::Static,
            primary_invariant: invariant,
            evidence_files: vec!["bom.json".to_owned()],
            reference_behavior: None,
            description: "a fixture".to_owned(),
        }
    }

    #[test]
    fn the_registry_holds_exactly_the_twelve_approved_invariants() {
        // DESIGN section 19 fixes the list. A thirteenth added during execution
        // would change what the cycle claims to have proved without anyone
        // reviewing the claim.
        assert_eq!(SupplyChainInvariant::all().len(), 12);
        let names: BTreeSet<&str> = SupplyChainInvariant::all()
            .iter()
            .map(|invariant| invariant.as_str())
            .collect();
        assert_eq!(names.len(), 12, "two invariants share a name");
        for expected in [
            "COMPONENT_PROVENANCE_SUFFICIENT",
            "EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED",
            "COMPONENT_IDENTITY_UNAMBIGUOUS",
            "ARTIFACT_DIGEST_BOUND_TO_COMPONENT",
            "MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY",
            "COMPONENT_SOURCE_TRUST_PRESERVED",
            "PROVENANCE_SUBJECT_AND_BUILDER_BOUND",
            "ATTESTATION_SUBJECT_DIGEST_PRESERVED",
            "DEPENDENCY_EDGE_INTEGRITY_PRESERVED",
            "MODEL_LINEAGE_PRESERVED",
            "DATASET_PROVENANCE_PRESERVED",
            "BOM_REQUIRED_EVIDENCE_PRESENT",
        ] {
            assert!(names.contains(expected), "{expected} is missing");
        }
    }

    #[test]
    fn the_property_mapping_is_exactly_the_one_design_fixed() {
        use SupplyChainInvariant as I;
        for (invariant, property) in [
            (I::ComponentProvenanceSufficient, "COMPONENT_PROVENANCE"),
            (I::ProvenanceSubjectAndBuilderBound, "COMPONENT_PROVENANCE"),
            (I::ExternalCapabilityDriftNotObserved, "CAPABILITY_DRIFT"),
            (I::ComponentIdentityUnambiguous, "COMPONENT_IDENTITY"),
            (
                I::MutableReferenceNotUsedAsImmutableIdentity,
                "COMPONENT_IDENTITY",
            ),
            (I::ArtifactDigestBoundToComponent, "ARTIFACT_INTEGRITY"),
            (I::ComponentSourceTrustPreserved, "SOURCE_TRUST"),
            (I::AttestationSubjectDigestPreserved, "ATTESTATION_BINDING"),
            (I::DependencyEdgeIntegrityPreserved, "DEPENDENCY_INTEGRITY"),
            (I::ModelLineagePreserved, "MODEL_LINEAGE"),
            (I::DatasetProvenancePreserved, "DATASET_PROVENANCE"),
            (I::BomRequiredEvidencePresent, "BOM_COMPLETENESS"),
        ] {
            assert_eq!(
                invariant.property_id(),
                format!("{PROPERTY_PREFIX}{property}"),
                "{} maps to the wrong property",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn twelve_invariants_report_under_ten_properties() {
        // Two pairs share deliberately: provenance sufficiency and provenance
        // binding are different failures of one question, as are identity
        // ambiguity and mutable identity.
        assert_eq!(SupplyChainInvariant::properties().len(), 10);
    }

    #[test]
    fn every_property_is_in_the_frozen_namespace() {
        // Cycle 012 owns the namespace. A parallel `AGENT.SUPPLY.*` would give
        // a reader two places to look for one risk.
        for invariant in SupplyChainInvariant::all() {
            assert!(
                invariant.property_id().starts_with(PROPERTY_PREFIX),
                "{} left the frozen namespace",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn an_unknown_invariant_fails_to_decode() {
        assert!(serde_json::from_str::<SupplyChainInvariant>("\"SOMETHING_NEW\"").is_err());
    }

    #[test]
    fn a_scenario_cannot_declare_a_verdict_or_run_anything() {
        // The corpus authority boundary from DESIGN section 22, structural
        // rather than checked.
        for hostile in [
            serde_json::json!({ "expected_verdict": "FAIL" }),
            serde_json::json!({ "expected_findings": [] }),
            serde_json::json!({ "is_secure": false }),
            serde_json::json!({ "should_fail": true }),
            serde_json::json!({ "evaluator_override": "SKIP" }),
            serde_json::json!({ "command": "cargo run" }),
            serde_json::json!({ "hook": "./setup.sh" }),
        ] {
            let mut value = serde_json::to_value(scenario(
                "supply-lab-001",
                SupplyChainInvariant::ComponentIdentityUnambiguous,
            ))
            .expect("serializes");
            let object = value.as_object_mut().expect("an object");
            for (key, extra) in hostile.as_object().expect("an object") {
                object.insert(key.clone(), extra.clone());
            }
            assert!(
                serde_json::from_value::<SupplyChainScenario>(value).is_err(),
                "a scenario carrying {hostile} decoded"
            );
        }
    }

    #[test]
    fn the_primary_invariant_is_a_coverage_selector_and_not_a_verdict() {
        // Naming an invariant says which question the fixture was built to
        // exercise. It does not say what the answer is, and the field it lives
        // in cannot hold one.
        let scenario = scenario(
            "supply-lab-001",
            SupplyChainInvariant::ComponentIdentityUnambiguous,
        );
        let rendered = serde_json::to_string(&scenario).expect("serializes");
        for absent in ["verdict", "expected", "secure", "finding"] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "a scenario carries a `{absent}` field"
            );
        }
    }

    #[test]
    fn a_scenario_without_a_description_is_refused() {
        // A fixture nobody can explain is a fixture nobody can review, and a
        // corpus of them proves only that the engine agrees with itself.
        let mut nameless = scenario(
            "supply-lab-001",
            SupplyChainInvariant::ModelLineagePreserved,
        );
        nameless.description = "   ".to_owned();
        assert!(nameless.validate().is_err());
    }

    #[test]
    fn a_hostile_scenario_identifier_is_refused() {
        let mut hostile = scenario(
            "supply-lab-001",
            SupplyChainInvariant::ModelLineagePreserved,
        );
        hostile.evidence_files = vec!["../../etc/passwd".to_owned()];
        assert!(hostile.validate().is_err());
    }
}
