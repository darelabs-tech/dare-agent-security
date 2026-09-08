//! The local trust policy and the DARE expectation manifest.
//!
//! Everything else in this crate reads documents that describe *what a system
//! contains*. This module is the only one that reads a document describing
//! *what was approved* — and that asymmetry is the entire trust model.
//!
//! ```text
//! inventory != trust
//! ```
//!
//! A CycloneDX or SPDX document is a claim by whoever produced it. It can say a
//! component is supplied by Acme; it cannot say Acme was approved. Approval
//! lives here, in a local file the deployment controls, and
//! [`crate::component::SourceTrustAssessment::validate`] refuses an `Approved`
//! trust class that came from anywhere else.
//!
//! # What a manifest may not do
//!
//! It may not declare a verdict, an expected finding, or anything shaped like
//! one. The evaluator is the only verdict authority, and a manifest that could
//! state an outcome would reduce the engine to agreeing with whoever wrote the
//! manifest — which is the failure the whole paired-fixture discipline exists
//! to prevent.
//!
//! The refusal is structural rather than a check: there is no field for it, and
//! `deny_unknown_fields` means adding one fails to decode.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::component::ArtifactDigest;
use crate::error::{Result, SupplyChainError};
use crate::limits;
use crate::relationship::RelationType;

/// Identities a local policy approves.
///
/// Five separate sets, because they are five separate concepts. A publisher is
/// not a builder; a builder is not a signer; approving one approves one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_sources: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_suppliers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_publishers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_builders: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_signers: BTreeSet<String>,
}

impl TrustPolicy {
    pub fn validate(&self) -> Result<()> {
        for (set, label) in [
            (&self.approved_sources, "approved source"),
            (&self.approved_suppliers, "approved supplier"),
            (&self.approved_publishers, "approved publisher"),
            (&self.approved_builders, "approved builder"),
            (&self.approved_signers, "approved signer"),
        ] {
            for identity in set {
                assert_safe_identifier(identity, label)?;
            }
        }
        Ok(())
    }

    /// Whether the policy says anything at all.
    ///
    /// An empty policy is not a policy that approves nothing — it is the
    /// absence of a policy, and the evaluator reports that as a gap rather than
    /// as universal denial. The difference matters: denying everything would
    /// make every component a finding, which is indistinguishable from a broken
    /// engine.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub fn approves_builder(&self, builder_id: &str) -> bool {
        self.approved_builders.contains(builder_id)
    }

    pub fn approves_signer(&self, signer_id: &str) -> bool {
        self.approved_signers.contains(signer_id)
    }

    /// Whether every source-shaped claim a component supplied is approved by
    /// the corresponding local-policy set.
    ///
    /// Source, supplier and publisher are separate concepts. One approved claim
    /// must not mask a conflicting unapproved claim on another boundary. With
    /// no claims at all the answer remains `None`: nobody supplied origin
    /// evidence to decide.
    pub fn approves_origin(
        &self,
        source_id: Option<&str>,
        supplier_id: Option<&str>,
        publisher_id: Option<&str>,
    ) -> Option<bool> {
        let claims = [
            (source_id, &self.approved_sources),
            (supplier_id, &self.approved_suppliers),
            (publisher_id, &self.approved_publishers),
        ];
        let mut saw_claim = false;
        for (claim, approved) in claims {
            let Some(claim) = claim else { continue };
            saw_claim = true;
            if !approved.contains(claim) {
                return Some(false);
            }
        }
        saw_claim.then_some(true)
    }
}

/// An approved component identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedComponent {
    pub component_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The digests the deployment approved for this component.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub digests: BTreeSet<ArtifactDigest>,
}

impl ApprovedComponent {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.component_id, "approved component id")?;
        if let Some(name) = &self.name {
            assert_safe_identifier(name, "approved component name")?;
        }
        if let Some(version) = &self.version {
            assert_safe_identifier(version, "approved component version")?;
        }
        for digest in &self.digests {
            digest.validate()?;
        }
        Ok(())
    }
}

/// An edge the deployment expects to exist.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEdge {
    pub source_id: String,
    pub target_id: String,
    pub relation: RelationType,
}

impl ExpectedEdge {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.source_id, "expected edge source")?;
        assert_safe_identifier(&self.target_id, "expected edge target")?;
        Ok(())
    }
}

/// The base model a model component is expected to derive from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedLineage {
    pub component_id: String,
    /// The approved base-model component id.
    ///
    /// An id, not a name. `model name alone cannot prove lineage` is the whole
    /// point of the property, and expressing the expectation as a name would
    /// build the defect into the expectation.
    pub base_component_id: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub base_digests: BTreeSet<ArtifactDigest>,
}

impl ExpectedLineage {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.component_id, "lineage component id")?;
        assert_safe_identifier(&self.base_component_id, "lineage base component id")?;
        for digest in &self.base_digests {
            digest.validate()?;
        }
        if self.component_id == self.base_component_id {
            return Err(SupplyChainError::invalid(
                "a model cannot be its own base model".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The DARE-native expectation manifest.
///
/// Expresses what a deployment approved, in the vocabulary this engine
/// evaluates. It exists because a BOM cannot say "this is what we approved" —
/// a BOM says "this is what we found".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DareManifest {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_id: Option<String>,

    #[serde(default, skip_serializing_if = "TrustPolicy::is_empty")]
    pub trust_policy: TrustPolicy,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_components: BTreeSet<ApprovedComponent>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expected_edges: BTreeSet<ExpectedEdge>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expected_lineage: BTreeSet<ExpectedLineage>,
    /// Components the deployment declares its system contains.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub declared_component_ids: BTreeSet<String>,
    /// Approved capability sets, keyed by component id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub approved_capabilities: BTreeMap<String, BTreeSet<String>>,
}

impl DareManifest {
    pub fn validate(&self) -> Result<()> {
        if !self.schema_version.is_empty() && self.schema_version != "1" {
            return Err(SupplyChainError::schema(format!(
                "manifest schema version `{}` is not supported; guessing what an unknown \
                 version meant is how an expectation quietly changes",
                self.schema_version
            )));
        }
        if let Some(id) = &self.manifest_id {
            assert_safe_identifier(id, "manifest id")?;
        }
        self.trust_policy.validate()?;

        if self.approved_components.len() as u32 > limits::HARD_MAX_COMPONENTS {
            return Err(SupplyChainError::BudgetExhausted(
                "the manifest approves more components than the hard maximum".to_owned(),
            ));
        }
        for component in &self.approved_components {
            component.validate()?;
        }

        if self.expected_edges.len() as u32 > limits::HARD_MAX_RELATIONSHIPS {
            return Err(SupplyChainError::BudgetExhausted(
                "the manifest expects more edges than the hard maximum".to_owned(),
            ));
        }
        for edge in &self.expected_edges {
            edge.validate()?;
        }
        for lineage in &self.expected_lineage {
            lineage.validate()?;
        }
        for id in &self.declared_component_ids {
            assert_safe_identifier(id, "declared component id")?;
        }
        for (component_id, capabilities) in &self.approved_capabilities {
            assert_safe_identifier(component_id, "capability component id")?;
            if capabilities.len() as u32 > limits::HARD_MAX_CAPABILITIES_PER_COMPONENT {
                return Err(SupplyChainError::BudgetExhausted(format!(
                    "the manifest approves more capabilities for `{component_id}` than the \
                     hard maximum"
                )));
            }
            for capability in capabilities {
                assert_safe_identifier(capability, "approved capability")?;
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The approved entry for a component, if the manifest names one.
    pub fn approved(&self, component_id: &str) -> Option<&ApprovedComponent> {
        self.approved_components
            .iter()
            .find(|component| component.component_id == component_id)
    }

    /// The expected base model for a component, if one was declared.
    pub fn lineage_for(&self, component_id: &str) -> Option<&ExpectedLineage> {
        self.expected_lineage
            .iter()
            .find(|lineage| lineage.component_id == component_id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::digest;

    pub(crate) fn policy() -> TrustPolicy {
        TrustPolicy {
            approved_sources: BTreeSet::from(["registry-internal".to_owned()]),
            approved_suppliers: BTreeSet::from(["acme".to_owned()]),
            approved_publishers: BTreeSet::new(),
            approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
            approved_signers: BTreeSet::from(["signer-release".to_owned()]),
        }
    }

    pub(crate) fn manifest() -> DareManifest {
        DareManifest {
            schema_version: "1".to_owned(),
            manifest_id: Some("manifest-1".to_owned()),
            trust_policy: policy(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(),
                name: Some("react".to_owned()),
                version: Some("1.0.0".to_owned()),
                digests: BTreeSet::from([digest("a")]),
            }]),
            expected_edges: BTreeSet::new(),
            expected_lineage: BTreeSet::new(),
            declared_component_ids: BTreeSet::from(["react".to_owned()]),
            approved_capabilities: BTreeMap::new(),
        }
    }

    #[test]
    fn the_fixture_manifest_validates() {
        manifest().validate().expect("valid");
    }

    #[test]
    fn a_manifest_cannot_declare_a_verdict() {
        // Structural rather than checked: there is no field, and
        // `deny_unknown_fields` means adding one fails to decode. A manifest
        // that could state an outcome would reduce the engine to agreeing with
        // whoever wrote the manifest.
        for hostile in [
            serde_json::json!({ "schema_version": "1", "expected_verdict": "PASS" }),
            serde_json::json!({ "schema_version": "1", "is_secure": true }),
            serde_json::json!({ "schema_version": "1", "expected_findings": [] }),
            serde_json::json!({ "schema_version": "1", "should_fail": false }),
        ] {
            assert!(
                serde_json::from_value::<DareManifest>(hostile).is_err(),
                "a manifest declared its own outcome"
            );
        }
    }

    #[test]
    fn an_unsupported_manifest_version_is_refused_rather_than_guessed() {
        let mut manifest = manifest();
        manifest.schema_version = "2".to_owned();
        let err = manifest.validate().expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn the_five_approved_identity_sets_are_separate_concepts() {
        // A publisher is not a builder, and approving one approves one.
        let policy = policy();
        assert!(policy.approves_builder("builder-ci"));
        assert!(!policy.approves_signer("builder-ci"));
        assert!(policy.approves_signer("signer-release"));
        assert!(!policy.approves_builder("signer-release"));
    }

    #[test]
    fn an_absent_policy_is_a_gap_rather_than_universal_denial() {
        // Denying everything would make every component a finding, which is
        // indistinguishable from a broken engine. The evaluator needs to be
        // able to tell "nobody wrote a policy" from "the policy says no".
        let empty = TrustPolicy::default();
        assert!(empty.is_empty());
        assert_eq!(empty.approves_origin(None, None, None), None);
    }

    #[test]
    fn a_claim_that_matches_nothing_is_a_decision_not_a_gap() {
        let policy = policy();
        assert_eq!(
            policy.approves_origin(Some("registry-unknown"), None, None),
            Some(false)
        );
        assert_eq!(
            policy.approves_origin(Some("registry-internal"), None, None),
            Some(true)
        );
    }

    #[test]
    fn origin_claims_are_independent_and_one_approved_claim_does_not_mask_another() {
        let policy = policy();
        assert_eq!(policy.approves_origin(None, Some("acme"), None), Some(true));
        assert_eq!(
            policy.approves_origin(Some("registry-internal"), Some("acme"), None),
            Some(true)
        );
        assert_eq!(
            policy.approves_origin(Some("registry-unknown"), Some("acme"), None),
            Some(false)
        );
    }

    #[test]
    fn expected_lineage_is_expressed_as_an_id_and_not_a_name() {
        // "A model name alone cannot prove lineage" is the property. Expressing
        // the expectation as a name would build the defect into the
        // expectation itself.
        let lineage = ExpectedLineage {
            component_id: "fine-tuned".to_owned(),
            base_component_id: "base-model".to_owned(),
            base_digests: BTreeSet::from([digest("a")]),
        };
        lineage.validate().expect("valid");
        // The field is a component id, and the type has no `base_name`.
        let hostile = serde_json::json!({
            "component_id": "fine-tuned",
            "base_component_id": "base-model",
            "base_name": "llama-3"
        });
        assert!(serde_json::from_value::<ExpectedLineage>(hostile).is_err());
    }

    #[test]
    fn a_model_cannot_be_its_own_base() {
        let lineage = ExpectedLineage {
            component_id: "model".to_owned(),
            base_component_id: "model".to_owned(),
            base_digests: BTreeSet::new(),
        };
        assert!(lineage.validate().is_err());
    }

    #[test]
    fn a_hostile_identity_in_the_policy_is_refused() {
        let mut policy = policy();
        policy
            .approved_builders
            .insert("builder\u{202E}evil".to_owned());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn manifest_collections_are_order_independent() {
        // The manifest is part of the binding, so two equivalent manifests must
        // digest identically or a reordering would read as a substitution.
        let mut left = manifest();
        left.declared_component_ids =
            BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()]);
        let mut right = manifest();
        right.declared_component_ids =
            BTreeSet::from(["c".to_owned(), "a".to_owned(), "b".to_owned()]);
        assert_eq!(
            crate::canonical::digest(&left).unwrap(),
            crate::canonical::digest(&right).unwrap()
        );
    }
}
