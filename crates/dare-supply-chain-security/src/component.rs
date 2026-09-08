//! The normalized component model.
//!
//! Everything the engine reasons about ends up here, whatever document it came
//! from. A CycloneDX component and the SPDX package describing the same thing
//! must land on the same shape, or cross-format equivalence is a comparison of
//! two parsers rather than of two descriptions.
//!
//! Ordered collections throughout — `BTreeSet`, `BTreeMap` — so that two
//! documents listing the same digests in different orders digest identically.
//! Using a `Vec` here would make canonicalization depend on the order somebody
//! else's tool happened to emit.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{Result, SupplyChainError};
use crate::limits;
use crate::source::{ComponentType, DigestAlgorithm, EvidenceSource, ObservationKind, TrustClass};

/// One immutable digest for an artifact.
///
/// Algorithm and value are separate fields rather than a `sha256:…` string,
/// because an allowlisted algorithm is a decision and a parsed prefix is a
/// guess. An unrecognised algorithm fails to decode rather than becoming an
/// opaque label that looks like integrity evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub algorithm: DigestAlgorithm,
    /// Lowercase hexadecimal, exactly as long as the algorithm requires.
    pub value: String,
}

impl ArtifactDigest {
    pub fn validate(&self) -> Result<()> {
        let expected = self.algorithm.hex_len();
        if self.value.len() != expected {
            return Err(SupplyChainError::invalid(format!(
                "a {} digest must be {expected} hex characters",
                self.algorithm.as_str()
            )));
        }
        if !self
            .value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            // Lowercase specifically: `AB…` and `ab…` are the same digest and
            // would compare as different strings, which is a substitution the
            // engine would report as a finding when nothing had changed.
            return Err(SupplyChainError::invalid(
                "a digest must be lowercase hexadecimal".to_owned(),
            ));
        }
        Ok(())
    }

    /// The `algorithm:value` form used in reports.
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.algorithm.as_str(), self.value)
    }
}

/// A package coordinate or other identifier a document supplied.
///
/// Held as inert metadata. A purl names where something could be obtained; this
/// engine records that it was named and never acts on it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentIdentifier {
    /// `purl`, `cpe`, `swid`, `spdx-id`, `model-id` and similar.
    pub kind: String,
    pub value: String,
    /// Whether this identifier can distinguish an immutable artifact.
    ///
    /// A purl carrying a version is *not* immutable: two builds can publish the
    /// same version. A purl carrying a digest qualifier is. The document does
    /// not decide this — `identity.rs` does, from the value's shape.
    #[serde(default)]
    pub immutable: bool,
}

impl ComponentIdentifier {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.kind, "identifier kind")?;
        if self.value.trim().is_empty() {
            return Err(SupplyChainError::invalid("an identifier has no value"));
        }
        if self.value.len() > 512 {
            return Err(SupplyChainError::refusal(
                "an identifier value is longer than 512 bytes".to_owned(),
            ));
        }
        if self.value.chars().any(char::is_control) {
            return Err(SupplyChainError::refusal(
                "an identifier value carries a control character".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Who a document says supplied, published, built or signed a component.
///
/// A *claim*, and the type says so: there is no field here that could make it
/// an approval. Trust arrives separately, from local policy, in
/// [`SourceTrustAssessment`].
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplierClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    /// The registry or source the document names. Inert metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

impl SupplierClaim {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.supplier_id, "supplier id"),
            (&self.publisher_id, "publisher id"),
            (&self.builder_id, "builder id"),
            (&self.signer_id, "signer id"),
            (&self.source_id, "source id"),
        ] {
            if let Some(value) = value {
                assert_safe_identifier(value, label)?;
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// What a local policy says about a component's source.
///
/// Separate from [`SupplierClaim`] on purpose. The claim is what a document
/// asserts; this is what a local approved-identity policy establishes, and
/// only the second can carry [`TrustClass::Approved`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustAssessment {
    pub trust: TrustClass,
    /// Where the assessment came from. Only a local approval source may carry
    /// `Approved`, and `validate` enforces it.
    pub established_by: EvidenceSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_identity_id: Option<String>,
}

impl SourceTrustAssessment {
    pub fn validate(&self) -> Result<()> {
        if let Some(id) = &self.approved_identity_id {
            assert_safe_identifier(id, "approved identity id")?;
        }
        if self.trust.may_establish_authority() && !self.established_by.may_establish_approval() {
            // The structural guard behind "a BOM claiming trusted=true does not
            // establish trust". A CycloneDX document cannot hand itself an
            // approval by setting a field.
            return Err(SupplyChainError::refusal(format!(
                "a {} source cannot establish an approved trust class; approval comes from \
                 local policy",
                self.established_by.as_str()
            )));
        }
        if self.trust.may_establish_authority() && self.approved_identity_id.is_none() {
            return Err(SupplyChainError::invalid(
                "an approved trust class names no approved identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A capability an external component exposes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRef {
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl CapabilityRef {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.capability_id, "capability id")?;
        if let Some(kind) = &self.kind {
            assert_safe_identifier(kind, "capability kind")?;
        }
        Ok(())
    }
}

/// The approved and observed capability sets for one component.
///
/// Both sides are needed to say anything. One side alone is a description of
/// what a component exposes, or of what it was approved to expose, and drift is
/// the difference between them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProjection {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved: BTreeSet<CapabilityRef>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub observed: BTreeSet<CapabilityRef>,
}

impl CapabilityProjection {
    pub fn validate(&self) -> Result<()> {
        for capability in self.approved.iter().chain(&self.observed) {
            capability.validate()?;
        }
        let total = self.approved.len() + self.observed.len();
        if total as u32 > limits::HARD_MAX_CAPABILITIES_PER_COMPONENT * 2 {
            return Err(SupplyChainError::BudgetExhausted(
                "a component declares more capabilities than the hard maximum".to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether both sides were supplied, so drift can be decided at all.
    pub fn is_comparable(&self) -> bool {
        !self.approved.is_empty() && !self.observed.is_empty()
    }

    /// Capabilities present in the observed set and absent from the approved
    /// one. Named rather than counted so a finding is actionable.
    pub fn introduced(&self) -> Vec<&CapabilityRef> {
        self.observed.difference(&self.approved).collect()
    }

    /// Capabilities that were approved and are no longer observed.
    ///
    /// Recorded but not itself a violation: a component doing less than it was
    /// approved to do has not crossed a boundary.
    pub fn withdrawn(&self) -> Vec<&CapabilityRef> {
        self.approved.difference(&self.observed).collect()
    }
}

/// One normalized component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    /// The engine's own canonical identifier for this component.
    pub component_id: String,
    pub component_type: ComponentType,
    /// The name a document gave it. A name, not an identity.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub digests: BTreeSet<ArtifactDigest>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub identifiers: BTreeSet<ComponentIdentifier>,

    #[serde(default, skip_serializing_if = "SupplierClaim::is_empty")]
    pub supplier: SupplierClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_trust: Option<SourceTrustAssessment>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CapabilityProjection>,

    /// Whether this component was declared, observed, or both.
    pub observation: ObservationKind,
    /// Which document this component came from.
    pub evidence_source: EvidenceSource,

    /// Bounded free-form metadata a document carried. Never authority-bearing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Component {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.component_id, "component id")?;
        assert_safe_identifier(&self.name, "component name")?;
        if let Some(version) = &self.version {
            assert_safe_identifier(version, "component version")?;
        }

        if self.digests.len() as u32 > limits::HARD_MAX_HASHES_PER_COMPONENT {
            return Err(SupplyChainError::BudgetExhausted(format!(
                "component `{}` carries {} digests; the hard maximum is {}",
                self.component_id,
                self.digests.len(),
                limits::HARD_MAX_HASHES_PER_COMPONENT
            )));
        }
        for digest in &self.digests {
            digest.validate()?;
        }

        if self.identifiers.len() as u32 > limits::HARD_MAX_IDENTIFIERS_PER_COMPONENT {
            return Err(SupplyChainError::BudgetExhausted(format!(
                "component `{}` carries {} identifiers; the hard maximum is {}",
                self.component_id,
                self.identifiers.len(),
                limits::HARD_MAX_IDENTIFIERS_PER_COMPONENT
            )));
        }
        for identifier in &self.identifiers {
            identifier.validate()?;
        }

        self.supplier.validate()?;
        if let Some(trust) = &self.source_trust {
            trust.validate()?;
        }
        if let Some(capabilities) = &self.capabilities {
            capabilities.validate()?;
        }

        let metadata_bytes: usize = self
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        if metadata_bytes > limits::HARD_MAX_METADATA_BYTES_PER_COMPONENT {
            return Err(SupplyChainError::BudgetExhausted(format!(
                "component `{}` carries {metadata_bytes} bytes of metadata; the hard maximum \
                 is {}",
                self.component_id,
                limits::HARD_MAX_METADATA_BYTES_PER_COMPONENT
            )));
        }
        for key in self.metadata.keys() {
            assert_safe_identifier(key, "metadata key")?;
        }

        Ok(())
    }

    /// Whether this component carries at least one immutable digest.
    pub fn has_digest(&self) -> bool {
        !self.digests.is_empty()
    }

    /// Whether an immutable artifact digest is expected and absent.
    ///
    /// Returns `None` when the class does not expect one at all — a different
    /// answer from "expected and missing", and the evaluator treats it
    /// differently.
    pub fn missing_expected_digest(&self) -> Option<bool> {
        if !self.component_type.expects_immutable_artifact() {
            return None;
        }
        Some(!self.has_digest())
    }

    /// The trust class a local policy established, if any.
    ///
    /// `None` means no policy spoke about this component, which is a gap rather
    /// than a denial.
    pub fn established_trust(&self) -> Option<TrustClass> {
        self.source_trust.as_ref().map(|trust| trust.trust)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn digest(value: &str) -> ArtifactDigest {
        ArtifactDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: value.repeat(64 / value.len()),
        }
    }

    pub(crate) fn component(id: &str, kind: ComponentType) -> Component {
        Component {
            component_id: id.to_owned(),
            component_type: kind,
            name: id.to_owned(),
            version: Some("1.0.0".to_owned()),
            digests: BTreeSet::from([digest("a")]),
            identifiers: BTreeSet::new(),
            supplier: SupplierClaim::default(),
            source_trust: None,
            capabilities: None,
            observation: ObservationKind::DeclaredAndObserved,
            evidence_source: EvidenceSource::CycloneDx,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn the_fixture_component_validates() {
        component("react", ComponentType::Package)
            .validate()
            .expect("valid");
    }

    #[test]
    fn a_digest_of_the_wrong_length_for_its_algorithm_is_refused() {
        // A hex string that is well-formed and the wrong length is not a digest
        // of that thing, however convincing it looks.
        let mut component = component("react", ComponentType::Package);
        component.digests = BTreeSet::from([ArtifactDigest {
            algorithm: DigestAlgorithm::Sha512,
            value: "a".repeat(64),
        }]);
        assert!(component.validate().is_err());
    }

    #[test]
    fn an_uppercase_digest_is_refused_rather_than_normalized() {
        // `AB…` and `ab…` are the same digest and compare as different strings.
        // Normalizing quietly would work; refusing says which form the engine
        // stores, so two documents cannot disagree about it.
        let mut component = component("react", ComponentType::Package);
        component.digests = BTreeSet::from([ArtifactDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: "A".repeat(64),
        }]);
        assert!(component.validate().is_err());
    }

    #[test]
    fn a_malformed_digest_fails_closed() {
        let mut component = component("react", ComponentType::Package);
        component.digests = BTreeSet::from([ArtifactDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: "z".repeat(64),
        }]);
        assert!(component.validate().is_err());
    }

    #[test]
    fn a_document_cannot_hand_itself_an_approval() {
        // The structural form of "a BOM claiming trusted=true does not
        // establish trust". The combination is refused at validation, so it
        // cannot exist in the model for an evaluator to read.
        let mut component = component("react", ComponentType::Package);
        component.source_trust = Some(SourceTrustAssessment {
            trust: TrustClass::Approved,
            established_by: EvidenceSource::CycloneDx,
            approved_identity_id: Some("meta".to_owned()),
        });
        let err = component.validate().expect_err("must be refused");
        assert!(err.is_refusal());

        // The same assessment from a local policy is fine.
        component.source_trust = Some(SourceTrustAssessment {
            trust: TrustClass::Approved,
            established_by: EvidenceSource::LocalPolicy,
            approved_identity_id: Some("meta".to_owned()),
        });
        component.validate().expect("local policy may approve");
    }

    #[test]
    fn an_approval_must_name_the_identity_it_approved() {
        let mut component = component("react", ComponentType::Package);
        component.source_trust = Some(SourceTrustAssessment {
            trust: TrustClass::Approved,
            established_by: EvidenceSource::LocalPolicy,
            approved_identity_id: None,
        });
        assert!(component.validate().is_err());
    }

    #[test]
    fn too_many_digests_or_identifiers_are_refused_rather_than_truncated() {
        let mut component = component("react", ComponentType::Package);
        component.digests = (0..(limits::HARD_MAX_HASHES_PER_COMPONENT + 1))
            .map(|n| ArtifactDigest {
                algorithm: DigestAlgorithm::Sha256,
                value: format!("{n:064x}"),
            })
            .collect();
        assert!(component.validate().is_err());
    }

    #[test]
    fn oversized_metadata_is_refused() {
        let mut component = component("react", ComponentType::Package);
        component.metadata.insert(
            "notes".to_owned(),
            "x".repeat(limits::HARD_MAX_METADATA_BYTES_PER_COMPONENT + 1),
        );
        assert!(component.validate().is_err());
    }

    #[test]
    fn a_digest_expectation_depends_on_what_the_class_is() {
        // Three answers, not two. "Not expected" and "expected and missing" are
        // different, and an engine that collapsed them would report a gap
        // against an endpoint that has no bytes to digest.
        let mut package = component("react", ComponentType::Package);
        assert_eq!(package.missing_expected_digest(), Some(false));
        package.digests.clear();
        assert_eq!(package.missing_expected_digest(), Some(true));

        let mut agent = component("planner", ComponentType::Agent);
        agent.digests.clear();
        assert_eq!(agent.missing_expected_digest(), None);
    }

    #[test]
    fn capability_drift_needs_both_sides_to_be_decidable() {
        let mut projection = CapabilityProjection::default();
        assert!(!projection.is_comparable());

        projection.approved = BTreeSet::from([CapabilityRef {
            capability_id: "read-file".to_owned(),
            kind: None,
        }]);
        assert!(
            !projection.is_comparable(),
            "one side alone describes what a component exposes, not whether it drifted"
        );

        projection.observed = BTreeSet::from([
            CapabilityRef {
                capability_id: "read-file".to_owned(),
                kind: None,
            },
            CapabilityRef {
                capability_id: "write-file".to_owned(),
                kind: None,
            },
        ]);
        assert!(projection.is_comparable());
        assert_eq!(projection.introduced().len(), 1);
        assert_eq!(projection.introduced()[0].capability_id, "write-file");
        assert!(projection.withdrawn().is_empty());
    }

    #[test]
    fn a_withdrawn_capability_is_recorded_and_is_not_a_crossing() {
        // A component doing less than it was approved to do has not crossed a
        // boundary, and reporting it as drift would train a reader to ignore
        // drift findings.
        let projection = CapabilityProjection {
            approved: BTreeSet::from([
                CapabilityRef {
                    capability_id: "read-file".to_owned(),
                    kind: None,
                },
                CapabilityRef {
                    capability_id: "write-file".to_owned(),
                    kind: None,
                },
            ]),
            observed: BTreeSet::from([CapabilityRef {
                capability_id: "read-file".to_owned(),
                kind: None,
            }]),
        };
        assert!(projection.introduced().is_empty());
        assert_eq!(projection.withdrawn().len(), 1);
    }

    #[test]
    fn a_hostile_component_name_is_refused() {
        let mut component = component("react", ComponentType::Package);
        component.name = "react\u{202E}exe".to_owned();
        assert!(component.validate().is_err());
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_credential() {
        // Checked structurally: the field simply does not exist, so a document
        // carrying one cannot decode into a component.
        let hostile = serde_json::json!({
            "component_id": "react",
            "component_type": "PACKAGE",
            "name": "react",
            "observation": "OBSERVED",
            "evidence_source": "CYCLONEDX",
            "api_key": "x"
        });
        assert!(serde_json::from_value::<Component>(hostile).is_err());
    }

    #[test]
    fn digests_and_identifiers_are_order_independent() {
        // Two documents listing the same digests in different orders must
        // digest identically, or cross-format equivalence compares parsers
        // rather than descriptions.
        let mut left = component("react", ComponentType::Package);
        left.digests = BTreeSet::from([
            ArtifactDigest {
                algorithm: DigestAlgorithm::Sha256,
                value: format!("{:064x}", 1),
            },
            ArtifactDigest {
                algorithm: DigestAlgorithm::Sha512,
                value: format!("{:0128x}", 2),
            },
        ]);
        let mut right = component("react", ComponentType::Package);
        right.digests = BTreeSet::from([
            ArtifactDigest {
                algorithm: DigestAlgorithm::Sha512,
                value: format!("{:0128x}", 2),
            },
            ArtifactDigest {
                algorithm: DigestAlgorithm::Sha256,
                value: format!("{:064x}", 1),
            },
        ]);
        assert_eq!(
            crate::canonical::digest(&left).unwrap(),
            crate::canonical::digest(&right).unwrap()
        );
    }
}
