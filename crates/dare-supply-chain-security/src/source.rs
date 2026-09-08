//! Closed taxonomies.
//!
//! Every enum here fails closed: an unrecognised wire value is a decode error
//! rather than a default. That is the whole reason they are enums. A bill of
//! materials is a document somebody else wrote, and the one thing an engine
//! must not do with an unfamiliar value is guess which familiar one it meant.

use serde::{Deserialize, Serialize};

/// The fourteen approved component classes.
///
/// Closed, and deliberately without an `OTHER` variant. A component the engine
/// cannot classify is a component it cannot reason about, and admitting it
/// under a catch-all would put it in the graph while leaving every
/// type-specific evidence requirement unasked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentType {
    Agent,
    Model,
    EmbeddingModel,
    Dataset,
    Framework,
    Tool,
    SkillPlugin,
    McpServer,
    ServiceApi,
    Package,
    ContainerImage,
    PromptPolicyAsset,
    Guardrail,
    ExternalAgent,
}

impl ComponentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "AGENT",
            Self::Model => "MODEL",
            Self::EmbeddingModel => "EMBEDDING_MODEL",
            Self::Dataset => "DATASET",
            Self::Framework => "FRAMEWORK",
            Self::Tool => "TOOL",
            Self::SkillPlugin => "SKILL_PLUGIN",
            Self::McpServer => "MCP_SERVER",
            Self::ServiceApi => "SERVICE_API",
            Self::Package => "PACKAGE",
            Self::ContainerImage => "CONTAINER_IMAGE",
            Self::PromptPolicyAsset => "PROMPT_POLICY_ASSET",
            Self::Guardrail => "GUARDRAIL",
            Self::ExternalAgent => "EXTERNAL_AGENT",
        }
    }

    pub fn all() -> [Self; 14] {
        [
            Self::Agent,
            Self::Model,
            Self::EmbeddingModel,
            Self::Dataset,
            Self::Framework,
            Self::Tool,
            Self::SkillPlugin,
            Self::McpServer,
            Self::ServiceApi,
            Self::Package,
            Self::ContainerImage,
            Self::PromptPolicyAsset,
            Self::Guardrail,
            Self::ExternalAgent,
        ]
    }

    /// Whether an immutable artifact digest is expected for this class.
    ///
    /// The distinction is between things that *are* bytes and things that
    /// *describe* an arrangement. A package, an image, a model, an embedding
    /// model and a dataset are artifacts: two builds carrying the same version
    /// can be different bytes, and the digest is what tells them apart.
    ///
    /// An agent, a service API and an external agent are not artifacts in this
    /// sense — they are endpoints or roles — so requiring a digest of them
    /// would report a gap against a target that has nothing to supply.
    pub fn expects_immutable_artifact(self) -> bool {
        matches!(
            self,
            Self::Model
                | Self::EmbeddingModel
                | Self::Dataset
                | Self::Framework
                | Self::Tool
                | Self::SkillPlugin
                | Self::McpServer
                | Self::Package
                | Self::ContainerImage
                | Self::PromptPolicyAsset
                | Self::Guardrail
        )
    }

    /// Whether lineage evidence is meaningful for this class.
    pub fn expects_lineage(self) -> bool {
        matches!(self, Self::Model | Self::EmbeddingModel)
    }
}

/// How a component identity, digest or relationship was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    /// A CycloneDX document supplied locally.
    CycloneDx,
    /// An SPDX document supplied locally.
    Spdx,
    /// The DARE-native expectation manifest.
    DareManifest,
    /// A local provenance record.
    LocalProvenance,
    /// A local attestation or signature record.
    LocalAttestation,
    /// A local approved-identity trust policy.
    LocalPolicy,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CycloneDx => "CYCLONEDX",
            Self::Spdx => "SPDX",
            Self::DareManifest => "DARE_MANIFEST",
            Self::LocalProvenance => "LOCAL_PROVENANCE",
            Self::LocalAttestation => "LOCAL_ATTESTATION",
            Self::LocalPolicy => "LOCAL_POLICY",
        }
    }

    /// Whether this source may establish that something is *approved*.
    ///
    /// Only the two local ones. A CycloneDX or SPDX document describes what a
    /// build produced; it is a claim by whoever produced it, and a claim is not
    /// an approval however well-formed the document carrying it is.
    pub fn may_establish_approval(self) -> bool {
        matches!(self, Self::DareManifest | Self::LocalPolicy)
    }
}

/// How much an identity claim may be believed.
///
/// Ordered, so promotion is arithmetic rather than a table somebody must keep
/// consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustClass {
    /// The component, document or publisher says so about itself. A BOM field
    /// reading `"trusted": true` lands here and stays here.
    SelfDeclared,
    /// Recorded from a source the deployment configured, with no cryptographic
    /// proof in this evidence model.
    Declared,
    /// Named by a local approved-identity policy.
    Approved,
}

impl TrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfDeclared => "SELF_DECLARED",
            Self::Declared => "DECLARED",
            Self::Approved => "APPROVED",
        }
    }

    /// Whether this class may establish a source, publisher, builder or signer
    /// as authorized.
    ///
    /// Only `Approved`. This is the whole content of the source-trust boundary,
    /// expressed once so every caller agrees — and it is the reason a
    /// correctly verified signature by an unapproved signer is still a finding.
    pub fn may_establish_authority(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// What a local verification of a signature or attestation concluded.
///
/// Recorded as evidence about a verification somebody else performed. Nothing
/// in this cycle verifies a signature, because verifying one requires a key
/// this cycle is not allowed to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    /// A verification was performed and succeeded.
    Valid,
    /// A verification was performed and failed.
    Invalid,
    /// A verification was performed and could not complete.
    Indeterminate,
    /// No verification was recorded.
    Unrecorded,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Indeterminate => "INDETERMINATE",
            Self::Unrecorded => "UNRECORDED",
        }
    }

    /// Whether a verification happened at all, whatever it concluded.
    ///
    /// Distinct from [`may_be_relied_on`]. "Was it checked?" decides between
    /// INCONCLUSIVE and a verdict; "may it be relied on?" is a different
    /// question with a different answer, and Cycle 018 shipped a false PASS by
    /// letting the first stand in for the second.
    ///
    /// [`may_be_relied_on`]: Self::may_be_relied_on
    pub fn is_recorded_evidence(self) -> bool {
        !matches!(self, Self::Unrecorded)
    }

    /// Whether the verification result is favourable.
    ///
    /// Only `Valid`. And note what this still does not establish: a valid
    /// signature by a signer nobody approved is a correct signature and no
    /// authorization at all. Trust is [`TrustClass::may_establish_authority`],
    /// and the two are deliberately separate questions.
    pub fn may_be_relied_on(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Why this status is not something to rely on, where it is not.
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            Self::Valid => None,
            Self::Invalid => Some("the recorded verification failed"),
            Self::Indeterminate => Some("the recorded verification could not complete"),
            Self::Unrecorded => Some("no verification of it was ever recorded"),
        }
    }
}

/// Digest algorithms this engine will accept.
///
/// An allowlist rather than a parse. An unrecognised algorithm is refused, not
/// stored as an opaque string, because a digest nobody can compare is a field
/// that looks like integrity evidence and is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    #[serde(rename = "sha3-256")]
    Sha3_256,
    #[serde(rename = "sha3-512")]
    Sha3_512,
}

impl DigestAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_512 => "sha3-512",
        }
    }

    /// The exact hex length this algorithm's digest must have.
    pub fn hex_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 | Self::Sha3_512 => 128,
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::Sha3_256,
            Self::Sha3_512,
        ]
    }
}

/// Whether a component or edge was expected or seen.
///
/// The gap between the two is where several findings live: a dependency that
/// was declared and never observed, and one observed that nobody declared, are
/// different problems with different fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationKind {
    /// Named by an approved expectation.
    Declared,
    /// Seen in the evidence describing what the system actually contains.
    Observed,
    /// Both, and in agreement.
    DeclaredAndObserved,
}

impl ObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "DECLARED",
            Self::Observed => "OBSERVED",
            Self::DeclaredAndObserved => "DECLARED_AND_OBSERVED",
        }
    }
}

/// The reporting surface a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    ComponentIdentity,
    ArtifactIntegrity,
    SourceTrust,
    ProvenanceBinding,
    AttestationBinding,
    DependencyIntegrity,
    CapabilityDrift,
    ModelLineage,
    DatasetProvenance,
    BomCompleteness,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentIdentity => "COMPONENT_IDENTITY",
            Self::ArtifactIntegrity => "ARTIFACT_INTEGRITY",
            Self::SourceTrust => "SOURCE_TRUST",
            Self::ProvenanceBinding => "PROVENANCE_BINDING",
            Self::AttestationBinding => "ATTESTATION_BINDING",
            Self::DependencyIntegrity => "DEPENDENCY_INTEGRITY",
            Self::CapabilityDrift => "CAPABILITY_DRIFT",
            Self::ModelLineage => "MODEL_LINEAGE",
            Self::DatasetProvenance => "DATASET_PROVENANCE",
            Self::BomCompleteness => "BOM_COMPLETENESS",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::ComponentIdentity,
            Self::ArtifactIntegrity,
            Self::SourceTrust,
            Self::ProvenanceBinding,
            Self::AttestationBinding,
            Self::DependencyIntegrity,
            Self::CapabilityDrift,
            Self::ModelLineage,
            Self::DatasetProvenance,
            Self::BomCompleteness,
        ]
    }
}

/// Why a harness could not observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessErrorKind {
    /// The adapter itself failed.
    AdapterFailure,
    /// A document could not be admitted.
    DocumentRefused,
    /// A hard bound stopped the run.
    BudgetExhausted,
}

impl HarnessErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdapterFailure => "ADAPTER_FAILURE",
            Self::DocumentRefused => "DOCUMENT_REFUSED",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
        }
    }
}

/// What a reference fixture is staged to demonstrate.
///
/// A behaviour, never a verdict. `MULTIPLE_INDEPENDENT_VIOLATIONS` says a flow
/// crosses several boundaries; it does not say the run should FAIL, and the
/// evaluator remains the only thing that decides that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    Compliant,
    AmbiguousDuplicateIdentity,
    DigestSubstituted,
    MutableReferenceUsedAsIdentity,
    SourceSubstituted,
    ProvenanceSubjectMismatch,
    UnauthorizedBuilder,
    AttestationSubjectMismatch,
    UnapprovedSigner,
    UnexpectedDependencyEdge,
    MissingExpectedDependencyEdge,
    CapabilityDrifted,
    BaseModelSubstituted,
    DatasetSubstituted,
    UndeclaredExternalComponent,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    /// Whether this behaviour is legitimate activity rather than a crossing.
    ///
    /// Controls matter as much as attacks: a surface with only attack fixtures
    /// lets an over-strict engine look perfect while failing every legitimate
    /// flow on that surface.
    pub fn is_legitimate(self) -> bool {
        matches!(self, Self::Compliant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_taxonomy_is_closed_and_uniquely_named() {
        let types: BTreeSet<&str> = ComponentType::all().iter().map(|t| t.as_str()).collect();
        assert_eq!(types.len(), 14);
        let classes: BTreeSet<&str> = ScenarioClass::all().iter().map(|c| c.as_str()).collect();
        assert_eq!(classes.len(), 10);
        let algorithms: BTreeSet<&str> =
            DigestAlgorithm::all().iter().map(|a| a.as_str()).collect();
        assert_eq!(algorithms.len(), 5);
    }

    #[test]
    fn an_unknown_wire_value_fails_closed_rather_than_defaulting() {
        // The reason these are enums. A bill of materials is somebody else's
        // document, and guessing which familiar value an unfamiliar one meant
        // is how a component with an unreadable type ends up in the graph
        // with its evidence requirements unasked.
        assert!(serde_json::from_str::<ComponentType>("\"WEBASSEMBLY_THING\"").is_err());
        assert!(serde_json::from_str::<TrustClass>("\"MOSTLY_APPROVED\"").is_err());
        assert!(serde_json::from_str::<VerificationStatus>("\"PROBABLY_FINE\"").is_err());
        assert!(serde_json::from_str::<DigestAlgorithm>("\"md5\"").is_err());
        assert!(serde_json::from_str::<EvidenceSource>("\"REGISTRY_LOOKUP\"").is_err());
    }

    #[test]
    fn there_is_no_catch_all_component_type() {
        // An `OTHER` variant would admit anything, and admitting a component
        // whose class nobody could read means every type-specific evidence
        // requirement goes unasked while the component sits in the graph.
        for hostile in ["\"OTHER\"", "\"UNKNOWN\"", "\"GENERIC\"", "\"\""] {
            assert!(serde_json::from_str::<ComponentType>(hostile).is_err());
        }
    }

    #[test]
    fn only_a_local_approval_source_may_establish_approval() {
        // A CycloneDX document describes what a build produced. It is a claim
        // by whoever produced it, and a claim is not an approval however
        // well-formed the document carrying it is.
        assert!(!EvidenceSource::CycloneDx.may_establish_approval());
        assert!(!EvidenceSource::Spdx.may_establish_approval());
        assert!(!EvidenceSource::LocalProvenance.may_establish_approval());
        assert!(!EvidenceSource::LocalAttestation.may_establish_approval());
        assert!(EvidenceSource::DareManifest.may_establish_approval());
        assert!(EvidenceSource::LocalPolicy.may_establish_approval());
    }

    #[test]
    fn only_approved_trust_establishes_authority() {
        assert!(!TrustClass::SelfDeclared.may_establish_authority());
        assert!(!TrustClass::Declared.may_establish_authority());
        assert!(TrustClass::Approved.may_establish_authority());
    }

    #[test]
    fn trust_is_ordered_so_promotion_is_arithmetic() {
        assert!(TrustClass::SelfDeclared < TrustClass::Declared);
        assert!(TrustClass::Declared < TrustClass::Approved);
    }

    #[test]
    fn a_recorded_verification_is_not_the_same_as_a_favourable_one() {
        // Cycle 018 shipped a false PASS by letting "was it checked?" stand in
        // for "may it be relied on?". The two questions are kept apart here by
        // construction rather than by care.
        for status in [
            VerificationStatus::Valid,
            VerificationStatus::Invalid,
            VerificationStatus::Indeterminate,
        ] {
            assert!(status.is_recorded_evidence(), "{status:?}");
        }
        assert!(!VerificationStatus::Unrecorded.is_recorded_evidence());

        assert!(VerificationStatus::Valid.may_be_relied_on());
        for status in [
            VerificationStatus::Invalid,
            VerificationStatus::Indeterminate,
            VerificationStatus::Unrecorded,
        ] {
            assert!(!status.may_be_relied_on(), "{status:?}");
            assert!(status.refusal_reason().is_some());
        }
        assert!(VerificationStatus::Valid.refusal_reason().is_none());
    }

    #[test]
    fn verification_status_and_trust_stay_separate_questions() {
        // The distinction the whole source-trust property rests on: a valid
        // signature by an unapproved signer is a correct signature and no
        // authorization. Nothing in `VerificationStatus` can answer a trust
        // question, and there is no method that would let it.
        assert!(VerificationStatus::Valid.may_be_relied_on());
        assert!(!TrustClass::SelfDeclared.may_establish_authority());
        assert!(!TrustClass::Declared.may_establish_authority());
    }

    #[test]
    fn digest_lengths_are_pinned_per_algorithm() {
        // A hex string of the wrong length for its algorithm is not a digest
        // of that thing, however well-formed it looks.
        assert_eq!(DigestAlgorithm::Sha256.hex_len(), 64);
        assert_eq!(DigestAlgorithm::Sha384.hex_len(), 96);
        assert_eq!(DigestAlgorithm::Sha512.hex_len(), 128);
        assert_eq!(DigestAlgorithm::Sha3_256.hex_len(), 64);
        assert_eq!(DigestAlgorithm::Sha3_512.hex_len(), 128);
    }

    #[test]
    fn artifact_expectation_follows_what_a_class_actually_is() {
        // Bytes versus arrangements. Requiring a digest of an endpoint would
        // report a gap against a target that has nothing to supply, which
        // trains a reader to ignore the finding.
        for artifact in [
            ComponentType::Package,
            ComponentType::ContainerImage,
            ComponentType::Model,
            ComponentType::Dataset,
        ] {
            assert!(artifact.expects_immutable_artifact(), "{artifact:?}");
        }
        for role in [
            ComponentType::Agent,
            ComponentType::ServiceApi,
            ComponentType::ExternalAgent,
        ] {
            assert!(!role.expects_immutable_artifact(), "{role:?}");
        }
    }

    #[test]
    fn only_models_expect_lineage() {
        assert!(ComponentType::Model.expects_lineage());
        assert!(ComponentType::EmbeddingModel.expects_lineage());
        assert!(!ComponentType::Dataset.expects_lineage());
        assert!(!ComponentType::Package.expects_lineage());
    }

    #[test]
    fn a_reference_behaviour_is_a_behaviour_and_never_a_verdict() {
        // `MULTIPLE_INDEPENDENT_VIOLATIONS` says a flow crosses several
        // boundaries. It does not say the run should FAIL, and no variant
        // names a verdict.
        let rendered = format!("{:?}", ReferenceBehavior::MultipleIndependentViolations);
        for verdict in ["Pass", "Fail", "Inconclusive", "Secure"] {
            assert!(!rendered.contains(verdict));
        }
        assert!(ReferenceBehavior::Compliant.is_legitimate());
        assert!(!ReferenceBehavior::DigestSubstituted.is_legitimate());
    }

    #[test]
    fn the_wire_tokens_are_screaming_snake_case_and_stable() {
        assert_eq!(
            serde_json::to_string(&ComponentType::McpServer).expect("serializes"),
            "\"MCP_SERVER\""
        );
        assert_eq!(
            serde_json::to_string(&TrustClass::SelfDeclared).expect("serializes"),
            "\"SELF_DECLARED\""
        );
        assert_eq!(
            serde_json::to_string(&DigestAlgorithm::Sha3_256).expect("serializes"),
            "\"sha3-256\""
        );
    }
}
