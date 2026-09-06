//! Closed source, trust, classification and family vocabulary.
//!
//! Every taxonomy here is a closed set. An unknown value fails to decode rather
//! than degrading to a default, because a document whose classification or
//! trust class could not be read is exactly the document that must not be
//! assumed safe to return.
//!
//! The rule the cycle turns on lives in these types: a
//! [`DocumentTrustClass`] is not authority, and a high score is not a
//! classification. Where content came from constrains how far it may be
//! trusted; it never elevates it, and nothing about ranking touches it at all.

use serde::{Deserialize, Serialize};

use crate::error::{RagSecurityError, Result};

/// Where a document's content originally came from.
///
/// Closed on purpose. A source this cycle cannot name is a source it cannot
/// reason about, and defaulting it to something familiar would be a guess
/// presented as a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentSourceKind {
    /// Authored inside the system under policy.
    InternalAuthored,
    /// Uploaded by a known tenant user.
    TenantUpload,
    /// Ingested from outside the system.
    ExternalIngested,
    /// Produced by an agent or a model.
    AgentGenerated,
    /// Copied in from another index or corpus.
    ImportedCorpus,
    /// Returned by a tool and indexed.
    ToolOutput,
}

impl DocumentSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InternalAuthored => "INTERNAL_AUTHORED",
            Self::TenantUpload => "TENANT_UPLOAD",
            Self::ExternalIngested => "EXTERNAL_INGESTED",
            Self::AgentGenerated => "AGENT_GENERATED",
            Self::ImportedCorpus => "IMPORTED_CORPUS",
            Self::ToolOutput => "TOOL_OUTPUT",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::InternalAuthored,
            Self::TenantUpload,
            Self::ExternalIngested,
            Self::AgentGenerated,
            Self::ImportedCorpus,
            Self::ToolOutput,
        ]
    }

    /// The highest trust class this source may reach without an explicit
    /// policy grant.
    ///
    /// Only internally authored content is policy-authoritative by default.
    /// Everything else caps at `REFERENCE` however relevant it looks — and
    /// relevance is exactly what a retriever optimises for, which is why the
    /// ceiling is anchored to origin rather than to score.
    pub fn default_trust_ceiling(self) -> DocumentTrustClass {
        match self {
            Self::InternalAuthored => DocumentTrustClass::TrustedPolicy,
            Self::TenantUpload
            | Self::ExternalIngested
            | Self::AgentGenerated
            | Self::ImportedCorpus
            | Self::ToolOutput => DocumentTrustClass::Reference,
        }
    }

    /// True when content from this source must be treated as
    /// attacker-influenceable.
    pub fn is_externally_influenceable(self) -> bool {
        matches!(
            self,
            Self::TenantUpload | Self::ExternalIngested | Self::ImportedCorpus | Self::ToolOutput
        )
    }

    /// True when this source can, by itself, carry policy authority.
    pub fn may_be_policy_authoritative(self) -> bool {
        matches!(self, Self::InternalAuthored)
    }
}

/// How far a retrieved document may be trusted once returned.
///
/// Ordered: `Untrusted < Reference < TrustedPolicy`. The ordering is what makes
/// "promotion" a comparison rather than a judgement call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentTrustClass {
    /// Data. May be retrieved and shown; may not shape a protected decision.
    Untrusted,
    /// Usable as supporting material for an authorized objective, nothing wider.
    Reference,
    /// Policy-authoritative content.
    TrustedPolicy,
}

impl DocumentTrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "UNTRUSTED",
            Self::Reference => "REFERENCE",
            Self::TrustedPolicy => "TRUSTED_POLICY",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Untrusted, Self::Reference, Self::TrustedPolicy]
    }

    /// Rank, so promotion is arithmetic rather than an opinion.
    pub fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Reference => 1,
            Self::TrustedPolicy => 2,
        }
    }

    /// True when moving from `self` to `other` raises trust.
    ///
    /// Lowering trust is always allowed; raising it requires an explicit,
    /// machine-readable policy grant, which is checked elsewhere.
    pub fn is_promotion_to(self, other: Self) -> bool {
        other.rank() > self.rank()
    }

    /// True when content at this class may influence a protected decision.
    pub fn may_influence_protected_decision(self) -> bool {
        matches!(self, Self::TrustedPolicy)
    }
}

/// Sensitivity classification carried by a document.
///
/// Distinct from trust: trust is about whether content may *direct* the agent,
/// classification is about who may *see* it. A document can be entirely
/// trustworthy and still be one the acting principal must never receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassificationLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl ClassificationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Restricted => "RESTRICTED",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::Public,
            Self::Internal,
            Self::Confidential,
            Self::Restricted,
        ]
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Restricted => 3,
        }
    }

    /// True when this classification exceeds a ceiling the policy allows.
    pub fn exceeds(self, ceiling: Self) -> bool {
        self.rank() > ceiling.rank()
    }
}

/// Lifecycle state of a document at retrieval time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentState {
    /// Indexed and eligible for retrieval.
    Active,
    /// Superseded by a newer version but still present in the index.
    Superseded,
    /// Withdrawn; must not be returned.
    Withdrawn,
}

impl DocumentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Superseded => "SUPERSEDED",
            Self::Withdrawn => "WITHDRAWN",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Active, Self::Superseded, Self::Withdrawn]
    }

    /// True when a document in this state may be returned at all.
    pub fn is_retrievable(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Which retrieval-security surface a scenario exercises.
///
/// Surfaces are reported separately and never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    RetrievalAuthorization,
    DocumentIsolation,
    Provenance,
    ResultIntegrity,
    ContentTrust,
    ProtectedNondisclosure,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalAuthorization => "RETRIEVAL_AUTHORIZATION",
            Self::DocumentIsolation => "DOCUMENT_ISOLATION",
            Self::Provenance => "PROVENANCE",
            Self::ResultIntegrity => "RESULT_INTEGRITY",
            Self::ContentTrust => "CONTENT_TRUST",
            Self::ProtectedNondisclosure => "PROTECTED_NONDISCLOSURE",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::RetrievalAuthorization,
            Self::DocumentIsolation,
            Self::Provenance,
            Self::ResultIntegrity,
            Self::ContentTrust,
            Self::ProtectedNondisclosure,
        ]
    }
}

/// Closed retrieval-attack family taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalFamily {
    CrossPrincipalRetrieval,
    CrossTenantRetrieval,
    CrossCollectionRetrieval,
    UnauthorizedDocumentRetrieval,
    MetadataFilterBypass,
    ProvenanceMismatch,
    ChunkDocumentSubstitution,
    NonCandidateResultInjection,
    TopKOverflow,
    UntrustedContentPromotion,
    ProtectedDocumentDisclosure,
    FallbackAuthorityWidening,
}

impl RetrievalFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CrossPrincipalRetrieval => "CROSS_PRINCIPAL_RETRIEVAL",
            Self::CrossTenantRetrieval => "CROSS_TENANT_RETRIEVAL",
            Self::CrossCollectionRetrieval => "CROSS_COLLECTION_RETRIEVAL",
            Self::UnauthorizedDocumentRetrieval => "UNAUTHORIZED_DOCUMENT_RETRIEVAL",
            Self::MetadataFilterBypass => "METADATA_FILTER_BYPASS",
            Self::ProvenanceMismatch => "PROVENANCE_MISMATCH",
            Self::ChunkDocumentSubstitution => "CHUNK_DOCUMENT_SUBSTITUTION",
            Self::NonCandidateResultInjection => "NON_CANDIDATE_RESULT_INJECTION",
            Self::TopKOverflow => "TOP_K_OVERFLOW",
            Self::UntrustedContentPromotion => "UNTRUSTED_CONTENT_PROMOTION",
            Self::ProtectedDocumentDisclosure => "PROTECTED_DOCUMENT_DISCLOSURE",
            Self::FallbackAuthorityWidening => "FALLBACK_AUTHORITY_WIDENING",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::CrossPrincipalRetrieval,
            Self::CrossTenantRetrieval,
            Self::CrossCollectionRetrieval,
            Self::UnauthorizedDocumentRetrieval,
            Self::MetadataFilterBypass,
            Self::ProvenanceMismatch,
            Self::ChunkDocumentSubstitution,
            Self::NonCandidateResultInjection,
            Self::TopKOverflow,
            Self::UntrustedContentPromotion,
            Self::ProtectedDocumentDisclosure,
            Self::FallbackAuthorityWidening,
        ]
    }

    /// Which reporting surface this family belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::CrossPrincipalRetrieval
            | Self::CrossCollectionRetrieval
            | Self::FallbackAuthorityWidening => ScenarioClass::RetrievalAuthorization,
            Self::CrossTenantRetrieval
            | Self::UnauthorizedDocumentRetrieval
            | Self::MetadataFilterBypass => ScenarioClass::DocumentIsolation,
            Self::ProvenanceMismatch | Self::ChunkDocumentSubstitution => ScenarioClass::Provenance,
            Self::NonCandidateResultInjection | Self::TopKOverflow => {
                ScenarioClass::ResultIntegrity
            }
            Self::UntrustedContentPromotion => ScenarioClass::ContentTrust,
            Self::ProtectedDocumentDisclosure => ScenarioClass::ProtectedNondisclosure,
        }
    }
}

/// Where a scenario's observations came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalSourceKind {
    /// A document corpus authored for the synthetic lab.
    SyntheticCorpus,
    /// A sanitized local replay trace.
    ReplayTrace,
    /// A declared retrieval policy captured locally.
    DeclaredRetrievalPolicy,
}

impl RetrievalSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticCorpus => "SYNTHETIC_CORPUS",
            Self::ReplayTrace => "REPLAY_TRACE",
            Self::DeclaredRetrievalPolicy => "DECLARED_RETRIEVAL_POLICY",
        }
    }

    pub fn all() -> [Self; 3] {
        [
            Self::SyntheticCorpus,
            Self::ReplayTrace,
            Self::DeclaredRetrievalPolicy,
        ]
    }

    /// No source is authoritative about its own security.
    ///
    /// Always false, and a test pins it: a corpus that declares itself clean is
    /// making a claim, not supplying evidence.
    pub fn is_authoritative(self) -> bool {
        false
    }
}

/// Declared trust of the channel a scenario's corpus arrived through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustLevel {
    Trusted,
    Untrusted,
    Mixed,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Mixed => "MIXED",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Trusted, Self::Untrusted, Self::Mixed]
    }
}

/// Whether a corpus entry is an attack vector or a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    /// A vector that should produce a deterministic violation.
    RetrievalAttack,
    /// A control that should produce no violation at all.
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalAttack => "RETRIEVAL_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }

    pub fn all() -> [Self; 2] {
        [Self::RetrievalAttack, Self::BenignControl]
    }
}

/// Parse a closed-enum token, failing closed on anything unknown.
pub fn parse_closed<T: serde::de::DeserializeOwned>(token: &str, label: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(token.to_owned()))
        .map_err(|_| RagSecurityError::invalid(format!("`{token}` is not a known {label}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_taxonomy_is_closed_and_uniquely_named() {
        assert_eq!(DocumentSourceKind::all().len(), 6);
        assert_eq!(DocumentTrustClass::all().len(), 3);
        assert_eq!(ClassificationLevel::all().len(), 4);
        assert_eq!(DocumentState::all().len(), 3);
        assert_eq!(ScenarioClass::all().len(), 6);
        assert_eq!(RetrievalFamily::all().len(), 12);
        assert_eq!(RetrievalSourceKind::all().len(), 3);
        assert_eq!(TrustLevel::all().len(), 3);
        assert_eq!(CorpusClass::all().len(), 2);

        let names: BTreeSet<&str> = RetrievalFamily::all()
            .into_iter()
            .map(RetrievalFamily::as_str)
            .collect();
        assert_eq!(names.len(), 12, "two families share a name");
    }

    #[test]
    fn an_unknown_token_fails_closed_rather_than_defaulting() {
        // A document whose trust class could not be read is exactly the one
        // that must not be assumed safe.
        for token in ["VECTOR_MAGIC", "unknown", "", "trusted_policy"] {
            assert!(
                parse_closed::<DocumentTrustClass>(token, "trust class").is_err(),
                "{token}"
            );
        }
        for token in ["SEMI_PUBLIC", "public", ""] {
            assert!(
                parse_closed::<ClassificationLevel>(token, "classification").is_err(),
                "{token}"
            );
        }
        assert!(parse_closed::<DocumentTrustClass>("UNTRUSTED", "trust class").is_ok());
    }

    #[test]
    fn exactly_one_source_can_carry_policy_authority() {
        let authoritative: Vec<_> = DocumentSourceKind::all()
            .into_iter()
            .filter(|source| source.may_be_policy_authoritative())
            .collect();
        assert_eq!(authoritative, vec![DocumentSourceKind::InternalAuthored]);

        // And every other source caps below policy authority, however relevant
        // its content might be to a query.
        for source in DocumentSourceKind::all() {
            if source.may_be_policy_authoritative() {
                continue;
            }
            assert_ne!(
                source.default_trust_ceiling(),
                DocumentTrustClass::TrustedPolicy,
                "{source:?} reaches policy authority by default"
            );
        }
    }

    #[test]
    fn trust_promotion_is_arithmetic_rather_than_a_judgement() {
        assert!(DocumentTrustClass::Untrusted.is_promotion_to(DocumentTrustClass::Reference));
        assert!(DocumentTrustClass::Reference.is_promotion_to(DocumentTrustClass::TrustedPolicy));
        assert!(DocumentTrustClass::Untrusted.is_promotion_to(DocumentTrustClass::TrustedPolicy));

        // Lowering trust is never a promotion, and neither is standing still.
        assert!(!DocumentTrustClass::TrustedPolicy.is_promotion_to(DocumentTrustClass::Untrusted));
        assert!(!DocumentTrustClass::Reference.is_promotion_to(DocumentTrustClass::Reference));
    }

    #[test]
    fn only_policy_authoritative_content_may_influence_a_protected_decision() {
        let allowed: Vec<_> = DocumentTrustClass::all()
            .into_iter()
            .filter(|class| class.may_influence_protected_decision())
            .collect();
        assert_eq!(allowed, vec![DocumentTrustClass::TrustedPolicy]);
    }

    #[test]
    fn classification_and_trust_answer_different_questions() {
        // A document can be perfectly trustworthy and still be one this
        // principal must not see. Collapsing the two would let "we wrote it
        // ourselves" imply "anyone may read it".
        assert!(ClassificationLevel::Restricted.exceeds(ClassificationLevel::Confidential));
        assert!(!ClassificationLevel::Public.exceeds(ClassificationLevel::Internal));
        assert!(!ClassificationLevel::Internal.exceeds(ClassificationLevel::Internal));

        let internal = DocumentSourceKind::InternalAuthored;
        assert!(internal.may_be_policy_authoritative());
        // Being authoritative says nothing about who may read it.
        assert!(ClassificationLevel::Restricted.exceeds(ClassificationLevel::Public));
    }

    #[test]
    fn exactly_one_document_state_is_retrievable() {
        let retrievable: Vec<_> = DocumentState::all()
            .into_iter()
            .filter(|state| state.is_retrievable())
            .collect();
        assert_eq!(retrievable, vec![DocumentState::Active]);
    }

    #[test]
    fn every_family_belongs_to_exactly_one_surface_and_all_six_are_used() {
        let surfaces: BTreeSet<ScenarioClass> = RetrievalFamily::all()
            .into_iter()
            .map(RetrievalFamily::surface)
            .collect();
        assert_eq!(
            surfaces.len(),
            6,
            "a reporting surface has no family that reaches it"
        );
    }

    #[test]
    fn no_source_is_authoritative_about_its_own_security() {
        for source in RetrievalSourceKind::all() {
            assert!(!source.is_authoritative(), "{source:?}");
        }
    }

    #[test]
    fn the_wire_tokens_are_screaming_snake_case_and_stable() {
        assert_eq!(
            serde_json::to_string(&DocumentTrustClass::TrustedPolicy).expect("serializes"),
            "\"TRUSTED_POLICY\""
        );
        assert_eq!(
            serde_json::to_string(&ScenarioClass::ProtectedNondisclosure).expect("serializes"),
            "\"PROTECTED_NONDISCLOSURE\""
        );
        for family in RetrievalFamily::all() {
            let wire = serde_json::to_string(&family).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", family.as_str()));
        }
    }
}
