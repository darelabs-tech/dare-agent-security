//! Invariants, properties, scenarios and corpus entries.
//!
//! The twelve invariants are a closed set, each a deterministic comparison of
//! typed fields. There is no thirteenth "something looked wrong" case, because
//! a security verdict must be reproducible and a judgement call is not.
//!
//! The scenario type has one deliberate absence worth naming: there is no field
//! in which a fixture could state the verdict it expects. A scenario names the
//! *question* — which invariant is being evaluated — and describes how a
//! reference retriever behaved. What that behaviour means is the evaluator's to
//! decide, and the approved outcome for each lab lives in the test that runs
//! it. A fixture able to declare its own result would reduce the evaluator to
//! agreeing with whoever wrote the fixture.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::document::DocumentStore;
use crate::error::{RagSecurityError, Result};
use crate::policy::RetrievalPolicy;
use crate::query::{CandidateSet, QueryRequest, RetrievalContext};
use crate::source::{CorpusClass, RetrievalFamily, RetrievalSourceKind, ScenarioClass, TrustLevel};

/// The twelve deterministic invariants approved for Cycle 017.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RagInvariantType {
    /// Results stay inside the principals whose documents this principal may see.
    RetrievalPrincipalBoundaryPreserved,
    /// Results stay inside the acting tenant.
    RetrievalTenantBoundaryPreserved,
    /// Results stay inside the collections the query addressed.
    RetrievalCollectionBoundaryPreserved,
    /// Every returned document is in the allowed document set.
    DocumentAclEnforced,
    /// Every returned document satisfies the declared mandatory filters.
    MetadataFilterEnforced,
    /// No protected document or class appears in a result.
    ProtectedDocumentNotRetrieved,
    /// Returned content still carries machine-readable provenance.
    RetrievalProvenancePreserved,
    /// A returned chunk still belongs to the document it claims.
    ChunkDocumentBindingPreserved,
    /// The result set is a subset of the approved candidate set.
    ResultSetWithinApprovedCandidates,
    /// The result count stays within the approved top-k.
    TopKBoundPreserved,
    /// Untrusted retrieved content is not promoted into authority.
    UntrustedRetrievedContentNotPromotedToAuthority,
    /// A fallback retrieval does not widen the authority it ran under.
    RetrievalFallbackDoesNotWidenAuthority,
}

impl RagInvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalPrincipalBoundaryPreserved => "RETRIEVAL_PRINCIPAL_BOUNDARY_PRESERVED",
            Self::RetrievalTenantBoundaryPreserved => "RETRIEVAL_TENANT_BOUNDARY_PRESERVED",
            Self::RetrievalCollectionBoundaryPreserved => "RETRIEVAL_COLLECTION_BOUNDARY_PRESERVED",
            Self::DocumentAclEnforced => "DOCUMENT_ACL_ENFORCED",
            Self::MetadataFilterEnforced => "METADATA_FILTER_ENFORCED",
            Self::ProtectedDocumentNotRetrieved => "PROTECTED_DOCUMENT_NOT_RETRIEVED",
            Self::RetrievalProvenancePreserved => "RETRIEVAL_PROVENANCE_PRESERVED",
            Self::ChunkDocumentBindingPreserved => "CHUNK_DOCUMENT_BINDING_PRESERVED",
            Self::ResultSetWithinApprovedCandidates => "RESULT_SET_WITHIN_APPROVED_CANDIDATES",
            Self::TopKBoundPreserved => "TOP_K_BOUND_PRESERVED",
            Self::UntrustedRetrievedContentNotPromotedToAuthority => {
                "UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY"
            }
            Self::RetrievalFallbackDoesNotWidenAuthority => {
                "RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY"
            }
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::RetrievalPrincipalBoundaryPreserved,
            Self::RetrievalTenantBoundaryPreserved,
            Self::RetrievalCollectionBoundaryPreserved,
            Self::DocumentAclEnforced,
            Self::MetadataFilterEnforced,
            Self::ProtectedDocumentNotRetrieved,
            Self::RetrievalProvenancePreserved,
            Self::ChunkDocumentBindingPreserved,
            Self::ResultSetWithinApprovedCandidates,
            Self::TopKBoundPreserved,
            Self::UntrustedRetrievedContentNotPromotedToAuthority,
            Self::RetrievalFallbackDoesNotWidenAuthority,
        ]
    }

    /// Which reporting surface this invariant belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::RetrievalPrincipalBoundaryPreserved
            | Self::RetrievalCollectionBoundaryPreserved
            | Self::RetrievalFallbackDoesNotWidenAuthority => ScenarioClass::RetrievalAuthorization,
            Self::RetrievalTenantBoundaryPreserved
            | Self::DocumentAclEnforced
            | Self::MetadataFilterEnforced => ScenarioClass::DocumentIsolation,
            Self::RetrievalProvenancePreserved | Self::ChunkDocumentBindingPreserved => {
                ScenarioClass::Provenance
            }
            Self::ResultSetWithinApprovedCandidates | Self::TopKBoundPreserved => {
                ScenarioClass::ResultIntegrity
            }
            Self::UntrustedRetrievedContentNotPromotedToAuthority => ScenarioClass::ContentTrust,
            Self::ProtectedDocumentNotRetrieved => ScenarioClass::ProtectedNondisclosure,
        }
    }

    /// The `AGENT.RAG.*` property this invariant contributes to.
    pub fn property(self) -> RagProperty {
        match self.surface() {
            ScenarioClass::RetrievalAuthorization => RagProperty::RetrievalAuthorizationBoundary,
            ScenarioClass::DocumentIsolation => RagProperty::TenantDocumentIsolation,
            ScenarioClass::Provenance => RagProperty::ProvenanceIntegrity,
            ScenarioClass::ResultIntegrity => RagProperty::ResultSetIntegrity,
            ScenarioClass::ContentTrust => RagProperty::ContentTrustBoundary,
            ScenarioClass::ProtectedNondisclosure => RagProperty::ProtectedDocumentNondisclosure,
        }
    }
}

/// The six retrieval properties a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RagProperty {
    #[serde(rename = "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY")]
    RetrievalAuthorizationBoundary,
    #[serde(rename = "AGENT.RAG.TENANT_DOCUMENT_ISOLATION")]
    TenantDocumentIsolation,
    #[serde(rename = "AGENT.RAG.PROVENANCE_INTEGRITY")]
    ProvenanceIntegrity,
    #[serde(rename = "AGENT.RAG.CONTENT_TRUST_BOUNDARY")]
    ContentTrustBoundary,
    #[serde(rename = "AGENT.RAG.RESULT_SET_INTEGRITY")]
    ResultSetIntegrity,
    #[serde(rename = "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE")]
    ProtectedDocumentNondisclosure,
}

impl RagProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalAuthorizationBoundary => "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
            Self::TenantDocumentIsolation => "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
            Self::ProvenanceIntegrity => "AGENT.RAG.PROVENANCE_INTEGRITY",
            Self::ContentTrustBoundary => "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
            Self::ResultSetIntegrity => "AGENT.RAG.RESULT_SET_INTEGRITY",
            Self::ProtectedDocumentNondisclosure => "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::RetrievalAuthorizationBoundary,
            Self::TenantDocumentIsolation,
            Self::ProvenanceIntegrity,
            Self::ContentTrustBoundary,
            Self::ResultSetIntegrity,
            Self::ProtectedDocumentNondisclosure,
        ]
    }
}

/// How a reference retriever behaves for a fixture.
///
/// A behaviour, never a verdict. The evaluator decides what a behaviour means;
/// nothing here tells it the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    Compliant,
    CrossPrincipalResult,
    CrossTenantResult,
    CrossCollectionResult,
    UnauthorizedDocumentResult,
    MetadataFilterBypassed,
    ProtectedDocumentReturned,
    ProvenanceDetached,
    ChunkReboundToAnotherDocument,
    NonCandidateResultInjected,
    TopKExceeded,
    UntrustedContentPromoted,
    RetrievedWithoutPromotion,
    FallbackWithinAuthority,
    FallbackWidenedAuthority,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::CrossPrincipalResult => "CROSS_PRINCIPAL_RESULT",
            Self::CrossTenantResult => "CROSS_TENANT_RESULT",
            Self::CrossCollectionResult => "CROSS_COLLECTION_RESULT",
            Self::UnauthorizedDocumentResult => "UNAUTHORIZED_DOCUMENT_RESULT",
            Self::MetadataFilterBypassed => "METADATA_FILTER_BYPASSED",
            Self::ProtectedDocumentReturned => "PROTECTED_DOCUMENT_RETURNED",
            Self::ProvenanceDetached => "PROVENANCE_DETACHED",
            Self::ChunkReboundToAnotherDocument => "CHUNK_REBOUND_TO_ANOTHER_DOCUMENT",
            Self::NonCandidateResultInjected => "NON_CANDIDATE_RESULT_INJECTED",
            Self::TopKExceeded => "TOP_K_EXCEEDED",
            Self::UntrustedContentPromoted => "UNTRUSTED_CONTENT_PROMOTED",
            Self::RetrievedWithoutPromotion => "RETRIEVED_WITHOUT_PROMOTION",
            Self::FallbackWithinAuthority => "FALLBACK_WITHIN_AUTHORITY",
            Self::FallbackWidenedAuthority => "FALLBACK_WIDENED_AUTHORITY",
            Self::MultipleIndependentViolations => "MULTIPLE_INDEPENDENT_VIOLATIONS",
            Self::NoRelevantObservation => "NO_RELEVANT_OBSERVATION",
            Self::HarnessFailure => "HARNESS_FAILURE",
        }
    }

    pub fn all() -> [Self; 18] {
        [
            Self::Compliant,
            Self::CrossPrincipalResult,
            Self::CrossTenantResult,
            Self::CrossCollectionResult,
            Self::UnauthorizedDocumentResult,
            Self::MetadataFilterBypassed,
            Self::ProtectedDocumentReturned,
            Self::ProvenanceDetached,
            Self::ChunkReboundToAnotherDocument,
            Self::NonCandidateResultInjected,
            Self::TopKExceeded,
            Self::UntrustedContentPromoted,
            Self::RetrievedWithoutPromotion,
            Self::FallbackWithinAuthority,
            Self::FallbackWidenedAuthority,
            Self::MultipleIndependentViolations,
            Self::NoRelevantObservation,
            Self::HarnessFailure,
        ]
    }

    /// True when this behaviour is a legitimate one a control may declare.
    ///
    /// Three behaviours are compliant without being inaction: an agent that
    /// retrieved and changed nothing, and a fallback that stayed inside its
    /// authority, both *did something* legitimate. A control restricted to
    /// `COMPLIANT` could only demonstrate a retriever that did nothing, which
    /// proves nothing about whether real use survives the engine.
    pub fn is_legitimate(self) -> bool {
        matches!(
            self,
            Self::Compliant | Self::RetrievedWithoutPromotion | Self::FallbackWithinAuthority
        )
    }
}

/// The authorized task a retrieval supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagObjective {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub authorized_objective_id: String,
    /// Synthetic canary identifiers that must never leave in a result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_canaries: Vec<String>,
}

/// Source boundary of the retrieval corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSourceBoundary {
    pub kind: RetrievalSourceKind,
    pub trust: TrustLevel,
}

/// Which invariant a scenario is evaluated against.
///
/// The invariant only. A scenario names the question; it never carries the
/// answer, so there is deliberately no field here in which a fixture could
/// state the verdict it wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagInvariantSpec {
    #[serde(rename = "type")]
    pub type_: RagInvariantType,
}

/// Requested trial policy. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagTrialSpec {
    pub count: u32,
    #[serde(default = "default_stop_on_first_fail")]
    pub stop_on_first_fail: bool,
}

fn default_stop_on_first_fail() -> bool {
    crate::limits::STOP_ON_FIRST_FAIL
}

/// Requested safety envelope. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSafetySpec {
    pub local_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queries_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_queries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results_per_query: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
}

/// Synthetic-lab metadata. Carries no expected verdict, deliberately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagLabSpec {
    pub reference_behavior: ReferenceBehavior,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_trial: BTreeMap<String, ReferenceBehavior>,
}

impl RagLabSpec {
    /// Behaviour for one trial index, falling back to the default.
    pub fn behavior_for(&self, trial_index: u32) -> ReferenceBehavior {
        self.per_trial
            .get(&trial_index.to_string())
            .copied()
            .unwrap_or(self.reference_behavior)
    }
}

/// A standards attribution recorded on a scenario or corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagStandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagVectorRef {
    pub corpus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// A complete, versioned retrieval-security scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityScenario {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: ScenarioClass,
    pub property: RagProperty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<RetrievalFamily>,
    pub source: RagSourceBoundary,
    pub objective: RagObjective,
    pub store: DocumentStore,
    pub context: RetrievalContext,
    pub policy: RetrievalPolicy,
    pub queries: Vec<QueryRequest>,
    /// The candidates each query was approved to consider.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_sets: Vec<CandidateSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<RagVectorRef>,
    pub invariant: RagInvariantSpec,
    pub trials: RagTrialSpec,
    pub safety: RagSafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<RagLabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<RagStandardRef>,
}

impl RagSecurityScenario {
    /// The candidate set approved for one query, if the scenario declares one.
    pub fn candidate_set(&self, query_id: &str) -> Option<&CandidateSet> {
        self.candidate_sets
            .iter()
            .find(|set| set.query_id == query_id)
    }

    pub fn query(&self, query_id: &str) -> Option<&QueryRequest> {
        self.queries.iter().find(|query| query.query_id == query_id)
    }

    /// Structural checks beyond the schema.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(RagSecurityError::schema(format!(
                "scenario `{}` declares schema version `{}`; only `{}` is supported",
                self.id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.id, "scenario id")?;
        crate::canonical::assert_safe_identifier(&self.objective.id, "objective id")?;
        crate::canonical::assert_safe_identifier(
            &self.objective.authorized_objective_id,
            "authorized objective id",
        )?;

        self.store.validate()?;
        self.context.validate()?;
        self.policy.validate()?;

        // The policy must be written for the principal that is actually acting.
        // A policy for someone else would be evaluated against the wrong
        // authority while looking entirely well-formed.
        if self.policy.acting_principal_id != self.context.acting_principal_id {
            return Err(RagSecurityError::invalid(format!(
                "scenario `{}` runs as `{}` but its policy is written for `{}`",
                self.id, self.context.acting_principal_id, self.policy.acting_principal_id
            )));
        }

        if self.queries.is_empty() {
            return Err(RagSecurityError::invalid(format!(
                "scenario `{}` declares no query",
                self.id
            )));
        }
        if self.queries.len() as u32 > crate::limits::HARD_MAX_QUERIES_PER_TRIAL {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "scenario `{}` declares {} queries per trial; the hard maximum is {}",
                self.id,
                self.queries.len(),
                crate::limits::HARD_MAX_QUERIES_PER_TRIAL
            )));
        }

        let mut seen_queries = std::collections::BTreeSet::new();
        for query in &self.queries {
            query.validate()?;
            if !seen_queries.insert(query.query_id.as_str()) {
                return Err(RagSecurityError::invalid(format!(
                    "scenario `{}` declares query `{}` more than once",
                    self.id, query.query_id
                )));
            }
            // A query may not ask for more than its own policy allows. Catching
            // it here means the scenario is refused rather than producing a
            // top-k finding against a request nobody authorized.
            if query.requested_top_k > self.policy.top_k.max_top_k {
                return Err(RagSecurityError::invalid(format!(
                    "query `{}` requests {} results while policy `{}` allows {}",
                    query.query_id,
                    query.requested_top_k,
                    self.policy.policy_id,
                    self.policy.top_k.max_top_k
                )));
            }
            for collection_id in &query.collection_ids {
                if self.store.collection(collection_id).is_none() {
                    return Err(RagSecurityError::unknown_reference(format!(
                        "query `{}` addresses collection `{collection_id}`, which the corpus does \
                         not declare",
                        query.query_id
                    )));
                }
            }
        }

        for set in &self.candidate_sets {
            set.validate()?;
            // A candidate set for a query nobody declared cannot be compared
            // against anything.
            if self.query(&set.query_id).is_none() {
                return Err(RagSecurityError::unknown_reference(format!(
                    "candidate set names query `{}`, which the scenario does not declare",
                    set.query_id
                )));
            }
            for candidate in &set.candidates {
                let chunk = self
                    .store
                    .require_chunk(&candidate.chunk_id, "a candidate")?;
                if chunk.document_id != candidate.document_id {
                    return Err(RagSecurityError::invalid(format!(
                        "candidate `{}` claims document `{}` while the corpus binds it to `{}`",
                        candidate.chunk_id, candidate.document_id, chunk.document_id
                    )));
                }
            }
        }

        if self.trials.count == 0 {
            return Err(RagSecurityError::invalid(format!(
                "scenario `{}` requests zero trials",
                self.id
            )));
        }
        if !self.safety.local_only {
            return Err(RagSecurityError::refusal(format!(
                "scenario `{}` requests non-local execution; Cycle 017 is local only",
                self.id
            )));
        }

        Ok(())
    }
}

/// One inert, synthetic corpus vector or control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagCorpusEntry {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: CorpusClass,
    pub surface: ScenarioClass,
    pub property: RagProperty,
    pub family: RetrievalFamily,
    pub source_kind: RetrievalSourceKind,
    pub trust: TrustLevel,
    pub preconditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_note: Option<String>,
    pub reference_behavior: ReferenceBehavior,
    pub expected_invariant: RagInvariantType,
    pub safety_class: String,
    pub standards: Vec<RagStandardRef>,
    pub provenance: CorpusProvenance,
}

/// Corpus provenance. Synthetic origin only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusProvenance {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub created_at: String,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_twelve_invariants_are_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = RagInvariantType::all()
            .into_iter()
            .map(RagInvariantType::as_str)
            .collect();
        assert_eq!(names.len(), 12);

        // And the wire form matches the name exactly, so an artifact and a
        // report cannot disagree about what an invariant is called.
        for invariant in RagInvariantType::all() {
            let wire = serde_json::to_string(&invariant).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", invariant.as_str()));
        }
    }

    #[test]
    fn the_approved_invariant_names_are_exactly_these() {
        // Pinned against the approval verbatim: a renamed invariant would break
        // every artifact already filed against it.
        let names: Vec<&str> = RagInvariantType::all()
            .into_iter()
            .map(RagInvariantType::as_str)
            .collect();
        assert_eq!(
            names,
            vec![
                "RETRIEVAL_PRINCIPAL_BOUNDARY_PRESERVED",
                "RETRIEVAL_TENANT_BOUNDARY_PRESERVED",
                "RETRIEVAL_COLLECTION_BOUNDARY_PRESERVED",
                "DOCUMENT_ACL_ENFORCED",
                "METADATA_FILTER_ENFORCED",
                "PROTECTED_DOCUMENT_NOT_RETRIEVED",
                "RETRIEVAL_PROVENANCE_PRESERVED",
                "CHUNK_DOCUMENT_BINDING_PRESERVED",
                "RESULT_SET_WITHIN_APPROVED_CANDIDATES",
                "TOP_K_BOUND_PRESERVED",
                "UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY",
                "RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY",
            ]
        );
    }

    #[test]
    fn every_surface_and_property_is_reachable_from_some_invariant() {
        // A surface no invariant reaches would appear in every report as
        // permanently untested, which reads as a gap in the target rather than
        // a gap in the engine.
        let surfaces: BTreeSet<ScenarioClass> = RagInvariantType::all()
            .into_iter()
            .map(RagInvariantType::surface)
            .collect();
        assert_eq!(surfaces.len(), 6);

        let properties: BTreeSet<RagProperty> = RagInvariantType::all()
            .into_iter()
            .map(RagInvariantType::property)
            .collect();
        assert_eq!(properties.len(), 6);
    }

    #[test]
    fn the_property_wire_names_match_the_registry_exactly() {
        // These strings appear in the coverage registry and in every artifact.
        // A mismatch would file findings against a property nobody selected.
        assert_eq!(
            RagProperty::all().map(RagProperty::as_str),
            [
                "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
                "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
                "AGENT.RAG.PROVENANCE_INTEGRITY",
                "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
                "AGENT.RAG.RESULT_SET_INTEGRITY",
                "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
            ]
        );
        for property in RagProperty::all() {
            let wire = serde_json::to_string(&property).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", property.as_str()));
        }
    }

    #[test]
    fn a_scenario_type_has_no_field_for_an_expected_verdict() {
        // The absence is the design. Adding one would let a fixture decide its
        // own outcome, and `deny_unknown_fields` makes the attempt a decode
        // error rather than a silently ignored field.
        let raw = serde_json::json!({
            "schema_version": "1", "id": "RAG-LAB-001", "class": "PROVENANCE",
            "property": "AGENT.RAG.PROVENANCE_INTEGRITY",
            "expected_verdict": "PASS"
        });
        assert!(serde_json::from_value::<RagSecurityScenario>(raw).is_err());
    }

    #[test]
    fn three_behaviours_are_legitimate_and_the_rest_are_crossings() {
        let legitimate: Vec<&str> = ReferenceBehavior::all()
            .into_iter()
            .filter(|behavior| behavior.is_legitimate())
            .map(ReferenceBehavior::as_str)
            .collect();
        assert_eq!(
            legitimate,
            vec![
                "COMPLIANT",
                "RETRIEVED_WITHOUT_PROMOTION",
                "FALLBACK_WITHIN_AUTHORITY"
            ]
        );
    }

    #[test]
    fn a_lab_spec_can_vary_behaviour_per_trial() {
        let lab = RagLabSpec {
            reference_behavior: ReferenceBehavior::Compliant,
            per_trial: BTreeMap::from([("1".to_owned(), ReferenceBehavior::CrossTenantResult)]),
        };
        assert_eq!(lab.behavior_for(0), ReferenceBehavior::Compliant);
        assert_eq!(lab.behavior_for(1), ReferenceBehavior::CrossTenantResult);
        assert_eq!(lab.behavior_for(2), ReferenceBehavior::Compliant);
    }

    #[test]
    fn the_reference_behaviour_set_is_closed() {
        assert_eq!(ReferenceBehavior::all().len(), 18);
        let names: BTreeSet<&str> = ReferenceBehavior::all()
            .into_iter()
            .map(ReferenceBehavior::as_str)
            .collect();
        assert_eq!(names.len(), 18);

        for token in ["RETRIEVED_EVERYTHING", "compliant", ""] {
            assert!(crate::source::parse_closed::<ReferenceBehavior>(token, "behavior").is_err());
        }
    }
}
