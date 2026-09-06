//! The adapter contract and observation normalization.
//!
//! An adapter reports what a retriever *did*, in a raw transport shape. It
//! cannot report a verdict, and it cannot assert a binding fact it has no
//! standing to know.
//!
//! That second rule is what [`normalize`] enforces. A raw result names a chunk
//! and claims a document; normalization looks the chunk up in the scenario's
//! declared corpus and records **both** the claim and the binding. A trace
//! saying "this chunk came from the trusted handbook" therefore cannot make it
//! so — the corpus supplies the second half of every comparison, and the
//! mismatch becomes visible instead of being taken at face value.
//!
//! Cycle 016 shipped the opposite arrangement once, where a trace could carry
//! full item records and thereby assert its own bindings. That is the lesson
//! this module is built around.

use serde::{Deserialize, Serialize};

use crate::document::Document;
use crate::error::{RagSecurityError, Result};
use crate::model::RagSecurityScenario;
use crate::observation::{
    EvidenceText, HarnessErrorKind, InfluenceTarget, RagObservationEvent, ResolvedDocument,
};
use crate::source::DocumentTrustClass;

/// The three approved execution modes. There is no remote or live variant, and
/// no way to add one without changing this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessMode {
    /// Replay a sanitized local trace.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// Local synthetic execution under the Cycle 009 controls.
    LocalSynthetic,
}

impl HarnessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "REPLAY",
            Self::Simulated => "SIMULATED",
            Self::LocalSynthetic => "LOCAL_SYNTHETIC",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Replay, Self::Simulated, Self::LocalSynthetic]
    }

    /// True when observations were staged rather than recorded.
    pub fn is_synthetic(self) -> bool {
        matches!(self, Self::Simulated | Self::LocalSynthetic)
    }

    /// Parse an operator-supplied mode, failing closed on anything else.
    pub fn parse(token: &str) -> Result<Self> {
        Self::all()
            .into_iter()
            .find(|mode| mode.as_str() == token)
            .ok_or_else(|| {
                RagSecurityError::refusal(format!(
                    "unknown or unapproved harness mode `{token}`; Cycle 017 supports only \
                     REPLAY, SIMULATED and LOCAL_SYNTHETIC"
                ))
            })
    }
}

/// Raw candidate set as an adapter reports it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCandidateSet {
    pub query_id: String,
    pub candidates: Vec<crate::query::Candidate>,
}

/// Raw filter decision as an adapter reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFilterDecision {
    pub query_id: String,
    pub document_id: String,
    pub admitted: bool,
}

/// Raw result set as an adapter reports it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawResultSet {
    pub query_id: String,
    pub results: Vec<crate::query::RankedResult>,
    #[serde(default)]
    pub used_fallback: bool,
}

/// Raw influence as an adapter reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInfluence {
    pub document_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_id: Option<String>,
    pub target: InfluenceTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<String>,
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treated_as_trust_class: Option<DocumentTrustClass>,
}

/// Raw harness error as an adapter reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessError {
    pub kind: HarnessErrorKind,
    pub detail: String,
}

/// Everything one trial observed, in transport shape.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrialOutput {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<crate::query::QueryRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_sets: Vec<RawCandidateSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_decisions: Vec<RawFilterDecision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_sets: Vec<RawResultSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub influences: Vec<RawInfluence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// One trial's request to an adapter.
pub struct TrialRequest<'a> {
    pub trial_index: u32,
    pub scenario: &'a RagSecurityScenario,
}

/// What every execution mode implements.
pub trait HarnessAdapter {
    fn mode(&self) -> HarnessMode;

    /// Observe one trial.
    ///
    /// Implementations must not perform network I/O, spawn a process, open a
    /// database or vector store, compute an embedding, or fetch a document.
    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput>;

    /// How many trials this adapter can supply.
    ///
    /// A recorded source is bounded by what it recorded; a staged one can
    /// produce a trial for any index. The default is the hard maximum, so an
    /// adapter that does not override this never *lowers* a plan by accident —
    /// and none of them can raise one.
    fn trial_capacity(&self) -> u32 {
        crate::limits::HARD_MAX_TRIALS
    }

    /// Whether these observations describe something other than a production
    /// retriever, and so must never be reported as production evidence.
    ///
    /// Defaults to whether the mode *stages* observations. Replay is the case
    /// the default gets wrong: a replayed observation was recorded rather than
    /// staged, while every trace Cycle 017 admits is required to declare itself
    /// synthetic. The replay adapter answers from the trace it loaded.
    fn observations_are_synthetic(&self) -> bool {
        self.mode().is_synthetic()
    }
}

/// Convert raw adapter output into normalized, typed observation events.
///
/// Chunks and documents are resolved against the scenario's declared corpus
/// rather than taken on the adapter's word. That is what stops a trace from
/// asserting that a chunk belonged to a document it did not, or that a
/// cross-tenant document was inside the acting tenant all along.
pub fn normalize(
    raw: &RawTrialOutput,
    scenario: &RagSecurityScenario,
) -> Result<Vec<RagObservationEvent>> {
    let mut events = Vec::new();

    // A harness failure is reported alone: whatever else the adapter managed to
    // emit describes an incomplete observation, and mixing the two would let a
    // partial run look like a complete one.
    if let Some(error) = &raw.harness_error {
        events.push(RagObservationEvent::HarnessError {
            kind: error.kind,
            detail: EvidenceText::from_raw(&error.detail),
        });
        return Ok(events);
    }

    events.push(RagObservationEvent::RetrievalContext {
        context_id: scenario.context.context_id.clone(),
        acting_principal_id: scenario.context.acting_principal_id.clone(),
        tenant_id: scenario.context.tenant_id.clone(),
        collection_ids: scenario.context.collection_ids.clone(),
    });

    events.push(RagObservationEvent::RetrievalPolicy {
        policy_id: scenario.policy.policy_id.clone(),
        policy_digest: crate::canonical::policy_digest(&scenario.policy)?,
        max_top_k: scenario.policy.top_k.max_top_k,
        cross_tenant_allowed: scenario.policy.cross_tenant_allowed,
        cross_owner_allowed: scenario.policy.cross_owner_allowed,
        fallback_allowed: scenario.policy.fallback.allowed,
    });

    for query in &raw.queries {
        events.push(RagObservationEvent::QueryRequest {
            query_id: query.query_id.clone(),
            collection_ids: query.collection_ids.clone(),
            requested_top_k: query.requested_top_k,
            objective_id: query.objective_id.clone(),
            mandatory_filter_fields: query
                .filter
                .mandatory
                .iter()
                .map(|clause| clause.field.clone())
                .collect(),
        });
    }

    for set in &raw.candidate_sets {
        let chunk_ids: Vec<String> = set
            .candidates
            .iter()
            .map(|candidate| candidate.chunk_id.clone())
            .collect();
        let typed = crate::query::CandidateSet {
            query_id: set.query_id.clone(),
            candidates: set.candidates.clone(),
        };
        events.push(RagObservationEvent::CandidateSet {
            query_id: set.query_id.clone(),
            candidate_set_digest: crate::canonical::candidate_set_digest(&typed)?,
            candidate_count: chunk_ids.len() as u32,
            chunk_ids,
        });
    }

    for decision in &raw.filter_decisions {
        // Which clauses the document actually fails is computed from the
        // declared corpus and the declared filter, not from whatever the
        // adapter claims. An adapter that could name its own unsatisfied fields
        // could also name none.
        let unsatisfied_fields = scenario
            .store
            .document(&decision.document_id)
            .map(|document| {
                let filter = scenario
                    .query(&decision.query_id)
                    .map(|query| &query.filter)
                    .unwrap_or(&scenario.policy.metadata_filter);
                filter
                    .unsatisfied(&document.metadata)
                    .into_iter()
                    .map(|clause| clause.field.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        events.push(RagObservationEvent::FilterDecision {
            query_id: decision.query_id.clone(),
            document_id: decision.document_id.clone(),
            admitted: decision.admitted,
            unsatisfied_fields,
        });
    }

    let mut seen_documents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for set in &raw.result_sets {
        let typed = crate::query::RankedResultSet {
            query_id: set.query_id.clone(),
            results: set.results.clone(),
            used_fallback: set.used_fallback,
        };
        events.push(RagObservationEvent::RankedResultSet {
            query_id: set.query_id.clone(),
            result_set_digest: crate::canonical::result_set_digest(&typed)?,
            result_count: set.results.len() as u32,
            used_fallback: set.used_fallback,
            chunk_ids: set
                .results
                .iter()
                .map(|result| result.chunk_id.clone())
                .collect(),
        });

        for result in &set.results {
            // Resolve against the corpus. An unresolvable chunk is a refusal:
            // evaluating a result nobody declared would compare a claim against
            // nothing.
            let chunk = scenario
                .store
                .require_chunk(&result.chunk_id, "a returned result")?;
            let bound_document: &Document = scenario
                .store
                .require_document(&chunk.document_id, "a returned chunk")?;

            events.push(RagObservationEvent::RetrievedChunk {
                query_id: set.query_id.clone(),
                chunk_id: result.chunk_id.clone(),
                // What the retriever claimed...
                claimed_document_id: result.document_id.clone(),
                // ...and what the corpus says.
                bound_document_id: chunk.document_id.clone(),
                claimed_provenance_id: scenario
                    .store
                    .document(&result.document_id)
                    .map(|document| document.provenance.provenance_id.clone())
                    .unwrap_or_else(|| chunk.provenance_id.clone()),
                bound_provenance_id: bound_document.provenance.provenance_id.clone(),
                rank: result.rank,
                from_fallback: result.from_fallback,
            });

            if seen_documents.insert(bound_document.document_id.clone()) {
                events.push(RagObservationEvent::DocumentContext {
                    query_id: set.query_id.clone(),
                    document: ResolvedDocument::from_document(bound_document),
                });
                events.push(RagObservationEvent::ProvenanceContext {
                    document_id: bound_document.document_id.clone(),
                    provenance_id: bound_document.provenance.provenance_id.clone(),
                    source_kind: bound_document.provenance.source_kind,
                    source_id: bound_document.provenance.source_id.clone(),
                    machine_readable: bound_document.has_machine_readable_provenance(),
                });
            }
        }
    }

    for influence in &raw.influences {
        // The trust class the content was treated as comes from the adapter;
        // the ceilings come from the corpus and the policy.
        if let Some(document) = scenario.store.document(&influence.document_id) {
            if seen_documents.insert(document.document_id.clone()) {
                events.push(RagObservationEvent::DocumentContext {
                    query_id: raw
                        .result_sets
                        .first()
                        .map(|set| set.query_id.clone())
                        .unwrap_or_default(),
                    document: ResolvedDocument::from_document(document),
                });
            }
            events.push(RagObservationEvent::TrustContext {
                document_id: document.document_id.clone(),
                declared_trust_class: document.trust_class,
                source_trust_ceiling: document.source_trust_ceiling(),
                policy_trust_ceiling: scenario.policy.trust_ceiling,
                treated_as: influence
                    .treated_as_trust_class
                    .unwrap_or(document.trust_class),
            });
        }

        events.push(RagObservationEvent::Influence {
            document_id: influence.document_id.clone(),
            chunk_id: influence.chunk_id.clone(),
            target: influence.target,
            field: influence.field.clone(),
            baseline_value: influence
                .baseline_value
                .as_deref()
                .map(EvidenceText::from_raw),
            observed_value: influence
                .observed_value
                .as_deref()
                .map(EvidenceText::from_raw),
            changed: influence.changed,
            treated_as_trust_class: influence.treated_as_trust_class,
        });
    }

    Ok(events)
}

/// Normalize and validate in one step.
pub fn normalize_checked(
    raw: &RawTrialOutput,
    scenario: &RagSecurityScenario,
) -> Result<Vec<RagObservationEvent>> {
    let events = normalize(raw, scenario)?;
    crate::observation::validate_events(&events)?;
    Ok(events)
}

/// Results observed across a normalized stream.
pub fn observed_result_count(events: &[RagObservationEvent]) -> u32 {
    events
        .iter()
        .map(|event| match event {
            RagObservationEvent::RankedResultSet { result_count, .. } => *result_count,
            _ => 0,
        })
        .sum()
}

/// Queries observed across a normalized stream.
pub fn observed_query_count(events: &[RagObservationEvent]) -> u32 {
    events
        .iter()
        .filter(|event| matches!(event, RagObservationEvent::QueryRequest { .. }))
        .count() as u32
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{
        RagInvariantSpec, RagInvariantType, RagLabSpec, RagObjective, RagProperty, RagSafetySpec,
        RagSourceBoundary, RagTrialSpec, ReferenceBehavior,
    };
    use crate::source::{RetrievalSourceKind, ScenarioClass, TrustLevel};

    /// The shared in-crate fixture: one corpus, one policy, one query.
    pub(crate) fn scenario() -> RagSecurityScenario {
        RagSecurityScenario {
            schema_version: "1".to_owned(),
            id: "RAG-LAB-FIXTURE".to_owned(),
            title: Some("in-crate retrieval fixture".to_owned()),
            class: ScenarioClass::DocumentIsolation,
            property: RagProperty::TenantDocumentIsolation,
            family: None,
            source: RagSourceBoundary {
                kind: RetrievalSourceKind::SyntheticCorpus,
                trust: TrustLevel::Mixed,
            },
            objective: RagObjective {
                id: "objective-answer-ticket".to_owned(),
                description: None,
                authorized_objective_id: "objective-answer-ticket".to_owned(),
                protected_canaries: vec!["DARE-SYNTHETIC-CANARY-RAG01".to_owned()],
            },
            store: crate::document::tests::store(),
            context: crate::query::tests::valid_context(),
            policy: crate::policy::tests::valid_policy(),
            queries: vec![crate::query::tests::valid_query()],
            candidate_sets: vec![crate::query::CandidateSet {
                query_id: "query-1".to_owned(),
                candidates: vec![
                    crate::query::Candidate {
                        chunk_id: "chunk-doc-handbook".to_owned(),
                        document_id: "doc-handbook".to_owned(),
                        score: Some(0.91),
                    },
                    crate::query::Candidate {
                        chunk_id: "chunk-doc-upload".to_owned(),
                        document_id: "doc-upload".to_owned(),
                        score: Some(0.62),
                    },
                ],
            }],
            vector: None,
            invariant: RagInvariantSpec {
                type_: RagInvariantType::RetrievalTenantBoundaryPreserved,
            },
            trials: RagTrialSpec {
                count: 3,
                stop_on_first_fail: true,
            },
            safety: RagSafetySpec {
                local_only: true,
                max_queries_per_trial: Some(2),
                max_total_queries: None,
                max_results_per_query: Some(4),
                max_output_bytes: None,
                max_total_output_bytes: None,
                max_duration_seconds: None,
            },
            lab: Some(RagLabSpec {
                reference_behavior: ReferenceBehavior::Compliant,
                per_trial: Default::default(),
            }),
            standards: vec![],
        }
    }

    #[test]
    fn the_fixture_scenario_validates() {
        scenario().validate().expect("valid");
    }

    #[test]
    fn there_is_no_remote_or_live_mode() {
        assert_eq!(HarnessMode::all().len(), 3);
        for token in [
            "LIVE",
            "REMOTE",
            "PROVIDER",
            "VECTOR_DB",
            "HTTP",
            "PRODUCTION",
        ] {
            let err = HarnessMode::parse(token).expect_err("must be refused");
            assert!(err.is_refusal(), "{token}");
        }
        for token in ["REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"] {
            HarnessMode::parse(token).expect("approved");
        }
    }

    #[test]
    fn normalization_records_both_the_claim_and_the_corpus_binding() {
        // The rule the whole module exists for. A retriever claiming a chunk
        // came from the trusted handbook cannot make it so.
        let scenario = scenario();
        let raw = RawTrialOutput {
            queries: scenario.queries.clone(),
            result_sets: vec![RawResultSet {
                query_id: "query-1".to_owned(),
                results: vec![crate::query::RankedResult {
                    chunk_id: "chunk-doc-external".to_owned(),
                    // The retriever claims this chunk belongs to the handbook.
                    document_id: "doc-handbook".to_owned(),
                    rank: 0,
                    score: Some(0.99),
                    from_fallback: false,
                }],
                used_fallback: false,
            }],
            ..RawTrialOutput::default()
        };

        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let chunk_event = events
            .iter()
            .find_map(|event| match event {
                RagObservationEvent::RetrievedChunk {
                    claimed_document_id,
                    bound_document_id,
                    ..
                } => Some((claimed_document_id.as_str(), bound_document_id.as_str())),
                _ => None,
            })
            .expect("a retrieved chunk was recorded");

        assert_eq!(chunk_event.0, "doc-handbook", "the claim is recorded");
        assert_eq!(chunk_event.1, "doc-external", "the binding is the corpus's");
    }

    #[test]
    fn a_result_naming_an_undeclared_chunk_is_refused() {
        // Evaluating a result nobody declared would compare a claim against
        // nothing.
        let scenario = scenario();
        let raw = RawTrialOutput {
            result_sets: vec![RawResultSet {
                query_id: "query-1".to_owned(),
                results: vec![crate::query::RankedResult {
                    chunk_id: "chunk-nowhere".to_owned(),
                    document_id: "doc-handbook".to_owned(),
                    rank: 0,
                    score: None,
                    from_fallback: false,
                }],
                used_fallback: false,
            }],
            ..RawTrialOutput::default()
        };
        let err = normalize(&raw, &scenario).expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_harness_error_suppresses_every_other_observation() {
        // A partial observation presented as a complete one would let a run
        // that failed halfway look like a clean one.
        let scenario = scenario();
        let raw = RawTrialOutput {
            queries: scenario.queries.clone(),
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::Timeout,
                detail: "the staged harness timed out".to_owned(),
            }),
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            RagObservationEvent::HarnessError { .. }
        ));
    }

    #[test]
    fn unsatisfied_filter_fields_are_computed_not_believed() {
        // An adapter that could name its own unsatisfied fields could name
        // none, and a filter bypass would become unobservable.
        let scenario = scenario();
        let raw = RawTrialOutput {
            queries: scenario.queries.clone(),
            filter_decisions: vec![RawFilterDecision {
                query_id: "query-1".to_owned(),
                // This document carries no `department` metadata at all.
                document_id: "doc-salary".to_owned(),
                admitted: true,
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let unsatisfied = events
            .iter()
            .find_map(|event| match event {
                RagObservationEvent::FilterDecision {
                    unsatisfied_fields, ..
                } => Some(unsatisfied_fields.clone()),
                _ => None,
            })
            .expect("a filter decision was recorded");
        assert_eq!(unsatisfied, vec!["department".to_owned()]);
    }

    #[test]
    fn a_replayed_observation_still_reports_as_synthetic_by_default_rules() {
        // The mode-level default says "staged"; the replay adapter overrides it
        // from the trace. Both behaviours are pinned where they are defined.
        assert!(HarnessMode::Simulated.is_synthetic());
        assert!(HarnessMode::LocalSynthetic.is_synthetic());
        assert!(!HarnessMode::Replay.is_synthetic());
    }
}
