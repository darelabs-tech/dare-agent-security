//! DARE Cycle 017 — RAG and retrieval security validation.
//!
//! Bounded, deterministic, offline validation of whether a retrieval flow kept
//! returned context inside the principal, tenant, collection, document, source
//! and trust boundaries that should govern it.
//!
//! # The rule the crate is built on
//!
//! ```text
//! similarity_match  != permission
//! retrieved_content != trusted_instruction
//! high_score        != safe_source
//! ```
//!
//! A retriever can return exactly the most relevant document in the index and
//! still have violated a boundary. Relevance is a property of the query;
//! authorization is a property of the policy. Nothing in the verdict path is
//! allowed to let the first stand in for the second.
//!
//! # What is never the judge
//!
//! There is no model, no embedding, no cosine similarity, no reranker, no fuzzy
//! match and no prose heuristic anywhere in the evaluation path. Scores and
//! orderings *are* accepted — as evidence about ordering, supplied by a fixture
//! or a trace. The engine reasons about the policy and the integrity around
//! those numbers. It never asks whether an embedding is semantically sensible,
//! because that question has no deterministic answer and a security verdict
//! must have one.
//!
//! # What is never reached
//!
//! No Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch, Elasticsearch,
//! Chroma, Milvus, SaaS retrieval API, production retriever, customer corpus or
//! remote MCP server. That is a property of the dependency graph rather than a
//! promise in a comment: this crate declares no HTTP client, no database driver,
//! no vector-store SDK and no embedding runtime, and [`harness::HarnessMode`]
//! has no variant that could name a remote target.
//!
//! Documents are described from local synthetic fixtures. Nothing is fetched,
//! indexed, embedded or persisted; `state_changes` and `external_egress_bytes`
//! are zero in every artifact and are recorded so the zero is evidenced rather
//! than assumed.
//!
//! # Boundaries with the cycles either side
//!
//! Cycle 013 owns whether untrusted content acted as an instruction and stays
//! the final judge of it; this crate observes authority promotion structurally
//! and composes with that vocabulary instead of re-deriving it. Cycle 015 owns
//! principal and tenant identity, whose types are re-exported rather than
//! redefined. Cycle 016 owns persisted memory: retrieved content is *not*
//! memory, and becomes memory only through a separate memory event this cycle
//! neither produces nor records.

pub mod canonical;
pub mod compat;
pub mod corpus;
pub mod coverage;
pub mod document;
pub mod error;
pub mod evidence_bridge;
pub mod harness;
pub mod invariant;
pub mod local_synthetic;
pub mod model;
pub mod observation;
pub mod policy;
pub mod query;
pub mod replay;
pub mod result;
pub mod schema;
pub mod simulated;
pub mod source;
pub mod trials;

pub use canonical::{assert_safe_identifier, bind, digest, verify_digest, RagBinding};
pub use corpus::{builtin_corpus, load_corpus, RagCorpus};
pub use coverage::{assess_coverage, coverage_contract, CoverageContract, CoverageDecision};
pub use dare_security_evidence::Verdict;
pub use document::{Chunk, Collection, Document, DocumentStore, Provenance};
pub use error::{RagSecurityError, Result};
pub use evidence_bridge::{build_evidence, build_trial_evidence, evidence_id, EVIDENCE_SCHEMA_ID};
pub use harness::{normalize, normalize_checked, HarnessAdapter, HarnessMode, TrialRequest};
pub use invariant::{evaluate, supported_invariants, RagInvariantOutcome, RagViolation};
pub use local_synthetic::{synthetic_budget, LocalSyntheticAdapter, RagControlSnapshot};
pub use model::{
    RagCorpusEntry, RagInvariantSpec, RagInvariantType, RagProperty, RagSecurityScenario,
    ReferenceBehavior,
};
pub use observation::{mask_sensitive, EvidenceText, RagObservationEvent, REDACTION_MARKER};
pub use policy::{
    FilterClause, MetadataFilter, PolicyDimension, ProtectedSet, RetrievalPolicy, TopKPolicy,
};
pub use query::{CandidateSet, QueryRequest, RankedResult, RankedResultSet, RetrievalContext};
pub use replay::{load_trace, parse_trace, LoadedTrace, RagTrace, ReplayAdapter};
pub use result::{run_scenario, RagSecurityResult, RagTrialRecord, RESULT_SCHEMA_ID};
pub use simulated::{stage, SimulatedAdapter};
pub use source::{
    ClassificationLevel, CorpusClass, DocumentTrustClass, RetrievalFamily, RetrievalSourceKind,
    ScenarioClass, TrustLevel,
};
pub use trials::{BudgetSnapshot, StopReason, TrialGuard, TrialLedger, TrialPlan};

/// Hard bounds approved for Cycle 017.
///
/// Every one of these is a refusal threshold, never a clamp. A scenario may ask
/// for less; nothing may ask for more. The distinction matters because a
/// silently clamped request runs as though it had asked for something
/// reasonable, and the operator never learns their scenario was out of bounds.
///
/// Run-wide totals are enforced across the whole run and never reset between
/// trials — a counter that resets is not a bound.
pub mod limits {
    /// Trials executed when a scenario does not say otherwise.
    pub const DEFAULT_TRIALS: u32 = 3;
    /// Absolute ceiling on trials, whatever a scenario or flag requests.
    pub const HARD_MAX_TRIALS: u32 = 10;
    /// Stop the run once a trial has failed — after that trial's evidence has
    /// been fully collected, never before.
    pub const STOP_ON_FIRST_FAIL: bool = true;

    /// Documents a synthetic corpus may declare.
    pub const HARD_MAX_DOCUMENTS: u32 = 64;
    /// Chunks a synthetic corpus may declare.
    pub const HARD_MAX_CHUNKS: u32 = 256;
    /// Candidates one query may consider.
    pub const HARD_MAX_CANDIDATES_PER_QUERY: u32 = 64;
    /// Results one query may return.
    pub const HARD_MAX_RESULTS_PER_QUERY: u32 = 16;
    /// Queries one trial may issue.
    pub const HARD_MAX_QUERIES_PER_TRIAL: u32 = 8;
    /// Queries a whole run may issue, across every trial.
    pub const HARD_MAX_TOTAL_QUERIES: u32 = 24;
    /// Metadata fields one document may carry.
    pub const HARD_MAX_METADATA_FIELDS_PER_DOCUMENT: u32 = 32;
    /// Clauses one metadata filter may contain.
    pub const HARD_MAX_FILTER_CLAUSES: u32 = 16;

    /// Bytes of observation one trial may retain.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Bytes of observation a whole run may retain.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Wall-clock seconds one trial may take.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;

    /// Always zero. Cycle 017 indexes nothing and writes to no store.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Always zero. Cycle 017 contacts nothing.
    pub const EXTERNAL_EGRESS_BYTES: u64 = 0;

    /// Bytes of content one chunk may carry in a fixture.
    ///
    /// Chunks exist to be *identified*, not read. A bound here keeps a fixture
    /// from smuggling a document body through a field meant for an excerpt.
    pub const MAX_CONTENT_BYTES_PER_CHUNK: usize = 4_096;

    /// Dimensions a declared vector payload may carry.
    ///
    /// Cycle 017 never computes or compares an embedding. A fixture may carry a
    /// short synthetic vector purely as an identifier-like artifact, and this
    /// bound stops that field becoming a channel for arbitrary binary data.
    pub const MAX_VECTOR_DIMENSIONS: usize = 16;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_approved_bounds_are_exactly_what_design_records() {
            assert_eq!(DEFAULT_TRIALS, 3);
            assert_eq!(HARD_MAX_TRIALS, 10);
            assert_eq!(HARD_MAX_DOCUMENTS, 64);
            assert_eq!(HARD_MAX_CHUNKS, 256);
            assert_eq!(HARD_MAX_CANDIDATES_PER_QUERY, 64);
            assert_eq!(HARD_MAX_RESULTS_PER_QUERY, 16);
            assert_eq!(HARD_MAX_QUERIES_PER_TRIAL, 8);
            assert_eq!(HARD_MAX_TOTAL_QUERIES, 24);
            assert_eq!(HARD_MAX_METADATA_FIELDS_PER_DOCUMENT, 32);
            assert_eq!(HARD_MAX_FILTER_CLAUSES, 16);
            assert_eq!(MAX_OUTPUT_BYTES_PER_TRIAL, 16_384);
            assert_eq!(MAX_TOTAL_OUTPUT_BYTES, 65_536);
            assert_eq!(MAX_DURATION_SECONDS_PER_TRIAL, 30);
            assert_eq!(MAX_STATE_CHANGES, 0);
            assert_eq!(EXTERNAL_EGRESS_BYTES, 0);
        }

        #[test]
        fn the_zero_bounds_are_zero_and_stay_that_way() {
            // These two are the whole safety boundary expressed as numbers. A
            // non-zero value would mean the engine had acquired the ability to
            // change something or reach somewhere.
            const { assert!(MAX_STATE_CHANGES == 0) };
            const { assert!(EXTERNAL_EGRESS_BYTES == 0) };
        }

        #[test]
        fn per_trial_bounds_never_exceed_run_wide_ones() {
            // A per-trial bound above the run total would be unreachable, which
            // usually means one of the two was edited without the other.
            const { assert!(HARD_MAX_QUERIES_PER_TRIAL <= HARD_MAX_TOTAL_QUERIES) };
            const { assert!(MAX_OUTPUT_BYTES_PER_TRIAL <= MAX_TOTAL_OUTPUT_BYTES) };
            const { assert!(HARD_MAX_RESULTS_PER_QUERY <= HARD_MAX_CANDIDATES_PER_QUERY) };
            const { assert!(HARD_MAX_DOCUMENTS <= HARD_MAX_CHUNKS) };
        }

        #[test]
        fn a_result_set_can_never_be_wider_than_the_candidate_set() {
            // The result-set invariant depends on this being structurally
            // impossible to satisfy by widening the bound instead of the set.
            // Checked at compile time so the relationship cannot be edited away
            // in one place without the other.
            const { assert!(HARD_MAX_RESULTS_PER_QUERY < HARD_MAX_CANDIDATES_PER_QUERY) };
        }
    }
}
