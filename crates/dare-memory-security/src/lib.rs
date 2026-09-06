//! Bounded, evidence-first, offline-first memory and context poisoning
//! validation (Cycle 016).
//!
//! The engine answers one question deterministically:
//!
//! > Did a memory or persisted-context event prove that untrusted, stale,
//! > cross-tenant, cross-principal or integrity-violating state influenced a
//! > later agent decision or operation?
//!
//! The relation the whole cycle rests on:
//!
//! ```text
//! stored_data != trusted_instruction
//! ```
//!
//! Persisting data does not convert that data into authority. Two corollaries
//! follow, and both are enforced rather than documented: **memory availability
//! is not authorization**, and **recall is not permission to influence**.
//!
//! Untrusted memory may exist as data without producing a violation. A
//! violation requires deterministic evidence that it exceeded its authorized
//! boundary — which is why a fixture full of alarming stored text is not, by
//! itself, a finding.
//!
//! Design boundaries the implementation enforces rather than documents:
//!
//! - the model is never the judge; verdicts come from deterministic evaluators
//!   over typed, normalized memory observation events. No LLM, embedding,
//!   cosine or semantic similarity, fuzzy match or prose heuristic appears in
//!   the verdict path, and none is declared as a dependency;
//! - **absence of evidence is never evidence of absence** — every invariant
//!   declares the observation channels it needs, and a missing channel yields
//!   `INCONCLUSIVE`, never `PASS`;
//! - independently true violations are emitted independently; trust promotion,
//!   tenant crossing and integrity mutation can all be true in one trial, and
//!   one classification never masks another;
//! - a memory store is *described*, never connected to. There is no Redis,
//!   PostgreSQL, vector-database, SaaS-memory or MCP client anywhere in this
//!   crate, and no mode or flag that could reach one;
//! - retrieval, embeddings, similarity search and document-chunk authorization
//!   belong to Cycle 017; OAuth, JWT and live identity belong to Cycle 018;
//! - lifecycle is decided on declared logical time, never the machine clock, so
//!   a verdict cannot change because CI was slow;
//! - item, namespace, event, recall, output and duration budgets are hard
//!   bounds that input cannot raise.
//!
//! Verdict and evidence semantics are reused from Cycle 001; ROE, budget and
//! kill-switch controls from Cycle 009; the untrusted-data-is-not-an-instruction
//! rule from Cycle 013; principal and tenant conventions from Cycle 015.

pub mod binding;
pub mod canonical;
pub mod compat;
pub mod corpus;
pub mod coverage;
pub mod error;
pub mod harness;
pub mod invariant;
pub mod lifecycle;
pub mod local_synthetic;
pub mod memory;
pub mod model;
pub mod observation;
pub mod policy;
pub mod replay;
pub mod schema;
pub mod simulated;
pub mod source;
pub mod trials;

pub use binding::{MemoryContext, MemoryPrincipal, PrincipalKind};
pub use canonical::{assert_safe_identifier, digest, verify_digest, MemoryBinding};
pub use compat::{
    acting_principal_originates_authority, assert_identity_agreement, composed_boundary_properties,
    injection_source_for, memory_principal_from_identity,
};
pub use corpus::{builtin_corpus, load_corpus, MemoryCorpus};
pub use coverage::{
    all_contracts, assess_coverage, coverage_contract, ChannelRequirement, CoverageContract,
    CoverageDecision,
};
pub use dare_security_evidence::Verdict;
pub use error::{MemorySecurityError, Result};
pub use harness::{
    normalize, normalize_checked, HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest,
};
pub use invariant::{evaluate, supported_invariants, MemoryInvariantOutcome, MemoryViolation};
pub use lifecycle::{LogicalTime, ValidityWindow};
pub use local_synthetic::{synthetic_budget, LocalSyntheticAdapter, MemoryControlSnapshot};
pub use memory::{MemoryItem, MemoryStore, Provenance};
pub use model::{
    MemoryCorpusEntry, MemoryInvariantType, MemoryLabSpec, MemoryObjective, MemoryProperty,
    MemorySecurityScenario, ReferenceBehavior,
};
pub use observation::{
    observed_channels, validate_events, CoverageChannel, EvidenceText, InfluenceTarget,
    MemoryObservationEvent,
};
pub use policy::{MemoryPolicy, PolicyDimension, TrustElevationGrant};
pub use replay::{load_trace, parse_trace, LoadedTrace, MemoryTrace, ReplayAdapter};
pub use simulated::{stage, SimulatedAdapter};
pub use source::{
    CorpusClass, LifecycleState, MemorySourceKind, PoisoningFamily, ScenarioClass, SourceKind,
    TrustClass, TrustLevel,
};
pub use trials::{BudgetSnapshot, StopReason, TrialGuard, TrialLedger, TrialPlan};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-memory-security";

/// Approved Cycle 016 hard bounds.
///
/// These are security boundaries, not tunables. A scenario, policy or flag may
/// request less; none can request more, and an over-limit request is refused
/// rather than clamped down and quietly accepted. Run totals never reset
/// between trials.
pub mod limits {
    /// Trials executed when a scenario does not state a count.
    pub const DEFAULT_TRIALS: u32 = 3;
    /// Absolute ceiling on trials, regardless of scenario or CLI input.
    pub const HARD_MAX_TRIALS: u32 = 10;
    /// Stop as soon as a deterministic invariant violation is observed.
    ///
    /// Stopping later trials never erases violations already observed in the
    /// current trial.
    pub const STOP_ON_FIRST_FAIL: bool = true;
    /// Ceiling on memory items in one store snapshot.
    pub const HARD_MAX_MEMORY_ITEMS: u32 = 32;
    /// Ceiling on namespaces one store may span.
    pub const HARD_MAX_NAMESPACES: u32 = 8;
    /// Ceiling on normalized memory events within one trial.
    pub const MAX_MEMORY_EVENTS_PER_TRIAL: u32 = 32;
    /// Ceiling on normalized memory events across the whole run.
    pub const HARD_MAX_TOTAL_MEMORY_EVENTS: u32 = 96;
    /// Ceiling on items one recall request may return.
    pub const MAX_RECALL_ITEMS_PER_REQUEST: u32 = 8;
    /// Ceiling on retained content bytes for a single memory item.
    pub const MAX_CONTENT_BYTES_PER_ITEM: usize = 8_192;
    /// Ceiling on retained observation bytes for a single trial.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Ceiling on retained observation bytes across a whole run.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Ceiling on wall-clock duration for a single trial.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;
    /// Cycle 016 performs no state change. Ever.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Cycle 016 performs no external egress. Ever.
    pub const EXTERNAL_EGRESS_BYTES: u64 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }

    #[test]
    fn approved_limits_match_the_cycle_016_design() {
        assert_eq!(limits::DEFAULT_TRIALS, 3);
        assert_eq!(limits::HARD_MAX_TRIALS, 10);
        const { assert!(limits::STOP_ON_FIRST_FAIL) };
        assert_eq!(limits::HARD_MAX_MEMORY_ITEMS, 32);
        assert_eq!(limits::HARD_MAX_NAMESPACES, 8);
        assert_eq!(limits::MAX_MEMORY_EVENTS_PER_TRIAL, 32);
        assert_eq!(limits::HARD_MAX_TOTAL_MEMORY_EVENTS, 96);
        assert_eq!(limits::MAX_RECALL_ITEMS_PER_REQUEST, 8);
        assert_eq!(limits::MAX_CONTENT_BYTES_PER_ITEM, 8_192);
        assert_eq!(limits::MAX_OUTPUT_BYTES_PER_TRIAL, 16_384);
        assert_eq!(limits::MAX_TOTAL_OUTPUT_BYTES, 65_536);
        assert_eq!(limits::MAX_DURATION_SECONDS_PER_TRIAL, 30);
        assert_eq!(limits::MAX_STATE_CHANGES, 0);
        assert_eq!(limits::EXTERNAL_EGRESS_BYTES, 0);
    }

    #[test]
    fn the_zero_bounds_are_zero_and_not_merely_small() {
        // A non-zero value here would mean the engine may change state or send
        // bytes somewhere. Neither is ever true, so the constants are zero and
        // a test says so rather than a comment.
        const { assert!(limits::MAX_STATE_CHANGES == 0) };
        const { assert!(limits::EXTERNAL_EGRESS_BYTES == 0) };
    }

    #[test]
    fn per_trial_bounds_are_not_above_their_run_totals() {
        // A per-trial allowance larger than the run total would make the run
        // total unreachable, which is a bound that does not bound.
        const { assert!(limits::MAX_MEMORY_EVENTS_PER_TRIAL <= limits::HARD_MAX_TOTAL_MEMORY_EVENTS) };
        const { assert!(limits::MAX_OUTPUT_BYTES_PER_TRIAL <= limits::MAX_TOTAL_OUTPUT_BYTES) };
        const { assert!(limits::DEFAULT_TRIALS <= limits::HARD_MAX_TRIALS) };
        const { assert!(limits::MAX_RECALL_ITEMS_PER_REQUEST <= limits::HARD_MAX_MEMORY_ITEMS) };
        const { assert!(limits::MAX_CONTENT_BYTES_PER_ITEM <= limits::MAX_OUTPUT_BYTES_PER_TRIAL) };
    }

    #[test]
    fn the_verdict_vocabulary_is_reused_from_cycle_001() {
        // No second verdict vocabulary is defined anywhere in this crate.
        assert_eq!(Verdict::Pass.as_str(), "PASS");
        assert_eq!(Verdict::Fail.as_str(), "FAIL");
        assert_eq!(Verdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(Verdict::Error.as_str(), "ERROR");
    }

    #[test]
    fn principal_semantics_are_reused_from_cycle_015() {
        // Re-exported, not redefined: a HUMAN here is a HUMAN there.
        assert_eq!(PrincipalKind::all().len(), 4);
        assert!(PrincipalKind::Human.originates_authority());
        assert!(!PrincipalKind::Agent.originates_authority());
    }
}
