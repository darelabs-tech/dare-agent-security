//! Bounded, evidence-first, offline-first identity, privilege and delegation
//! validation (Cycle 015).
//!
//! The engine answers one question deterministically:
//!
//! > Did a controlled principal, delegation, privilege or authorization trace
//! > prove that effective authority exceeded, changed, crossed a boundary, or
//! > detached from the authority originally granted?
//!
//! The relation the whole cycle rests on:
//!
//! ```text
//! effective_authority <= delegated_or_source_authority_ceiling
//! ```
//!
//! Authority may remain equal or narrow through delegation. It may never
//! silently expand. And the corollary that motivates most of the fixtures:
//! **credential availability is not delegated authority**. A more privileged
//! service, workload or technical credential existing in the runtime does not
//! authorize the agent to exercise those privileges on the user's behalf.
//!
//! Design boundaries the implementation enforces rather than documents:
//!
//! - the model is never the judge; verdicts come from deterministic evaluators
//!   over typed, normalized identity observation events;
//! - **absence of evidence is never evidence of absence** — every invariant
//!   declares the observation channel it needs, and a missing channel yields
//!   `INCONCLUSIVE`, never `PASS`;
//! - independently true violations are emitted independently; principal
//!   substitution, tenant crossing and privilege amplification can all be true
//!   in one trace, and one classification never masks another;
//! - a denied or risky operation is *observed*, never dispatched. Nothing in
//!   this crate can act on a resource, and no operation leaves the process;
//! - there is no identity provider, OAuth server, PDP, AuthZEN endpoint, MCP
//!   client, token parser or credential flag. Cycle 015 models authority
//!   declaratively; protocol and cryptographic identity belong to Cycle 018;
//! - principal, delegation, operation, output and duration budgets are hard
//!   bounds that input cannot raise.
//!
//! Verdict and evidence semantics are reused from Cycle 001; the
//! authorization-to-execution binding from Cycle 003; ROE, budget and
//! kill-switch controls from Cycle 009; observation/evaluator patterns from
//! Cycles 013 and 014.

pub mod authority;
pub mod authorization;
pub mod canonical;
pub mod coverage;
pub mod delegation;
pub mod error;
pub mod harness;
pub mod invariant;
pub mod local_synthetic;
pub mod model;
pub mod observation;
pub mod operation;
pub mod principal;
pub mod replay;
pub mod resource;
pub mod schema;
pub mod simulated;
pub mod source;
pub mod trials;

pub use authority::{
    Authority, AuthorityAxis, AuthorityDimension, AuthorityExcess, LogicalTime, ValidityWindow,
};
pub use authorization::{AuthorizationDecision, AuthorizationPolicy, DecisionEffect};
pub use canonical::{assert_safe_identifier, digest, verify_digest, IdentityBinding};
pub use coverage::{
    all_contracts, assess_coverage, coverage_contract, ChannelRequirement, CoverageContract,
    CoverageDecision,
};
pub use dare_security_evidence::Verdict;
pub use delegation::{ChainDefect, DelegationChain, DelegationEdge};
pub use error::{IdentitySecurityError, Result};
pub use harness::{
    normalize, normalize_checked, HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest,
};
pub use invariant::{evaluate, supported_invariants, IdentityInvariantOutcome, IdentityViolation};
pub use local_synthetic::{synthetic_budget, IdentityControlSnapshot, LocalSyntheticAdapter};
pub use model::{
    IdentityCorpusEntry, IdentityInvariantType, IdentityLabSpec, IdentityObjective,
    IdentityProperty, IdentitySecurityScenario, ReferenceBehavior,
};
pub use observation::{
    observed_channels, validate_events, CoverageChannel, EvidenceText, IdentityObservationEvent,
};
pub use operation::{Operation, OperationDifference, OperationField, OperationProjection};
pub use principal::{Principal, PrincipalBindings, PrincipalSet};
pub use replay::{load_trace, parse_trace, LoadedTrace, ReplayAdapter, ReplayTrace};
pub use resource::{ResourceClassification, ResourceContext};
pub use simulated::{stage, SimulatedAdapter};
pub use source::{
    CorpusClass, DelegationKind, IdentitySourceKind, PrincipalKind, PrincipalRole, ScenarioClass,
    TrustLevel,
};
pub use trials::{BudgetSnapshot, StopReason, TrialGuard, TrialLedger, TrialPlan};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-identity-security";

/// Approved Cycle 015 hard bounds.
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
    /// Ceiling on principals in one scenario's principal set.
    pub const HARD_MAX_PRINCIPALS: u32 = 16;
    /// Ceiling on edges in one delegation chain.
    pub const HARD_MAX_DELEGATION_EDGES: u32 = 12;
    /// Ceiling on delegation chain depth.
    pub const HARD_MAX_DELEGATION_DEPTH: u32 = 4;
    /// Ceiling on authorization decisions observed within one trial.
    pub const MAX_AUTHORIZATION_DECISIONS_PER_TRIAL: u32 = 8;
    /// Ceiling on operations observed within one trial.
    pub const MAX_OPERATIONS_PER_TRIAL: u32 = 8;
    /// Ceiling on operations observed across the whole run.
    pub const HARD_MAX_TOTAL_OPERATIONS: u32 = 24;
    /// Ceiling on retained observation bytes for a single trial.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Ceiling on retained observation bytes across a whole run.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Ceiling on wall-clock duration for a single trial.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;
    /// Cycle 015 performs no state change. Ever.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Cycle 015 performs no external egress. Ever.
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
    fn approved_limits_match_the_cycle_015_approval() {
        assert_eq!(limits::DEFAULT_TRIALS, 3);
        assert_eq!(limits::HARD_MAX_TRIALS, 10);
        const { assert!(limits::STOP_ON_FIRST_FAIL) };
        assert_eq!(limits::HARD_MAX_PRINCIPALS, 16);
        assert_eq!(limits::HARD_MAX_DELEGATION_EDGES, 12);
        assert_eq!(limits::HARD_MAX_DELEGATION_DEPTH, 4);
        assert_eq!(limits::MAX_AUTHORIZATION_DECISIONS_PER_TRIAL, 8);
        assert_eq!(limits::MAX_OPERATIONS_PER_TRIAL, 8);
        assert_eq!(limits::HARD_MAX_TOTAL_OPERATIONS, 24);
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
        const { assert!(limits::MAX_OPERATIONS_PER_TRIAL <= limits::HARD_MAX_TOTAL_OPERATIONS) };
        const { assert!(limits::MAX_OUTPUT_BYTES_PER_TRIAL <= limits::MAX_TOTAL_OUTPUT_BYTES) };
        const { assert!(limits::DEFAULT_TRIALS <= limits::HARD_MAX_TRIALS) };
        const { assert!(limits::HARD_MAX_DELEGATION_DEPTH <= limits::HARD_MAX_DELEGATION_EDGES) };
    }

    #[test]
    fn the_verdict_vocabulary_is_reused_from_cycle_001() {
        // No second verdict vocabulary is defined anywhere in this crate.
        use dare_security_evidence::Verdict;
        assert_eq!(Verdict::Pass.as_str(), "PASS");
        assert_eq!(Verdict::Fail.as_str(), "FAIL");
        assert_eq!(Verdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(Verdict::Error.as_str(), "ERROR");
    }
}
