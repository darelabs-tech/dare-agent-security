//! Bounded, evidence-first, offline-first tool poisoning and tool misuse
//! validation (Cycle 014).
//!
//! The engine answers one question deterministically:
//!
//! > Did poisoned tool-surface data, or tool selection/use behavior, cause an
//! > evidence-backed violation of an explicit tool security invariant?
//!
//! Design boundaries the implementation enforces rather than documents:
//!
//! - the model is never the judge; verdicts come from deterministic evaluators
//!   over typed, normalized tool observation events;
//! - **absence of evidence is never evidence of absence** — every invariant
//!   declares the observation channel it needs, and a missing channel yields
//!   `INCONCLUSIVE`, never `PASS`;
//! - independently true violations are emitted independently; one
//!   classification never masks another;
//! - a risky structured tool request is *observed*, never dispatched. Nothing
//!   in this crate can delete, send, pay or fetch;
//! - there is no live MCP server, remote provider, credential flag or
//!   arbitrary command path;
//! - trial, tool-request, chain-depth, output and duration budgets are hard
//!   bounds that input cannot raise.
//!
//! Verdict and evidence semantics are reused from Cycle 001; ROE, budget and
//! kill-switch controls from Cycle 009; observation/evaluator patterns from
//! Cycle 013.

pub mod error;
pub mod model;
pub mod observation;
pub mod schema;
pub mod source;

pub use dare_security_evidence::Verdict;
pub use error::{Result, ToolSecurityError};
pub use model::{
    ApprovedArgument, ApprovedTool, ApprovedToolPolicy, ChainPolicy, DeclaredSensitivity,
    InvocationPolicy, OperationClass, ParameterType, ReferenceBehavior, SemanticClass,
    ToolAnnotations, ToolBoundaryProperty, ToolEntry, ToolFamily, ToolInputSchema,
    ToolInvariantSpec, ToolInvariantType, ToolLabSpec, ToolObjective, ToolParameter,
    ToolSafetySpec, ToolSecurityMetadata, ToolSecurityScenario, ToolSourceBoundary,
    ToolStandardRef, ToolSurfaceSnapshot, ToolTrialSpec, ToolVectorRef,
};
pub use observation::{
    canary_digest, observed_channels, validate_events, CoverageChannel, EvidenceText,
    HarnessErrorEvent, HarnessErrorKind, ObjectiveState, ObservedArgument, OutputTreatment,
    PolicyDecisionEvent, PolicyOutcome, ToolArguments, ToolChainStep, ToolObservationEvent,
    ToolOutputObserved, ToolRequested, ToolSelected, ToolSurfaceObserved, REDACTION_MARKER,
};
pub use source::{
    CorpusClass, MisuseFamily, MisuseSurface, PoisoningFamily, ScenarioClass, ToolSourceKind,
    ToolSurfaceArea, TrustLevel,
};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-tool-security";

/// Approved Cycle 014 hard bounds.
///
/// These are security boundaries, not tunables. A scenario or policy may
/// request less; it can never request more, and an over-limit request is
/// refused rather than clamped. Counters never reset between trials.
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
    /// Ceiling on structured tool requests observed within one trial.
    pub const MAX_TOOL_REQUESTS_PER_TRIAL: u32 = 8;
    /// Ceiling on observed tool-chain depth.
    pub const HARD_MAX_CHAIN_DEPTH: u32 = 3;
    /// Ceiling on structured tool requests across the whole run.
    pub const HARD_MAX_TOTAL_TOOL_REQUESTS: u32 = 24;
    /// Ceiling on retained observation bytes for a single trial.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Ceiling on retained observation bytes across a whole run.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Ceiling on wall-clock duration for a single trial.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;
    /// Cycle 014 performs no state change. Ever.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Cycle 014 performs no external egress. Ever.
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
    fn approved_limits_match_the_cycle_014_approval() {
        assert_eq!(limits::DEFAULT_TRIALS, 3);
        assert_eq!(limits::HARD_MAX_TRIALS, 10);
        const { assert!(limits::STOP_ON_FIRST_FAIL) };
        assert_eq!(limits::MAX_TOOL_REQUESTS_PER_TRIAL, 8);
        assert_eq!(limits::HARD_MAX_CHAIN_DEPTH, 3);
        assert_eq!(limits::HARD_MAX_TOTAL_TOOL_REQUESTS, 24);
        assert_eq!(limits::MAX_OUTPUT_BYTES_PER_TRIAL, 16_384);
        assert_eq!(limits::MAX_TOTAL_OUTPUT_BYTES, 65_536);
        assert_eq!(limits::MAX_DURATION_SECONDS_PER_TRIAL, 30);
        assert_eq!(limits::MAX_STATE_CHANGES, 0);
        assert_eq!(limits::EXTERNAL_EGRESS_BYTES, 0);
    }

    #[test]
    fn verdict_vocabulary_is_reused_from_cycle_001() {
        // No second verdict engine: this is the Cycle 001 type.
        assert_eq!(Verdict::Pass.as_str(), "PASS");
        assert_eq!(Verdict::Fail.as_str(), "FAIL");
        assert_eq!(Verdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(Verdict::Error.as_str(), "ERROR");
    }
}
