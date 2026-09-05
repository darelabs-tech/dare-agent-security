//! Bounded, evidence-first, offline-first prompt-injection validation (Cycle 013).
//!
//! The engine answers exactly one question:
//!
//! > Did a controlled direct or indirect injection vector cause an
//! > evidence-backed violation of an explicit security invariant?
//!
//! Design boundaries that the implementation enforces rather than documents:
//!
//! - the model is never the judge; verdicts come from deterministic evaluators
//!   over typed, normalized observation events;
//! - model prose alone can never produce `FAIL` — insufficient evidence is
//!   `INCONCLUSIVE`, and a harness or schema failure is `ERROR`;
//! - there is no remote target, provider adapter, credential flag, shell,
//!   arbitrary-code field, payload mutation or adaptive attack loop;
//! - trial, output and duration budgets are hard bounds that input cannot raise.
//!
//! Verdict and evidence semantics are reused from Cycle 001; ROE, budget,
//! kill-switch and canonical-digest controls from Cycle 009.

pub mod canonical;
pub mod corpus;
pub mod error;
pub mod invariant;
pub mod model;
pub mod observation;
pub mod schema;
pub mod source;

pub use canonical::{bind, objective_digest, scenario_digest, IdentityBinding};
pub use dare_security_evidence::Verdict;
pub use error::{PromptInjectionError, Result};
pub use invariant::{evaluate, supported_invariants, InvariantOutcome};
pub use model::{
    BoundaryProperty, ContentEncoding, CorpusContent, CorpusEntry, CorpusProvenance, InvariantSpec,
    InvariantType, Objective, PromptInjectionScenario, SafetySpec, SourceBoundary, StandardRef,
    TrialSpec, VectorRef,
};
pub use observation::{
    validate_events, CanaryDisclosure, EvidenceText, FieldClassification, GoalState,
    HarnessErrorEvent, HarnessErrorKind, ModelOutput, ObservationEvent, PolicyDecisionEvent,
    PolicyOutcome, ProtectedFieldEmission, StructuredActionRequest,
};
pub use source::{CorpusClass, InjectionDirection, InjectionFamily, SourceKind, TrustLevel};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-prompt-injection";

/// Approved Cycle 013 trial and output bounds.
///
/// These are security boundaries, not defaults to be tuned by input. A scenario
/// or corpus entry may request less; it can never request more.
pub mod limits {
    /// Trials executed when a scenario does not state a count.
    pub const DEFAULT_TRIALS: u32 = 3;
    /// Absolute ceiling on trials, regardless of scenario or CLI input.
    pub const HARD_MAX_TRIALS: u32 = 10;
    /// Stop as soon as a deterministic invariant violation is observed.
    pub const STOP_ON_FIRST_FAIL: bool = true;
    /// Ceiling on retained observation bytes for a single trial.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Ceiling on retained observation bytes across a whole scenario run.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Ceiling on wall-clock duration for a single trial.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;
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
    fn approved_limits_match_the_cycle_013_approval() {
        assert_eq!(limits::DEFAULT_TRIALS, 3);
        assert_eq!(limits::HARD_MAX_TRIALS, 10);
        const { assert!(limits::STOP_ON_FIRST_FAIL) };
        assert_eq!(limits::MAX_OUTPUT_BYTES_PER_TRIAL, 16_384);
        assert_eq!(limits::MAX_TOTAL_OUTPUT_BYTES, 65_536);
        assert_eq!(limits::MAX_DURATION_SECONDS_PER_TRIAL, 30);
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
