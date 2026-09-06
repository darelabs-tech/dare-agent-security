//! DARE Cycle 018 — MCP 2026 authentication and authorization hardening.
//!
//! Bounded, deterministic, offline validation of whether a recorded MCP
//! `2026-07-28` authorization flow kept its authentication and authorization
//! semantics bound to the operation actually being assessed.
//!
//! # The rules the crate is built on
//!
//! ```text
//! protocol_metadata != authenticated_identity
//! token_presence    != token_validity
//! valid_token       != correct_audience
//! correct_audience  != authorization_for_final_operation
//! inbound_mcp_token != upstream_service_token
//! scope_challenge   != permission_to_drop_prior_scopes
//! same scenario_id  != same authorization semantics
//! ```
//!
//! Each of those is a place where two things that look alike are not the same
//! thing, and where treating them as the same is how an authorization boundary
//! quietly stops existing. A token can be perfectly well formed, correctly
//! signed by the right authorization server, and still authorize nothing about
//! the request it arrived on.
//!
//! # What is never reached
//!
//! No authorization server, token endpoint, introspection endpoint, JWKS
//! endpoint, Protected Resource Metadata URL, authorization-server metadata
//! URL, registration endpoint, identity provider, browser, MCP server or
//! upstream API. That is a property of the dependency graph rather than a
//! promise in a comment: this crate declares no HTTP client, no OAuth client,
//! no JWT or JWKS library and no TLS stack, and [`harness::HarnessMode`] has no
//! variant that could name a remote target.
//!
//! The distinction matters more here than in most cycles. The specifications
//! this engine evaluates against are largely *about* calling those endpoints.
//! Evaluating recorded evidence of a flow and performing the flow are different
//! activities, and only the first one is in scope.
//!
//! # What is never a credential
//!
//! No raw bearer token, refresh token, authorization code, client secret,
//! private key or cookie is accepted, stored, compared or emitted. Token
//! evidence is a bounded projection — a synthetic id, an issuer, a subject, an
//! audience set, a scope set, a validity *state* — and the engine judges the
//! binding around that projection. It verifies no signature, because verifying
//! one would require a key it is not allowed to fetch.
//!
//! Credential reuse is therefore detected structurally: two credentials are
//! "the same" when their synthetic identities or digests match, never by
//! comparing secrets that were never stored.
//!
//! # Boundaries with the cycles around it
//!
//! Cycle 002 owns the MCP wire revision and the discovery lifecycle; the
//! revision constants are *imported* rather than restated, so the two cannot
//! drift. Cycle 003 owns authorization-to-execution binding and remains the
//! engine for final-operation mutation; this crate composes with it rather than
//! building a second stale-permit engine. Cycle 015 owns principal, tenant and
//! delegation semantics, whose types are re-exported rather than redefined —
//! token claims and MCP self-description may not create a second identity
//! model.

pub mod authorization;
pub mod canonical;
pub mod compat;
pub mod corpus;
pub mod coverage;
pub mod credential;
pub mod error;
pub mod evidence_bridge;
pub mod harness;
pub mod identity;
pub mod invariant;
pub mod local_synthetic;
pub mod metadata;
pub mod model;
pub mod observation;
pub mod pkce;
pub mod protocol;
pub mod redirect;
pub mod registration;
pub mod replay;
pub mod result;
pub mod schema;
pub mod scope;
pub mod simulated;
pub mod source;
pub mod token;
pub mod trials;

pub use canonical::{assert_safe_identifier, bind, digest, verify_digest, McpAuthBinding};
pub use corpus::{builtin_corpus, load_corpus, McpAuthCorpus};
pub use coverage::{assess_coverage, coverage_contract, CoverageContract, CoverageDecision};
pub use dare_security_evidence::Verdict;
pub use error::{McpAuthSecurityError, Result};
pub use evidence_bridge::{build_evidence, build_trial_evidence, evidence_id, EVIDENCE_SCHEMA_ID};
pub use harness::{normalize, normalize_checked, HarnessAdapter, HarnessMode, TrialRequest};
pub use invariant::{evaluate, supported_invariants, McpAuthInvariantOutcome, McpAuthViolation};
pub use model::{
    McpAuthCorpusEntry, McpAuthInvariantSpec, McpAuthInvariantType, McpAuthProperty,
    McpAuthScenario, ReferenceBehavior,
};
pub use observation::{mask_sensitive, EvidenceText, McpAuthObservation, REDACTION_MARKER};
pub use replay::{load_trace, parse_trace, McpAuthTrace, ReplayAdapter};
pub use result::{run_scenario, McpAuthSecurityResult, McpAuthTrialRecord, RESULT_SCHEMA_ID};
pub use simulated::{stage, SimulatedAdapter};
pub use source::{ScenarioClass, TrustClass};
pub use trials::{BudgetSnapshot, StopReason, TrialGuard, TrialLedger, TrialPlan};

/// The MCP wire revisions, imported from Cycle 002 rather than restated.
///
/// Writing `"2026-07-28"` into this crate would create a second source of truth
/// for the current revision. Two constants that must agree and are edited in
/// different files eventually disagree, and the failure would be silent: a
/// scenario would look current to one crate and legacy to the other.
pub use dare_mcp_discovery::adapter::{CURRENT_WIRE_REVISION, LEGACY_WIRE_REVISION};

/// Hard bounds approved for Cycle 018.
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

    /// Requests one trial may carry.
    pub const HARD_MAX_REQUESTS_PER_TRIAL: u32 = 8;
    /// Requests a whole run may carry, across every trial.
    pub const HARD_MAX_TOTAL_REQUESTS: u32 = 24;
    /// Metadata documents one scenario may declare.
    pub const HARD_MAX_METADATA_DOCUMENTS: u32 = 8;
    /// Authorization servers one scenario may declare.
    pub const HARD_MAX_AUTHORIZATION_SERVERS: u32 = 8;
    /// Audiences one token projection may declare.
    pub const HARD_MAX_AUDIENCES_PER_TOKEN: u32 = 16;
    /// Scopes one scope context may declare.
    pub const HARD_MAX_SCOPES_PER_CONTEXT: u32 = 32;
    /// Step-up retries a scope challenge may perform.
    ///
    /// A retry loop is the failure mode: a client that keeps retrying on every
    /// challenge will eventually be granted something, and an engine with no
    /// ceiling would follow it there.
    pub const HARD_MAX_SCOPE_STEP_UP_RETRIES: u32 = 2;
    /// Redirect URIs one client registration may declare.
    pub const HARD_MAX_REGISTRATION_REDIRECT_URIS: u32 = 16;
    /// Claim fields one token projection may carry.
    pub const HARD_MAX_CLAIM_FIELDS: u32 = 64;

    /// Bytes of observation one trial may retain.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 16_384;
    /// Bytes of observation a whole run may retain.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 65_536;
    /// Wall-clock seconds one trial may take.
    pub const MAX_DURATION_SECONDS_PER_TRIAL: u64 = 30;

    /// Always zero. Cycle 018 changes nothing anywhere.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Always zero. Cycle 018 contacts nothing.
    pub const EXTERNAL_EGRESS_BYTES: u64 = 0;

    /// Bytes one free-text evidence value may retain before truncation.
    pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_approved_bounds_are_exactly_what_design_records() {
            assert_eq!(DEFAULT_TRIALS, 3);
            assert_eq!(HARD_MAX_TRIALS, 10);
            assert_eq!(HARD_MAX_REQUESTS_PER_TRIAL, 8);
            assert_eq!(HARD_MAX_TOTAL_REQUESTS, 24);
            assert_eq!(HARD_MAX_METADATA_DOCUMENTS, 8);
            assert_eq!(HARD_MAX_AUTHORIZATION_SERVERS, 8);
            assert_eq!(HARD_MAX_AUDIENCES_PER_TOKEN, 16);
            assert_eq!(HARD_MAX_SCOPES_PER_CONTEXT, 32);
            assert_eq!(HARD_MAX_SCOPE_STEP_UP_RETRIES, 2);
            assert_eq!(HARD_MAX_REGISTRATION_REDIRECT_URIS, 16);
            assert_eq!(HARD_MAX_CLAIM_FIELDS, 64);
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
            const { assert!(HARD_MAX_REQUESTS_PER_TRIAL <= HARD_MAX_TOTAL_REQUESTS) };
            const { assert!(MAX_OUTPUT_BYTES_PER_TRIAL <= MAX_TOTAL_OUTPUT_BYTES) };
        }

        #[test]
        fn the_step_up_ceiling_is_small_enough_to_stop_a_loop() {
            // Two retries is a step-up. Ten would be a client grinding an
            // authorization server until something is granted, and an engine
            // with a generous ceiling would follow it there and call the result
            // evidence.
            const { assert!(HARD_MAX_SCOPE_STEP_UP_RETRIES <= 3) };
        }
    }

    #[cfg(test)]
    mod revision_tests {
        #[test]
        fn the_revision_constants_come_from_cycle_002() {
            // Not a tautology: the point is that this crate holds no literal of
            // its own to compare against. If Cycle 002 ever moves the current
            // revision, this crate moves with it rather than disagreeing.
            assert_eq!(crate::CURRENT_WIRE_REVISION, "2026-07-28");
            assert_eq!(crate::LEGACY_WIRE_REVISION, "2024-11-05");
            assert_ne!(crate::CURRENT_WIRE_REVISION, crate::LEGACY_WIRE_REVISION);
        }
    }
}
