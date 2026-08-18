//! Protocol-neutral security evidence kernel for DARE Agent Security.
//!
//! This library is the reusable Cycle 001 evidence contract: versioned,
//! machine-readable records of deterministic security verification. It does
//! not provide CLI, MCP, AuthZEN, COAZ, network, database, graph, or
//! customer-specific integration surfaces. Later crates may depend inward
//! on this kernel; this crate must not depend outward on those domains.

mod comparison;
mod error;
mod model;
mod redaction;
mod schema;
mod validation;
mod verdict;
mod version;

pub use comparison::{
    apply_derived_verdict, derive_verdict, validate_verdict_consistency, ComparisonResult,
    ExactOutcomeComparator, OutcomeComparator,
};

pub use error::EvidenceError;
pub use model::{
    AuthorizationContext, Decision, EvidenceArtifactRef, EvidenceTimestamps, ExpectedOutcome,
    HashRef, NormalizedOperation, ObservationSource, ObservedOutcome, Precondition, SchemaRef,
    SecurityEvidence, SeverityAssessment, SeverityLevel, StandardMapping, TargetRef, VectorRef,
};
pub use redaction::{
    validate_redaction_metadata, validate_secret_safety, RedactionMetadata, RedactionStrategy,
};
pub use schema::{
    evidence_schema_v1, evidence_schema_v1_path, validate_instance, EVIDENCE_SCHEMA_V1_ID,
    EVIDENCE_SCHEMA_V1_JSON,
};
pub use validation::{validate, SUPPORTED_SCHEMA_MAJOR};
pub use verdict::Verdict;
pub use version::{SchemaVersion, VersionParseError};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-security-evidence";

#[cfg(test)]
mod tests {
    #[test]
    fn evidence_crate_is_an_isolated_library() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
        assert!(env!("CARGO_MANIFEST_DIR").ends_with("dare-security-evidence"));
    }
}
