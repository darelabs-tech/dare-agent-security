//! Errors, and the distinction between refusing and finding.
//!
//! These are two different things and the codebase keeps them apart everywhere.
//!
//! A **refusal** means the engine declined to proceed: a document was
//! over-bound, a fixture smuggled a credential, a reference pointed at nothing.
//! It says something about the input, not about the target's security. Refusing
//! to run a scenario is never evidence that a retrieval boundary was crossed.
//!
//! A **violation** is a security finding, and it lives in
//! [`crate::invariant::RagViolation`] — never here. No error message in this
//! module may read as `PASS`, `FAIL` or `INCONCLUSIVE`, and a test pins that,
//! because a refusal that renders like a verdict will eventually be counted as
//! one by something downstream.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RagSecurityError {
    /// The input is structurally wrong: an unresolvable reference, a
    /// contradiction between declared objects, a count that cannot be right.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// The document did not satisfy its schema or declared an unsupported
    /// version.
    #[error("schema validation failed: {0}")]
    Schema(String),

    /// The engine declined to proceed on safety grounds: hostile fields,
    /// credential-shaped values, remote targets, a request past a hard bound.
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),

    /// A canonical digest did not match the approved binding.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),

    /// A bound was reached during a run.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    /// A reference named something no declared object provides.
    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl RagSecurityError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    pub fn schema(reason: impl Into<String>) -> Self {
        Self::Schema(reason.into())
    }

    pub fn refusal(reason: impl Into<String>) -> Self {
        Self::SafetyRefusal(reason.into())
    }

    pub fn unknown_reference(reason: impl Into<String>) -> Self {
        Self::UnknownReference(reason.into())
    }

    /// True when the engine declined to proceed rather than finding something.
    ///
    /// Callers use this to choose an exit code and a message. A refusal is a
    /// usage or safety outcome; it is deliberately not folded in with a
    /// security verdict.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::SafetyRefusal(_)
                | Self::DigestMismatch(_)
                | Self::BudgetExhausted(_)
                | Self::UnknownReference(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, RagSecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_distinguishable_from_invalid_input() {
        assert!(RagSecurityError::refusal("no").is_refusal());
        assert!(RagSecurityError::DigestMismatch("no".to_owned()).is_refusal());
        assert!(RagSecurityError::BudgetExhausted("no".to_owned()).is_refusal());
        assert!(RagSecurityError::unknown_reference("no").is_refusal());

        assert!(!RagSecurityError::invalid("no").is_refusal());
        assert!(!RagSecurityError::schema("no").is_refusal());
    }

    #[test]
    fn no_error_message_reads_as_a_security_verdict() {
        // A refusal rendered as PASS or FAIL would eventually be filed as one.
        let errors = [
            RagSecurityError::invalid("a document reference resolves to nothing"),
            RagSecurityError::schema("the trace declares an unsupported version"),
            RagSecurityError::refusal("the fixture carries an executable field"),
            RagSecurityError::DigestMismatch("the policy does not match its binding".to_owned()),
            RagSecurityError::BudgetExhausted("the query bound was reached".to_owned()),
            RagSecurityError::unknown_reference("chunk names an undeclared document"),
        ];
        for error in errors {
            let text = error.to_string();
            for banned in ["PASS", "FAIL", "INCONCLUSIVE", "Verdict"] {
                assert!(!text.contains(banned), "`{text}` reads as a verdict");
            }
        }
    }

    #[test]
    fn a_refusal_says_what_it_refused_without_repeating_it() {
        // The message names the category, so an operator can act on it, and not
        // the value, so an artifact does not become a copy of the thing that was
        // refused. The value-level check lives in the hostile-fixture suite.
        let error = RagSecurityError::refusal("the fixture carries a credential-shaped value");
        let text = error.to_string();
        assert!(text.contains("credential-shaped"));
        assert!(!text.contains("sk-live-"));
    }
}
