//! Errors, kept distinguishable from security verdicts.
//!
//! A refusal and a `FAIL` are different outcomes and must never be reported as
//! one another. A refusal says the engine would not evaluate the input — the
//! document was malformed, carried a credential, named a remote endpoint, or
//! asked for something outside the approved bounds. A `FAIL` says the engine
//! evaluated the input and the authorization boundary was violated.
//!
//! Collapsing the two in either direction is a real failure. Reporting a
//! refusal as `FAIL` would manufacture a finding about a scenario nobody
//! assessed; reporting a `FAIL` as a refusal would bury one.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, McpAuthSecurityError>;

#[derive(Debug, Error)]
pub enum McpAuthSecurityError {
    /// The document was structurally invalid.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// The document failed schema validation.
    #[error("schema violation: {0}")]
    Schema(String),

    /// The engine refused to proceed on safety grounds.
    ///
    /// Credentials, remote endpoints, executable fields, smuggled verdicts,
    /// hostile identifiers. Never a statement about the security of the
    /// scenario, because the scenario was never evaluated.
    #[error("refused: {0}")]
    Refusal(String),

    /// An approved bound was exceeded. Refused, never clamped upward.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    /// Two things that had to agree did not.
    #[error("binding mismatch: {0}")]
    DigestMismatch(String),

    /// The harness could not observe. Distinct from every security outcome.
    #[error("harness failure: {0}")]
    Harness(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl McpAuthSecurityError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    pub fn schema(reason: impl Into<String>) -> Self {
        Self::Schema(reason.into())
    }

    pub fn refusal(reason: impl Into<String>) -> Self {
        Self::Refusal(reason.into())
    }

    pub fn harness(reason: impl Into<String>) -> Self {
        Self::Harness(reason.into())
    }

    /// Whether this outcome is a refusal rather than a security finding.
    ///
    /// Callers use this to keep the two apart in exit codes and reports. A
    /// refusal writes no verdict artifact at all.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::Refusal(_) | Self::BudgetExhausted(_) | Self::DigestMismatch(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_never_a_security_verdict() {
        assert!(McpAuthSecurityError::refusal("x").is_refusal());
        assert!(McpAuthSecurityError::BudgetExhausted("x".into()).is_refusal());
        assert!(McpAuthSecurityError::DigestMismatch("x".into()).is_refusal());
        // A harness failure is an ERROR outcome, not a refusal: the engine did
        // try, and the run has something to report about why it could not.
        assert!(!McpAuthSecurityError::harness("x").is_refusal());
        assert!(!McpAuthSecurityError::invalid("x").is_refusal());
    }

    #[test]
    fn no_error_message_reads_as_a_verdict() {
        // An operator scanning stderr must not find a word that looks like a
        // result. A refusal that printed "FAIL" would be read as a finding
        // about a scenario that was never evaluated.
        let errors = [
            McpAuthSecurityError::invalid("bad reference"),
            McpAuthSecurityError::schema("unknown field"),
            McpAuthSecurityError::refusal("credential-shaped value"),
            McpAuthSecurityError::BudgetExhausted("too many trials".into()),
            McpAuthSecurityError::DigestMismatch("issuer moved".into()),
            McpAuthSecurityError::harness("adapter stopped"),
        ];
        for error in errors {
            let text = error.to_string();
            for verdict in ["PASS", "FAIL", "INCONCLUSIVE"] {
                assert!(
                    !text.contains(verdict),
                    "`{text}` reads as the verdict {verdict}"
                );
            }
        }
    }
}
