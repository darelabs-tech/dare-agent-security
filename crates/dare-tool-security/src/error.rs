//! Fail-closed error vocabulary for the tool-security engine.
//!
//! Every variant is a refusal or a bounded failure. No variant degrades an
//! unsupported input into a passing result, and no refusal is convertible into
//! `Verdict::Fail`: refusing to run is not evidence that a tool invariant was
//! violated.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolSecurityError {
    /// Input parsed but violates a Cycle 014 contract.
    #[error("invalid tool-security input: {0}")]
    Invalid(String),
    /// Input is structurally rejected by a versioned JSON Schema.
    #[error("schema validation failed: {0}")]
    Schema(String),
    /// The engine refuses to proceed for a safety reason.
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    /// A hard trial/request/chain/output bound was reached. Bounds never grow.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    /// Identity binding between scenario, corpus, objective, policy or tool
    /// surface did not verify.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ToolSecurityError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn schema(message: impl Into<String>) -> Self {
        Self::Schema(message.into())
    }

    pub fn refusal(message: impl Into<String>) -> Self {
        Self::SafetyRefusal(message.into())
    }

    /// True when the condition is a refusal rather than an evaluable outcome.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::SafetyRefusal(_) | Self::DigestMismatch(_) | Self::BudgetExhausted(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, ToolSecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_distinguishable_from_invalid_input() {
        assert!(ToolSecurityError::refusal("no").is_refusal());
        assert!(ToolSecurityError::DigestMismatch("no".to_owned()).is_refusal());
        assert!(ToolSecurityError::BudgetExhausted("no".to_owned()).is_refusal());
        assert!(!ToolSecurityError::invalid("no").is_refusal());
        assert!(!ToolSecurityError::schema("no").is_refusal());
    }

    #[test]
    fn error_messages_never_read_as_a_security_verdict() {
        for error in [
            ToolSecurityError::refusal("live tool execution refused"),
            ToolSecurityError::invalid("unknown field"),
            ToolSecurityError::DigestMismatch("tool surface substituted".to_owned()),
        ] {
            let text = error.to_string();
            assert!(!text.contains("FAIL"));
            assert!(!text.contains("PASS"));
        }
    }
}
