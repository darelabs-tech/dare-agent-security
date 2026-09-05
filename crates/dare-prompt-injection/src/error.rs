//! Fail-closed error vocabulary for the prompt-injection engine.
//!
//! Every variant is a refusal or a bounded failure. There is no variant that
//! degrades an unsupported input into a passing result.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PromptInjectionError {
    /// Input parsed but violates a Cycle 013 contract.
    #[error("invalid prompt-injection input: {0}")]
    Invalid(String),
    /// Input is structurally rejected by a versioned JSON Schema.
    #[error("schema validation failed: {0}")]
    Schema(String),
    /// The engine refuses to proceed for a safety reason (never a FAIL verdict).
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    /// A hard trial/output/time bound was reached. Execution stops; bounds never grow.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    /// Identity binding between scenario, corpus or objective did not verify.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl PromptInjectionError {
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
    ///
    /// Callers must not translate a refusal into `Verdict::Fail`: refusing to run
    /// is not evidence that a security invariant was violated.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::SafetyRefusal(_) | Self::DigestMismatch(_) | Self::BudgetExhausted(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, PromptInjectionError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_distinguishable_from_invalid_input() {
        assert!(PromptInjectionError::refusal("no").is_refusal());
        assert!(PromptInjectionError::DigestMismatch("no".to_owned()).is_refusal());
        assert!(PromptInjectionError::BudgetExhausted("no".to_owned()).is_refusal());
        assert!(!PromptInjectionError::invalid("no").is_refusal());
        assert!(!PromptInjectionError::schema("no").is_refusal());
    }

    #[test]
    fn error_messages_do_not_leak_a_verdict_token() {
        // A refusal must never read as a security verdict.
        for error in [
            PromptInjectionError::refusal("remote target refused"),
            PromptInjectionError::invalid("unknown field"),
        ] {
            let text = error.to_string();
            assert!(!text.contains("FAIL"));
            assert!(!text.contains("PASS"));
        }
    }
}
