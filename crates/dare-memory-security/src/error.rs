//! Fail-closed error vocabulary for the memory-security engine.
//!
//! Every variant is a refusal or a bounded failure. No variant degrades an
//! unsupported input into a passing result, and no refusal is convertible into
//! `Verdict::Fail`: refusing to run is not evidence that memory was poisoned.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemorySecurityError {
    /// Input parsed but violates a Cycle 016 contract.
    #[error("invalid memory-security input: {0}")]
    Invalid(String),
    /// Input is structurally rejected by a versioned JSON Schema.
    #[error("schema validation failed: {0}")]
    Schema(String),
    /// The engine refuses to proceed for a safety reason.
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    /// A hard item/event/recall/trial/output bound was reached. Bounds never
    /// grow to accommodate the work in front of them.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    /// Canonical binding between store, item, policy, provenance, recall or
    /// corpus did not verify.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    /// A reference names something the scenario never declared. Unknown memory
    /// items, namespaces and principals fail closed here rather than being
    /// treated as absent.
    #[error("unresolved reference: {0}")]
    UnknownReference(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl MemorySecurityError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn schema(message: impl Into<String>) -> Self {
        Self::Schema(message.into())
    }

    pub fn refusal(message: impl Into<String>) -> Self {
        Self::SafetyRefusal(message.into())
    }

    pub fn unknown_reference(message: impl Into<String>) -> Self {
        Self::UnknownReference(message.into())
    }

    /// True when the condition is a refusal rather than an evaluable outcome.
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

pub type Result<T> = std::result::Result<T, MemorySecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_distinguishable_from_invalid_input() {
        assert!(MemorySecurityError::refusal("no").is_refusal());
        assert!(MemorySecurityError::DigestMismatch("no".to_owned()).is_refusal());
        assert!(MemorySecurityError::BudgetExhausted("no".to_owned()).is_refusal());
        assert!(MemorySecurityError::unknown_reference("no").is_refusal());

        assert!(!MemorySecurityError::invalid("no").is_refusal());
        assert!(!MemorySecurityError::schema("no").is_refusal());
    }

    #[test]
    fn no_error_message_reads_as_a_security_verdict() {
        // Refusing to run says nothing about whether memory was poisoned, so no
        // error may render as PASS, FAIL or INCONCLUSIVE.
        let errors = [
            MemorySecurityError::invalid("bad item"),
            MemorySecurityError::schema("bad shape"),
            MemorySecurityError::refusal("hostile field"),
            MemorySecurityError::BudgetExhausted("too many items".to_owned()),
            MemorySecurityError::DigestMismatch("store moved".to_owned()),
            MemorySecurityError::unknown_reference("no such namespace"),
        ];
        for error in errors {
            let text = error.to_string();
            for banned in ["PASS", "FAIL", "INCONCLUSIVE", "Verdict"] {
                assert!(!text.contains(banned), "`{banned}` in `{text}`");
            }
        }
    }

    #[test]
    fn io_and_json_failures_are_not_refusals() {
        // A missing file is an environment problem, not a security finding.
        let io = MemorySecurityError::Io(std::io::Error::other("gone"));
        assert!(!io.is_refusal());

        let json = MemorySecurityError::Json(
            serde_json::from_str::<serde_json::Value>("{").expect_err("invalid json"),
        );
        assert!(!json.is_refusal());
    }
}
