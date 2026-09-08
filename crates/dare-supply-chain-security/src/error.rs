//! Errors, and the one thing they must never be mistaken for.
//!
//! A refusal is a statement about a *document*: it was too large, it carried a
//! field this engine will not read, it named a digest algorithm nobody
//! allowlisted. It is never a statement about the security of the system the
//! document describes.
//!
//! That distinction matters because both end up in the same place — an
//! operator's terminal — and a refusal that reads like a verdict is a verdict
//! nobody computed. `no_error_message_reads_as_a_verdict` holds the line.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SupplyChainError>;

#[derive(Debug, Error)]
pub enum SupplyChainError {
    /// The document is structurally wrong.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// The document failed a compiled schema.
    #[error("schema rejected the document: {0}")]
    Schema(String),

    /// The document carries something this engine will not read.
    ///
    /// Separate from `Invalid` because the two mean different things to an
    /// operator: one says "this document is malformed", the other says "this
    /// document is well-formed and I am declining to read part of it".
    #[error("refused: {0}")]
    Refusal(String),

    /// A hard bound was reached.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    /// Two pieces of evidence that must agree do not.
    #[error("binding mismatch: {0}")]
    BindingMismatch(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("serialization failed for {kind}")]
    Serialization { kind: &'static str },
}

impl SupplyChainError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    pub fn schema(reason: impl Into<String>) -> Self {
        Self::Schema(reason.into())
    }

    pub fn refusal(reason: impl Into<String>) -> Self {
        Self::Refusal(reason.into())
    }

    /// Whether this is a refusal rather than a failure.
    ///
    /// The CLI maps refusals to a usage exit code rather than a scanner-error
    /// one, because a refused document is not a broken engine.
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refusal(_) | Self::Schema(_))
    }
}

impl From<std::io::Error> for SupplyChainError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for SupplyChainError {
    fn from(value: serde_json::Error) -> Self {
        // Deliberately not the serde message verbatim. Serde's `Display`
        // embeds the offending input, and a document that smuggled a
        // credential into a field name would have it echoed into a log by the
        // very error refusing it.
        Self::Schema(format!(
            "the document could not be decoded into the expected shape (line {}, column {})",
            value.line(),
            value.column()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_never_a_security_verdict() {
        let error = SupplyChainError::refusal("the document declares an unsupported BOM version");
        let words: Vec<String> = error
            .to_string()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .map(str::to_uppercase)
            .collect();
        for verdict in ["PASS", "FAIL", "INCONCLUSIVE", "SECURE", "VULNERABLE"] {
            assert!(
                !words.iter().any(|word| word == verdict),
                "the refusal reads as {verdict}"
            );
        }
    }

    #[test]
    fn no_error_message_reads_as_a_verdict() {
        // Swept across every variant rather than sampled, because a new variant
        // is exactly where this would slip in.
        let errors = [
            SupplyChainError::invalid("a component declares no identity"),
            SupplyChainError::schema("a required field is absent"),
            SupplyChainError::refusal("a field carries an executable hook"),
            SupplyChainError::BudgetExhausted("component ceiling reached".to_owned()),
            SupplyChainError::BindingMismatch("subject digest differs".to_owned()),
            SupplyChainError::Io("no such file".to_owned()),
            SupplyChainError::Serialization { kind: "result" },
        ];
        for error in errors {
            // Whole words, not substrings. `serialization failed` contains
            // "FAIL", and a substring check would have failed this test for a
            // message that reads as nothing of the kind — the same false
            // positive that cost Cycle 013 a red build when `SECURE` matched
            // inside `INSECURE_INTER_AGENT_COMMUNICATION`.
            let words: Vec<String> = error
                .to_string()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .map(str::to_uppercase)
                .collect();
            for verdict in [
                "PASS",
                "FAIL",
                "INCONCLUSIVE",
                "SECURE",
                "INSECURE",
                "VULNERABLE",
            ] {
                assert!(
                    !words.iter().any(|word| word == verdict),
                    "`{error}` reads as {verdict}"
                );
            }
        }
    }

    #[test]
    fn a_decode_failure_reports_a_position_and_never_the_value() {
        // Serde's Display embeds the offending input. A document smuggling a
        // credential into a field name would otherwise have it echoed into a
        // log by the error that refused it.
        let err: SupplyChainError =
            serde_json::from_str::<crate::source::ComponentType>("\"sk-live-000000000000\"")
                .expect_err("must fail")
                .into();
        let message = err.to_string();
        assert!(!message.contains("sk-live-"));
        assert!(message.contains("line") && message.contains("column"));
    }

    #[test]
    fn refusals_and_failures_are_distinguishable() {
        assert!(SupplyChainError::refusal("x").is_refusal());
        assert!(SupplyChainError::schema("x").is_refusal());
        assert!(!SupplyChainError::invalid("x").is_refusal());
        assert!(!SupplyChainError::Io("x".to_owned()).is_refusal());
    }
}
