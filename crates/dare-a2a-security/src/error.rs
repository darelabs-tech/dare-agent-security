//! Errors, and the one thing they must never be mistaken for.
//!
//! A refusal is a statement about a *document*: it was too large, it carried a
//! field this engine will not read, it named a security scheme nobody
//! allowlisted. It is never a statement about the security of the peer the
//! document describes.
//!
//! That distinction matters because both end up in the same place — an
//! operator's terminal — and a refusal that reads like a verdict is a verdict
//! nobody computed. `no_error_message_reads_as_a_verdict` holds the line.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, A2aSecurityError>;

#[derive(Debug, Error)]
pub enum A2aSecurityError {
    /// The document is structurally wrong.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// The document failed a schema or version check.
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

impl A2aSecurityError {
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

impl From<std::io::Error> for A2aSecurityError {
    fn from(value: std::io::Error) -> Self {
        // The `kind` rather than the message: an OS error string can carry a
        // filesystem path the operator did not choose to print.
        Self::Io(value.kind().to_string())
    }
}

impl From<serde_json::Error> for A2aSecurityError {
    fn from(value: serde_json::Error) -> Self {
        // Deliberately not the serde message verbatim. Serde's `Display`
        // embeds the offending input, and a document that smuggled a credential
        // into a field would have it quoted back into an error log — storing
        // the thing the parser declined to store.
        Self::Schema(format!(
            "the document could not be decoded at line {}, column {}",
            value.line(),
            value.column()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_error_message_reads_as_a_verdict() {
        // A refusal and a verdict end up in the same terminal. One of them was
        // computed from evidence and the other was not.
        let errors = [
            A2aSecurityError::invalid("a card names no provider"),
            A2aSecurityError::schema("version 0.9 is not supported"),
            A2aSecurityError::refusal("a credential-shaped field was refused"),
            A2aSecurityError::BudgetExhausted("too many exchanges".to_owned()),
            A2aSecurityError::BindingMismatch("the task id changed".to_owned()),
            A2aSecurityError::Io("NotFound".to_owned()),
            A2aSecurityError::Serialization { kind: "result" },
        ];

        for error in errors {
            let text = error.to_string().to_uppercase();
            // Whole-word comparison. `SECURE` inside
            // `INSECURE_INTER_AGENT_COMMUNICATION` cost Cycle 013 a red build,
            // and `FAIL` inside `failed` would cost this one.
            let words: Vec<&str> = text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect();
            for verdict in ["PASS", "FAIL", "SECURE", "INSECURE", "VULNERABLE"] {
                assert!(
                    !words.contains(&verdict),
                    "`{text}` reads as the verdict {verdict}"
                );
            }
        }
    }

    #[test]
    fn a_serde_error_does_not_echo_the_document() {
        // The document is the attacker-controlled surface. Serde's own message
        // quotes it, so it is replaced with a position.
        let error: A2aSecurityError =
            serde_json::from_str::<serde_json::Value>("{\"api_key\": \"not-a-real-secret-value\"")
                .expect_err("malformed")
                .into();
        let message = error.to_string();
        assert!(!message.contains("not-a-real-secret-value"));
        assert!(message.contains("line"));
    }

    #[test]
    fn an_io_error_does_not_echo_a_filesystem_path() {
        let error: A2aSecurityError = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/home/operator/secret/card.json",
        )
        .into();
        assert!(!error.to_string().contains("/home/operator"));
    }

    #[test]
    fn a_refusal_is_distinguishable_from_a_failure() {
        assert!(A2aSecurityError::refusal("x").is_refusal());
        assert!(A2aSecurityError::schema("x").is_refusal());
        assert!(!A2aSecurityError::invalid("x").is_refusal());
        assert!(!A2aSecurityError::BudgetExhausted("x".to_owned()).is_refusal());
    }
}
