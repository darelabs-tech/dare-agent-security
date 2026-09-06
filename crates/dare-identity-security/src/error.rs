//! Fail-closed error vocabulary for the identity-security engine.
//!
//! Every variant is a refusal or a bounded failure. No variant degrades an
//! unsupported input into a passing result, and no refusal is convertible into
//! `Verdict::Fail`: refusing to run is not evidence that an authority boundary
//! was crossed.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentitySecurityError {
    /// Input parsed but violates a Cycle 015 contract.
    #[error("invalid identity-security input: {0}")]
    Invalid(String),
    /// Input is structurally rejected by a versioned JSON Schema.
    #[error("schema validation failed: {0}")]
    Schema(String),
    /// The engine refuses to proceed for a safety reason.
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    /// A hard trial/principal/delegation/operation/output bound was reached.
    /// Bounds never grow to accommodate the work in front of them.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    /// Canonical binding between scenario, principal set, delegation chain,
    /// authority, resource context, policy, decision, operation or corpus did
    /// not verify.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    /// A reference names something the scenario never declared. Unknown
    /// principals and unknown delegation edges fail closed here rather than
    /// being treated as absent.
    #[error("unresolved reference: {0}")]
    UnknownReference(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl IdentitySecurityError {
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

pub type Result<T> = std::result::Result<T, IdentitySecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_distinguishable_from_invalid_input() {
        assert!(IdentitySecurityError::refusal("no").is_refusal());
        assert!(IdentitySecurityError::DigestMismatch("no".to_owned()).is_refusal());
        assert!(IdentitySecurityError::BudgetExhausted("no".to_owned()).is_refusal());
        assert!(IdentitySecurityError::unknown_reference("no").is_refusal());
        assert!(!IdentitySecurityError::invalid("no").is_refusal());
        assert!(!IdentitySecurityError::schema("no").is_refusal());
    }

    #[test]
    fn error_messages_never_read_as_a_security_verdict() {
        // A refusal is not a finding. If an error string could be mistaken for
        // a verdict token, a log reader could read "refused to run" as "the
        // boundary held" or as "the boundary broke", and both are wrong.
        for error in [
            IdentitySecurityError::refusal("live identity provider execution refused"),
            IdentitySecurityError::invalid("unknown field"),
            IdentitySecurityError::DigestMismatch("principal set substituted".to_owned()),
            IdentitySecurityError::unknown_reference("delegation edge names an unknown principal"),
        ] {
            let text = error.to_string();
            for token in ["PASS", "FAIL", "INCONCLUSIVE"] {
                assert!(!text.contains(token), "{text} contains {token}");
            }
        }
    }

    #[test]
    fn an_unknown_reference_is_a_refusal_not_an_absence() {
        // An edge naming a principal nobody declared is not an edge with a
        // missing field; it is a chain that cannot be evaluated at all. Treating
        // it as absent would silently shorten the chain being validated.
        let error = IdentitySecurityError::unknown_reference(
            "delegation edge references principal `ghost` which the principal set does not declare",
        );
        assert!(error.is_refusal());
        assert!(error.to_string().contains("unresolved reference"));
    }
}
