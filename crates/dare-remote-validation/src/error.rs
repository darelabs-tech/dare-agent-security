//! Errors.
//!
//! No message carries an input value, a credential, a header or a response
//! body. Messages name fields, rules and code points only, so an error can be
//! printed, logged or written to an artifact without leaking what caused it.

use dare_adversarial::KillTrigger;
use thiserror::Error;

use crate::outcome::TransportOutcome;

pub type Result<T> = std::result::Result<T, RemoteError>;

/// Which authorization rule refused the run (BLUEPRINT §4.5, rules 1–16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationRefusal {
    Version,
    SignatureNotSupported,
    ProductionRefused,
    Origin,
    ScopeEnvironment,
    AddressNotPermitted,
    Window,
    Prohibitions,
    DataClass,
    ProtocolScope,
    Limits,
    DigestMismatch,
    PlanOutsideScope,
    ScenarioNotGranted,
    ConfirmationMismatch,
    CredentialMissing,
}

impl AuthorizationRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Version => "schema version is not supported",
            Self::SignatureNotSupported => "signature is reserved and must be absent in v1",
            Self::ProductionRefused => "production targets are refused in v1",
            Self::Origin => "an origin is malformed, duplicated or out of range",
            Self::ScopeEnvironment => "network scope and environment disagree",
            Self::AddressNotPermitted => "an origin address is not permitted in this scope",
            Self::Window => "the authorization window is invalid or not current",
            Self::Prohibitions => "a mandatory prohibition is missing",
            Self::DataClass => "data classes are empty or outside SYNTHETIC/CANARY/TEST",
            Self::ProtocolScope => "a protocol lacks its endpoint or a method lacks its protocol",
            Self::Limits => "a limit is zero or above its hard maximum",
            Self::DigestMismatch => "the plan does not pin this authorization's digest",
            Self::PlanOutsideScope => "the plan's origin, protocol or methods are not granted",
            Self::ScenarioNotGranted => "a planned scenario is not granted with this digest",
            Self::ConfirmationMismatch => "--confirm-origin does not equal the planned origin",
            Self::CredentialMissing => {
                "the referenced credential variable is not set or out of range"
            }
        }
    }
}

impl std::fmt::Display for AuthorizationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the gateway refused to send a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    MethodNotPlanned,
    PathNotAuthorized,
    RequestTooLarge,
    AddressNotPermitted,
    Resolution,
}

impl std::fmt::Display for EgressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MethodNotPlanned => "method is not in the plan",
            Self::PathNotAuthorized => "path is not an authorized endpoint",
            Self::RequestTooLarge => "request body exceeds the limit",
            Self::AddressNotPermitted => "a resolved address is not permitted",
            Self::Resolution => "the host did not resolve",
        })
    }
}

#[derive(Debug, Error)]
pub enum RemoteError {
    // Refusals: exit 3, before any egress.
    #[error("document refused: {0}")]
    Refused(&'static str),
    #[error("schema violation at {pointer}")]
    Schema { pointer: String },
    #[error("authorization refused: {0}")]
    Authorization(AuthorizationRefusal),
    #[error("bound {name} raised above the hard maximum")]
    BoundRaised { name: &'static str },
    #[error("bound {name} is zero")]
    BoundZero { name: &'static str },
    #[error("forbidden character U+{codepoint:04X} in {field}")]
    ForbiddenCharacter { field: &'static str, codepoint: u32 },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },

    // Run-time stops: reported through the result, never as a verdict.
    #[error("egress refused: {0}")]
    Egress(EgressRefusal),
    #[error("transport: {0}")]
    Transport(TransportOutcome),
    #[error("kill switch: {0:?}")]
    Killed(KillTrigger),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    #[error("capture tampered at entry {0}")]
    CaptureTampered(u32),
    #[error("output budget exceeded")]
    OutputBudgetExceeded,
    #[error("engine: {0}")]
    Engine(String),
    #[error("serialization failed for {0}")]
    Serialization(&'static str),
    #[error("io error: {0}")]
    Io(String),
}

impl RemoteError {
    /// True when the input was declined before any egress. A refusal writes
    /// nothing and exits 3; it is never a statement about the target.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::Refused(_)
                | Self::Schema { .. }
                | Self::Authorization(_)
                | Self::BoundRaised { .. }
                | Self::BoundZero { .. }
                | Self::ForbiddenCharacter { .. }
                | Self::InvalidIdentifier { .. }
        )
    }
}

impl From<std::io::Error> for RemoteError {
    fn from(error: std::io::Error) -> Self {
        // The kind only: an io::Error display can carry a path.
        Self::Io(error.kind().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<RemoteError> {
        vec![
            RemoteError::Refused("oversize"),
            RemoteError::Schema {
                pointer: "/origins/0".into(),
            },
            RemoteError::Authorization(AuthorizationRefusal::Window),
            RemoteError::BoundRaised { name: "max_rps" },
            RemoteError::BoundZero { name: "max_rps" },
            RemoteError::ForbiddenCharacter {
                field: "origin",
                codepoint: 0x202e,
            },
            RemoteError::InvalidIdentifier {
                field: "authorization_id",
            },
            RemoteError::Egress(EgressRefusal::PathNotAuthorized),
            RemoteError::Transport(TransportOutcome::Tls),
            RemoteError::Killed(KillTrigger::SecretDetected),
            RemoteError::BudgetExhausted("requests"),
            RemoteError::CaptureTampered(3),
            RemoteError::OutputBudgetExceeded,
            RemoteError::Engine("replay binding failed".into()),
            RemoteError::Serialization("capture"),
            RemoteError::Io("NotFound".into()),
        ]
    }

    #[test]
    fn refusals_are_exactly_the_pre_egress_variants() {
        let refusals: Vec<bool> = every_variant()
            .iter()
            .map(RemoteError::is_refusal)
            .collect();
        assert_eq!(
            refusals,
            [
                true, true, true, true, true, true, true, false, false, false, false, false, false,
                false, false, false
            ]
        );
    }

    #[test]
    fn no_error_message_carries_input_values() {
        // A credential, URL or body can never reach a message, because no
        // variant has a field that could hold one. The words a verdict would
        // use must not appear either: an error is never a verdict.
        for error in every_variant() {
            let message = error.to_string().to_ascii_lowercase();
            for leak in ["bearer ", "https://", "http://", "sk-", "password"] {
                assert!(!message.contains(leak), "{message}");
            }
            for verdict in ["pass", "fail", "secure", "vulnerable"] {
                assert!(
                    !message
                        .split(|c: char| !c.is_ascii_alphabetic())
                        .any(|w| w == verdict),
                    "{message}"
                );
            }
        }
    }

    #[test]
    fn every_authorization_refusal_has_its_own_message() {
        use AuthorizationRefusal::*;
        let all = [
            Version,
            SignatureNotSupported,
            ProductionRefused,
            Origin,
            ScopeEnvironment,
            AddressNotPermitted,
            Window,
            Prohibitions,
            DataClass,
            ProtocolScope,
            Limits,
            DigestMismatch,
            PlanOutsideScope,
            ScenarioNotGranted,
            ConfirmationMismatch,
            CredentialMissing,
        ];
        let messages: std::collections::BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(messages.len(), all.len());
    }

    #[test]
    fn io_errors_keep_only_their_kind() {
        let error: RemoteError =
            std::io::Error::new(std::io::ErrorKind::NotFound, "/secret/path").into();
        assert!(!error.to_string().contains("/secret/path"));
    }
}
