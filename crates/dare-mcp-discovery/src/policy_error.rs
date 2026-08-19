//! Typed policy refusal errors.
//!
//! Display and Debug expose method metadata and a reason code only. Arguments,
//! headers, URLs, and secrets must never be stored on these types.

use std::fmt;

/// Stable reason code for an allowlist miss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// The JSON-RPC method name was empty.
    EmptyMethod,
    /// The method is not on the active profile allowlist.
    MethodNotAllowlisted,
}

impl RefusalReason {
    /// Machine-stable reason code (never a payload).
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::EmptyMethod => "EMPTY_METHOD",
            Self::MethodNotAllowlisted => "METHOD_NOT_ALLOWLISTED",
        }
    }
}

/// Allowlist refusal for a single outbound MCP method.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    method: String,
    reason: RefusalReason,
}

impl PolicyRefusal {
    pub(super) fn new(method: impl Into<String>, reason: RefusalReason) -> Self {
        Self {
            method: method.into(),
            reason,
        }
    }

    /// JSON-RPC method that was refused.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Reason code for the refusal.
    pub fn reason(&self) -> RefusalReason {
        self.reason
    }
}

impl fmt::Debug for PolicyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyRefusal")
            .field("method", &self.method)
            .field("reason", &self.reason.as_code())
            .finish()
    }
}

impl fmt::Display for PolicyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "passive policy refused method `{}` (reason: {})",
            self.method,
            self.reason.as_code()
        )
    }
}

impl std::error::Error for PolicyRefusal {}

/// Error returned by policy-gated outbound dispatch.
#[derive(Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The method was not authorized.
    Refused(PolicyRefusal),
    /// Transport failed after authorization. `kind` is a stable code only.
    Transport {
        /// Stable failure kind, never a payload, URL, or secret.
        kind: String,
    },
}

impl PolicyError {
    /// Transport failure with a stable kind code.
    pub fn transport(kind: impl Into<String>) -> Self {
        Self::Transport { kind: kind.into() }
    }
}

impl From<PolicyRefusal> for PolicyError {
    fn from(value: PolicyRefusal) -> Self {
        Self::Refused(value)
    }
}

impl fmt::Debug for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => f.debug_tuple("Refused").field(refusal).finish(),
            Self::Transport { kind } => f.debug_struct("Transport").field("kind", kind).finish(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Transport { kind } => write!(f, "outbound transport error ({kind})"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Transport { .. } => None,
        }
    }
}
