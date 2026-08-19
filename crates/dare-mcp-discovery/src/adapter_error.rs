//! Typed adapter errors.
//!
//! Display and Debug expose stable kind codes only. URLs, headers, SDK
//! payloads, and credentials are never stored or interpolated.

use std::fmt;

use crate::policy::PolicyError;

/// Phase that exceeded a configured timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutPhase {
    /// Connect / handshake budget.
    Connect,
    /// Single request budget.
    Request,
    /// Overall operation budget.
    Overall,
}

impl TimeoutPhase {
    /// Machine-stable phase code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Request => "request",
            Self::Overall => "overall",
        }
    }
}

/// Errors from the version-aware MCP discovery adapter.
#[derive(Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// Passive policy refused the outbound method.
    Policy(PolicyError),
    /// Protocol revision is not one of the two supported profiles.
    UnsupportedRevision {
        /// Requested or negotiated revision date (`YYYY-MM-DD`).
        revision: String,
    },
    /// A configured timeout fired.
    Timeout {
        /// Which timeout fired.
        phase: TimeoutPhase,
    },
    /// Transport failed after authorization. `kind` is a stable code only.
    Transport {
        /// Stable failure kind, never a payload, URL, or secret.
        kind: String,
    },
    /// Target specification was invalid. `kind` is a stable code only.
    InvalidTarget {
        /// Stable failure kind, never the raw URL or argv payload.
        kind: String,
    },
    /// Serialized response exceeded `max_response_bytes`.
    ResponseLimit,
    /// TLS is required and the target was not an `https` URL.
    TlsRequired,
}

impl AdapterError {
    pub(crate) fn transport(kind: impl Into<String>) -> Self {
        Self::Transport { kind: kind.into() }
    }

    pub(crate) fn invalid_target(kind: impl Into<String>) -> Self {
        Self::InvalidTarget { kind: kind.into() }
    }

    pub(crate) fn unsupported_revision(revision: impl Into<String>) -> Self {
        Self::UnsupportedRevision {
            revision: revision.into(),
        }
    }

    /// Convert an untrusted SDK/transport message into a kind-only error.
    ///
    /// The raw text is discarded and never stored.
    pub(crate) fn from_untrusted_transport_message(kind: &'static str, raw: &str) -> Self {
        let _ = raw;
        Self::transport(kind)
    }
}

impl From<PolicyError> for AdapterError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl fmt::Debug for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(err) => f.debug_tuple("Policy").field(err).finish(),
            Self::UnsupportedRevision { revision } => f
                .debug_struct("UnsupportedRevision")
                .field("revision", revision)
                .finish(),
            Self::Timeout { phase } => f.debug_struct("Timeout").field("phase", phase).finish(),
            Self::Transport { kind } => f.debug_struct("Transport").field("kind", kind).finish(),
            Self::InvalidTarget { kind } => {
                f.debug_struct("InvalidTarget").field("kind", kind).finish()
            }
            Self::ResponseLimit => f.debug_tuple("ResponseLimit").finish(),
            Self::TlsRequired => f.debug_tuple("TlsRequired").finish(),
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = match self {
            Self::Policy(err) => err.to_string(),
            Self::UnsupportedRevision { revision } => {
                format!("unsupported MCP protocol revision `{revision}`")
            }
            Self::Timeout { phase } => format!("discovery timeout ({})", phase.as_str()),
            Self::Transport { kind } => format!("adapter transport error ({kind})"),
            Self::InvalidTarget { kind } => format!("invalid discovery target ({kind})"),
            Self::ResponseLimit => "discovery response exceeded configured byte limit".to_owned(),
            Self::TlsRequired => "TLS is required for HTTP discovery targets".to_owned(),
        };
        f.write_str(&crate::sanitize::redact_text(&raw))
    }
}

impl std::error::Error for AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

    #[test]
    fn untrusted_sdk_payloads_are_not_echoed() {
        let raw = format!("https://user:{PLANTED}@mcp.example.test/path?token={PLANTED}");
        let err = AdapterError::from_untrusted_transport_message("handshake", &raw);
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(PLANTED));
        assert!(!debug.contains(PLANTED));
        assert!(!display.contains("mcp.example.test"));
        assert_eq!(display, "adapter transport error (handshake)");
    }
}
