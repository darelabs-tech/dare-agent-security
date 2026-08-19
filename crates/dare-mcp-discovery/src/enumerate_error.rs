//! Typed errors for bounded catalog enumeration.
//!
//! Display and Debug expose stable kind codes only. Cursors, URIs, payloads,
//! and secrets are never stored or interpolated.

use std::fmt;

use crate::adapter::{AdapterError, TimeoutPhase};
use crate::policy::{PolicyError, PolicyRefusal};

/// Catalog being enumerated when an error is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionKind {
    /// `tools/list`.
    Tools,
    /// `resources/list`.
    Resources,
    /// `resources/templates/list`.
    ResourceTemplates,
    /// `prompts/list`.
    Prompts,
}

impl CollectionKind {
    /// Wire JSON-RPC method used to page this collection.
    pub const fn method(self) -> &'static str {
        match self {
            Self::Tools => "tools/list",
            Self::Resources => "resources/list",
            Self::ResourceTemplates => "resources/templates/list",
            Self::Prompts => "prompts/list",
        }
    }

    /// Stable collection identity for warning messages.
    pub const fn as_str(self) -> &'static str {
        self.method()
    }
}

/// Errors from the bounded enumeration engine.
#[derive(Clone, PartialEq, Eq)]
pub enum EnumerateError {
    /// Passive policy refused the outbound list method.
    Policy(PolicyError),
    /// Adapter/transport failure after authorization. `kind` is a stable code.
    Adapter(AdapterError),
    /// A configured timeout fired.
    Timeout {
        /// Which timeout fired.
        phase: TimeoutPhase,
    },
    /// A page could not be interpreted as a catalog listing.
    MalformedPage {
        /// Collection that produced the malformed page.
        collection: CollectionKind,
    },
    /// Serialized page exceeded `max_response_bytes`.
    ResponseLimit,
    /// Bound configuration was invalid. `kind` is a stable code only.
    InvalidBounds {
        /// Stable failure kind, never a payload.
        kind: String,
    },
}

impl EnumerateError {
    pub(crate) fn invalid_bounds(kind: impl Into<String>) -> Self {
        Self::InvalidBounds { kind: kind.into() }
    }

    /// Construct a malformed-page error for `collection`.
    pub fn malformed_page(collection: CollectionKind) -> Self {
        Self::MalformedPage { collection }
    }
}

impl From<AdapterError> for EnumerateError {
    fn from(value: AdapterError) -> Self {
        match value {
            AdapterError::Policy(err) => Self::Policy(err),
            AdapterError::Timeout { phase } => Self::Timeout { phase },
            AdapterError::ResponseLimit => Self::ResponseLimit,
            other => Self::Adapter(other),
        }
    }
}

impl From<PolicyError> for EnumerateError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl From<PolicyRefusal> for EnumerateError {
    fn from(value: PolicyRefusal) -> Self {
        Self::Policy(PolicyError::from(value))
    }
}

impl fmt::Debug for EnumerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(err) => f.debug_tuple("Policy").field(err).finish(),
            Self::Adapter(err) => f.debug_tuple("Adapter").field(err).finish(),
            Self::Timeout { phase } => f.debug_struct("Timeout").field("phase", phase).finish(),
            Self::MalformedPage { collection } => f
                .debug_struct("MalformedPage")
                .field("collection", collection)
                .finish(),
            Self::ResponseLimit => f.debug_tuple("ResponseLimit").finish(),
            Self::InvalidBounds { kind } => {
                f.debug_struct("InvalidBounds").field("kind", kind).finish()
            }
        }
    }
}

impl fmt::Display for EnumerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(err) => write!(f, "{err}"),
            Self::Adapter(err) => write!(f, "{err}"),
            Self::Timeout { phase } => write!(f, "enumeration timeout ({})", phase.as_str()),
            Self::MalformedPage { collection } => {
                write!(f, "malformed catalog page ({})", collection.as_str())
            }
            Self::ResponseLimit => {
                write!(f, "enumeration response exceeded configured byte limit")
            }
            Self::InvalidBounds { kind } => write!(f, "invalid enumeration bounds ({kind})"),
        }
    }
}

impl std::error::Error for EnumerateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(err) => Some(err),
            Self::Adapter(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

    #[test]
    fn errors_do_not_echo_untrusted_payloads() {
        let err = EnumerateError::malformed_page(CollectionKind::Tools);
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(PLANTED));
        assert!(!debug.contains(PLANTED));
        assert_eq!(display, "malformed catalog page (tools/list)");
    }

    #[test]
    fn collection_methods_match_enumeration_allowlist() {
        assert_eq!(CollectionKind::Tools.method(), "tools/list");
        assert_eq!(CollectionKind::Resources.method(), "resources/list");
        assert_eq!(
            CollectionKind::ResourceTemplates.method(),
            "resources/templates/list"
        );
        assert_eq!(CollectionKind::Prompts.method(), "prompts/list");
    }
}
