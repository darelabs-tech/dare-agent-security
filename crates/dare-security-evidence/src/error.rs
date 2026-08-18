//! Typed errors for evidence validation and serialization.
//!
//! Display output is secret-safe: rejected values are never interpolated.

use std::fmt;

use crate::version::SchemaVersion;

/// Top-level evidence kernel error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// Schema major version is not supported. Fail closed.
    UnsupportedSchemaVersion {
        /// Parsed version when available.
        found: Option<SchemaVersion>,
        /// Raw version string when parsing failed or for display of the major only.
        found_major: u64,
        /// Currently supported major version.
        supported_major: u64,
    },
    /// JSON Schema structural validation failed.
    StructuralValidation {
        /// JSON Pointer-like path, never a rejected payload.
        path: String,
        /// Validator keyword or reason code.
        reason: String,
    },
    /// Semantic invariant failed.
    SemanticValidation {
        /// Field or invariant identifier.
        invariant: String,
        /// Human-readable explanation without user payloads.
        message: String,
    },
    /// Verdict is inconsistent with expected/observed outcomes.
    VerdictConsistency {
        /// Short reason code.
        reason: String,
    },
    /// Redaction metadata or secret-safety rule was violated.
    RedactionViolation {
        /// Location of the violation (field path or map name), never the secret.
        location: String,
        /// Reason code.
        reason: String,
    },
    /// Serialization/deserialization failed without echoing payloads.
    Serialization {
        /// Stable kind (`json`, `utf8`, ...).
        kind: String,
    },
}

impl EvidenceError {
    pub(crate) fn semantic(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self::SemanticValidation {
            invariant: invariant.into(),
            message: message.into(),
        }
    }

    pub(crate) fn redaction(location: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::RedactionViolation {
            location: location.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion {
                found_major,
                supported_major,
                ..
            } => write!(
                f,
                "unsupported schema major version {found_major}; supported major is {supported_major}"
            ),
            Self::StructuralValidation { path, reason } => {
                write!(f, "structural validation failed at {path}: {reason}")
            }
            Self::SemanticValidation {
                invariant,
                message,
            } => write!(f, "semantic validation failed ({invariant}): {message}"),
            Self::VerdictConsistency { reason } => {
                write!(f, "verdict consistency failed: {reason}")
            }
            Self::RedactionViolation { location, reason } => {
                write!(f, "redaction violation at {location}: {reason}")
            }
            Self::Serialization { kind } => write!(f, "serialization error ({kind})"),
        }
    }
}

impl std::error::Error for EvidenceError {}
