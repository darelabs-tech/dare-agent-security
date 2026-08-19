//! Typed errors for COAZ integrity vector/result validation.
//!
//! Display output is secret-safe: rejected values are never interpolated.

use std::fmt;

use crate::version::SchemaVersion;

/// Top-level integrity contract error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// Schema major version is not supported. Fail closed.
    UnsupportedSchemaVersion {
        found: Option<SchemaVersion>,
        found_major: u64,
        supported_major: u64,
    },
    /// JSON Schema structural validation failed.
    StructuralValidation { path: String, reason: String },
    /// Semantic invariant failed.
    SemanticValidation { invariant: String, message: String },
    /// Verdict is inconsistent with expected/observed enforcement.
    VerdictConsistency { reason: String },
    /// Secret-safety or redaction rule was violated.
    SecretSafety { location: String, reason: String },
    /// Serialization/deserialization failed without echoing payloads.
    Serialization { kind: String },
}

impl IntegrityError {
    pub(crate) fn semantic(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self::SemanticValidation {
            invariant: invariant.into(),
            message: message.into(),
        }
    }

    pub(crate) fn secret(location: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SecretSafety {
            location: location.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for IntegrityError {
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
            Self::SecretSafety { location, reason } => {
                write!(f, "secret safety violation at {location}: {reason}")
            }
            Self::Serialization { kind } => write!(f, "serialization error ({kind})"),
        }
    }
}

impl std::error::Error for IntegrityError {}
