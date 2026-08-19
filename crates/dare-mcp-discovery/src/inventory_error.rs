//! Typed errors for discovery inventory validation and serialization.
//!
//! Display output is secret-safe: rejected values are never interpolated.

use std::fmt;

use crate::inventory_version::InventorySchemaVersion;

/// Top-level discovery inventory error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    /// Schema major version is not supported. Fail closed.
    UnsupportedSchemaVersion {
        /// Parsed version when available.
        found: Option<InventorySchemaVersion>,
        /// Major component that was rejected.
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
    /// Serialization/deserialization failed without echoing payloads.
    Serialization {
        /// Stable kind (`json`, `schema-json`, ...).
        kind: String,
    },
}

impl InventoryError {
    pub(crate) fn semantic(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self::SemanticValidation {
            invariant: invariant.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for InventoryError {
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
            Self::Serialization { kind } => write!(f, "serialization error ({kind})"),
        }
    }
}

impl std::error::Error for InventoryError {}
