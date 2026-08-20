//! Errors for scenario validation and lab framework operations.

use thiserror::Error;

/// Failures while loading, validating, or running lab fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LabError {
    #[error("structural validation failed at {path}: {reason}")]
    StructuralValidation { path: String, reason: String },

    #[error("semantic validation failed: {reason}")]
    SemanticValidation { reason: String },

    #[error("safety policy refused: {reason}")]
    SafetyPolicy { reason: String },

    #[error("failed to read scenario at {path}: {reason}")]
    Io { path: String, reason: String },

    #[error("serialization error: {kind}")]
    Serialization { kind: &'static str },
}
