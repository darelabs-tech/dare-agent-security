//! Typed errors for the Cycle 001 evidence bridge.
//!
//! Display interpolates stable kind codes only. Rejected payloads and raw
//! secrets are never stored on this type.

use std::fmt;

/// Failure while converting a vector result into evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceBridgeError {
    /// Timestamp ordering violates `started_at <= observed_at <= recorded_at`.
    InvalidTimestamps,
    /// Cycle 001 structural or semantic validation rejected the record.
    Validation {
        /// Stable failure kind (`semantic`, `structural`, `verdict`, `redaction`).
        kind: String,
    },
    /// Serialization of a constructed record failed.
    Serialization,
    /// Result digest computation failed.
    ResultDigest,
}

impl EvidenceBridgeError {
    pub(super) fn from_evidence(err: &dare_security_evidence::EvidenceError) -> Self {
        let kind = match err {
            dare_security_evidence::EvidenceError::UnsupportedSchemaVersion { .. } => {
                "unsupported-schema"
            }
            dare_security_evidence::EvidenceError::StructuralValidation { .. } => "structural",
            dare_security_evidence::EvidenceError::SemanticValidation { .. } => "semantic",
            dare_security_evidence::EvidenceError::VerdictConsistency { .. } => "verdict",
            dare_security_evidence::EvidenceError::RedactionViolation { .. } => "redaction",
            dare_security_evidence::EvidenceError::Serialization { .. } => "serialization",
        };
        Self::Validation {
            kind: kind.to_owned(),
        }
    }
}

impl fmt::Display for EvidenceBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimestamps => {
                write!(
                    f,
                    "evidence timestamps must satisfy started_at <= observed_at <= recorded_at"
                )
            }
            Self::Validation { kind } => {
                write!(
                    f,
                    "constructed evidence failed Cycle 001 validation ({kind})"
                )
            }
            Self::Serialization => write!(f, "evidence serialization error"),
            Self::ResultDigest => write!(f, "vector result digest computation failed"),
        }
    }
}

impl std::error::Error for EvidenceBridgeError {}
