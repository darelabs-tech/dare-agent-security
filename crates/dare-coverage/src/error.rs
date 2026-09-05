//! Coverage engine errors. Messages must not include secrets.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("schema validation failed at {path}: {reason}")]
    Schema { path: String, reason: String },
    #[error("unknown property id: {0}")]
    UnknownProperty(String),
    #[error("unknown predicate: {0}")]
    UnknownPredicate(String),
    #[error("unknown profile id: {0}")]
    UnknownProfile(String),
    #[error("duplicate property id: {0}")]
    DuplicateProperty(String),
    #[error("invalid coverage state: {0}")]
    InvalidState(String),
    #[error("profile tamper or digest mismatch")]
    ProfileDigest,
    #[error("I/O error at {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("serialization error ({kind})")]
    Serialization { kind: &'static str },
}

fn compact(msg: &str) -> String {
    msg.chars().take(240).collect()
}

impl CoverageError {
    pub fn schema(path: impl Into<String>, reason: impl AsRef<str>) -> Self {
        Self::Schema {
            path: path.into(),
            reason: compact(reason.as_ref()),
        }
    }
}
