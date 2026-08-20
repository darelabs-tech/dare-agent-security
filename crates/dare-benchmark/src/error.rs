//! Benchmark errors. Messages must not include secrets.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("schema validation failed at {path}: {reason}")]
    Schema { path: String, reason: String },
    #[error("invalid benchmark state: {0}")]
    InvalidState(String),
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    #[error("I/O error at {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("serialization error ({kind})")]
    Serialization { kind: &'static str },
}

fn compact(msg: &str) -> String {
    msg.chars().take(240).collect()
}

impl BenchmarkError {
    pub fn schema(path: impl Into<String>, reason: impl AsRef<str>) -> Self {
        Self::Schema {
            path: path.into(),
            reason: compact(reason.as_ref()),
        }
    }
}
