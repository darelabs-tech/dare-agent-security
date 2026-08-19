//! Operator-safe emit context for integrity evidence bridge input.

use time::OffsetDateTime;

/// Options controlling evidence emission from a validated [`VectorResult`](crate::VectorResult).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitOptions {
    /// Stable relative path to the serialized vector result artifact, when persisted.
    pub result_artifact_path: Option<String>,
    /// When evidence is recorded. Must be >= `VectorResult::finished_at`.
    pub recorded_at: OffsetDateTime,
}

impl EmitOptions {
    /// Builds emit options with a deterministic recorded timestamp one second after finish.
    #[must_use]
    pub fn deterministic_for_result(result: &crate::VectorResult) -> Self {
        Self {
            result_artifact_path: None,
            recorded_at: result.finished_at + time::Duration::seconds(1),
        }
    }

    /// Associates a stable artifact path with the emitted record.
    #[must_use]
    pub fn with_result_artifact_path(mut self, path: impl Into<String>) -> Self {
        self.result_artifact_path = Some(path.into());
        self
    }
}
