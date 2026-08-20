use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("invalid graph input: {0}")]
    Invalid(String),
    #[error("graph traversal refused: {0}")]
    SafetyRefusal(String),
    #[error("graph I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("graph JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, GraphError>;
