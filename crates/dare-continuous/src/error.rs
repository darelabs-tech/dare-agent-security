use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContinuousError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema validation failed at {path}: {message}")]
    Schema { path: String, message: String },
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    #[error("invalid continuous-validation input: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, ContinuousError>;
