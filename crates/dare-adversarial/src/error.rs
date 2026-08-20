use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdversarialError {
    #[error("invalid adversarial input: {0}")]
    Invalid(String),
    #[error("safety refusal: {0}")]
    SafetyRefusal(String),
    #[error("execution budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("kill switch triggered: {0}")]
    KillTriggered(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema validation failed: {0}")]
    Schema(String),
}

pub type Result<T> = std::result::Result<T, AdversarialError>;
