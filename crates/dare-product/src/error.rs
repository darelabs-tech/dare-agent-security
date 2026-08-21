//! Categorized product errors for actionable CLI UX.

use std::fmt;

use thiserror::Error;

/// Stable error categories surfaced to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Configuration,
    UnsupportedTarget,
    BlockedAssessment,
    SecurityGateFailure,
    Environment,
    Internal,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::UnsupportedTarget => "unsupported_target",
            Self::BlockedAssessment => "blocked_assessment",
            Self::SecurityGateFailure => "security_gate_failure",
            Self::Environment => "environment",
            Self::Internal => "internal",
        }
    }

    /// Map category to product CLI exit code (see EXIT.md).
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Configuration | Self::UnsupportedTarget => 3,
            Self::BlockedAssessment | Self::SecurityGateFailure => 2,
            Self::Environment | Self::Internal => 1,
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum ProductError {
    #[error("[{category}] {message}")]
    Categorized {
        category: ErrorCategory,
        message: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
}

impl ProductError {
    pub fn categorized(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self::Categorized {
            category,
            message: message.into(),
        }
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::Configuration, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::UnsupportedTarget, message)
    }

    pub fn blocked(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::BlockedAssessment, message)
    }

    pub fn gate_failure(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::SecurityGateFailure, message)
    }

    pub fn environment(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::Environment, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::categorized(ErrorCategory::Internal, message)
    }

    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::Categorized { category, .. } => *category,
            Self::Io(_) => ErrorCategory::Environment,
            Self::Json(_) | Self::Yaml(_) => ErrorCategory::Configuration,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.category().exit_code()
    }

    /// Operator-facing message with category prefix (already redacted by callers).
    pub fn actionable_message(&self) -> String {
        match self {
            Self::Categorized { category, message } => {
                format!("[{}] {message}", category.as_str())
            }
            other => format!("[{}] {other}", other.category().as_str()),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProductError>;
