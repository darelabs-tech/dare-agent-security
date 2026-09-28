//! Transport outcomes and stop reasons (BLUEPRINT §4.10).
//!
//! The overlay that applies them to an engine verdict is implemented in
//! task-021; the vocabulary is defined here so every module shares it.

use serde::{Deserialize, Serialize};

/// What happened to one exchange at the transport level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportOutcome {
    ConnectTimeout,
    ReadTimeout,
    Tls,
    Connection,
    Oversize,
    RateLimited,
    ServerError,
    UnexpectedAuth,
    ProtocolViolation,
    NotFound,
}

impl TransportOutcome {
    pub const ALL: [TransportOutcome; 10] = [
        Self::ConnectTimeout,
        Self::ReadTimeout,
        Self::Tls,
        Self::Connection,
        Self::Oversize,
        Self::RateLimited,
        Self::ServerError,
        Self::UnexpectedAuth,
        Self::ProtocolViolation,
        Self::NotFound,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectTimeout => "CONNECT_TIMEOUT",
            Self::ReadTimeout => "READ_TIMEOUT",
            Self::Tls => "TLS",
            Self::Connection => "CONNECTION",
            Self::Oversize => "OVERSIZE",
            Self::RateLimited => "RATE_LIMITED",
            Self::ServerError => "SERVER_ERROR",
            Self::UnexpectedAuth => "UNEXPECTED_AUTH",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::NotFound => "NOT_FOUND",
        }
    }
}

impl std::fmt::Display for TransportOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopReason {
    Completed,
    FirstFail,
    BudgetExhausted,
    RateLimited,
    TransportError,
    KillSwitch,
    WindowExpired,
}
