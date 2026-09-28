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

use dare_security_evidence::Verdict;

/// Apply a transport outcome to an engine verdict (BLUEPRINT §4.10).
///
/// Never returns `Pass` when a transport outcome is present, and never lowers
/// a `Fail`: a violation the engine already established stands whatever the
/// transport did afterwards. A missing or broken exchange makes an otherwise
/// passing scenario inconclusive; a protocol violation or connection failure
/// is the harness's error.
pub fn overlay(engine: Verdict, transport: Option<TransportOutcome>) -> Verdict {
    let Some(outcome) = transport else {
        return engine;
    };
    match engine {
        Verdict::Fail => Verdict::Fail,
        Verdict::Error => Verdict::Error,
        Verdict::Pass | Verdict::Inconclusive => match outcome {
            TransportOutcome::ConnectTimeout
            | TransportOutcome::ReadTimeout
            | TransportOutcome::Tls
            | TransportOutcome::Connection
            | TransportOutcome::ProtocolViolation => Verdict::Error,
            TransportOutcome::Oversize
            | TransportOutcome::RateLimited
            | TransportOutcome::ServerError
            | TransportOutcome::UnexpectedAuth
            | TransportOutcome::NotFound => Verdict::Inconclusive,
        },
    }
}

/// The transport outcome of an HTTP status the engines cannot use.
///
/// `challenge_expected` is true for a step whose scenario observes the
/// target's authentication challenge (MCP auth discovery through
/// `WWW-Authenticate`): there a 401 or 403 is the observation, not a failure.
pub fn classify_status(status: u16, challenge_expected: bool) -> Option<TransportOutcome> {
    match status {
        200..=299 => None,
        401 | 403 if challenge_expected => None,
        401 | 403 => Some(TransportOutcome::UnexpectedAuth),
        404 => Some(TransportOutcome::NotFound),
        429 => Some(TransportOutcome::RateLimited),
        500..=599 => Some(TransportOutcome::ServerError),
        _ => Some(TransportOutcome::ProtocolViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERDICTS: [Verdict; 4] = [
        Verdict::Pass,
        Verdict::Fail,
        Verdict::Inconclusive,
        Verdict::Error,
    ];

    #[test]
    fn no_transport_outcome_can_produce_pass() {
        for outcome in TransportOutcome::ALL {
            for verdict in VERDICTS {
                assert_ne!(
                    overlay(verdict, Some(outcome)),
                    Verdict::Pass,
                    "{verdict:?} + {outcome:?}"
                );
            }
        }
    }

    #[test]
    fn a_fail_is_never_lowered() {
        for outcome in TransportOutcome::ALL {
            assert_eq!(overlay(Verdict::Fail, Some(outcome)), Verdict::Fail);
        }
    }

    #[test]
    fn without_a_transport_outcome_the_engine_verdict_stands() {
        for verdict in VERDICTS {
            assert_eq!(overlay(verdict, None), verdict);
        }
    }

    #[test]
    fn the_blueprint_table() {
        use TransportOutcome::*;
        for outcome in [
            ConnectTimeout,
            ReadTimeout,
            Tls,
            Connection,
            ProtocolViolation,
        ] {
            assert_eq!(
                overlay(Verdict::Pass, Some(outcome)),
                Verdict::Error,
                "{outcome:?}"
            );
        }
        for outcome in [Oversize, RateLimited, ServerError, UnexpectedAuth, NotFound] {
            assert_eq!(
                overlay(Verdict::Pass, Some(outcome)),
                Verdict::Inconclusive,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn statuses_map_to_outcomes() {
        assert_eq!(classify_status(200, false), None);
        assert_eq!(classify_status(204, false), None);
        assert_eq!(
            classify_status(401, false),
            Some(TransportOutcome::UnexpectedAuth)
        );
        assert_eq!(classify_status(401, true), None);
        assert_eq!(
            classify_status(403, false),
            Some(TransportOutcome::UnexpectedAuth)
        );
        assert_eq!(
            classify_status(404, false),
            Some(TransportOutcome::NotFound)
        );
        assert_eq!(
            classify_status(429, false),
            Some(TransportOutcome::RateLimited)
        );
        assert_eq!(
            classify_status(503, false),
            Some(TransportOutcome::ServerError)
        );
        assert_eq!(
            classify_status(302, false),
            Some(TransportOutcome::ProtocolViolation)
        );
    }
}
