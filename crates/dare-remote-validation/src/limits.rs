//! Hard maxima and lower-only limits (BLUEPRINT §4.2).
//!
//! An authorization and a plan may each lower a limit, never raise one. A
//! missing value resolves to the hard maximum; zero is refused rather than
//! read as "disabled", because a zero budget that silently meant "unlimited"
//! would be the worst possible misreading.

use serde::{Deserialize, Serialize};

use crate::error::{RemoteError, Result};

pub const MAX_REQUESTS: u32 = 500;
/// Requests per second.
pub const MAX_RPS: u32 = 2;
pub const MAX_DURATION_S: u64 = 1_800;
pub const MAX_REQUEST_BYTES: u64 = 65_536;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
/// Longest authorization window, in seconds.
pub const MAX_WINDOW_S: i64 = 7 * 24 * 3_600;
pub const MAX_ORIGINS: usize = 4;
pub const MAX_SCENARIOS: usize = 32;
pub const CONNECT_TIMEOUT_MS: u64 = 5_000;
/// Per request, total.
pub const READ_TIMEOUT_MS: u64 = 15_000;
/// Authorization and plan documents.
pub const MAX_INPUT_BYTES: usize = 262_144;
pub const MAX_CAPTURE_BYTES: usize = 16 * 1_048_576;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1_048_576;

/// Optional limits as written in an authorization or a plan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_request_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
}

/// Limits after resolution: every field is set and within its ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveLimits {
    pub max_requests: u32,
    pub max_rps: u32,
    pub max_duration_s: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
}

impl EffectiveLimits {
    /// The hard maxima.
    pub const HARD: EffectiveLimits = EffectiveLimits {
        max_requests: MAX_REQUESTS,
        max_rps: MAX_RPS,
        max_duration_s: MAX_DURATION_S,
        max_request_bytes: MAX_REQUEST_BYTES,
        max_response_bytes: MAX_RESPONSE_BYTES,
    };
}

fn lower<T: Copy + PartialOrd + Default>(
    value: Option<T>,
    ceiling: T,
    name: &'static str,
) -> Result<T> {
    match value {
        None => Ok(ceiling),
        Some(v) if v == T::default() => Err(RemoteError::BoundZero { name }),
        Some(v) if v > ceiling => Err(RemoteError::BoundRaised { name }),
        Some(v) => Ok(v),
    }
}

impl Limits {
    /// Resolve against the hard maxima.
    pub fn resolve(&self) -> Result<EffectiveLimits> {
        self.resolve_within(&EffectiveLimits::HARD)
    }

    /// Resolve against `ceiling`, which may itself be lowered (a plan resolves
    /// against its authorization's effective limits).
    pub fn resolve_within(&self, ceiling: &EffectiveLimits) -> Result<EffectiveLimits> {
        Ok(EffectiveLimits {
            max_requests: lower(self.max_requests, ceiling.max_requests, "max_requests")?,
            max_rps: lower(self.max_rps, ceiling.max_rps, "max_rps")?,
            max_duration_s: lower(
                self.max_duration_s,
                ceiling.max_duration_s,
                "max_duration_s",
            )?,
            max_request_bytes: lower(
                self.max_request_bytes,
                ceiling.max_request_bytes,
                "max_request_bytes",
            )?,
            max_response_bytes: lower(
                self.max_response_bytes,
                ceiling.max_response_bytes,
                "max_response_bytes",
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hard_maxima_match_the_approved_design() {
        assert_eq!((MAX_REQUESTS, MAX_RPS, MAX_DURATION_S), (500, 2, 1_800));
        assert_eq!((MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES), (65_536, 1_048_576));
        assert_eq!((MAX_WINDOW_S, MAX_ORIGINS), (604_800, 4));
    }

    #[test]
    fn absent_limits_resolve_to_the_hard_maxima() {
        assert_eq!(Limits::default().resolve().unwrap(), EffectiveLimits::HARD);
    }

    #[test]
    fn every_limit_can_be_lowered_to_one() {
        let one = Limits {
            max_requests: Some(1),
            max_rps: Some(1),
            max_duration_s: Some(1),
            max_request_bytes: Some(1),
            max_response_bytes: Some(1),
        };
        let resolved = one.resolve().unwrap();
        assert_eq!(
            (
                resolved.max_requests,
                resolved.max_rps,
                resolved.max_duration_s
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn raising_any_limit_is_refused_by_name() {
        let cases: [(Limits, &str); 5] = [
            (
                Limits {
                    max_requests: Some(501),
                    ..Default::default()
                },
                "max_requests",
            ),
            (
                Limits {
                    max_rps: Some(3),
                    ..Default::default()
                },
                "max_rps",
            ),
            (
                Limits {
                    max_duration_s: Some(1_801),
                    ..Default::default()
                },
                "max_duration_s",
            ),
            (
                Limits {
                    max_request_bytes: Some(65_537),
                    ..Default::default()
                },
                "max_request_bytes",
            ),
            (
                Limits {
                    max_response_bytes: Some(1_048_577),
                    ..Default::default()
                },
                "max_response_bytes",
            ),
        ];
        for (limits, field) in cases {
            match limits.resolve() {
                Err(RemoteError::BoundRaised { name }) => assert_eq!(name, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_zero_limit_is_refused_rather_than_disabling_the_bound() {
        let cases: [(Limits, &str); 5] = [
            (
                Limits {
                    max_requests: Some(0),
                    ..Default::default()
                },
                "max_requests",
            ),
            (
                Limits {
                    max_rps: Some(0),
                    ..Default::default()
                },
                "max_rps",
            ),
            (
                Limits {
                    max_duration_s: Some(0),
                    ..Default::default()
                },
                "max_duration_s",
            ),
            (
                Limits {
                    max_request_bytes: Some(0),
                    ..Default::default()
                },
                "max_request_bytes",
            ),
            (
                Limits {
                    max_response_bytes: Some(0),
                    ..Default::default()
                },
                "max_response_bytes",
            ),
        ];
        for (limits, field) in cases {
            match limits.resolve() {
                Err(RemoteError::BoundZero { name }) => assert_eq!(name, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_plan_may_only_lower_its_authorization() {
        let auth = Limits {
            max_requests: Some(10),
            ..Default::default()
        }
        .resolve()
        .unwrap();
        let plan = Limits {
            max_requests: Some(11),
            ..Default::default()
        };
        assert!(matches!(
            plan.resolve_within(&auth),
            Err(RemoteError::BoundRaised {
                name: "max_requests"
            })
        ));
        let plan = Limits {
            max_requests: Some(5),
            ..Default::default()
        };
        assert_eq!(plan.resolve_within(&auth).unwrap().max_requests, 5);
    }
}
