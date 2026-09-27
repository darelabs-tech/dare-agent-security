//! Hard maxima, and the only direction a scenario may move them.
//!
//! Every limit here is an upper bound fixed at compile time. A scenario may ask
//! for a *smaller* bound through [`Bounds`]; asking for a larger one is
//! [`MultiTurnError::BoundRaised`], a refusal. A test suite that could raise
//! its own ceiling would have no ceiling.

use serde::{Deserialize, Serialize};

use crate::error::{MultiTurnError, Result};

/// Largest input file read from disk.
pub const MAX_INPUT_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Deepest JSON nesting accepted in any input document.
pub const MAX_JSON_DEPTH: usize = 32;
/// Nodes in one strategy graph.
pub const MAX_NODES: usize = 256;
/// Edges in one strategy graph.
pub const MAX_EDGES: usize = 1_024;
/// Root-to-terminal paths one strategy graph may enumerate.
pub const MAX_PATHS: u64 = 64;
/// Turns in one conversation. Also bounds the longest path in a graph.
pub const MAX_TURNS_PER_CONVERSATION: u32 = 32;
/// Conversations in one scenario.
pub const MAX_CONVERSATIONS: usize = 4;
/// Bytes in one turn's template content or one target output.
pub const MAX_TURN_BYTES: usize = 16 * 1024;
/// Canaries declared by one scenario.
pub const MAX_CANARIES: usize = 16;
/// Fewest fragments in a composite prohibited objective.
pub const MIN_COMPOSITE_FRAGMENTS: usize = 2;
/// Most fragments in a composite prohibited objective.
pub const MAX_COMPOSITE_FRAGMENTS: usize = 8;
/// Actions one target output may report.
pub const MAX_ACTIONS_PER_TURN: usize = 8;
/// Bytes of an action's argument text kept for canary matching.
pub const MAX_ACTION_ARGUMENT_BYTES: usize = 1_024;
/// Characters of redacted excerpt kept per turn.
pub const MAX_EXCERPT_CHARS: usize = 256;
/// Bytes all persisted artifacts of one run may occupy together.
pub const MAX_TOTAL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Scenario-supplied bounds. Each may only lower its hard maximum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    #[serde(default)]
    pub max_turns_per_conversation: Option<u32>,
    #[serde(default)]
    pub max_paths: Option<u64>,
    #[serde(default)]
    pub max_total_output_bytes: Option<usize>,
}

/// Bounds after validation: every value is concrete and within its maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveBounds {
    pub max_turns_per_conversation: u32,
    pub max_paths: u64,
    pub max_total_output_bytes: usize,
}

impl Default for EffectiveBounds {
    fn default() -> Self {
        Self {
            max_turns_per_conversation: MAX_TURNS_PER_CONVERSATION,
            max_paths: MAX_PATHS,
            max_total_output_bytes: MAX_TOTAL_OUTPUT_BYTES,
        }
    }
}

impl Bounds {
    /// Resolve against the hard maxima, refusing any attempt to raise one.
    pub fn resolve(&self) -> Result<EffectiveBounds> {
        Ok(EffectiveBounds {
            max_turns_per_conversation: lower_only(
                self.max_turns_per_conversation,
                MAX_TURNS_PER_CONVERSATION,
                "max_turns_per_conversation",
            )?,
            max_paths: lower_only(self.max_paths, MAX_PATHS, "max_paths")?,
            max_total_output_bytes: lower_only(
                self.max_total_output_bytes,
                MAX_TOTAL_OUTPUT_BYTES,
                "max_total_output_bytes",
            )?,
        })
    }
}

fn lower_only<T>(requested: Option<T>, max: T, name: &'static str) -> Result<T>
where
    T: Copy + PartialOrd + From<u8>,
{
    match requested {
        None => Ok(max),
        Some(value) if value < T::from(1) => Err(MultiTurnError::BoundZero { name }),
        Some(value) if value <= max => Ok(value),
        Some(_) => Err(MultiTurnError::BoundRaised { name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_bounds_resolve_to_the_hard_maxima() {
        assert_eq!(Bounds::default().resolve(), Ok(EffectiveBounds::default()));
    }

    #[test]
    fn a_bound_may_be_lowered_down_to_one() {
        let bounds = Bounds {
            max_turns_per_conversation: Some(1),
            max_paths: Some(64),
            max_total_output_bytes: Some(1024),
        };
        let resolved = bounds.resolve().expect("lowering is allowed");
        assert_eq!(resolved.max_turns_per_conversation, 1);
        assert_eq!(resolved.max_paths, 64);
        assert_eq!(resolved.max_total_output_bytes, 1024);
    }

    #[test]
    fn raising_any_bound_is_refused() {
        let cases = [
            (
                Bounds {
                    max_turns_per_conversation: Some(33),
                    ..Bounds::default()
                },
                "max_turns_per_conversation",
            ),
            (
                Bounds {
                    max_paths: Some(65),
                    ..Bounds::default()
                },
                "max_paths",
            ),
            (
                Bounds {
                    max_total_output_bytes: Some(MAX_TOTAL_OUTPUT_BYTES + 1),
                    ..Bounds::default()
                },
                "max_total_output_bytes",
            ),
        ];
        for (bounds, name) in cases {
            assert_eq!(bounds.resolve(), Err(MultiTurnError::BoundRaised { name }));
        }
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_silently_disabling_the_run() {
        let bounds = Bounds {
            max_paths: Some(0),
            ..Bounds::default()
        };
        assert_eq!(
            bounds.resolve(),
            Err(MultiTurnError::BoundZero { name: "max_paths" })
        );
    }

    #[test]
    fn the_hard_maxima_match_the_approved_design() {
        // DESIGN §13 Q2, decided 2026-09-27. Literals, so a silent edit fails here.
        assert_eq!(MAX_TURNS_PER_CONVERSATION, 32);
        assert_eq!(MAX_NODES, 256);
        assert_eq!(MAX_PATHS, 64);
        assert_eq!(MAX_TURN_BYTES, 16_384);
        assert_eq!(MAX_TOTAL_OUTPUT_BYTES, 8_388_608);
    }
}
