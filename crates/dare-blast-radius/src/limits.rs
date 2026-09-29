//! Hard maxima (DESIGN §4.3, BLUEPRINT §4.2). Inputs may only lower them.
use crate::error::Refusal;

pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SCENARIO_BYTES: u64 = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_SEEDS: usize = 64;
pub const MAX_DEPTH: u32 = 12;
pub const DEFAULT_DEPTH: u32 = 8;
pub const MAX_STATES_PER_SEARCH: u64 = 1_000_000;
pub const MAX_STATES_TOTAL: u64 = 5_000_000;
pub const MAX_DELTA_EDGES: usize = 64;

/// Bounds of one search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_depth: u32,
    pub max_states: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_DEPTH,
            max_states: MAX_STATES_PER_SEARCH,
        }
    }
}

impl Bounds {
    /// Refuses 0 and any value above its maximum; never clamps.
    pub fn validate(&self) -> Result<(), Refusal> {
        check("max_depth", u64::from(self.max_depth), u64::from(MAX_DEPTH))?;
        check("max_states", self.max_states, MAX_STATES_PER_SEARCH)
    }

    /// The lower of two bound sets, each already validated.
    pub fn lower(self, max_depth: Option<u32>, max_states: Option<u64>) -> Self {
        Self {
            max_depth: max_depth.map_or(self.max_depth, |d| d.min(self.max_depth)),
            max_states: max_states.map_or(self.max_states, |s| s.min(self.max_states)),
        }
    }
}

pub fn check(bound: &'static str, value: u64, maximum: u64) -> Result<(), Refusal> {
    if value == 0 {
        return Err(Refusal::BoundZero { bound });
    }
    if value > maximum {
        return Err(Refusal::BoundAboveMaximum { bound });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_within_the_maxima() {
        assert_eq!(Bounds::default().validate(), Ok(()));
        const { assert!(DEFAULT_DEPTH <= MAX_DEPTH) };
        const { assert!(MAX_STATES_PER_SEARCH <= MAX_STATES_TOTAL) };
    }

    #[test]
    fn every_bound_refuses_zero_and_values_above_its_maximum() {
        let depth = |d| Bounds {
            max_depth: d,
            ..Bounds::default()
        };
        let states = |s| Bounds {
            max_states: s,
            ..Bounds::default()
        };
        assert_eq!(
            depth(0).validate(),
            Err(Refusal::BoundZero { bound: "max_depth" })
        );
        assert_eq!(
            depth(MAX_DEPTH + 1).validate(),
            Err(Refusal::BoundAboveMaximum { bound: "max_depth" })
        );
        assert_eq!(depth(MAX_DEPTH).validate(), Ok(()));
        assert_eq!(
            states(0).validate(),
            Err(Refusal::BoundZero {
                bound: "max_states"
            })
        );
        assert_eq!(
            states(MAX_STATES_PER_SEARCH + 1).validate(),
            Err(Refusal::BoundAboveMaximum {
                bound: "max_states"
            })
        );
        assert_eq!(states(1).validate(), Ok(()));
    }

    #[test]
    fn lowering_takes_the_smaller_value() {
        let b = Bounds::default().lower(Some(3), Some(10));
        assert_eq!((b.max_depth, b.max_states), (3, 10));
        let b = Bounds {
            max_depth: 2,
            max_states: 5,
        }
        .lower(Some(9), Some(9));
        assert_eq!((b.max_depth, b.max_states), (2, 5));
    }
}
