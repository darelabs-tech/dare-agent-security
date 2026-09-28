//! Hard maxima (BLUEPRINT §4.2). Flags may only lower the three path bounds.
use crate::error::{Refusal, Result};

pub const MAX_ARTIFACT_DIRS: usize = 64;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_MODEL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_MODEL_ENTITIES: usize = 2_000;
pub const MAX_MODEL_ALIASES: usize = 10_000;
pub const MAX_MODEL_DECLARED_EDGES: usize = 5_000;
pub const MAX_MODEL_BOUNDARIES: usize = 64;
pub const MAX_BOUNDARY_MEMBERS: usize = 500;
pub const MAX_NODES: usize = 10_000;
pub const MAX_EDGES: usize = 50_000;
pub const MAX_PATH_EDGES: u32 = 12;
pub const DEFAULT_PATH_EDGES: u32 = 8;
pub const MAX_PATHS: u32 = 10_000;
pub const MAX_PATHS_PER_PAIR: u32 = 64;
pub const MAX_STEPS: u64 = 5_000_000;
pub const MAX_TRUNCATED_PAIRS_LISTED: usize = 1_000;

/// The three lowerable path bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructOptions {
    pub max_path_edges: u32,
    pub max_paths: u32,
    pub max_paths_per_pair: u32,
}

impl Default for ConstructOptions {
    fn default() -> Self {
        Self {
            max_path_edges: DEFAULT_PATH_EDGES,
            max_paths: MAX_PATHS,
            max_paths_per_pair: MAX_PATHS_PER_PAIR,
        }
    }
}

impl ConstructOptions {
    pub fn validate(&self) -> Result<()> {
        for (bound, given, max) in [
            ("max_path_edges", self.max_path_edges, MAX_PATH_EDGES),
            ("max_paths", self.max_paths, MAX_PATHS),
            (
                "max_paths_per_pair",
                self.max_paths_per_pair,
                MAX_PATHS_PER_PAIR,
            ),
        ] {
            if given == 0 {
                return Err(Refusal::BoundZero { bound }.into());
            }
            if given > max {
                return Err(Refusal::BoundAboveMaximum {
                    bound,
                    given: u64::from(given),
                    max: u64::from(max),
                }
                .into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AttackPathError;

    fn refusal(options: ConstructOptions) -> Option<Refusal> {
        match options.validate() {
            Ok(()) => None,
            Err(AttackPathError::Refused(r)) => Some(r),
            Err(other) => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn defaults_are_within_the_maxima() {
        assert_eq!(refusal(ConstructOptions::default()), None);
        let at_max = ConstructOptions {
            max_path_edges: MAX_PATH_EDGES,
            max_paths: MAX_PATHS,
            max_paths_per_pair: MAX_PATHS_PER_PAIR,
        };
        assert_eq!(refusal(at_max), None);
    }

    #[test]
    fn every_bound_refuses_zero_and_values_above_its_maximum() {
        let base = ConstructOptions::default();
        type Setter = fn(&mut ConstructOptions, u32);
        let cases: [(&str, Setter, u32); 3] = [
            (
                "max_path_edges",
                |o, v| o.max_path_edges = v,
                MAX_PATH_EDGES,
            ),
            ("max_paths", |o, v| o.max_paths = v, MAX_PATHS),
            (
                "max_paths_per_pair",
                |o, v| o.max_paths_per_pair = v,
                MAX_PATHS_PER_PAIR,
            ),
        ];
        for (name, set, max) in cases {
            let mut zero = base;
            set(&mut zero, 0);
            assert_eq!(refusal(zero), Some(Refusal::BoundZero { bound: name }));
            let mut above = base;
            set(&mut above, max + 1);
            assert_eq!(
                refusal(above),
                Some(Refusal::BoundAboveMaximum {
                    bound: name,
                    given: u64::from(max + 1),
                    max: u64::from(max)
                })
            );
        }
    }
}
