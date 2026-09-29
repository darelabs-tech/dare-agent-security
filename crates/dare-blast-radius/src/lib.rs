//! Blast-radius analysis over a DARE v2 attack graph (Cycle 024).
//!
//! Given a graph written by `validate attack-paths` and a set of compromised
//! seeds, this crate computes what each seed can reach under the Cycle 023
//! continuity rules, in two views: every feasible relationship, and only
//! relationships no observed control held on. It reports reach as routes and
//! counts, never as a score, and it never executes, sends or schedules
//! anything.
pub mod admit;
pub mod analyze;
pub mod classify;
pub mod delta;
pub mod error;
pub mod impact;
pub mod limits;
pub mod model;
pub mod reach;
pub mod render;
pub mod scenario;
pub mod summary;
pub mod validate;

pub use analyze::{analyze, Analysis, Options, Seeding};
pub use error::{BlastError, Refusal, Result};
pub use validate::validate_blast_radius;
