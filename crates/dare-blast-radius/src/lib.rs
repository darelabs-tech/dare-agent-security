//! Blast-radius analysis over a DARE v2 attack graph (Cycle 024).
//!
//! Given a graph written by `validate attack-paths` and a set of compromised
//! seeds, this crate computes what each seed can reach under the Cycle 023
//! continuity rules, in two views: every feasible relationship, and only
//! relationships no observed control held on. It reports reach as routes and
//! counts, never as a score, and it never executes, sends or schedules
//! anything.
pub mod admit;
pub mod error;
pub mod limits;
pub mod model;
pub mod scenario;

pub use error::{BlastError, Refusal, Result};
