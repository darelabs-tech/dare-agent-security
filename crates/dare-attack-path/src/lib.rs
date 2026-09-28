//! DARE Cycle 023 — evidence-derived attack-path construction.
//!
//! Projectors read the artifacts the engines of Cycles 013–022 already wrote,
//! together with the input documents those artifacts pin by digest, and emit
//! Cycle 008 graph facts with provenance. An explicit system model resolves
//! engine-local identifiers by alias only. A bounded path engine then
//! enumerates entry → target paths and classifies each one by evidence
//! state, authority continuity and control state.
//!
//! This crate never re-judges a property, never executes a path, and has no
//! network capability.
pub mod admit;
pub mod bundle;
pub mod error;
pub mod evidence_index;
pub mod ids;
pub mod limits;
pub mod load;
pub mod model;
pub mod sweep;

pub use error::{AttackPathError, ModelRefusal, Refusal, Result};
pub use ids::{EngineSlug, RunTag};
pub use limits::ConstructOptions;
