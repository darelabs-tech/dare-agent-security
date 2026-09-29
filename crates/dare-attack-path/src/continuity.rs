//! Authority continuity (BLUEPRINT §7.3, task-032). The rule lives in
//! `dare_attack_graph::v2::continuity` since Cycle 024 (AD-02), so path
//! feasibility and blast-radius reach share one implementation.
pub use dare_attack_graph::v2::continuity::{discontinuity, Authority, MUTATION_PROPERTIES};
