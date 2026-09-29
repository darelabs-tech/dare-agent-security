//! Attack graph v2 contract (Cycle 023). Additive over v1; no engine dependency.
pub mod continuity;
pub mod control;
pub mod model;
pub mod render;
pub mod validate;

pub use continuity::{discontinuity, Authority, MUTATION_PROPERTIES};
pub use control::{edge_control, is_structural, path_control, EdgeControl};
pub use model::*;
pub use render::{to_dot_v2, to_mermaid_v2};
pub use validate::{
    graph_id_v2, impact_factors, path_id, path_status, validate_graph_v2, validate_paths_v2,
    validate_projection_report, ATTACK_GRAPH_SCHEMA_V2_JSON, ATTACK_PATHS_SCHEMA_V2_JSON,
    PROJECTION_REPORT_SCHEMA_V2_JSON,
};
