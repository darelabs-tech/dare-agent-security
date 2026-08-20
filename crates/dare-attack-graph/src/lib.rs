//! Deterministic, analysis-only Agent Attack Graph MVP.
pub mod authority;
pub mod builder;
pub mod canonical;
pub mod edge;
pub mod error;
pub mod evidence;
pub mod facts;
pub mod mapping;
pub mod model;
pub mod node;
pub mod path;
pub mod provenance;
pub mod render;
pub mod validate;

pub use authority::AuthorityContext;
pub use builder::build_attack_graph;
pub use edge::{build_edge_id, EdgeType};
pub use error::{GraphError, Result};
pub use evidence::{validate_edge_evidence, EdgeEvidence, EdgeEvidenceStatus};
pub use facts::{load_facts_file, GraphFact, GraphFactEdge, GraphFactNode, GraphFactsInput};
pub use model::{
    AttackGraph, Edge, EdgeSecurity, GraphEngine, GraphSources, ImpactFactors, Node, NodeSecurity,
    Path, PathStatus, SchemaRef,
};
pub use node::{build_node_id, NodeType};
pub use path::{derive_paths, PathOptions};
pub use provenance::graph_digest;
pub use render::{to_dot, to_mermaid};
pub use validate::{validate_graph, validate_safe_label, ATTACK_GRAPH_SCHEMA_V1_JSON};
