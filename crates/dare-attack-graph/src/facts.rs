//! Normalized fact input contract.
//!
//! JSON contains target identity/version, engine commit, source digests, and
//! `nodes`/`edges`. Edge endpoints use local IDs plus their explicit node
//! types; the builder converts them to `node:<kebab-type>:<local_id>`.
use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    authority::AuthorityContext,
    edge::EdgeType,
    error::Result,
    evidence::EdgeEvidence,
    model::{EdgeSecurity, GraphSources, NodeSecurity},
    node::NodeType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFactNode {
    pub local_id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub display_name: String,
    #[serde(default)]
    pub security: NodeSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFactEdge {
    #[serde(rename = "type")]
    pub edge_type: EdgeType,
    pub source_local_id: String,
    pub source_type: NodeType,
    pub target_local_id: String,
    pub target_type: NodeType,
    #[serde(default)]
    pub authority: AuthorityContext,
    pub evidence: EdgeEvidence,
    #[serde(default)]
    pub security: EdgeSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFactsInput {
    pub target_id: String,
    pub target_version: String,
    pub engine_commit: String,
    #[serde(default = "default_generated_at")]
    pub generated_at: String,
    pub sources: GraphSources,
    pub nodes: Vec<GraphFactNode>,
    pub edges: Vec<GraphFactEdge>,
}

fn default_generated_at() -> String {
    "1970-01-01T00:00:00Z".into()
}

pub type GraphFact = GraphFactEdge;

pub fn load_facts_file(path: &Path) -> Result<GraphFactsInput> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
