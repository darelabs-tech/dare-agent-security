use serde::{Deserialize, Serialize};

use crate::error::{GraphError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeType {
    Human,
    Agent,
    Identity,
    DelegatedAuthority,
    McpServer,
    Capability,
    Tool,
    Credential,
    DownstreamService,
    Resource,
    Data,
    Tenant,
    PolicyDecisionPoint,
    PolicyEnforcementPoint,
}

impl NodeType {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Identity => "identity",
            Self::DelegatedAuthority => "delegated-authority",
            Self::McpServer => "mcp-server",
            Self::Capability => "capability",
            Self::Tool => "tool",
            Self::Credential => "credential",
            Self::DownstreamService => "downstream-service",
            Self::Resource => "resource",
            Self::Data => "data",
            Self::Tenant => "tenant",
            Self::PolicyDecisionPoint => "policy-decision-point",
            Self::PolicyEnforcementPoint => "policy-enforcement-point",
        }
    }
}

pub fn build_node_id(node_type: NodeType, local_id: &str) -> Result<String> {
    let local_id = local_id.trim();
    if local_id.is_empty()
        || local_id.len() > 160
        || !local_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(GraphError::Invalid("unsafe node local_id".into()));
    }
    Ok(format!("node:{}:{local_id}", node_type.slug()))
}
