use serde::{Deserialize, Serialize};

use crate::authority::AuthorityContext;
use crate::edge::EdgeType;
use crate::evidence::EdgeEvidence;
use crate::node::NodeType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSources {
    pub inventory_digest: String,
    pub assessment_plan_digest: String,
    pub evidence_bundle_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benchmark_record_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_registry_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEngine {
    pub name: String,
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSecurity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub destructive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "NodeSecurity::is_empty")]
    pub security: NodeSecurity,
}

impl NodeSecurity {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSecurity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_impact: Option<String>,
    #[serde(default)]
    pub authority_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: String,
    #[serde(rename = "type")]
    pub edge_type: EdgeType,
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub authority: AuthorityContext,
    pub evidence: EdgeEvidence,
    #[serde(default)]
    pub security: EdgeSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathStatus {
    NotTested,
    Inferred,
    Proven,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactFactors {
    pub cross_tenant: bool,
    pub uses_privileged_credential: bool,
    pub reaches_sensitive_resource: bool,
    pub contains_destructive_capability: bool,
    pub contains_failed_security_property: bool,
    pub contains_authorization_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Path {
    pub id: String,
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
    pub status: PathStatus,
    pub impact_factors: ImpactFactors,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackGraph {
    pub schema: SchemaRef,
    pub id: String,
    pub target_id: String,
    pub target_version: String,
    pub generated_at: String,
    pub sources: GraphSources,
    pub engine: GraphEngine,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub paths: Vec<Path>,
}
