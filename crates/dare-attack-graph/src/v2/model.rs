//! Attack graph v2 contract (Cycle 023, BLUEPRINT §4.7).
//!
//! v2 is additive: it reuses the v1 node and edge enums, authority, edge
//! evidence, node security and impact factors unchanged, and adds provenance,
//! guards, designations, feasibility and control state. v1 types and v1
//! serialization are not touched.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    authority::AuthorityContext,
    edge::EdgeType,
    evidence::EdgeEvidence,
    model::{GraphEngine, ImpactFactors, NodeSecurity, PathStatus, SchemaRef},
    node::NodeType,
};

pub const GRAPH_SCHEMA_ID_V2: &str =
    "https://darelabs.tech/schemas/attack-graph/v2/attack-graph.schema.json";
pub const PATHS_SCHEMA_ID_V2: &str =
    "https://darelabs.tech/schemas/attack-graph/v2/attack-paths.schema.json";
pub const REPORT_SCHEMA_ID_V2: &str =
    "https://darelabs.tech/schemas/attack-graph/v2/projection-report.schema.json";
pub const GRAPH_SCHEMA_VERSION_V2: &str = "2.0.0";
pub const DOCUMENT_SCHEMA_VERSION: &str = "2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackGraphV2 {
    pub schema: SchemaRef,
    pub id: String,
    pub target_id: String,
    pub target_version: String,
    pub sources: SourcesV2,
    pub engine: GraphEngine,
    pub nodes: Vec<NodeV2>,
    pub edges: Vec<EdgeV2>,
    pub entry_points: Vec<EntryDesignation>,
    pub targets: Vec<TargetDesignation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_digest: Option<String>,
    pub artifacts: Vec<ArtifactSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSource {
    pub index: u32,
    pub engine: String,
    pub run: String,
    pub mode: String,
    pub synthetic: bool,
    pub dynamic_authorized: bool,
    pub result_digest: String,
    pub evidence_digest: String,
    pub input_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// `None` means the relationship or entity comes from the system model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_index: Option<u32>,
    /// The engine's own kind name, e.g. `ComponentType::MODEL`.
    pub original_kind: String,
    /// JSON pointer into the result, an input document or the system model.
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeV2 {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub display_name: String,
    #[serde(default)]
    pub security: NodeSecurity,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardVerdict {
    Pass,
    Fail,
    Inconclusive,
    Error,
}

impl GuardVerdict {
    /// Cycle 018 precedence: FAIL > ERROR > INCONCLUSIVE > PASS.
    pub fn severity(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Inconclusive => 1,
            Self::Error => 2,
            Self::Fail => 3,
        }
    }

    pub fn worst(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardScope {
    Run,
    Entity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub property: String,
    pub verdict: GuardVerdict,
    pub evidence_ids: Vec<String>,
    pub scope: GuardScope,
    pub artifact_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeV2 {
    pub id: String,
    #[serde(rename = "type")]
    pub edge_type: EdgeType,
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub authority: AuthorityContext,
    pub evidence: EdgeEvidence,
    pub guards: Vec<Guard>,
    pub authority_mutation: bool,
    pub crosses_trust_boundary: Vec<String>,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryClass {
    UntrustedInput,
    ExternalContent,
    RetrievedDocument,
    MemoryWrite,
    PeerAgent,
    SupplyChainComponent,
    LowPrivilegePrincipal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetClass {
    SensitiveResource,
    PrivilegedCredential,
    DestructiveCapability,
    CrossTenantResource,
    ExternalPublication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DesignationOrigin {
    Default,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryDesignation {
    pub node: String,
    pub class: EntryClass,
    pub origin: DesignationOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDesignation {
    pub node: String,
    pub class: TargetClass,
    pub origin: DesignationOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Feasibility {
    Feasible,
    Discontinuous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlState {
    ControlFailed,
    ControlUndecided,
    ControlsHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRef {
    pub edge: String,
    pub property: String,
    pub artifact_index: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactFactorsV2 {
    #[serde(flatten)]
    pub v1: ImpactFactors,
    pub crosses_trust_boundary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathV2 {
    pub id: String,
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
    pub status: PathStatus,
    pub feasibility: Feasibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discontinuity_at: Option<u32>,
    pub control_state: ControlState,
    pub failed_guards: Vec<GuardRef>,
    pub undecided_edges: Vec<String>,
    pub entry: String,
    pub entry_class: EntryClass,
    pub target: String,
    pub target_class: TargetClass,
    pub impact_factors: ImpactFactorsV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBound {
    MaxPathsPerPair,
    MaxPaths,
    MaxSteps,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRef {
    pub entry: String,
    pub target: String,
    pub target_class: TargetClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enumeration {
    pub max_path_edges: u32,
    pub max_paths: u32,
    pub max_paths_per_pair: u32,
    pub max_steps: u64,
    pub steps_used: u64,
    pub truncated: bool,
    pub stopped_by: Vec<StopBound>,
    pub pairs_total: u32,
    pub pairs_exhausted: u32,
    pub pairs_truncated_count: u32,
    pub pairs_truncated: Vec<PairRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chokepoint {
    pub target: String,
    pub edge: String,
    pub properties: Vec<String>,
    pub failed_paths: u32,
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackPathsDoc {
    pub schema_id: String,
    pub schema_version: String,
    pub graph_id: String,
    pub paths: Vec<PathV2>,
    pub discontinuous_paths: Vec<PathV2>,
    pub chokepoints: Vec<Chokepoint>,
    pub enumeration: Enumeration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactCounts {
    pub nodes: u32,
    pub edges: u32,
    pub guards: u32,
    pub entries: u32,
    pub targets: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReport {
    pub index: u32,
    pub engine: String,
    pub run: String,
    pub mode: String,
    pub synthetic: bool,
    pub dynamic_authorized: bool,
    pub result_digest: String,
    pub evidence_digest: String,
    pub verified_inputs: Vec<String>,
    pub facts: FactCounts,
    pub unprojected: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasReport {
    pub engine: String,
    pub local_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub entity_id: String,
    pub matched_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReport {
    pub schema_id: String,
    pub schema_version: String,
    pub graph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_digest: Option<String>,
    pub artifacts: Vec<ArtifactReport>,
    pub aliases_used: Vec<AliasReport>,
    pub aliases_unused: Vec<AliasReport>,
}
