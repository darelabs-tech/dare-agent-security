//! The blast-radius document (BLUEPRINT §4.4) and the embedded schemas.
//! Counts and routes only: no field holds a score, probability or weight
//! (RS-07).
use std::collections::BTreeMap;

use dare_attack_graph::v2::{ControlState, GuardRef, TargetClass};
use serde::{Deserialize, Serialize};

pub const BLAST_RADIUS_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/blast-radius/v1/blast-radius.schema.json";
pub const BLAST_RADIUS_SCHEMA_VERSION: &str = "1.0.0";
pub const BLAST_RADIUS_SCHEMA_JSON: &str =
    include_str!("../../../schemas/blast-radius/v1/blast-radius.schema.json");
pub const COMPROMISE_SCHEMA_JSON: &str =
    include_str!("../../../schemas/blast-radius/v1/compromise.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeedKind {
    PrincipalTakeover,
    CredentialLeak,
    ContentInjection,
    ComponentCompromise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Exposure {
    Exposed,
    Contained,
    ContainmentUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBound {
    MaxStates,
    MaxStatesTotal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocBounds {
    pub max_depth: u32,
    pub max_states: u64,
    pub max_states_total: u64,
    pub max_delta_edges: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusDoc {
    pub schema_id: String,
    pub schema_version: String,
    pub graph_id: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_digest: Option<String>,
    pub bounds: DocBounds,
    pub seeds: Vec<SeedReport>,
    pub seeds_skipped: u32,
    pub seeds_omitted: u32,
    pub totals: Totals,
    pub frontier: Vec<FrontierEdge>,
    pub remediation_delta: Vec<DeltaEdge>,
    pub truncated: bool,
    pub stopped_by: Vec<StopBound>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedReport {
    pub node: String,
    pub kind: SeedKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub structural: SearchReport,
    pub uncontained: SearchReport,
    pub targets: Vec<TargetReach>,
    pub impact: ViewImpact,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchReport {
    pub states_explored: u64,
    pub nodes_reached: u32,
    pub refused_steps: u64,
    pub held_edges_skipped: u64,
    pub depth_cut: bool,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_by: Option<StopBound>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReach {
    pub node: String,
    pub class: TargetClass,
    pub exposure: Exposure,
    pub structural_route: Route,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncontained_route: Option<Route>,
    pub frontier: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
    pub control_state: ControlState,
    pub failed_guards: Vec<GuardRef>,
    pub undecided_edges: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactCounts {
    pub targets_by_class: BTreeMap<TargetClass, u32>,
    pub tenants_reached: Vec<String>,
    pub trust_boundaries_crossed: Vec<String>,
    pub privileged_credentials_acquired: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewImpact {
    pub structural: ImpactCounts,
    pub uncontained: ImpactCounts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    pub exposed: u32,
    pub contained: u32,
    pub containment_unknown: u32,
    pub exposed_by_class: BTreeMap<TargetClass, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierEdge {
    pub edge: String,
    pub properties: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub contained_targets: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaEdge {
    pub edge: String,
    pub properties: Vec<String>,
    pub targets_contained_if_held: u32,
    pub partial: bool,
}
