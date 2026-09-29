//! Compromise scenarios and seed resolution (BLUEPRINT §4.3, §6.1).
use std::{collections::BTreeMap, path::Path};

use dare_attack_graph::{
    canonical::digest_value,
    v2::{AttackGraphV2, EntryClass, NodeV2},
    NodeType,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    admit::read_admitted,
    error::{BlastError, Refusal, Result},
    limits::{check, MAX_DEPTH, MAX_SCENARIO_BYTES, MAX_SEEDS, MAX_STATES_PER_SEARCH},
    model::{SeedKind, COMPROMISE_SCHEMA_JSON},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompromiseScenario {
    pub schema_version: String,
    pub scenario_id: String,
    pub graph_id: String,
    pub seeds: Vec<Seed>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub max_states: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub entity_id: Option<String>,
    pub kind: SeedKind,
    #[serde(default)]
    pub note: Option<String>,
}

/// A seed resolved to a graph node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedSeed {
    pub node: String,
    pub kind: SeedKind,
    pub tenant: Option<String>,
}

/// Seeds and the scenario's own bounds, ready for the search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seeding {
    pub scenario_id: String,
    pub scenario_digest: Option<String>,
    pub seeds: Vec<ResolvedSeed>,
    pub skipped: u32,
    pub omitted: u32,
    pub max_depth: Option<u32>,
    pub max_states: Option<u64>,
}

/// The kind-fits-type table (BLUEPRINT §4.3).
pub fn kind_fits(kind: SeedKind, node_type: NodeType) -> bool {
    match kind {
        SeedKind::PrincipalTakeover => matches!(
            node_type,
            NodeType::Human | NodeType::Agent | NodeType::Identity
        ),
        SeedKind::CredentialLeak => node_type == NodeType::Credential,
        SeedKind::ContentInjection => node_type == NodeType::Data,
        SeedKind::ComponentCompromise => matches!(
            node_type,
            NodeType::Tool
                | NodeType::McpServer
                | NodeType::Capability
                | NodeType::DownstreamService
        ),
    }
}

/// The kind an entry class implies (BLUEPRINT §4.3).
pub fn kind_for_entry(class: EntryClass) -> SeedKind {
    match class {
        EntryClass::LowPrivilegePrincipal | EntryClass::PeerAgent => SeedKind::PrincipalTakeover,
        EntryClass::UntrustedInput
        | EntryClass::ExternalContent
        | EntryClass::RetrievedDocument
        | EntryClass::MemoryWrite => SeedKind::ContentInjection,
        EntryClass::SupplyChainComponent => SeedKind::ComponentCompromise,
    }
}

fn node<'g>(graph: &'g AttackGraphV2, id: &str) -> Option<&'g NodeV2> {
    graph.nodes.iter().find(|n| n.id == id)
}

fn internal(message: &'static str) -> BlastError {
    BlastError::Internal(message)
}

fn check_schema(value: &Value) -> Result<()> {
    let schema: Value =
        serde_json::from_str(COMPROMISE_SCHEMA_JSON).map_err(|_| internal("embedded schema"))?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|_| internal("embedded schema"))?;
    if validator.iter_errors(value).next().is_some() {
        return Err(Refusal::InvalidDocument { file: "scenario" }.into());
    }
    Ok(())
}

/// Reads, admits and resolves a scenario file against `graph`.
pub fn load_scenario(path: &Path, graph: &AttackGraphV2) -> Result<Seeding> {
    let value = read_admitted(path, "scenario", MAX_SCENARIO_BYTES)?;
    scenario_from_value(&value, graph)
}

/// Validates and resolves a scenario document (§6.1).
pub fn scenario_from_value(value: &Value, graph: &AttackGraphV2) -> Result<Seeding> {
    check_schema(value)?;
    let scenario: CompromiseScenario = serde_json::from_value(value.clone())
        .map_err(|_| Refusal::InvalidDocument { file: "scenario" })?;
    if scenario.seeds.is_empty() || scenario.seeds.len() > MAX_SEEDS {
        return Err(Refusal::InvalidDocument { file: "scenario" }.into());
    }
    if let Some(depth) = scenario.max_depth {
        check("max_depth", u64::from(depth), u64::from(MAX_DEPTH))?;
    }
    if let Some(states) = scenario.max_states {
        check("max_states", states, MAX_STATES_PER_SEARCH)?;
    }
    if scenario.graph_id != graph.id {
        return Err(Refusal::GraphMismatch.into());
    }
    let mut seen: BTreeMap<(String, SeedKind), usize> = BTreeMap::new();
    let mut seeds = Vec::with_capacity(scenario.seeds.len());
    for (index, seed) in scenario.seeds.iter().enumerate() {
        let id = match (&seed.node_id, &seed.entity_id) {
            (Some(node_id), None) => node(graph, node_id)
                .map(|n| n.id.clone())
                .ok_or(Refusal::UnknownSeed { seed: index })?,
            (None, Some(entity)) => resolve_entity(graph, entity, index)?,
            _ => return Err(Refusal::InvalidDocument { file: "scenario" }.into()),
        };
        let found = node(graph, &id).ok_or(Refusal::UnknownSeed { seed: index })?;
        if !kind_fits(seed.kind, found.node_type) {
            return Err(Refusal::SeedKindMismatch { seed: index }.into());
        }
        if let Some(first) = seen.insert((id.clone(), seed.kind), index) {
            return Err(Refusal::DuplicateSeed {
                first,
                second: index,
            }
            .into());
        }
        seeds.push(ResolvedSeed {
            node: id,
            kind: seed.kind,
            tenant: found.security.tenant.clone(),
        });
    }
    seeds.sort();
    let digest = digest_value(value).map_err(|_| internal("scenario digest"))?;
    Ok(Seeding {
        scenario_id: scenario.scenario_id,
        scenario_digest: Some(format!("sha256:{digest}")),
        seeds,
        skipped: 0,
        omitted: 0,
        max_depth: scenario.max_depth,
        max_states: scenario.max_states,
    })
}

/// An entity id names the node `node:<slug>:<entity_id>` of its own type.
/// Run-scoped ids have more segments, so they never match.
fn resolve_entity(graph: &AttackGraphV2, entity: &str, index: usize) -> Result<String> {
    let matches: Vec<&NodeV2> = graph
        .nodes
        .iter()
        .filter(|n| n.id == format!("node:{}:{entity}", n.node_type.slug()))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err(Refusal::UnknownSeed { seed: index }.into()),
        _ => Err(Refusal::AmbiguousSeed { seed: index }.into()),
    }
}

/// Every entry point becomes a seed of the kind its class implies (§4.3).
pub fn entry_point_seeds(graph: &AttackGraphV2) -> Result<Seeding> {
    if graph.entry_points.is_empty() {
        return Err(Refusal::NoSeeds.into());
    }
    let mut all: Vec<ResolvedSeed> = Vec::new();
    let mut skipped = 0u32;
    for designation in &graph.entry_points {
        let found = node(graph, &designation.node).ok_or(internal("entry names a node"))?;
        let kind = kind_for_entry(designation.class);
        if !kind_fits(kind, found.node_type) {
            skipped += 1;
            continue;
        }
        all.push(ResolvedSeed {
            node: found.id.clone(),
            kind,
            tenant: found.security.tenant.clone(),
        });
    }
    all.sort();
    all.dedup();
    if all.is_empty() {
        return Err(Refusal::NoSeeds.into());
    }
    let omitted = all.len().saturating_sub(MAX_SEEDS) as u32;
    all.truncate(MAX_SEEDS);
    Ok(Seeding {
        scenario_id: "entry-points".into(),
        scenario_digest: None,
        seeds: all,
        skipped,
        omitted,
        max_depth: None,
        max_states: None,
    })
}
