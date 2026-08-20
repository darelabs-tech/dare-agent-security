use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    canonical::digest_value,
    error::{GraphError, Result},
    evidence::EdgeEvidenceStatus,
    model::{AttackGraph, ImpactFactors, Path, PathStatus},
    node::NodeType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathOptions {
    pub max_depth: usize,
    pub max_paths: usize,
    pub source_filter: Option<NodeType>,
    pub target_filter: Option<NodeType>,
}

impl Default for PathOptions {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_paths: 64,
            source_filter: None,
            target_filter: None,
        }
    }
}

pub fn derive_paths(graph: &AttackGraph, options: &PathOptions) -> Result<Vec<Path>> {
    if options.max_depth == 0 || options.max_paths == 0 {
        return Err(GraphError::SafetyRefusal(
            "max_depth and max_paths must be bounded and non-zero".into(),
        ));
    }
    if options.max_depth > 64 || options.max_paths > 10_000 {
        return Err(GraphError::SafetyRefusal(
            "requested path bounds exceed safety limits".into(),
        ));
    }
    let nodes: BTreeMap<_, _> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let edges: BTreeMap<_, _> = graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &graph.edges {
        adjacency
            .entry(edge.source.as_str())
            .or_default()
            .push(edge.id.as_str());
    }
    for edge_ids in adjacency.values_mut() {
        edge_ids.sort();
    }
    let mut paths = Vec::new();
    for start in &graph.nodes {
        if options
            .source_filter
            .is_some_and(|filter| filter != start.node_type)
        {
            continue;
        }
        let mut visited = BTreeSet::from([start.id.clone()]);
        let mut node_path = vec![start.id.clone()];
        let mut edge_path = Vec::new();
        let mut state = SearchState {
            graph,
            options,
            nodes: &nodes,
            edges: &edges,
            adjacency: &adjacency,
            paths: &mut paths,
        };
        dfs(
            start.id.as_str(),
            &mut visited,
            &mut node_path,
            &mut edge_path,
            &mut state,
        )?;
        if paths.len() >= options.max_paths {
            break;
        }
    }
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(paths)
}

struct SearchState<'a> {
    graph: &'a AttackGraph,
    options: &'a PathOptions,
    nodes: &'a BTreeMap<&'a str, &'a crate::model::Node>,
    edges: &'a BTreeMap<&'a str, &'a crate::model::Edge>,
    adjacency: &'a BTreeMap<&'a str, Vec<&'a str>>,
    paths: &'a mut Vec<Path>,
}

fn dfs(
    current: &str,
    visited: &mut BTreeSet<String>,
    node_path: &mut Vec<String>,
    edge_path: &mut Vec<String>,
    state: &mut SearchState<'_>,
) -> Result<()> {
    if state.paths.len() >= state.options.max_paths || edge_path.len() >= state.options.max_depth {
        return Ok(());
    }
    for edge_id in state.adjacency.get(current).into_iter().flatten() {
        if state.paths.len() >= state.options.max_paths {
            break;
        }
        let edge = state.edges[edge_id];
        if visited.contains(edge.target.as_str()) {
            continue;
        }
        visited.insert(edge.target.clone());
        node_path.push(edge.target.clone());
        edge_path.push(edge.id.clone());
        let target = state.nodes[edge.target.as_str()];
        let emit = state.options.target_filter.map_or_else(
            || state.adjacency.get(edge.target.as_str()).is_none(),
            |kind| target.node_type == kind,
        );
        if emit {
            state
                .paths
                .push(make_path(state.graph, node_path, edge_path)?);
        }
        dfs(edge.target.as_str(), visited, node_path, edge_path, state)?;
        edge_path.pop();
        node_path.pop();
        visited.remove(edge.target.as_str());
    }
    Ok(())
}

fn make_path(graph: &AttackGraph, nodes: &[String], edge_ids: &[String]) -> Result<Path> {
    let edges: Vec<_> = edge_ids
        .iter()
        .map(|id| graph.edges.iter().find(|edge| &edge.id == id).unwrap())
        .collect();
    let status = if edges
        .iter()
        .any(|edge| edge.evidence.status == EdgeEvidenceStatus::NotTested)
    {
        PathStatus::NotTested
    } else if edges
        .iter()
        .any(|edge| edge.evidence.status == EdgeEvidenceStatus::Inferred)
    {
        PathStatus::Inferred
    } else {
        PathStatus::Proven
    };
    let path_nodes: Vec<_> = nodes
        .iter()
        .filter_map(|id| graph.nodes.iter().find(|node| &node.id == id))
        .collect();
    let tenants: BTreeSet<_> = edges
        .iter()
        .filter_map(|edge| edge.authority.tenant.as_deref())
        .collect();
    let impact_factors = ImpactFactors {
        cross_tenant: tenants.len() > 1,
        uses_privileged_credential: path_nodes
            .iter()
            .any(|node| node.node_type == NodeType::Credential && node.security.privileged),
        reaches_sensitive_resource: path_nodes.iter().any(|node| node.security.sensitive),
        contains_destructive_capability: path_nodes.iter().any(|node| node.security.destructive),
        contains_failed_security_property: edges
            .iter()
            .any(|edge| edge.security.verdict.as_deref() == Some("FAIL")),
        contains_authorization_mutation: edges.iter().any(|edge| edge.security.authority_mutation),
    };
    let value = serde_json::json!({"edges": edge_ids, "nodes": nodes});
    Ok(Path {
        id: format!("path:{}", digest_value(&value)?),
        nodes: nodes.to_vec(),
        edges: edge_ids.to_vec(),
        status,
        impact_factors,
    })
}
