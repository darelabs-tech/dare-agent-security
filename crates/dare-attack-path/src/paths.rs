//! Path classification and the attack-paths document (BLUEPRINT §7, task-035).
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::v2::{
    impact_factors, path_control, path_id, path_status, AttackGraphV2, AttackPathsDoc, EdgeV2,
    EntryClass, Feasibility, NodeV2, PathV2, TargetClass, DOCUMENT_SCHEMA_VERSION,
    PATHS_SCHEMA_ID_V2,
};

use crate::{
    chokepoint::chokepoints,
    continuity::discontinuity,
    designate::cross_tenant_targets,
    enumerate::{enumerate, Bounds, PairSpec},
    error::{AttackPathError, Result},
    limits::{ConstructOptions, MAX_STEPS},
};

fn internal(message: &'static str) -> AttackPathError {
    AttackPathError::Internal(message)
}

/// One pair per (entry node, target node), carrying the first entry and
/// target class in enum order, so a path is reported once (REGRESSION R-11).
pub fn pairs(graph: &AttackGraphV2) -> Vec<PairSpec> {
    let nodes: BTreeMap<&str, &NodeV2> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut entry_class: BTreeMap<&str, EntryClass> = BTreeMap::new();
    for d in &graph.entry_points {
        let slot = entry_class.entry(d.node.as_str()).or_insert(d.class);
        *slot = (*slot).min(d.class);
    }
    let mut out: BTreeMap<(String, String), PairSpec> = BTreeMap::new();
    for (&entry, &class) in &entry_class {
        let mut targets: BTreeMap<&str, TargetClass> = BTreeMap::new();
        for d in &graph.targets {
            let slot = targets.entry(d.node.as_str()).or_insert(d.class);
            *slot = (*slot).min(d.class);
        }
        if let Some(node) = nodes.get(entry) {
            for id in cross_tenant_targets(node, graph.nodes.iter()) {
                if let Some((stored, _)) = nodes.get_key_value(id.as_str()) {
                    targets
                        .entry(stored)
                        .or_insert(TargetClass::CrossTenantResource);
                }
            }
        }
        for (target, target_class) in targets {
            if target == entry {
                continue;
            }
            out.insert(
                (entry.to_owned(), target.to_owned()),
                PairSpec {
                    entry: entry.to_owned(),
                    target: target.to_owned(),
                    entry_class: class,
                    target_class,
                },
            );
        }
    }
    out.into_values().collect()
}

pub fn attack_paths(graph: &AttackGraphV2, options: &ConstructOptions) -> Result<AttackPathsDoc> {
    let nodes: BTreeMap<&str, &NodeV2> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let edges: BTreeMap<&str, &EdgeV2> = graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();
    let pairs = pairs(graph);
    let bounds = Bounds {
        max_path_edges: options.max_path_edges,
        max_paths: options.max_paths,
        max_paths_per_pair: options.max_paths_per_pair,
        max_steps: MAX_STEPS,
    };
    let (raw, enumeration) = enumerate(graph, &pairs, &bounds);
    let mut feasible = Vec::new();
    let mut discontinuous = Vec::new();
    let mut seen = BTreeSet::new();
    for path in raw {
        let pair = &pairs[path.pair];
        let path_edges: Vec<&EdgeV2> = path.edges.iter().map(|&i| &graph.edges[i]).collect();
        let mut node_ids = vec![pair.entry.clone()];
        node_ids.extend(path_edges.iter().map(|e| e.target.clone()));
        let edge_ids: Vec<String> = path_edges.iter().map(|e| e.id.clone()).collect();
        let id = path_id(&node_ids, &edge_ids).map_err(|_| internal("path id"))?;
        if !seen.insert(id.clone()) {
            continue;
        }
        let path_nodes = node_ids
            .iter()
            .map(|n| {
                nodes
                    .get(n.as_str())
                    .copied()
                    .ok_or_else(|| internal("path node"))
            })
            .collect::<Result<Vec<_>>>()?;
        let entry = path_nodes[0];
        let gap = discontinuity(entry, &path_edges, |id| nodes.get(id).map(|n| n.node_type));
        let (control_state, failed_guards, undecided_edges) = path_control(&path_edges);
        let classified = PathV2 {
            id,
            status: path_status(&path_edges),
            feasibility: if gap.is_some() {
                Feasibility::Discontinuous
            } else {
                Feasibility::Feasible
            },
            discontinuity_at: gap,
            control_state,
            failed_guards,
            undecided_edges,
            entry: pair.entry.clone(),
            entry_class: pair.entry_class,
            target: pair.target.clone(),
            target_class: pair.target_class,
            impact_factors: impact_factors(&path_nodes, &path_edges),
            nodes: node_ids,
            edges: edge_ids,
        };
        if gap.is_some() {
            discontinuous.push(classified);
        } else {
            feasible.push(classified);
        }
    }
    let chokepoints = chokepoints(&feasible, &edges, &enumeration);
    Ok(AttackPathsDoc {
        schema_id: PATHS_SCHEMA_ID_V2.into(),
        schema_version: DOCUMENT_SCHEMA_VERSION.into(),
        graph_id: graph.id.clone(),
        paths: feasible,
        discontinuous_paths: discontinuous,
        chokepoints,
        enumeration,
    })
}
