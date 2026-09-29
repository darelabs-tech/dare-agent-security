//! Targets, exposure, routes and frontier (BLUEPRINT §6.4).
use std::collections::BTreeSet;

use dare_attack_graph::{
    v2::{path_control, EdgeV2, TargetClass},
    NodeType,
};

use crate::{
    model::{Exposure, Route, TargetReach},
    reach::{is_held, Found, Indexed, Walk},
    scenario::ResolvedSeed,
};

/// The candidate targets of a seed: every designated target other than the
/// seed, plus RESOURCE and DATA nodes of another tenant when the seed has a
/// tenant (BQ-4). Sorted by `(node, class)`, without duplicates.
pub fn candidates(index: &Indexed<'_>, seed: &ResolvedSeed) -> Vec<(String, TargetClass)> {
    let mut out: BTreeSet<(String, TargetClass)> = index
        .graph
        .targets
        .iter()
        .filter(|t| t.node != seed.node)
        .map(|t| (t.node.clone(), t.class))
        .collect();
    if let Some(tenant) = seed.tenant.as_deref() {
        for node in &index.graph.nodes {
            let other_tenant = node.security.tenant.as_deref().is_some_and(|t| t != tenant);
            if other_tenant
                && matches!(node.node_type, NodeType::Resource | NodeType::Data)
                && node.id != seed.node
            {
                out.insert((node.id.clone(), TargetClass::CrossTenantResource));
            }
        }
    }
    out.into_iter().collect()
}

/// A route with its Cycle 023 control fields.
pub fn route(index: &Indexed<'_>, nodes: Vec<String>, edges: Vec<String>) -> Route {
    let refs: Vec<&EdgeV2> = edges.iter().filter_map(|id| index.edge(id)).collect();
    let (control_state, failed_guards, undecided_edges) = path_control(&refs);
    Route {
        nodes,
        edges,
        control_state,
        failed_guards,
        undecided_edges,
    }
}

fn from_walk(index: &Indexed<'_>, walk: Walk) -> Route {
    route(index, walk.nodes, walk.edges)
}

/// The held edges of a route, sorted and without duplicates.
pub fn frontier_of(index: &Indexed<'_>, route: &Route) -> Vec<String> {
    let set: BTreeSet<String> = route
        .edges
        .iter()
        .filter(|id| index.edge(id).is_some_and(is_held))
        .cloned()
        .collect();
    set.into_iter().collect()
}

/// One `TargetReach` per candidate the structural view reached.
pub fn classify(
    index: &Indexed<'_>,
    seed: &ResolvedSeed,
    structural: &Found<'_>,
    uncontained: &Found<'_>,
) -> Vec<TargetReach> {
    let mut out = Vec::new();
    for (node, class) in candidates(index, seed) {
        let Some(walk) = structural.walk_to(&node) else {
            continue;
        };
        let structural_route = from_walk(index, walk);
        let (exposure, uncontained_route, frontier) = match uncontained.walk_to(&node) {
            Some(walk) => (Exposure::Exposed, Some(from_walk(index, walk)), vec![]),
            None if uncontained.report.truncated => (Exposure::ContainmentUnknown, None, vec![]),
            None => (
                Exposure::Contained,
                None,
                frontier_of(index, &structural_route),
            ),
        };
        out.push(TargetReach {
            node,
            class,
            exposure,
            structural_route,
            uncontained_route,
            frontier,
        });
    }
    out
}
