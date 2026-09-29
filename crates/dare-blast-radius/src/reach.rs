//! Reach search (BLUEPRINT §6.3, REGRESSION R-2).
//!
//! A breadth-first search over authority states `(node, P, A)`: one search
//! per seed and view. A step is taken only when the Cycle 023 continuity rule
//! (`Authority::step`, C1–C6) explains it. The search is over **walks**: a
//! node may be entered again under a different authority, so every state
//! reachable within `max_depth` is found, and a target the uncontained view
//! does not reach truly has no uncontained walk within the bounds.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use dare_attack_graph::{
    v2::{edge_control, AttackGraphV2, Authority, EdgeControl, EdgeV2, GuardVerdict, NodeV2},
    NodeType,
};

use crate::{
    limits::Bounds,
    model::{SearchReport, SeedKind, StopBound},
};

/// Lookups built once per graph. Out-edges are sorted by `(target, edge id)`
/// (AD-07), so the order never depends on the input arrays.
pub struct Indexed<'g> {
    pub graph: &'g AttackGraphV2,
    nodes: HashMap<&'g str, &'g NodeV2>,
    edges: HashMap<&'g str, &'g EdgeV2>,
    out: HashMap<&'g str, Vec<&'g EdgeV2>>,
}

impl<'g> Indexed<'g> {
    pub fn new(graph: &'g AttackGraphV2) -> Self {
        let nodes = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let edges = graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();
        let mut out: HashMap<&str, Vec<&EdgeV2>> = HashMap::new();
        for edge in &graph.edges {
            out.entry(edge.source.as_str()).or_default().push(edge);
        }
        for list in out.values_mut() {
            list.sort_by(|a, b| (&a.target, &a.id).cmp(&(&b.target, &b.id)));
        }
        Self {
            graph,
            nodes,
            edges,
            out,
        }
    }

    pub fn node(&self, id: &str) -> Option<&'g NodeV2> {
        self.nodes.get(id).copied()
    }

    pub fn edge(&self, id: &str) -> Option<&'g EdgeV2> {
        self.edges.get(id).copied()
    }

    pub fn node_type(&self, id: &str) -> Option<NodeType> {
        self.node(id).map(|n| n.node_type)
    }

    pub fn out(&self, id: &str) -> &[&'g EdgeV2] {
        self.out.get(id).map_or(&[], Vec::as_slice)
    }
}

/// The initial authority of a seed (BLUEPRINT §6.2).
pub fn initial_authority(kind: SeedKind, seed: &str) -> Authority {
    match kind {
        SeedKind::PrincipalTakeover | SeedKind::CredentialLeak => Authority::acting(seed),
        SeedKind::ContentInjection => Authority::unset(),
        SeedKind::ComponentCompromise => Authority::component(seed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Structural,
    Uncontained,
}

/// True when the uncontained view refuses to cross `edge`: every guard
/// `PASS` (the Cycle 023 edge-control rule). Structural edges are exempt and
/// stay traversable.
pub fn is_held(edge: &EdgeV2) -> bool {
    edge_control(edge) == EdgeControl::Decided(GuardVerdict::Pass)
}

#[derive(Debug, Clone)]
pub struct StateRec<'g> {
    pub node: &'g str,
    pub authority: Authority,
    pub depth: u32,
    pub parent: Option<usize>,
    pub via: Option<&'g str>,
}

/// A walk from the seed: `nodes.len() == edges.len() + 1`, and
/// `authorities[i]` is the authority held on arriving at `nodes[i]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
    pub authorities: Vec<Authority>,
}

pub struct Found<'g> {
    pub states: Vec<StateRec<'g>>,
    /// The first state that reached each node: its witness (AD-07).
    pub reached: BTreeMap<&'g str, usize>,
    pub report: SearchReport,
}

impl Found<'_> {
    pub fn walk_to(&self, node: &str) -> Option<Walk> {
        let mut index = *self.reached.get(node)?;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut authorities = Vec::new();
        loop {
            let state = &self.states[index];
            nodes.push(state.node.to_owned());
            authorities.push(state.authority.clone());
            match (state.parent, state.via) {
                (Some(parent), Some(via)) => {
                    edges.push(via.to_owned());
                    index = parent;
                }
                _ => break,
            }
        }
        nodes.reverse();
        edges.reverse();
        authorities.reverse();
        Some(Walk {
            nodes,
            edges,
            authorities,
        })
    }
}

/// One search from `seed`. `budget` is the run-wide state budget, shared by
/// every search including the remediation delta; `excluded` is an edge to
/// treat as held (the delta's recount).
pub fn search<'g>(
    index: &Indexed<'g>,
    seed: &str,
    init: Authority,
    view: View,
    bounds: Bounds,
    budget: &mut u64,
    excluded: Option<&str>,
) -> Found<'g> {
    let mut found = Found {
        states: Vec::new(),
        reached: BTreeMap::new(),
        report: SearchReport::default(),
    };
    let Some(seed_node) = index.node(seed) else {
        return found;
    };
    let seed_id = seed_node.id.as_str();
    let mut visited: HashSet<(&'g str, Authority)> = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert((seed_id, init.clone()));
    found.states.push(StateRec {
        node: seed_id,
        authority: init,
        depth: 0,
        parent: None,
        via: None,
    });
    queue.push_back(0usize);
    let report = &mut found.report;
    'search: while let Some(current) = queue.pop_front() {
        let node = found.states[current].node;
        let depth = found.states[current].depth;
        let outs = index.out(node);
        if depth >= bounds.max_depth {
            if !outs.is_empty() {
                report.depth_cut = true;
            }
            continue;
        }
        for &edge in outs {
            if excluded == Some(edge.id.as_str()) {
                continue;
            }
            if view == View::Uncontained && is_held(edge) {
                report.held_edges_skipped += 1;
                continue;
            }
            let mut authority = found.states[current].authority.clone();
            if !authority.step(edge, |id| index.node_type(id)) {
                report.refused_steps += 1;
                continue;
            }
            let target = edge.target.as_str();
            let key = (target, authority);
            if visited.contains(&key) {
                continue;
            }
            if report.states_explored >= bounds.max_states {
                report.truncated = true;
                report.stopped_by = Some(StopBound::MaxStates);
                break 'search;
            }
            if *budget == 0 {
                report.truncated = true;
                report.stopped_by = Some(StopBound::MaxStatesTotal);
                break 'search;
            }
            report.states_explored += 1;
            *budget -= 1;
            let (target, authority) = key;
            visited.insert((target, authority.clone()));
            let id = found.states.len();
            found.states.push(StateRec {
                node: target,
                authority,
                depth: depth + 1,
                parent: Some(current),
                via: Some(edge.id.as_str()),
            });
            if target != seed_id {
                found.reached.entry(target).or_insert(id);
            }
            queue.push_back(id);
        }
    }
    found.report.nodes_reached = found.reached.len() as u32;
    found
}
