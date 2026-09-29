//! Reach search (BLUEPRINT §6.3, REGRESSION R-2).
//!
//! A breadth-first search over authority states `(node, P, A)`: one search
//! per seed and view. A step is taken only when the Cycle 023 continuity rule
//! (`Authority::step`, C1–C6) explains it. The search is over **walks**: a
//! node may be entered again under a different authority, so every state
//! reachable within `max_depth` is found, and a target the uncontained view
//! does not reach truly has no uncontained walk within the bounds.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hash::{BuildHasherDefault, Hash, Hasher},
    rc::Rc,
};

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
///
/// Every id an edge can name (its source, its target and its authority's
/// principal) is interned to a `u32`, so the search carries compact
/// authority states. The mapping is injective, and the continuity rule is
/// the same one, applied through `Authority::step_by` (Cycle 025 follow-up).
pub struct Indexed<'g> {
    pub graph: &'g AttackGraphV2,
    nodes: HashMap<&'g str, &'g NodeV2>,
    edges: HashMap<&'g str, &'g EdgeV2>,
    out: HashMap<&'g str, Vec<&'g EdgeV2>>,
    ids: HashMap<&'g str, u32, BuildHasherDefault<Fx>>,
    names: Rc<[&'g str]>,
}

/// The compact authority the search carries: interned node ids.
pub type Compact = Authority<u32>;

/// Never produced for an id of the graph: every id `key` is asked for was
/// interned when the index was built.
const UNINTERNED: u32 = u32::MAX;

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
        let mut ids: HashMap<&str, u32, BuildHasherDefault<Fx>> = HashMap::default();
        let mut names = Vec::new();
        let mut intern = |id: &'g str| {
            ids.entry(id).or_insert_with(|| {
                names.push(id);
                (names.len() - 1) as u32
            });
        };
        for node in &graph.nodes {
            intern(&node.id);
        }
        for edge in &graph.edges {
            intern(&edge.source);
            intern(&edge.target);
            if let Some(principal) = edge.authority.principal.as_deref() {
                intern(principal);
            }
        }
        Self {
            graph,
            nodes,
            edges,
            out,
            ids,
            names: names.into(),
        }
    }

    /// The interned key of a node id the graph names.
    pub fn key(&self, id: &str) -> u32 {
        self.ids.get(id).copied().unwrap_or(UNINTERNED)
    }

    fn compact(&self, authority: &Authority) -> Compact {
        Compact {
            principal: authority.principal.as_deref().map(|p| self.key(p)),
            actors: authority.actors.iter().map(|a| self.key(a)).collect(),
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

/// The id of each interned key, for turning a compact state back into the
/// `String` authority the outputs and the validator use.
fn expand(names: &[&str], authority: &Compact) -> Authority {
    let name = |k: &u32| {
        names
            .get(*k as usize)
            .map_or_else(String::new, |n| (*n).to_owned())
    };
    Authority {
        principal: authority.principal.as_ref().map(name),
        actors: authority.actors.iter().map(name).collect(),
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
    pub authority: Compact,
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
    names: Rc<[&'g str]>,
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
            authorities.push(expand(&self.names, &state.authority));
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

/// FxHash (rustc's hasher): fast, not DoS-resistant, which does not matter
/// here since a bucket is always confirmed by full equality.
#[derive(Default)]
struct Fx(u64);

impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.add(u64::from_le_bytes(*word));
        }
        for &byte in rest {
            self.add(u64::from(byte));
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
}

impl Fx {
    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

fn fingerprint(node: &str, authority: &Compact) -> u64 {
    let mut hasher = Fx::default();
    node.hash(&mut hasher);
    authority.hash(&mut hasher);
    hasher.finish()
}

/// States already seen: the first state per fingerprint, then a chain
/// through the arena, each confirmed by equality. Each authority is stored
/// once, in the arena, and a state costs no allocation here.
#[derive(Default)]
struct Visited {
    head: HashMap<u64, usize, BuildHasherDefault<Fx>>,
    next: Vec<Option<usize>>,
}

impl Visited {
    fn contains(
        &self,
        states: &[StateRec<'_>],
        print: u64,
        node: &str,
        authority: &Compact,
    ) -> bool {
        let mut at = self.head.get(&print).copied();
        while let Some(i) = at {
            if states[i].node == node && states[i].authority == *authority {
                return true;
            }
            at = self.next[i];
        }
        false
    }

    /// `state` must be the next arena index.
    fn insert(&mut self, print: u64, state: usize) {
        let previous = self.head.insert(print, state);
        self.next.push(previous);
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
    let init = index.compact(&init);
    let mut found = Found {
        names: Rc::clone(&index.names),
        states: Vec::new(),
        reached: BTreeMap::new(),
        report: SearchReport::default(),
    };
    let Some(seed_node) = index.node(seed) else {
        return found;
    };
    let seed_id = seed_node.id.as_str();
    let mut visited = Visited::default();
    // The first state per node, collected unordered and sorted once.
    let mut first: HashMap<&'g str, usize, BuildHasherDefault<Fx>> = HashMap::default();
    let mut queue = VecDeque::new();
    visited.insert(fingerprint(seed_id, &init), 0);
    found.states.push(StateRec {
        node: seed_id,
        authority: init,
        depth: 0,
        parent: None,
        via: None,
    });
    queue.push_back(0usize);
    let report = &mut found.report;
    let states = &mut found.states;
    'search: while let Some(current) = queue.pop_front() {
        let node = states[current].node;
        let depth = states[current].depth;
        let outs = index.out(node);
        if depth >= bounds.max_depth {
            if !outs.is_empty() {
                report.depth_cut = true;
            }
            continue;
        }
        // A refused step leaves the authority unchanged, so one copy serves
        // every edge until a step succeeds.
        let mut scratch: Option<Compact> = None;
        for &edge in outs {
            if excluded == Some(edge.id.as_str()) {
                continue;
            }
            if view == View::Uncontained && is_held(edge) {
                report.held_edges_skipped += 1;
                continue;
            }
            let mut authority = match scratch.take() {
                Some(authority) => authority,
                None => states[current].authority.clone(),
            };
            if !authority.step_by(edge, |id| index.key(id), |id| index.node_type(id)) {
                report.refused_steps += 1;
                scratch = Some(authority);
                continue;
            }
            let target = edge.target.as_str();
            let print = fingerprint(target, &authority);
            if visited.contains(states, print, target, &authority) {
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
            let id = states.len();
            visited.insert(print, id);
            states.push(StateRec {
                node: target,
                authority,
                depth: depth + 1,
                parent: Some(current),
                via: Some(edge.id.as_str()),
            });
            if target != seed_id {
                first.entry(target).or_insert(id);
            }
            queue.push_back(id);
        }
    }
    found.reached = first.into_iter().collect();
    found.report.nodes_reached = found.reached.len() as u32;
    found
}
