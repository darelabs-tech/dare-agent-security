//! Bounded pairwise enumeration (BLUEPRINT §7.2, task-033).
//!
//! For each (entry, target) pair, simple paths are collected level by
//! level: every path of length L before any of length L+1. Within a level
//! the order is the depth-first order over adjacency sorted by (next node
//! id, edge id), so the result never depends on input order (REGRESSION
//! R-10). Every bound that stops the search is reported.
use std::collections::BTreeMap;

use dare_attack_graph::v2::{AttackGraphV2, Enumeration, PairRef, StopBound, TargetClass};

use crate::limits::{MAX_STEPS, MAX_TRUNCATED_PAIRS_LISTED};

/// One (entry, target) pair to enumerate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairSpec {
    pub entry: String,
    pub target: String,
    pub entry_class: dare_attack_graph::v2::EntryClass,
    pub target_class: TargetClass,
}

/// A raw path: its pair and edge indices into `graph.edges`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPath {
    pub pair: usize,
    pub edges: Vec<usize>,
}

pub struct Bounds {
    pub max_path_edges: u32,
    pub max_paths: u32,
    pub max_paths_per_pair: u32,
    pub max_steps: u64,
}

struct Index<'a> {
    node: BTreeMap<&'a str, usize>,
    /// Outgoing edge indices per node, sorted by (target id, edge id).
    adjacency: Vec<Vec<usize>>,
    targets: Vec<usize>,
}

fn index(graph: &AttackGraphV2) -> Index<'_> {
    let node: BTreeMap<&str, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), i))
        .collect();
    let mut adjacency = vec![Vec::new(); graph.nodes.len()];
    let mut targets = vec![0; graph.edges.len()];
    for (e, edge) in graph.edges.iter().enumerate() {
        let (Some(&s), Some(&t)) = (
            node.get(edge.source.as_str()),
            node.get(edge.target.as_str()),
        ) else {
            continue;
        };
        adjacency[s].push(e);
        targets[e] = t;
    }
    for list in &mut adjacency {
        list.sort_by(|a, b| {
            (graph.edges[*a].target.as_str(), graph.edges[*a].id.as_str())
                .cmp(&(graph.edges[*b].target.as_str(), graph.edges[*b].id.as_str()))
        });
    }
    Index {
        node,
        adjacency,
        targets,
    }
}

struct Search<'a> {
    index: &'a Index<'a>,
    target: usize,
    want: usize,
    steps: u64,
    max_steps: u64,
    found: Vec<Vec<usize>>,
    visited: Vec<bool>,
    stack: Vec<usize>,
}

impl Search<'_> {
    /// Simple paths of exactly `remaining` more edges ending at the target.
    /// Returns false when a bound stopped the search.
    fn dfs(&mut self, at: usize, remaining: u32) -> bool {
        for &e in &self.index.adjacency[at] {
            if self.found.len() >= self.want {
                return true;
            }
            self.steps += 1;
            if self.steps > self.max_steps {
                return false;
            }
            let next = self.index.targets[e];
            if self.visited[next] {
                continue;
            }
            if next == self.target {
                if remaining == 1 {
                    let mut path = self.stack.clone();
                    path.push(e);
                    self.found.push(path);
                }
                continue;
            }
            if remaining > 1 {
                self.visited[next] = true;
                self.stack.push(e);
                let ok = self.dfs(next, remaining - 1);
                self.stack.pop();
                self.visited[next] = false;
                if !ok {
                    return false;
                }
            }
        }
        true
    }
}

/// Enumerates `pairs` in order under `bounds`.
pub fn enumerate(
    graph: &AttackGraphV2,
    pairs: &[PairSpec],
    bounds: &Bounds,
) -> (Vec<RawPath>, Enumeration) {
    let index = index(graph);
    let max_steps = bounds.max_steps.min(MAX_STEPS);
    let mut out = Vec::new();
    let mut steps = 0u64;
    let mut stopped: Vec<StopBound> = Vec::new();
    let mut exhausted = 0u32;
    let mut truncated_pairs: Vec<PairRef> = Vec::new();
    let mut truncated_count = 0u32;
    let mut halt = false;
    for (p, pair) in pairs.iter().enumerate() {
        if halt {
            break;
        }
        let (Some(&entry), Some(&target)) = (
            index.node.get(pair.entry.as_str()),
            index.node.get(pair.target.as_str()),
        ) else {
            continue;
        };
        let remaining_global = bounds.max_paths as usize - out.len();
        let per_pair = bounds.max_paths_per_pair as usize;
        let budget = per_pair.min(remaining_global);
        let mut search = Search {
            index: &index,
            target,
            // One more than the budget, to learn whether anything was cut.
            want: budget + 1,
            steps,
            max_steps,
            found: Vec::new(),
            visited: vec![false; graph.nodes.len()],
            stack: Vec::new(),
        };
        search.visited[entry] = true;
        let mut completed = true;
        for length in 1..=bounds.max_path_edges {
            if !search.dfs(entry, length) {
                completed = false;
                break;
            }
            if search.found.len() > budget {
                break;
            }
        }
        steps = search.steps;
        let mut found = search.found;
        let mut fired = None;
        if !completed {
            fired = Some(StopBound::MaxSteps);
            halt = true;
        } else if found.len() > budget {
            found.truncate(budget);
            if budget < per_pair {
                fired = Some(StopBound::MaxPaths);
                halt = true;
            } else {
                fired = Some(StopBound::MaxPathsPerPair);
            }
        }
        out.extend(found.into_iter().map(|edges| RawPath { pair: p, edges }));
        match fired {
            None => exhausted += 1,
            Some(bound) => {
                if !stopped.contains(&bound) {
                    stopped.push(bound);
                }
                truncated_count += 1;
                if truncated_pairs.len() < MAX_TRUNCATED_PAIRS_LISTED {
                    truncated_pairs.push(PairRef {
                        entry: pair.entry.clone(),
                        target: pair.target.clone(),
                        target_class: pair.target_class,
                    });
                }
            }
        }
        if out.len() >= bounds.max_paths as usize && p + 1 < pairs.len() && !halt {
            // The global budget is spent and pairs remain unenumerated.
            if !stopped.contains(&StopBound::MaxPaths) {
                stopped.push(StopBound::MaxPaths);
            }
            halt = true;
        }
    }
    stopped.sort();
    let enumeration = Enumeration {
        max_path_edges: bounds.max_path_edges,
        max_paths: bounds.max_paths,
        max_paths_per_pair: bounds.max_paths_per_pair,
        max_steps,
        steps_used: steps,
        truncated: !stopped.is_empty(),
        stopped_by: stopped,
        pairs_total: pairs.len() as u32,
        pairs_exhausted: exhausted,
        pairs_truncated_count: truncated_count,
        pairs_truncated: truncated_pairs,
    };
    (out, enumeration)
}
