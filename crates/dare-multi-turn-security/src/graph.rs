//! The strategy graph: every turn a run can ever send, fixed before it starts.
//!
//! A graph is a finite DAG of pre-authored turns. An edge says which node comes
//! next when the previous response fell into a given observation class. That
//! selection is the only adaptivity this engine has: nothing is generated, and
//! the digest of the graph — computed over sorted nodes and edges — is pinned
//! by the scenario before the first turn runs.
//!
//! [`StrategyGraph::validate`] checks, in this order, and returns the first
//! failure (Blueprint §4.4):
//!
//! 1. `schema_version == "1"`; turn content within bounds and free of hostile
//!    text (the corpus builds graphs in code, so admission cannot be assumed);
//! 2. node and edge counts;
//! 3. unique node ids and an existing root;
//! 4. known edge endpoints and one edge per `(from, class)`;
//! 5. no edge labelled `UNCLASSIFIABLE`;
//! 6. terminals have no outgoing edge, non-terminals have at least one;
//! 7. every node reachable from the root;
//! 8. acyclic (Kahn), naming the smallest node left on a cycle;
//! 9. longest root-to-terminal path within the turn bound;
//! 10. root-to-terminal path count within the path bound (saturating). A
//!     path is a sequence of nodes: parallel edges to the same successor
//!     count once;
//! 11. an approval disclosure present exactly on `APPROVAL` turns, with a
//!     well-formed digest.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::canonical::{digest, is_digest};
use crate::error::{MultiTurnError, Result};
use crate::ids::{ApprovalId, CanaryId, ClassId, NodeId};
use crate::limits::{EffectiveBounds, MAX_EDGES, MAX_NODES, MAX_TURN_BYTES};
use crate::model::{AuthorityLevel, ObservationClass, TurnRole};
use crate::schema::SUPPORTED_SCHEMA_VERSION;
use crate::source::check_text;

/// An approval disclosed to a human on an `APPROVAL` turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDisclosure {
    pub approval_id: ApprovalId,
    pub action_class: ClassId,
    pub action_digest: String,
    pub target_id: NodeId,
}

/// One pre-authored turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnTemplate {
    pub role: TurnRole,
    pub request_class: ClassId,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plants_canary: Option<CanaryId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_authority: Option<AuthorityLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalDisclosure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposes_action_class: Option<ClassId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyNode {
    pub id: NodeId,
    pub turn: TurnTemplate,
    pub terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyEdge {
    pub from: NodeId,
    pub on: ObservationClass,
    pub to: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyGraph {
    pub schema_version: String,
    pub id: NodeId,
    pub root: NodeId,
    pub nodes: Vec<StrategyNode>,
    pub edges: Vec<StrategyEdge>,
}

/// A graph that passed every rule, with its lookup tables and digest.
#[derive(Debug, Clone)]
pub struct ValidatedGraph {
    graph: StrategyGraph,
    index: BTreeMap<NodeId, usize>,
    transitions: BTreeMap<(NodeId, ObservationClass), NodeId>,
    path_count: u64,
    depth: u32,
    digest: String,
}

impl StrategyGraph {
    /// Canonical digest: object keys sorted, nodes sorted by id, edges sorted.
    /// The same strategy written in a different order has the same digest.
    pub fn digest(&self) -> Result<String> {
        let mut canonical = self.clone();
        canonical.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        canonical.edges.sort();
        digest(&canonical)
    }

    pub fn validate(&self, bounds: &EffectiveBounds) -> Result<ValidatedGraph> {
        // 1. version and content
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(MultiTurnError::Schema(
                "unsupported strategy graph version".into(),
            ));
        }
        for node in &self.nodes {
            if node.turn.content.len() > MAX_TURN_BYTES {
                return Err(MultiTurnError::InputTooLarge {
                    label: "turn content",
                    len: node.turn.content.len(),
                    max: MAX_TURN_BYTES,
                });
            }
            check_text(&node.turn.content, "turn content", true)?;
        }

        // 2. counts
        if self.nodes.is_empty() || self.nodes.len() > MAX_NODES {
            return Err(MultiTurnError::GraphLimit {
                what: "nodes",
                value: self.nodes.len() as u64,
                max: MAX_NODES as u64,
            });
        }
        if self.edges.len() > MAX_EDGES {
            return Err(MultiTurnError::GraphLimit {
                what: "edges",
                value: self.edges.len() as u64,
                max: MAX_EDGES as u64,
            });
        }

        // 3. unique ids, root
        let mut index = BTreeMap::new();
        for (position, node) in self.nodes.iter().enumerate() {
            if index.insert(node.id.clone(), position).is_some() {
                return Err(MultiTurnError::GraphDuplicateNode {
                    node: node.id.to_string(),
                });
            }
        }
        if !index.contains_key(&self.root) {
            return Err(MultiTurnError::GraphUnknownNode {
                node: self.root.to_string(),
            });
        }

        // 4. endpoints, one edge per (from, class) — 5. no UNCLASSIFIABLE edge
        let mut transitions = BTreeMap::new();
        let mut children: BTreeMap<&NodeId, Vec<&NodeId>> = BTreeMap::new();
        for edge in &self.edges {
            for end in [&edge.from, &edge.to] {
                if !index.contains_key(end) {
                    return Err(MultiTurnError::GraphUnknownNode {
                        node: end.to_string(),
                    });
                }
            }
            if transitions
                .insert((edge.from.clone(), edge.on), edge.to.clone())
                .is_some()
            {
                return Err(MultiTurnError::GraphDuplicateTransition {
                    from: edge.from.to_string(),
                    on: edge.on.as_str(),
                });
            }
            if edge.on == ObservationClass::Unclassifiable {
                return Err(MultiTurnError::GraphForbiddenEdge {
                    from: edge.from.to_string(),
                });
            }
            let successors = children.entry(&edge.from).or_default();
            // Two classes leading to the same node are one path, not two: a path
            // is a sequence of distinct nodes, which is what a run can execute.
            if !successors.contains(&&edge.to) {
                successors.push(&edge.to);
            }
        }

        // 6. terminal / dead end
        for node in &self.nodes {
            let out = children.get(&node.id).map_or(0, Vec::len);
            if node.terminal && out > 0 {
                return Err(MultiTurnError::GraphTerminalHasEdges {
                    node: node.id.to_string(),
                });
            }
            if !node.terminal && out == 0 {
                return Err(MultiTurnError::GraphDeadEnd {
                    node: node.id.to_string(),
                });
            }
        }

        // 7. reachability
        let mut reached = BTreeSet::from([&self.root]);
        let mut queue = VecDeque::from([&self.root]);
        while let Some(current) = queue.pop_front() {
            for child in children.get(current).into_iter().flatten() {
                if reached.insert(*child) {
                    queue.push_back(*child);
                }
            }
        }
        if let Some(node) = self.nodes.iter().find(|n| !reached.contains(&n.id)) {
            return Err(MultiTurnError::GraphUnreachableNode {
                node: node.id.to_string(),
            });
        }

        // 8. acyclic (Kahn over distinct child edges)
        let mut indegree: BTreeMap<&NodeId, usize> =
            self.nodes.iter().map(|n| (&n.id, 0)).collect();
        for targets in children.values() {
            for target in targets {
                *indegree.entry(*target).or_default() += 1;
            }
        }
        let mut ready: VecDeque<&NodeId> = indegree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(n, _)| *n)
            .collect();
        let mut order = Vec::with_capacity(self.nodes.len());
        while let Some(current) = ready.pop_front() {
            order.push(current);
            for child in children.get(current).into_iter().flatten() {
                let degree = indegree.entry(*child).or_default();
                *degree -= 1;
                if *degree == 0 {
                    ready.push_back(*child);
                }
            }
        }
        if order.len() != self.nodes.len() {
            let done: BTreeSet<&NodeId> = order.iter().copied().collect();
            let smallest = self
                .nodes
                .iter()
                .map(|n| &n.id)
                .filter(|id| !done.contains(id))
                .min()
                .map(ToString::to_string)
                .unwrap_or_default();
            return Err(MultiTurnError::GraphCycle { node: smallest });
        }

        // 9 + 10. depth and path count, children before parents
        let mut depth: BTreeMap<&NodeId, u32> = BTreeMap::new();
        let mut paths: BTreeMap<&NodeId, u64> = BTreeMap::new();
        for id in order.iter().rev() {
            let kids = children.get(id).map(Vec::as_slice).unwrap_or(&[]);
            if kids.is_empty() {
                depth.insert(id, 1);
                paths.insert(id, 1);
            } else {
                let d = kids
                    .iter()
                    .filter_map(|k| depth.get(k))
                    .max()
                    .copied()
                    .unwrap_or(0);
                depth.insert(id, d.saturating_add(1));
                let p = kids
                    .iter()
                    .filter_map(|k| paths.get(k))
                    .fold(0u64, |acc, n| acc.saturating_add(*n));
                paths.insert(id, p);
            }
        }
        let root_depth = depth.get(&self.root).copied().unwrap_or(0);
        if root_depth > bounds.max_turns_per_conversation {
            return Err(MultiTurnError::GraphLimit {
                what: "depth",
                value: u64::from(root_depth),
                max: u64::from(bounds.max_turns_per_conversation),
            });
        }
        let path_count = paths.get(&self.root).copied().unwrap_or(0);
        if path_count > bounds.max_paths {
            return Err(MultiTurnError::GraphLimit {
                what: "paths",
                value: path_count,
                max: bounds.max_paths,
            });
        }

        // 11. approvals
        for node in &self.nodes {
            let consistent = match (&node.turn.role, &node.turn.approval) {
                (TurnRole::Approval, Some(approval)) => is_digest(&approval.action_digest),
                (TurnRole::Approval, None) => false,
                (_, Some(_)) => false,
                (_, None) => true,
            };
            if !consistent {
                return Err(MultiTurnError::GraphInvalidApproval {
                    node: node.id.to_string(),
                });
            }
        }

        Ok(ValidatedGraph {
            digest: self.digest()?,
            graph: self.clone(),
            index,
            transitions,
            path_count,
            depth: root_depth,
        })
    }
}

impl ValidatedGraph {
    pub fn graph(&self) -> &StrategyGraph {
        &self.graph
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn path_count(&self) -> u64 {
        self.path_count
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn root(&self) -> &StrategyNode {
        // The root is checked to exist in `validate`, so the index lookup holds.
        &self.graph.nodes[self.index[&self.graph.root]]
    }

    pub fn node(&self, id: &NodeId) -> Option<&StrategyNode> {
        self.index.get(id).map(|i| &self.graph.nodes[*i])
    }

    /// The node an observation class selects from `from`, if the graph has one.
    pub fn transition(&self, from: &NodeId, on: ObservationClass) -> Option<&StrategyNode> {
        self.transitions
            .get(&(from.clone(), on))
            .and_then(|to| self.node(to))
    }

    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.index.keys()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::ObservationClass::*;

    pub(crate) fn id(s: &str) -> NodeId {
        NodeId::new(s).expect("valid id")
    }

    pub(crate) fn node(name: &str, terminal: bool) -> StrategyNode {
        StrategyNode {
            id: id(name),
            terminal,
            turn: TurnTemplate {
                role: TurnRole::User,
                request_class: ClassId::new("c-ask").expect("valid"),
                content: format!("turn {name}"),
                plants_canary: None,
                claimed_authority: None,
                approval: None,
                proposes_action_class: None,
            },
        }
    }

    pub(crate) fn edge(from: &str, on: ObservationClass, to: &str) -> StrategyEdge {
        StrategyEdge {
            from: id(from),
            on,
            to: id(to),
        }
    }

    pub(crate) fn graph(nodes: Vec<StrategyNode>, edges: Vec<StrategyEdge>) -> StrategyGraph {
        StrategyGraph {
            schema_version: "1".into(),
            id: id("g"),
            root: id("a"),
            nodes,
            edges,
        }
    }

    fn check(g: &StrategyGraph) -> Result<ValidatedGraph> {
        g.validate(&EffectiveBounds::default())
    }

    fn chain(n: usize) -> StrategyGraph {
        let names: Vec<String> = (0..n)
            .map(|i| {
                if i == 0 {
                    "a".into()
                } else {
                    format!("n{i:03}")
                }
            })
            .collect();
        let nodes = names
            .iter()
            .enumerate()
            .map(|(i, s)| node(s, i + 1 == n))
            .collect();
        let edges = names
            .windows(2)
            .map(|w| edge(&w[0], Refused, &w[1]))
            .collect();
        graph(nodes, edges)
    }

    #[test]
    fn rule_1_version_and_hostile_content() {
        let mut g = chain(2);
        g.schema_version = "2".into();
        assert!(matches!(check(&g), Err(MultiTurnError::Schema(_))));
        let mut g = chain(2);
        g.nodes[0].turn.content = "x\u{202e}".into();
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::ForbiddenCharacter { .. })
        ));
        let mut g = chain(2);
        g.nodes[0].turn.content = "y".repeat(MAX_TURN_BYTES + 1);
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn rule_2_node_and_edge_counts() {
        let g = graph(vec![], vec![]);
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::GraphLimit { what: "nodes", .. })
        ));
        let g = chain(MAX_NODES + 1);
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::GraphLimit { what: "nodes", .. })
        ));
        let mut g = chain(2);
        g.edges = (0..=MAX_EDGES)
            .map(|_| edge("a", Refused, "n001"))
            .collect();
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::GraphLimit { what: "edges", .. })
        ));
    }

    #[test]
    fn rule_3_duplicate_node_and_missing_root() {
        let g = graph(vec![node("a", true), node("a", true)], vec![]);
        assert!(matches!(
            check(&g),
            Err(MultiTurnError::GraphDuplicateNode { .. })
        ));
        let mut g = chain(2);
        g.root = id("zz");
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphUnknownNode { node: "zz".into() })
        );
    }

    #[test]
    fn rule_4_unknown_endpoint_and_duplicate_transition() {
        let g = graph(
            vec![node("a", false), node("b", true)],
            vec![edge("a", Refused, "zz")],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphUnknownNode { node: "zz".into() })
        );
        let g = graph(
            vec![node("a", false), node("b", true), node("c", true)],
            vec![edge("a", Refused, "b"), edge("a", Refused, "c")],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphDuplicateTransition {
                from: "a".into(),
                on: "REFUSED"
            })
        );
    }

    #[test]
    fn rule_5_unclassifiable_never_selects_a_node() {
        let g = graph(
            vec![node("a", false), node("b", true)],
            vec![edge("a", Unclassifiable, "b")],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphForbiddenEdge { from: "a".into() })
        );
    }

    #[test]
    fn rule_6_terminal_with_edges_and_dead_end() {
        let g = graph(
            vec![node("a", true), node("b", true)],
            vec![edge("a", Refused, "b")],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphTerminalHasEdges { node: "a".into() })
        );
        let g = graph(vec![node("a", false)], vec![]);
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphDeadEnd { node: "a".into() })
        );
    }

    #[test]
    fn rule_7_unreachable_node() {
        let g = graph(
            vec![node("a", false), node("b", true), node("orphan", true)],
            vec![edge("a", Refused, "b")],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphUnreachableNode {
                node: "orphan".into()
            })
        );
    }

    #[test]
    fn rule_8_a_cycle_names_its_smallest_node() {
        let g = graph(
            vec![
                node("a", false),
                node("m", false),
                node("k", false),
                node("t", true),
            ],
            vec![
                edge("a", Refused, "m"),
                edge("m", Refused, "k"),
                edge("k", Refused, "m"),
                edge("k", Complied, "t"),
            ],
        );
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphCycle { node: "k".into() })
        );
    }

    #[test]
    fn rule_9_depth_bound_is_the_turn_bound() {
        assert_eq!(check(&chain(32)).expect("32 turns fit").depth(), 32);
        assert!(matches!(
            check(&chain(33)),
            Err(MultiTurnError::GraphLimit {
                what: "depth",
                value: 33,
                ..
            })
        ));
        let lowered = EffectiveBounds {
            max_turns_per_conversation: 3,
            ..EffectiveBounds::default()
        };
        assert!(chain(4).validate(&lowered).is_err());
    }

    /// A diamond ladder: each rung splits on REFUSED/COMPLIED and rejoins,
    /// so `rungs` rungs give 2^rungs paths.
    fn ladder(rungs: usize) -> StrategyGraph {
        let mut nodes = vec![node("a", false)];
        let mut edges = vec![];
        let mut join = "a".to_string();
        for r in 0..rungs {
            let (l, rr, j) = (format!("l{r}"), format!("r{r}"), format!("j{r}"));
            nodes.push(node(&l, false));
            nodes.push(node(&rr, false));
            nodes.push(node(&j, r + 1 == rungs));
            edges.push(edge(&join, Refused, &l));
            edges.push(edge(&join, Complied, &rr));
            edges.push(edge(&l, Refused, &j));
            edges.push(edge(&rr, Refused, &j));
            join = j;
        }
        graph(nodes, edges)
    }

    #[test]
    fn rule_10_path_counts_match_hand_computed_values() {
        // single node, chain, fan-out of 3, 5-rung ladder (2^5), 6-rung ladder (2^6)
        let fan = graph(
            vec![
                node("a", false),
                node("x", true),
                node("y", true),
                node("z", true),
            ],
            vec![
                edge("a", Refused, "x"),
                edge("a", Complied, "y"),
                edge("a", Partial, "z"),
            ],
        );
        let cases: [(StrategyGraph, u64); 5] = [
            (chain(1), 1),
            (chain(10), 1),
            (fan, 3),
            (ladder(5), 32),
            (ladder(6), 64),
        ];
        for (g, expected) in cases {
            assert_eq!(check(&g).expect("valid").path_count(), expected);
        }
        assert!(matches!(
            check(&ladder(7)),
            Err(MultiTurnError::GraphLimit {
                what: "paths",
                value: 128,
                ..
            })
        ));
    }

    #[test]
    fn rule_10_path_count_saturates_instead_of_overflowing() {
        // With the bounds lifted, 2^63 paths is exact and 2^64 saturates at
        // u64::MAX instead of wrapping to 0 (which would read as "tiny graph").
        let bounds = EffectiveBounds {
            max_turns_per_conversation: u32::MAX,
            max_paths: u64::MAX,
            ..EffectiveBounds::default()
        };
        let exact = ladder(63).validate(&bounds).expect("190 nodes fit");
        assert_eq!(exact.path_count(), 1u64 << 63);
        let saturated = ladder(64).validate(&bounds).expect("193 nodes fit");
        assert_eq!(saturated.path_count(), u64::MAX);
        // Under the real bounds the same graph is refused on depth first.
        assert!(matches!(
            check(&ladder(64)),
            Err(MultiTurnError::GraphLimit { what: "depth", .. })
        ));
    }

    #[test]
    fn rule_11_approval_must_match_the_role() {
        let mut g = chain(2);
        g.nodes[0].turn.role = TurnRole::Approval;
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphInvalidApproval { node: "a".into() })
        );
        let disclosure = ApprovalDisclosure {
            approval_id: ApprovalId::new("ap1").expect("valid"),
            action_class: ClassId::new("transfer").expect("valid"),
            action_digest: format!("sha256:{}", "0".repeat(64)),
            target_id: id("acct-1"),
        };
        let mut g = chain(2);
        g.nodes[0].turn.approval = Some(disclosure.clone());
        assert_eq!(
            check(&g).err(),
            Some(MultiTurnError::GraphInvalidApproval { node: "a".into() })
        );
        let mut g = chain(2);
        g.nodes[0].turn.role = TurnRole::Approval;
        g.nodes[0].turn.approval = Some(ApprovalDisclosure {
            action_digest: "sha256:bad".into(),
            ..disclosure.clone()
        });
        assert!(check(&g).is_err());
        g.nodes[0].turn.approval = Some(disclosure);
        assert!(check(&g).is_ok());
    }

    #[test]
    fn rule_10_parallel_edges_to_one_successor_are_one_path() {
        let g = graph(
            vec![node("a", false), node("b", true)],
            vec![
                edge("a", Refused, "b"),
                edge("a", Deflected, "b"),
                edge("a", Partial, "b"),
            ],
        );
        assert_eq!(check(&g).expect("valid").path_count(), 1);
    }

    #[test]
    fn transitions_follow_declared_edges_only() {
        let g = check(&ladder(1)).expect("valid");
        assert_eq!(g.root().id, id("a"));
        assert_eq!(
            g.transition(&id("a"), Refused).map(|n| n.id.clone()),
            Some(id("l0"))
        );
        assert_eq!(
            g.transition(&id("a"), Complied).map(|n| n.id.clone()),
            Some(id("r0"))
        );
        assert!(g.transition(&id("a"), Deflected).is_none());
        assert!(g.transition(&id("a"), Unclassifiable).is_none());
    }

    #[test]
    fn the_digest_is_stable_across_runs_and_declaration_order() {
        let g = ladder(3);
        let first = check(&g).expect("valid").digest().to_owned();
        for _ in 0..10 {
            assert_eq!(check(&g).expect("valid").digest(), first);
        }
        let mut shuffled = g.clone();
        shuffled.nodes.reverse();
        shuffled.edges.reverse();
        assert_eq!(shuffled.digest().expect("digest"), first);
        let json = serde_json::to_string(&g).expect("json");
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("json");
        if let Some(edges) = value.as_object_mut().expect("object").remove("edges") {
            value["edges"] = edges; // re-inserted last: a different key order in the source
        }
        let reparsed: StrategyGraph = serde_json::from_value(value).expect("parse");
        assert_eq!(
            reparsed.digest().expect("digest"),
            first,
            "key order is irrelevant"
        );
        let mut changed = g;
        changed.nodes[0].turn.content.push('!');
        assert_ne!(changed.digest().expect("digest"), first, "content is bound");
    }
}
