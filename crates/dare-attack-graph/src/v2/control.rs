//! Control state of a path (BLUEPRINT §7.4).
//!
//! The rule lives here, next to `validate_paths_v2`, so the validator can
//! recompute it and a document can never claim a better state than its
//! guards support.
use crate::edge::EdgeType;

use super::model::{ControlState, EdgeV2, GuardRef, GuardVerdict};

/// How one edge contributes to its path's control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeControl {
    /// Structural edge; no property can guard it (BQ-1).
    Exempt,
    /// A non-structural edge with no guard.
    Unassessed,
    /// The Cycle 018 aggregate of the edge's guards.
    Decided(GuardVerdict),
}

/// `BELONGS_TO_TENANT` and `ENFORCED_BY` state facts, not accesses (BQ-1).
pub fn is_structural(edge_type: EdgeType) -> bool {
    matches!(edge_type, EdgeType::BelongsToTenant | EdgeType::EnforcedBy)
}

pub fn edge_control(edge: &EdgeV2) -> EdgeControl {
    if is_structural(edge.edge_type) {
        return EdgeControl::Exempt;
    }
    edge.guards
        .iter()
        .map(|guard| guard.verdict)
        .reduce(GuardVerdict::worst)
        .map_or(EdgeControl::Unassessed, EdgeControl::Decided)
}

/// The state of a path plus the guards that failed and the edges left
/// undecided, both sorted.
pub fn path_control(edges: &[&EdgeV2]) -> (ControlState, Vec<GuardRef>, Vec<String>) {
    let mut failed = Vec::new();
    let mut undecided = Vec::new();
    for edge in edges {
        match edge_control(edge) {
            EdgeControl::Exempt | EdgeControl::Decided(GuardVerdict::Pass) => {}
            EdgeControl::Decided(GuardVerdict::Fail) => {
                failed.extend(
                    edge.guards
                        .iter()
                        .filter(|guard| guard.verdict == GuardVerdict::Fail)
                        .map(|guard| GuardRef {
                            edge: edge.id.clone(),
                            property: guard.property.clone(),
                            artifact_index: guard.artifact_index,
                        }),
                );
            }
            EdgeControl::Unassessed
            | EdgeControl::Decided(GuardVerdict::Error | GuardVerdict::Inconclusive) => {
                undecided.push(edge.id.clone());
            }
        }
    }
    failed.sort();
    failed.dedup();
    undecided.sort();
    undecided.dedup();
    let state = if !failed.is_empty() {
        ControlState::ControlFailed
    } else if !undecided.is_empty() {
        ControlState::ControlUndecided
    } else {
        ControlState::ControlsHeld
    };
    (state, failed, undecided)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evidence::{EdgeEvidence, EdgeEvidenceStatus},
        v2::model::{Guard, GuardScope},
    };

    fn edge(id: usize, edge_type: EdgeType, guard: Option<GuardVerdict>) -> EdgeV2 {
        EdgeV2 {
            id: format!("edge:{id:064x}"),
            edge_type,
            source: "node:agent:a".into(),
            target: "node:tool:b".into(),
            authority: Default::default(),
            evidence: EdgeEvidence {
                status: EdgeEvidenceStatus::Observed,
                evidence_ids: vec!["ev".into()],
                rationale: None,
                source_facts: vec![],
                reason: None,
            },
            guards: guard
                .map(|verdict| Guard {
                    property: "AGENT.TOOL.AUTHORIZATION_BOUNDARY".into(),
                    verdict,
                    evidence_ids: vec!["ev".into()],
                    scope: GuardScope::Run,
                    artifact_index: 0,
                })
                .into_iter()
                .collect(),
            authority_mutation: false,
            crosses_trust_boundary: vec![],
            provenance: vec![],
        }
    }

    /// Every combination of up to four edges over the five per-edge states:
    /// the path state is never better than its weakest edge.
    #[test]
    fn the_state_is_never_better_than_the_weakest_edge() {
        let states = [
            None,
            Some(GuardVerdict::Pass),
            Some(GuardVerdict::Fail),
            Some(GuardVerdict::Inconclusive),
            Some(GuardVerdict::Error),
        ];
        let mut checked = 0;
        for length in 1..=4u32 {
            for combo in 0..5usize.pow(length) {
                let mut code = combo;
                let edges: Vec<EdgeV2> = (0..length as usize)
                    .map(|index| {
                        let state = states[code % 5];
                        code /= 5;
                        edge(index, EdgeType::Calls, state)
                    })
                    .collect();
                let refs: Vec<&EdgeV2> = edges.iter().collect();
                let (state, failed, undecided) = path_control(&refs);
                let any_fail = edges
                    .iter()
                    .any(|e| e.guards.iter().any(|g| g.verdict == GuardVerdict::Fail));
                let any_open = edges.iter().any(|e| {
                    e.guards.is_empty()
                        || e.guards.iter().any(|g| {
                            matches!(g.verdict, GuardVerdict::Error | GuardVerdict::Inconclusive)
                        })
                });
                let expected = if any_fail {
                    ControlState::ControlFailed
                } else if any_open {
                    ControlState::ControlUndecided
                } else {
                    ControlState::ControlsHeld
                };
                assert_eq!(state, expected);
                assert_eq!(any_fail, !failed.is_empty());
                if !any_fail {
                    assert_eq!(any_open, !undecided.is_empty());
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 5 + 25 + 125 + 625);
    }

    #[test]
    fn structural_edges_need_no_guard_but_other_unguarded_edges_do() {
        let tenant = edge(1, EdgeType::BelongsToTenant, None);
        let enforced = edge(2, EdgeType::EnforcedBy, None);
        let held = edge(3, EdgeType::Reads, Some(GuardVerdict::Pass));
        assert_eq!(
            path_control(&[&held, &tenant, &enforced]).0,
            ControlState::ControlsHeld
        );
        let bare = edge(4, EdgeType::Reads, None);
        let (state, _, undecided) = path_control(&[&held, &bare]);
        assert_eq!(state, ControlState::ControlUndecided);
        assert_eq!(undecided, vec![bare.id.clone()]);
    }

    #[test]
    fn one_failing_guard_among_passing_guards_fails_the_edge() {
        let mut mixed = edge(5, EdgeType::Calls, Some(GuardVerdict::Pass));
        mixed.guards.push(Guard {
            property: "AGENT.TOOL.CHAIN_BOUNDARY".into(),
            verdict: GuardVerdict::Fail,
            evidence_ids: vec!["ev2".into()],
            scope: GuardScope::Entity,
            artifact_index: 1,
        });
        let (state, failed, _) = path_control(&[&mixed]);
        assert_eq!(state, ControlState::ControlFailed);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].property, "AGENT.TOOL.CHAIN_BOUNDARY");
    }
}
