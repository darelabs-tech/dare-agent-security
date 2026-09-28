//! Chokepoints (BLUEPRINT §7.5, task-034; MUST per Q7).
//!
//! For each target, the edges every feasible CONTROL_FAILED path to it
//! shares. They are counts over the enumerated set, flagged `partial` when
//! enumeration was cut, and never weighted or ranked.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::v2::{
    is_structural, Chokepoint, ControlState, EdgeV2, Enumeration, GuardVerdict, PathV2,
};

pub fn chokepoints(
    paths: &[PathV2],
    edges: &BTreeMap<&str, &EdgeV2>,
    enumeration: &Enumeration,
) -> Vec<Chokepoint> {
    let globally_cut = enumeration
        .stopped_by
        .iter()
        .any(|b| !matches!(b, dare_attack_graph::v2::StopBound::MaxPathsPerPair));
    let cut_targets: BTreeSet<&str> = enumeration
        .pairs_truncated
        .iter()
        .map(|p| p.target.as_str())
        .collect();
    let mut by_target: BTreeMap<&str, Vec<&PathV2>> = BTreeMap::new();
    for path in paths {
        if path.control_state == ControlState::ControlFailed {
            by_target
                .entry(path.target.as_str())
                .or_default()
                .push(path);
        }
    }
    let mut out = Vec::new();
    for (target, failed) in by_target {
        let Some(first) = failed.first() else {
            continue;
        };
        let partial = globally_cut
            || cut_targets.contains(target)
            // The listed pairs are capped; an unlisted truncated pair may
            // still name this target.
            || enumeration.pairs_truncated_count as usize > enumeration.pairs_truncated.len();
        for edge_id in &first.edges {
            if !failed.iter().all(|p| p.edges.contains(edge_id)) {
                continue;
            }
            let Some(edge) = edges.get(edge_id.as_str()) else {
                continue;
            };
            if is_structural(edge.edge_type) {
                continue;
            }
            let mut properties: Vec<String> = edge
                .guards
                .iter()
                .filter(|g| g.verdict != GuardVerdict::Pass)
                .map(|g| g.property.clone())
                .collect();
            properties.sort();
            properties.dedup();
            out.push(Chokepoint {
                target: target.to_owned(),
                edge: edge_id.clone(),
                properties,
                failed_paths: failed.len() as u32,
                partial,
            });
        }
    }
    out.sort();
    out
}
