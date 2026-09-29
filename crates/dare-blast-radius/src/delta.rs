//! Remediation delta (BLUEPRINT §6.7, RF-10, SHOULD): for each failed edge on
//! an exposed route, how many exposed targets its seed would no longer reach
//! if that edge's controls held. Counts only; never a ranking of risk.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::v2::{edge_control, EdgeControl, GuardVerdict};

use crate::{
    limits::{Bounds, MAX_DELTA_EDGES},
    model::{DeltaEdge, Exposure, SeedReport},
    reach::{initial_authority, search, Indexed, View},
    scenario::ResolvedSeed,
};

pub fn remediation_delta(
    index: &Indexed<'_>,
    seeds: &[(ResolvedSeed, &SeedReport)],
    bounds: Bounds,
    budget: &mut u64,
) -> Vec<DeltaEdge> {
    // Candidates: failed edges on exposed routes, nearest the seed first.
    let mut position: BTreeMap<String, usize> = BTreeMap::new();
    let mut seeds_of: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for (seed_index, (_, report)) in seeds.iter().enumerate() {
        for target in &report.targets {
            let Some(route) = &target.uncontained_route else {
                continue;
            };
            for (at, id) in route.edges.iter().enumerate() {
                let failed = index
                    .edge(id)
                    .is_some_and(|e| edge_control(e) == EdgeControl::Decided(GuardVerdict::Fail));
                if failed {
                    let best = position.entry(id.clone()).or_insert(at);
                    *best = (*best).min(at);
                    seeds_of.entry(id.clone()).or_default().insert(seed_index);
                }
            }
        }
    }
    let mut candidates: Vec<(usize, String)> =
        position.into_iter().map(|(id, at)| (at, id)).collect();
    candidates.sort();
    candidates.truncate(MAX_DELTA_EDGES);

    let mut out = Vec::with_capacity(candidates.len());
    for (_, id) in candidates {
        let Some(edge) = index.edge(&id) else {
            continue;
        };
        let properties: BTreeSet<String> = edge
            .guards
            .iter()
            .filter(|g| g.verdict == GuardVerdict::Fail)
            .map(|g| g.property.clone())
            .collect();
        let mut count = 0u32;
        let mut partial = false;
        for &seed_index in seeds_of.get(&id).into_iter().flatten() {
            let (seed, report) = &seeds[seed_index];
            if *budget == 0 {
                partial = true;
                continue;
            }
            let found = search(
                index,
                &seed.node,
                initial_authority(seed.kind, &seed.node),
                View::Uncontained,
                bounds,
                budget,
                Some(&id),
            );
            if found.report.truncated {
                // What a truncated recount did not reach is not known to be
                // unreachable; count nothing from it.
                partial = true;
                continue;
            }
            count += report
                .targets
                .iter()
                .filter(|t| t.exposure == Exposure::Exposed)
                .filter(|t| !found.reached.contains_key(t.node.as_str()))
                .count() as u32;
        }
        out.push(DeltaEdge {
            edge: id,
            properties: properties.into_iter().collect(),
            targets_contained_if_held: count,
            partial,
        });
    }
    out.sort_by(|a, b| {
        b.targets_contained_if_held
            .cmp(&a.targets_contained_if_held)
            .then_with(|| a.edge.cmp(&b.edge))
    });
    out
}
