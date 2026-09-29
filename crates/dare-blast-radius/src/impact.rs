//! Impact facts (BLUEPRINT §6.6): counts and lists, never a score.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::NodeType;

use crate::{
    model::{Exposure, FrontierEdge, ImpactCounts, SeedReport, TargetReach, Totals, ViewImpact},
    reach::{Found, Indexed},
    scenario::ResolvedSeed,
};

/// Impact of one view (§6.6). `targets` are the targets that view reaches;
/// their witness walks come from `found`.
pub fn impact(
    index: &Indexed<'_>,
    seed: &ResolvedSeed,
    found: &Found<'_>,
    targets: &[&TargetReach],
) -> ImpactCounts {
    let mut targets_by_class = BTreeMap::new();
    let mut boundaries = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for target in targets {
        let Some(walk) = found.walk_to(&target.node) else {
            continue;
        };
        *targets_by_class.entry(target.class).or_insert(0u32) += 1;
        for id in &walk.edges {
            if let Some(edge) = index.edge(id) {
                boundaries.extend(edge.crosses_trust_boundary.iter().cloned());
            }
        }
        for principal in walk
            .authorities
            .iter()
            .filter_map(|a| a.principal.as_deref())
        {
            let privileged = index
                .node(principal)
                .is_some_and(|n| n.node_type == NodeType::Credential && n.security.privileged);
            if privileged {
                credentials.insert(principal.to_owned());
            }
        }
    }
    let tenants: BTreeSet<String> = found
        .reached
        .keys()
        .filter_map(|id| index.node(id))
        .filter_map(|n| n.security.tenant.clone())
        .filter(|t| seed.tenant.as_deref() != Some(t.as_str()))
        .collect();
    ImpactCounts {
        targets_by_class,
        tenants_reached: tenants.into_iter().collect(),
        trust_boundaries_crossed: boundaries.into_iter().collect(),
        privileged_credentials_acquired: credentials.into_iter().collect(),
    }
}

/// Both views of one seed: the structural view counts every target reached,
/// the uncontained view only the exposed ones.
pub fn view_impact(
    index: &Indexed<'_>,
    seed: &ResolvedSeed,
    structural: &Found<'_>,
    uncontained: &Found<'_>,
    targets: &[TargetReach],
) -> ViewImpact {
    let all: Vec<&TargetReach> = targets.iter().collect();
    let exposed: Vec<&TargetReach> = targets
        .iter()
        .filter(|t| t.exposure == Exposure::Exposed)
        .collect();
    ViewImpact {
        structural: impact(index, seed, structural, &all),
        uncontained: impact(index, seed, uncontained, &exposed),
    }
}

/// Totals over `(seed, target)` pairs.
pub fn totals(seeds: &[SeedReport]) -> Totals {
    let mut totals = Totals::default();
    for target in seeds.iter().flat_map(|s| &s.targets) {
        match target.exposure {
            Exposure::Exposed => {
                totals.exposed += 1;
                *totals.exposed_by_class.entry(target.class).or_insert(0) += 1;
            }
            Exposure::Contained => totals.contained += 1,
            Exposure::ContainmentUnknown => totals.containment_unknown += 1,
        }
    }
    totals
}

/// The held edges that contain at least one target, with the number of
/// `(seed, target)` pairs whose frontier lists them.
pub fn frontier(index: &Indexed<'_>, seeds: &[SeedReport]) -> Vec<FrontierEdge> {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for target in seeds.iter().flat_map(|s| &s.targets) {
        for edge in &target.frontier {
            *counts.entry(edge.as_str()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .filter_map(|(id, contained_targets)| {
            let edge = index.edge(id)?;
            let properties: BTreeSet<String> =
                edge.guards.iter().map(|g| g.property.clone()).collect();
            let evidence: BTreeSet<String> = edge
                .guards
                .iter()
                .flat_map(|g| g.evidence_ids.iter().cloned())
                .collect();
            Some(FrontierEdge {
                edge: id.to_owned(),
                properties: properties.into_iter().collect(),
                evidence_ids: evidence.into_iter().collect(),
                contained_targets,
            })
        })
        .collect()
}
