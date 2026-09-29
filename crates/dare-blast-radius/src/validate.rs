//! Document invariants (BLUEPRINT §4.5). A document that breaks one is an
//! internal error: the engine never writes it.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::{
    v2::{edge_control, path_control, AttackGraphV2, EdgeControl, EdgeV2, GuardVerdict},
    NodeType,
};

use crate::{
    error::{BlastError, Result},
    impact::frontier,
    impact::totals,
    limits::{MAX_DELTA_EDGES, MAX_DEPTH, MAX_STATES_PER_SEARCH, MAX_STATES_TOTAL},
    model::{
        BlastRadiusDoc, Exposure, ImpactCounts, Route, SeedReport, StopBound, TargetReach,
        BLAST_RADIUS_SCHEMA_ID, BLAST_RADIUS_SCHEMA_VERSION,
    },
    reach::{initial_authority, is_held, Indexed},
    scenario::kind_fits,
};

fn fail<T>(why: &'static str) -> Result<T> {
    Err(BlastError::Internal(why))
}

fn ensure(ok: bool, why: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        fail(why)
    }
}

fn sorted_unique<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}

pub fn validate_blast_radius(graph: &AttackGraphV2, doc: &BlastRadiusDoc) -> Result<()> {
    let index = Indexed::new(graph);
    header(graph, doc)?;
    for seed in &doc.seeds {
        seed_report(&index, doc, seed)?;
    }
    counts(&index, doc)?;
    order(doc)
}

/// Invariant 1, plus the bounds the document records.
fn header(graph: &AttackGraphV2, doc: &BlastRadiusDoc) -> Result<()> {
    ensure(doc.graph_id == graph.id, "invariant 1: graph_id")?;
    ensure(
        doc.schema_id == BLAST_RADIUS_SCHEMA_ID
            && doc.schema_version == BLAST_RADIUS_SCHEMA_VERSION,
        "invariant 1: schema id or version",
    )?;
    let b = &doc.bounds;
    ensure(
        (1..=MAX_DEPTH).contains(&b.max_depth)
            && (1..=MAX_STATES_PER_SEARCH).contains(&b.max_states)
            && b.max_states_total == MAX_STATES_TOTAL
            && b.max_delta_edges as usize == MAX_DELTA_EDGES,
        "invariant 1: bounds",
    )
}

fn seed_report(index: &Indexed<'_>, doc: &BlastRadiusDoc, seed: &SeedReport) -> Result<()> {
    let node = index
        .node(&seed.node)
        .map_or_else(|| fail("invariant 2: unknown seed node"), Ok)?;
    ensure(
        kind_fits(seed.kind, node.node_type),
        "invariant 2: seed kind",
    )?;
    ensure(
        seed.tenant == node.security.tenant,
        "invariant 2: seed tenant",
    )?;
    ensure(
        seed.structural.held_edges_skipped == 0,
        "invariant 8: structural view skipped a held edge",
    )?;
    for report in [&seed.structural, &seed.uncontained] {
        ensure(
            report.truncated == report.stopped_by.is_some(),
            "invariant 8: truncated and stopped_by disagree",
        )?;
    }
    for target in &seed.targets {
        ensure(
            target.node != seed.node,
            "invariant 2: seed is its own target",
        )?;
        ensure(
            index.node(&target.node).is_some(),
            "invariant 2: unknown target node",
        )?;
        route(index, doc, seed, target, &target.structural_route, false)?;
        if let Some(open) = &target.uncontained_route {
            route(index, doc, seed, target, open, true)?;
        }
        exposure(seed, target)?;
        target_frontier(index, target)?;
    }
    impact_of(index, seed, &seed.impact.structural, false)?;
    impact_of(index, seed, &seed.impact.uncontained, true)
}

/// Invariants 2 to 5 for one route.
fn route(
    index: &Indexed<'_>,
    doc: &BlastRadiusDoc,
    seed: &SeedReport,
    target: &TargetReach,
    route: &Route,
    uncontained: bool,
) -> Result<()> {
    ensure(
        route.nodes.len() == route.edges.len() + 1
            && !route.edges.is_empty()
            && route.edges.len() <= doc.bounds.max_depth as usize,
        "invariant 2: route length",
    )?;
    ensure(
        route.nodes.first() == Some(&seed.node) && route.nodes.last() == Some(&target.node),
        "invariant 2: route ends",
    )?;
    let mut edges: Vec<&EdgeV2> = Vec::with_capacity(route.edges.len());
    for (i, id) in route.edges.iter().enumerate() {
        let edge = index
            .edge(id)
            .map_or_else(|| fail("invariant 2: unknown route edge"), Ok)?;
        ensure(
            edge.source == route.nodes[i] && edge.target == route.nodes[i + 1],
            "invariant 2: route is not a walk",
        )?;
        edges.push(edge);
    }
    // Invariant 3: every step is explained from the seed's initial authority.
    let mut authority = initial_authority(seed.kind, &seed.node);
    for edge in &edges {
        ensure(
            authority.step(edge, |id| index.node_type(id)),
            "invariant 3: route breaks continuity",
        )?;
    }
    // Invariant 4.
    let (state, failed, undecided) = path_control(&edges);
    ensure(
        route.control_state == state
            && route.failed_guards == failed
            && route.undecided_edges == undecided,
        "invariant 4: control fields",
    )?;
    // Invariant 5.
    if uncontained {
        ensure(
            !edges.iter().any(|e| is_held(e)),
            "invariant 5: uncontained route crosses a held edge",
        )?;
    }
    Ok(())
}

/// Invariant 6.
fn exposure(seed: &SeedReport, target: &TargetReach) -> Result<()> {
    let ok = match target.exposure {
        Exposure::Exposed => target.uncontained_route.is_some(),
        Exposure::Contained => {
            target.uncontained_route.is_none()
                && !seed.uncontained.truncated
                && !target.frontier.is_empty()
        }
        Exposure::ContainmentUnknown => {
            target.uncontained_route.is_none() && seed.uncontained.truncated
        }
    };
    ensure(ok, "invariant 6: exposure")
}

/// Invariant 7 (only a `Contained` target lists its frontier, §4.4).
fn target_frontier(index: &Indexed<'_>, target: &TargetReach) -> Result<()> {
    let want: BTreeSet<&String> = if target.exposure == Exposure::Contained {
        target
            .structural_route
            .edges
            .iter()
            .filter(|id| {
                index
                    .edge(id)
                    .is_some_and(|e| edge_control(e) == EdgeControl::Decided(GuardVerdict::Pass))
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    let got: Vec<&String> = target.frontier.iter().collect();
    ensure(
        got == want.into_iter().collect::<Vec<_>>(),
        "invariant 7: frontier",
    )
}

/// Invariant 8 for one view's impact. `tenants_reached` covers nodes the
/// document does not list, so it is checked as a superset of the tenants on
/// the view's routes (REGRESSION R-4).
fn impact_of(
    index: &Indexed<'_>,
    seed: &SeedReport,
    counts: &ImpactCounts,
    uncontained: bool,
) -> Result<()> {
    let mut by_class = BTreeMap::new();
    let mut boundaries = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    let mut tenants = BTreeSet::new();
    for target in &seed.targets {
        let route = if uncontained {
            match &target.uncontained_route {
                Some(route) => route,
                None => continue,
            }
        } else {
            &target.structural_route
        };
        *by_class.entry(target.class).or_insert(0u32) += 1;
        let mut authority = initial_authority(seed.kind, &seed.node);
        let mut principals = vec![authority.principal.clone()];
        for id in &route.edges {
            let Some(edge) = index.edge(id) else {
                return fail("invariant 2: unknown route edge");
            };
            boundaries.extend(edge.crosses_trust_boundary.iter().cloned());
            authority.step(edge, |n| index.node_type(n));
            principals.push(authority.principal.clone());
        }
        for principal in principals.into_iter().flatten() {
            if index
                .node(&principal)
                .is_some_and(|n| n.node_type == NodeType::Credential && n.security.privileged)
            {
                credentials.insert(principal);
            }
        }
        for node in route.nodes.iter().skip(1) {
            if let Some(tenant) = index.node(node).and_then(|n| n.security.tenant.clone()) {
                if seed.tenant.as_ref() != Some(&tenant) {
                    tenants.insert(tenant);
                }
            }
        }
    }
    ensure(
        counts.targets_by_class == by_class,
        "invariant 8: targets_by_class",
    )?;
    ensure(
        counts.trust_boundaries_crossed == boundaries.into_iter().collect::<Vec<_>>(),
        "invariant 8: trust_boundaries_crossed",
    )?;
    ensure(
        counts.privileged_credentials_acquired == credentials.into_iter().collect::<Vec<_>>(),
        "invariant 8: privileged_credentials_acquired",
    )?;
    let reached: BTreeSet<&String> = counts.tenants_reached.iter().collect();
    ensure(
        tenants.iter().all(|t| reached.contains(t))
            && seed
                .tenant
                .as_ref()
                .is_none_or(|own| !reached.contains(own)),
        "invariant 8: tenants_reached",
    )
}

/// Invariant 8 at document level.
fn counts(index: &Indexed<'_>, doc: &BlastRadiusDoc) -> Result<()> {
    ensure(doc.totals == totals(&doc.seeds), "invariant 8: totals")?;
    ensure(
        doc.frontier == frontier(index, &doc.seeds),
        "invariant 8: frontier",
    )?;
    let search_stops: BTreeSet<StopBound> = doc
        .seeds
        .iter()
        .flat_map(|s| [s.structural.stopped_by, s.uncontained.stopped_by])
        .flatten()
        .collect();
    let any_search = doc
        .seeds
        .iter()
        .any(|s| s.structural.truncated || s.uncontained.truncated);
    let stops: BTreeSet<StopBound> = doc.stopped_by.iter().copied().collect();
    // A budget that ran out in the delta also truncates the run; it leaves a
    // partial delta entry behind.
    let delta_budget = stops.contains(&StopBound::MaxStatesTotal)
        && !search_stops.contains(&StopBound::MaxStatesTotal);
    ensure(
        !delta_budget || doc.remediation_delta.iter().any(|d| d.partial),
        "invariant 8: stopped_by",
    )?;
    let mut want = search_stops;
    if delta_budget {
        want.insert(StopBound::MaxStatesTotal);
    }
    ensure(stops == want, "invariant 8: stopped_by")?;
    ensure(
        doc.truncated == (any_search || delta_budget),
        "invariant 8: truncated",
    )?;
    for delta in &doc.remediation_delta {
        let edge = index
            .edge(&delta.edge)
            .map_or_else(|| fail("invariant 2: unknown delta edge"), Ok)?;
        ensure(
            edge_control(edge) == EdgeControl::Decided(GuardVerdict::Fail),
            "invariant 8: delta edge did not fail",
        )?;
        let properties: BTreeSet<&String> = edge
            .guards
            .iter()
            .filter(|g| g.verdict == GuardVerdict::Fail)
            .map(|g| &g.property)
            .collect();
        ensure(
            delta.properties.iter().collect::<Vec<_>>()
                == properties.into_iter().collect::<Vec<_>>(),
            "invariant 8: delta properties",
        )?;
    }
    ensure(
        doc.remediation_delta.len() <= MAX_DELTA_EDGES,
        "invariant 8: delta above its bound",
    )
}

/// Invariant 9.
fn order(doc: &BlastRadiusDoc) -> Result<()> {
    let seeds: Vec<(&String, _)> = doc.seeds.iter().map(|s| (&s.node, s.kind)).collect();
    ensure(sorted_unique(&seeds), "invariant 9: seeds")?;
    for seed in &doc.seeds {
        let targets: Vec<(&String, _)> = seed.targets.iter().map(|t| (&t.node, t.class)).collect();
        ensure(sorted_unique(&targets), "invariant 9: targets")?;
        for target in &seed.targets {
            ensure(
                sorted_unique(&target.frontier),
                "invariant 9: target frontier",
            )?;
        }
        for counts in [&seed.impact.structural, &seed.impact.uncontained] {
            ensure(
                sorted_unique(&counts.tenants_reached)
                    && sorted_unique(&counts.trust_boundaries_crossed)
                    && sorted_unique(&counts.privileged_credentials_acquired),
                "invariant 9: impact lists",
            )?;
        }
    }
    let frontier: Vec<&String> = doc.frontier.iter().map(|f| &f.edge).collect();
    ensure(sorted_unique(&frontier), "invariant 9: frontier")?;
    for edge in &doc.frontier {
        ensure(
            sorted_unique(&edge.properties) && sorted_unique(&edge.evidence_ids),
            "invariant 9: frontier lists",
        )?;
    }
    let delta: Vec<(std::cmp::Reverse<u32>, &String)> = doc
        .remediation_delta
        .iter()
        .map(|d| (std::cmp::Reverse(d.targets_contained_if_held), &d.edge))
        .collect();
    let ids: BTreeSet<&String> = doc.remediation_delta.iter().map(|d| &d.edge).collect();
    ensure(
        sorted_unique(&delta) && ids.len() == delta.len(),
        "invariant 9: remediation_delta",
    )?;
    for d in &doc.remediation_delta {
        ensure(
            sorted_unique(&d.properties),
            "invariant 9: delta properties",
        )?;
    }
    ensure(sorted_unique(&doc.stopped_by), "invariant 9: stopped_by")
}
