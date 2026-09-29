//! Impact facts and the remediation delta (tasks 014-015, BLUEPRINT
//! §6.5-§6.7).
mod support;

use dare_attack_graph::{
    v2::{AttackGraphV2, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_blast_radius::{
    classify::classify,
    delta::remediation_delta,
    impact::{frontier, totals, view_impact},
    limits::{Bounds, MAX_DELTA_EDGES},
    model::{Exposure, SeedKind, SeedReport},
    reach::{initial_authority, search, Indexed, View},
    scenario::ResolvedSeed,
};
use support::{Gd, G};

fn bounds() -> Bounds {
    Bounds {
        max_depth: 8,
        max_states: 1_000_000,
    }
}

fn report(index: &Indexed<'_>, s: &ResolvedSeed, budget: &mut u64) -> SeedReport {
    let run = |view, budget: &mut u64| {
        search(
            index,
            &s.node,
            initial_authority(s.kind, &s.node),
            view,
            bounds(),
            budget,
            None,
        )
    };
    let structural = run(View::Structural, budget);
    let uncontained = run(View::Uncontained, budget);
    let targets = classify(index, s, &structural, &uncontained);
    let impact = view_impact(index, s, &structural, &uncontained, &targets);
    SeedReport {
        node: s.node.clone(),
        kind: s.kind,
        tenant: s.tenant.clone(),
        structural: structural.report.clone(),
        uncontained: uncontained.report.clone(),
        targets,
        impact,
    }
}

fn takeover(node: &str, tenant: Option<&str>) -> ResolvedSeed {
    ResolvedSeed {
        node: node.into(),
        kind: SeedKind::PrincipalTakeover,
        tenant: tenant.map(str::to_owned),
    }
}

struct Lab {
    graph: AttackGraphV2,
    user: String,
    admin_key: String,
    vault: String,
    ledger: String,
    rows: String,
    fail_a: String,
    fail_b: String,
    held: String,
}

/// user(t:a) → agent → admin key → vault (failed) and ledger (held);
/// agent → rows of tenant b through a failed edge crossing a boundary.
fn lab() -> Lab {
    let mut g = G::new();
    let user = g.node_with(NodeType::Human, "user", G::tenant("a"));
    let agent = g.node_with(NodeType::Agent, "agent", G::tenant("a"));
    let admin_key = g.node_with(
        NodeType::Credential,
        "admin",
        NodeSecurity {
            privileged: true,
            ..NodeSecurity::default()
        },
    );
    let vault = g.node(NodeType::Resource, "vault");
    let ledger = g.node(NodeType::Resource, "ledger");
    let rows = g.node_with(NodeType::Data, "rows", G::tenant("b"));
    g.edge(&user, EdgeType::DelegatesTo, &agent, Gd::None);
    g.edge(&agent, EdgeType::UsesCredential, &admin_key, Gd::None);
    let fail_a = g.edge(&admin_key, EdgeType::CanReach, &vault, Gd::Fail);
    let held = g.edge(&admin_key, EdgeType::CanReach, &ledger, Gd::Pass);
    let fail_b = g.edge_full(
        &agent,
        EdgeType::Reads,
        &rows,
        Gd::Fail,
        None,
        &["tenant-boundary"],
    );
    g.target(&vault, TargetClass::SensitiveResource);
    g.target(&ledger, TargetClass::SensitiveResource);
    g.target(&admin_key, TargetClass::PrivilegedCredential);
    Lab {
        graph: g.build(),
        user,
        admin_key,
        vault,
        ledger,
        rows,
        fail_a,
        fail_b,
        held,
    }
}

#[test]
fn impact_counts_follow_each_view() {
    let l = lab();
    let index = Indexed::new(&l.graph);
    let mut budget = 5_000_000;
    let r = report(&index, &takeover(&l.user, Some("a")), &mut budget);
    let exposure = |n: &str| r.targets.iter().find(|t| t.node == n).unwrap().exposure;
    assert_eq!(exposure(&l.vault), Exposure::Exposed);
    assert_eq!(exposure(&l.ledger), Exposure::Contained);
    assert_eq!(exposure(&l.rows), Exposure::Exposed);
    assert_eq!(exposure(&l.admin_key), Exposure::Exposed);

    let s = &r.impact.structural;
    assert_eq!(s.targets_by_class[&TargetClass::SensitiveResource], 2);
    assert_eq!(s.targets_by_class[&TargetClass::CrossTenantResource], 1);
    assert_eq!(s.targets_by_class[&TargetClass::PrivilegedCredential], 1);
    assert_eq!(s.tenants_reached, vec!["b".to_owned()]);
    assert_eq!(
        s.trust_boundaries_crossed,
        vec!["tenant-boundary".to_owned()]
    );
    assert_eq!(s.privileged_credentials_acquired, vec![l.admin_key.clone()]);

    let u = &r.impact.uncontained;
    assert_eq!(u.targets_by_class[&TargetClass::SensitiveResource], 1);
    assert_eq!(u.privileged_credentials_acquired, vec![l.admin_key.clone()]);
    // The seed's own tenant is never counted.
    assert!(!u.tenants_reached.contains(&"a".to_owned()));
}

#[test]
fn totals_and_frontier_count_seed_target_pairs() {
    let l = lab();
    let index = Indexed::new(&l.graph);
    let mut budget = 5_000_000;
    let a = report(&index, &takeover(&l.user, Some("a")), &mut budget);
    let b = report(&index, &takeover(&l.user, None), &mut budget);
    let seeds = vec![a, b];
    let t = totals(&seeds);
    // With tenant: vault, admin key, rows exposed; ledger contained.
    // Without tenant: vault, admin key exposed; ledger contained.
    assert_eq!((t.exposed, t.contained, t.containment_unknown), (5, 2, 0));
    assert_eq!(t.exposed_by_class[&TargetClass::CrossTenantResource], 1);

    let f = frontier(&index, &seeds);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].edge, l.held);
    assert_eq!(f[0].contained_targets, 2);
    assert_eq!(f[0].properties, vec![support::PROP.to_owned()]);
    assert_eq!(f[0].evidence_ids, vec!["urn:ev:guard".to_owned()]);
}

#[test]
fn the_delta_counts_targets_each_failed_edge_would_contain() {
    let l = lab();
    let index = Indexed::new(&l.graph);
    let mut budget = 5_000_000;
    let s = takeover(&l.user, Some("a"));
    let r = report(&index, &s, &mut budget);
    let delta = remediation_delta(&index, &[(s, &r)], bounds(), &mut budget);
    let edges: Vec<(&str, u32, bool)> = delta
        .iter()
        .map(|d| (d.edge.as_str(), d.targets_contained_if_held, d.partial))
        .collect();
    let mut want = vec![(l.fail_a.as_str(), 1, false), (l.fail_b.as_str(), 1, false)];
    want.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    assert_eq!(edges, want);
    assert!(delta
        .iter()
        .all(|d| d.properties == vec![support::PROP.to_owned()]));
}

/// A failed edge shared by two exposed routes contains both targets; an
/// alternative open route means holding the edge contains nothing.
#[test]
fn the_delta_recounts_through_alternatives_and_orders_by_count() {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    let agent = g.node(NodeType::Agent, "agent");
    let x = g.node(NodeType::Resource, "x");
    let y = g.node(NodeType::Resource, "y");
    let z = g.node(NodeType::Resource, "z");
    let shared = g.edge(&user, EdgeType::DelegatesTo, &agent, Gd::Fail);
    g.edge(&agent, EdgeType::Reads, &x, Gd::None);
    g.edge(&agent, EdgeType::Writes, &y, Gd::None);
    let direct = g.edge(&user, EdgeType::Reads, &z, Gd::Fail);
    g.edge(&user, EdgeType::Writes, &z, Gd::None);
    for t in [&x, &y, &z] {
        g.target(t, TargetClass::SensitiveResource);
    }
    let graph = g.build();
    let index = Indexed::new(&graph);
    let mut budget = 5_000_000;
    let s = takeover(&user, None);
    let r = report(&index, &s, &mut budget);
    let delta = remediation_delta(&index, &[(s, &r)], bounds(), &mut budget);
    let counts: Vec<(&str, u32)> = delta
        .iter()
        .map(|d| (d.edge.as_str(), d.targets_contained_if_held))
        .collect();
    let z_route = &r.targets.iter().find(|t| t.node == z).unwrap();
    let z_via_direct = z_route
        .uncontained_route
        .as_ref()
        .unwrap()
        .edges
        .contains(&direct);
    let mut want = vec![(shared.as_str(), 2)];
    if z_via_direct {
        want.push((direct.as_str(), 0));
    }
    assert_eq!(counts, want);
}

#[test]
fn an_exhausted_budget_marks_the_delta_partial() {
    let l = lab();
    let index = Indexed::new(&l.graph);
    let mut budget = 5_000_000;
    let s = takeover(&l.user, Some("a"));
    let r = report(&index, &s, &mut budget);
    let mut empty = 0;
    let delta = remediation_delta(&index, &[(s.clone(), &r)], bounds(), &mut empty);
    assert_eq!(delta.len(), 2);
    assert!(delta
        .iter()
        .all(|d| d.partial && d.targets_contained_if_held == 0));
    // A truncated recount is partial too, and counts nothing it did not settle.
    let tight = Bounds {
        max_depth: 8,
        max_states: 1,
    };
    let mut budget = 5_000_000;
    let delta = remediation_delta(&index, &[(s, &r)], tight, &mut budget);
    assert!(delta.iter().all(|d| d.partial));
    assert!(delta.iter().all(|d| d.targets_contained_if_held == 0));
}

#[test]
fn the_delta_keeps_at_most_the_bound() {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    for i in 0..(MAX_DELTA_EDGES + 6) {
        let r = g.node(NodeType::Resource, &format!("r{i:03}"));
        g.edge(&user, EdgeType::Reads, &r, Gd::Fail);
        g.target(&r, TargetClass::SensitiveResource);
    }
    let graph = g.build();
    let index = Indexed::new(&graph);
    let mut budget = 5_000_000;
    let s = takeover(&user, None);
    let r = report(&index, &s, &mut budget);
    let delta = remediation_delta(&index, &[(s, &r)], bounds(), &mut budget);
    assert_eq!(delta.len(), MAX_DELTA_EDGES);
    assert!(delta.iter().all(|d| d.targets_contained_if_held == 1));
    assert!(delta.windows(2).all(|w| w[0].edge < w[1].edge));
}
