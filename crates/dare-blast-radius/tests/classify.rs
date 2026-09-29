//! Targets, exposure, routes and frontier (task-013, BLUEPRINT §6.4).
mod support;

use std::collections::BTreeSet;

use dare_attack_graph::{
    v2::{AttackGraphV2, Authority, ControlState, TargetClass},
    EdgeType, NodeType,
};
use dare_blast_radius::{
    classify::{candidates, classify},
    limits::Bounds,
    model::{Exposure, SeedKind, TargetReach},
    reach::{initial_authority, is_held, search, Found, Indexed, View},
    scenario::ResolvedSeed,
};
use support::{Gd, G};

fn seed(node: &str, kind: SeedKind, tenant: Option<&str>) -> ResolvedSeed {
    ResolvedSeed {
        node: node.to_owned(),
        kind,
        tenant: tenant.map(str::to_owned),
    }
}

fn both<'g>(index: &Indexed<'g>, seed: &ResolvedSeed, bounds: Bounds) -> (Found<'g>, Found<'g>) {
    let mut budget = 5_000_000;
    let run = |view, budget: &mut u64| {
        search(
            index,
            &seed.node,
            initial_authority(seed.kind, &seed.node),
            view,
            bounds,
            budget,
            None,
        )
    };
    let structural = run(View::Structural, &mut budget);
    let uncontained = run(View::Uncontained, &mut budget);
    (structural, uncontained)
}

fn default_bounds() -> Bounds {
    Bounds {
        max_depth: 8,
        max_states: 1_000_000,
    }
}

fn classify_all(graph: &AttackGraphV2, s: &ResolvedSeed, bounds: Bounds) -> Vec<TargetReach> {
    let index = Indexed::new(graph);
    let (structural, uncontained) = both(&index, s, bounds);
    classify(&index, s, &structural, &uncontained)
}

/// user → agent → {secret via a held edge, db via a failed edge}.
fn fork() -> (AttackGraphV2, String, String, String, String, String) {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    let agent = g.node(NodeType::Agent, "agent");
    let secret = g.node(NodeType::Resource, "secret");
    let db = g.node(NodeType::Resource, "db");
    g.edge(&user, EdgeType::DelegatesTo, &agent, Gd::None);
    let held = g.edge(&agent, EdgeType::Reads, &secret, Gd::Pass);
    let failed = g.edge(&agent, EdgeType::Writes, &db, Gd::Fail);
    g.target(&secret, TargetClass::SensitiveResource);
    g.target(&db, TargetClass::SensitiveResource);
    (g.build(), user, secret, db, held, failed)
}

#[test]
fn exposure_follows_the_uncontained_view() {
    let (graph, user, secret, db, held, failed) = fork();
    let s = seed(&user, SeedKind::PrincipalTakeover, None);
    let targets = classify_all(&graph, &s, default_bounds());
    assert_eq!(targets.len(), 2);
    let by_node = |n: &str| targets.iter().find(|t| t.node == n).unwrap();

    let exposed = by_node(&db);
    assert_eq!(exposed.exposure, Exposure::Exposed);
    let route = exposed.uncontained_route.as_ref().unwrap();
    assert_eq!(route.edges.last(), Some(&failed));
    assert_eq!(route.control_state, ControlState::ControlFailed);
    assert_eq!(route.failed_guards.len(), 1);
    assert!(exposed.frontier.is_empty());

    let contained = by_node(&secret);
    assert_eq!(contained.exposure, Exposure::Contained);
    assert!(contained.uncontained_route.is_none());
    assert_eq!(contained.frontier, vec![held.clone()]);
    // The structural route is the one the held edge stops.
    assert_eq!(contained.structural_route.edges.last(), Some(&held));
    assert_eq!(contained.structural_route.nodes.first(), Some(&user));
}

/// A contained target's frontier is never empty: its structural witness must
/// cross a held edge, or the uncontained search would have taken it.
#[test]
fn every_contained_target_has_a_non_empty_frontier() {
    for case in 0..200u64 {
        let (graph, seeds) = random_graph(case);
        let index = Indexed::new(&graph);
        for s in &seeds {
            let (structural, uncontained) = both(&index, s, small_bounds());
            for t in classify(&index, s, &structural, &uncontained) {
                if t.exposure == Exposure::Contained {
                    assert!(!t.frontier.is_empty(), "case {case} {}", t.node);
                    assert!(t.frontier.iter().all(|e| is_held(index.edge(e).unwrap())));
                }
            }
        }
    }
}

#[test]
fn a_truncated_uncontained_search_never_claims_containment() {
    let (graph, user, secret, db, _, _) = fork();
    let s = seed(&user, SeedKind::PrincipalTakeover, None);
    let bounds = Bounds {
        max_depth: 8,
        max_states: 1,
    };
    let index = Indexed::new(&graph);
    let mut budget = 5_000_000;
    let structural = search(
        &index,
        &user,
        initial_authority(s.kind, &user),
        View::Structural,
        default_bounds(),
        &mut budget,
        None,
    );
    let uncontained = search(
        &index,
        &user,
        initial_authority(s.kind, &user),
        View::Uncontained,
        bounds,
        &mut budget,
        None,
    );
    assert!(uncontained.report.truncated);
    let targets = classify(&index, &s, &structural, &uncontained);
    for t in &targets {
        assert_ne!(t.exposure, Exposure::Contained, "{}", t.node);
    }
    let unknown: BTreeSet<&str> = targets
        .iter()
        .filter(|t| t.exposure == Exposure::ContainmentUnknown)
        .map(|t| t.node.as_str())
        .collect();
    assert_eq!(unknown, BTreeSet::from([secret.as_str(), db.as_str()]));
    assert!(targets
        .iter()
        .filter(|t| t.exposure == Exposure::ContainmentUnknown)
        .all(|t| t.frontier.is_empty() && t.uncontained_route.is_none()));
}

#[test]
fn the_seed_is_never_its_own_target_and_unreached_targets_are_absent() {
    let mut g = G::new();
    let cred = g.node(NodeType::Credential, "key");
    let res = g.node(NodeType::Resource, "res");
    let island = g.node(NodeType::Resource, "island");
    g.edge(&cred, EdgeType::CanReach, &res, Gd::None);
    g.target(&cred, TargetClass::PrivilegedCredential);
    g.target(&res, TargetClass::SensitiveResource);
    g.target(&island, TargetClass::SensitiveResource);
    let graph = g.build();
    let s = seed(&cred, SeedKind::CredentialLeak, None);
    let targets = classify_all(&graph, &s, default_bounds());
    let nodes: Vec<&str> = targets.iter().map(|t| t.node.as_str()).collect();
    assert_eq!(nodes, vec![res.as_str()]);
    assert_eq!(targets[0].exposure, Exposure::Exposed);
    // An unguarded access leaves the route undecided.
    let route = targets[0].uncontained_route.as_ref().unwrap();
    assert_eq!(route.control_state, ControlState::ControlUndecided);
}

/// BQ-4: another tenant's RESOURCE or DATA is a candidate only for a seed
/// with a tenant; a node of the seed's own tenant never is.
#[test]
fn cross_tenant_candidates_need_a_seed_tenant() {
    let mut g = G::new();
    let user = g.node_with(NodeType::Human, "user", G::tenant("a"));
    let mine = g.node_with(NodeType::Resource, "mine", G::tenant("a"));
    let theirs = g.node_with(NodeType::Resource, "theirs", G::tenant("b"));
    let data = g.node_with(NodeType::Data, "rows", G::tenant("b"));
    let agent = g.node_with(NodeType::Agent, "bot", G::tenant("b"));
    let _ = (mine, agent);
    let graph = g.build();
    let index = Indexed::new(&graph);

    let with = candidates(&index, &seed(&user, SeedKind::PrincipalTakeover, Some("a")));
    let mut want = vec![
        (data.clone(), TargetClass::CrossTenantResource),
        (theirs.clone(), TargetClass::CrossTenantResource),
    ];
    want.sort();
    assert_eq!(with, want);

    let without = candidates(&index, &seed(&user, SeedKind::PrincipalTakeover, None));
    assert!(without.is_empty());
}

// ---------------------------------------------------------------------------
// Property test: 0 false CONTAINED over 200 fixed-seed random graphs.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TYPES: [NodeType; 9] = [
    NodeType::Human,
    NodeType::Agent,
    NodeType::Identity,
    NodeType::Credential,
    NodeType::Tool,
    NodeType::Resource,
    NodeType::Data,
    NodeType::McpServer,
    NodeType::Tenant,
];

const EDGES: [EdgeType; 14] = [
    EdgeType::AuthenticatesAs,
    EdgeType::DelegatesTo,
    EdgeType::CanInvoke,
    EdgeType::Calls,
    EdgeType::UsesCredential,
    EdgeType::AuthorizedBy,
    EdgeType::EnforcedBy,
    EdgeType::Reads,
    EdgeType::Writes,
    EdgeType::Deletes,
    EdgeType::TransfersTo,
    EdgeType::BelongsToTenant,
    EdgeType::CrossesTrustBoundary,
    EdgeType::CanReach,
];

const GUARDS: [Gd; 5] = [Gd::None, Gd::Pass, Gd::Pass, Gd::Fail, Gd::Inconclusive];

fn small_bounds() -> Bounds {
    Bounds {
        max_depth: 5,
        max_states: 1_000_000,
    }
}

fn kind_for(t: NodeType) -> SeedKind {
    match t {
        NodeType::Human | NodeType::Agent | NodeType::Identity => SeedKind::PrincipalTakeover,
        NodeType::Credential => SeedKind::CredentialLeak,
        NodeType::Data => SeedKind::ContentInjection,
        _ => SeedKind::ComponentCompromise,
    }
}

/// About 30 nodes and 45 edges; every non-tenant node is a target and the
/// first four non-tenant nodes are seeds.
fn random_graph(case: u64) -> (AttackGraphV2, Vec<ResolvedSeed>) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (case + 1).wrapping_mul(0xD1B5_4A32_D192_ED03));
    let mut g = G::new();
    let count = 26 + rng.below(9);
    let mut ids = Vec::new();
    let mut types = Vec::new();
    for i in 0..count {
        let t = TYPES[rng.below(TYPES.len())];
        ids.push(g.node(t, &format!("n{i}")));
        types.push(t);
    }
    let principals: Vec<usize> = (0..count)
        .filter(|&i| {
            matches!(
                types[i],
                NodeType::Human | NodeType::Agent | NodeType::Identity | NodeType::Credential
            )
        })
        .collect();
    let edges = count + count / 2 + rng.below(8);
    for _ in 0..edges {
        let s = rng.below(count);
        let d = rng.below(count);
        let t = EDGES[rng.below(EDGES.len())];
        let guard = GUARDS[rng.below(GUARDS.len())];
        let principal = (!principals.is_empty() && rng.below(3) == 0)
            .then(|| ids[principals[rng.below(principals.len())]].clone());
        g.edge_full(&ids[s], t, &ids[d], guard, principal.as_deref(), &[]);
    }
    let mut seeds = Vec::new();
    for i in 0..count {
        if types[i] == NodeType::Tenant {
            continue;
        }
        g.target(&ids[i], TargetClass::SensitiveResource);
        if seeds.len() < 4 {
            seeds.push(seed(&ids[i], kind_for(types[i]), None));
        }
    }
    (g.build(), seeds)
}

/// Independent oracle: every node some walk of at most `depth` edges reaches
/// from the seed, enumerating walks exhaustively (no state dedup).
fn oracle(index: &Indexed<'_>, s: &ResolvedSeed, depth: u32, skip_held: bool) -> BTreeSet<String> {
    fn go(
        index: &Indexed<'_>,
        node: &str,
        authority: &Authority,
        left: u32,
        skip_held: bool,
        out: &mut BTreeSet<String>,
    ) {
        if left == 0 {
            return;
        }
        for edge in &index.graph.edges {
            if edge.source != node || (skip_held && is_held(edge)) {
                continue;
            }
            let mut next = authority.clone();
            if next.step(edge, |id| index.node_type(id)) {
                out.insert(edge.target.clone());
                go(index, &edge.target, &next, left - 1, skip_held, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    go(
        index,
        &s.node,
        &initial_authority(s.kind, &s.node),
        depth,
        skip_held,
        &mut out,
    );
    // The seed is never its own reach.
    out.remove(&s.node);
    out
}

#[test]
fn no_random_graph_yields_a_false_containment() {
    let bounds = small_bounds();
    let mut checked = 0u32;
    let mut contained = 0u32;
    let mut exposed = 0u32;
    for case in 0..200u64 {
        let (graph, seeds) = random_graph(case);
        let index = Indexed::new(&graph);
        for s in &seeds {
            let (structural, uncontained) = both(&index, s, bounds);
            assert!(!uncontained.report.truncated, "case {case}");
            let reach_all = oracle(&index, s, bounds.max_depth, false);
            let reach_open = oracle(&index, s, bounds.max_depth, true);
            // The search reaches exactly what the enumeration reaches.
            let got_all: BTreeSet<String> =
                structural.reached.keys().map(|k| (*k).to_owned()).collect();
            let got_open: BTreeSet<String> = uncontained
                .reached
                .keys()
                .map(|k| (*k).to_owned())
                .collect();
            assert_eq!(got_all, reach_all, "case {case} structural");
            assert_eq!(got_open, reach_open, "case {case} uncontained");
            for t in classify(&index, s, &structural, &uncontained) {
                checked += 1;
                match t.exposure {
                    Exposure::Contained => {
                        contained += 1;
                        assert!(
                            !reach_open.contains(&t.node),
                            "false CONTAINED: case {case} seed {} target {}",
                            s.node,
                            t.node
                        );
                    }
                    Exposure::Exposed => {
                        exposed += 1;
                        assert!(reach_open.contains(&t.node));
                    }
                    Exposure::ContainmentUnknown => panic!("no truncation expected"),
                }
            }
        }
    }
    eprintln!("pairs {checked}, contained {contained}, exposed {exposed}");
    // The corpus exercises both outcomes.
    assert!(checked > 1000, "{checked}");
    assert!(contained > 50, "{contained}");
    assert!(exposed > 50, "{exposed}");
}
