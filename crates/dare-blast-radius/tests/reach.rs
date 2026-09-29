//! The reach search (tasks 011-012, BLUEPRINT §6.2-§6.3, REGRESSION R-2).
mod support;

use dare_attack_graph::{
    v2::{AttackGraphV2, Authority},
    EdgeType, NodeType,
};
use dare_blast_radius::{
    limits::Bounds,
    model::{SeedKind, StopBound},
    reach::{initial_authority, search, Found, Indexed, View},
};
use support::{Gd, G};

fn bounds(depth: u32) -> Bounds {
    Bounds {
        max_depth: depth,
        max_states: 1_000_000,
    }
}

fn run<'g>(index: &Indexed<'g>, seed: &str, kind: SeedKind, view: View, depth: u32) -> Found<'g> {
    let mut budget = 5_000_000;
    search(
        index,
        seed,
        initial_authority(kind, seed),
        view,
        bounds(depth),
        &mut budget,
        None,
    )
}

fn reached(found: &Found<'_>) -> Vec<String> {
    found.reached.keys().map(|k| (*k).to_owned()).collect()
}

#[test]
fn initial_states_follow_the_kind_table() {
    assert_eq!(
        initial_authority(SeedKind::PrincipalTakeover, "node:human:a"),
        Authority::acting("node:human:a")
    );
    assert_eq!(
        initial_authority(SeedKind::CredentialLeak, "node:credential:c"),
        Authority::acting("node:credential:c")
    );
    assert_eq!(
        initial_authority(SeedKind::ContentInjection, "node:data:d"),
        Authority::unset()
    );
    assert_eq!(
        initial_authority(SeedKind::ComponentCompromise, "node:tool:t"),
        Authority::component("node:tool:t")
    );
}

/// C1..C6 inside a search: delegation hands authority on and the delegator
/// stops acting; a credential widens P; an access under an unacquired
/// principal is refused and counted; content reaching an agent steers it;
/// structural edges never break a walk.
#[test]
fn continuity_decides_every_step() {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    let agent = g.node(NodeType::Agent, "agent");
    let other = g.node(NodeType::Human, "other");
    let cred = g.node(NodeType::Credential, "cred");
    let res = g.node(NodeType::Resource, "res");
    let secret = g.node(NodeType::Resource, "secret");
    let doc = g.node(NodeType::Data, "doc");
    let tenant = g.node(NodeType::Tenant, "t");
    g.edge(&user, EdgeType::DelegatesTo, &agent, Gd::None); // C1
    g.edge(&agent, EdgeType::UsesCredential, &cred, Gd::None); // C2
    g.edge(&cred, EdgeType::CanReach, &res, Gd::None); // C3
    g.edge_full(
        &agent,
        EdgeType::CanReach,
        &secret,
        Gd::None,
        Some(&other),
        &[],
    ); // C3 refused
    g.edge(&res, EdgeType::BelongsToTenant, &tenant, Gd::None); // C6
    g.edge(&doc, EdgeType::TransfersTo, &agent, Gd::None); // C5
    let graph = g.build();
    let index = Indexed::new(&graph);

    let from_user = run(
        &index,
        &user,
        SeedKind::PrincipalTakeover,
        View::Structural,
        8,
    );
    assert_eq!(
        reached(&from_user),
        [agent.clone(), cred.clone(), res.clone(), tenant.clone()]
    );
    assert!(!from_user.reached.contains_key(secret.as_str()));
    assert!(from_user.report.refused_steps >= 1);
    let walk = from_user.walk_to(&tenant).unwrap();
    assert_eq!(
        walk.nodes,
        [
            user.clone(),
            agent.clone(),
            cred.clone(),
            res.clone(),
            tenant.clone()
        ]
    );
    assert_eq!(walk.edges.len(), 4);
    assert_eq!(
        walk.authorities[2].principal.as_deref(),
        Some(cred.as_str())
    );

    let from_doc = run(
        &index,
        &doc,
        SeedKind::ContentInjection,
        View::Structural,
        8,
    );
    assert_eq!(
        reached(&from_doc),
        [agent.clone(), cred.clone(), res.clone(), tenant.clone()]
    );
    // The injected agent acts as itself, so the access under `other` is refused.
    assert!(!from_doc.reached.contains_key(secret.as_str()));
}

/// REGRESSION R-3: a compromised component starts with no principal and
/// acts as itself. Under C3 an access that names a principal the walk never
/// acquired is refused (and counted); an unnamed access, a credential (C2) or
/// a delegation (C1) carries it on.
#[test]
fn a_component_continues_through_unnamed_access_credentials_and_delegation() {
    let mut g = G::new();
    let tool = g.node(NodeType::Tool, "tool");
    let owner = g.node(NodeType::Human, "owner");
    let named = g.node(NodeType::Resource, "named");
    let open = g.node(NodeType::Resource, "open");
    let cred = g.node(NodeType::Credential, "cred");
    let vault = g.node(NodeType::Resource, "vault");
    g.edge_full(
        &tool,
        EdgeType::CanReach,
        &named,
        Gd::None,
        Some(&owner),
        &[],
    );
    g.edge(&tool, EdgeType::CanReach, &open, Gd::None);
    g.edge(&tool, EdgeType::UsesCredential, &cred, Gd::None);
    g.edge_full(&cred, EdgeType::Reads, &vault, Gd::None, Some(&cred), &[]);
    let graph = g.build();
    let index = Indexed::new(&graph);
    let found = run(
        &index,
        &tool,
        SeedKind::ComponentCompromise,
        View::Structural,
        8,
    );
    assert_eq!(reached(&found), [cred, open, vault]);
    assert!(!found.reached.contains_key(named.as_str()));
    assert_eq!(found.report.refused_steps, 1);
}

/// R-2: a node is entered again when the authority differs, so reach that
/// needs a return visit is found; the same state is never expanded twice.
#[test]
fn walks_revisit_a_node_only_under_new_authority_and_cycles_terminate() {
    let mut g = G::new();
    let agent = g.node(NodeType::Agent, "agent");
    let cred = g.node(NodeType::Credential, "cred");
    let tool = g.node(NodeType::Tool, "tool");
    let vault = g.node(NodeType::Resource, "vault");
    // agent -> tool -> agent (cycle), agent self-loop, and the vault needs the
    // credential as principal: agent -> cred (C2) -> ... -> vault.
    g.edge(&agent, EdgeType::Calls, &tool, Gd::None);
    g.edge(&tool, EdgeType::Calls, &agent, Gd::None);
    g.edge(&agent, EdgeType::Calls, &agent, Gd::None);
    g.edge(&agent, EdgeType::UsesCredential, &cred, Gd::None);
    g.edge_full(&tool, EdgeType::Reads, &vault, Gd::None, Some(&cred), &[]);
    let graph = g.build();
    let index = Indexed::new(&graph);
    let found = run(
        &index,
        &agent,
        SeedKind::PrincipalTakeover,
        View::Structural,
        12,
    );
    // The vault read needs P = cred while the tool acts. Here nothing leads
    // from the credential back to the tool, so the read is never explained.
    assert!(!found.reached.contains_key(vault.as_str()));
    assert!(found.report.states_explored < 50, "cycles terminate");
    assert!(!found.report.truncated);
    // With a return edge from the credential to the tool, the read becomes
    // explained on the second visit to `tool`.
    let mut g2 = G::new();
    let agent = g2.node(NodeType::Agent, "agent");
    let cred = g2.node(NodeType::Credential, "cred");
    let tool = g2.node(NodeType::Tool, "tool");
    let vault = g2.node(NodeType::Resource, "vault");
    g2.edge(&agent, EdgeType::Calls, &tool, Gd::None);
    g2.edge(&tool, EdgeType::Calls, &agent, Gd::None);
    g2.edge(&agent, EdgeType::UsesCredential, &cred, Gd::None);
    g2.edge(&cred, EdgeType::CanReach, &tool, Gd::None);
    g2.edge_full(&tool, EdgeType::Reads, &vault, Gd::None, Some(&cred), &[]);
    let graph2 = g2.build();
    let index2 = Indexed::new(&graph2);
    let found = run(
        &index2,
        &agent,
        SeedKind::PrincipalTakeover,
        View::Structural,
        12,
    );
    let walk = found
        .walk_to(&vault)
        .expect("reached on a second visit to the tool");
    assert_eq!(
        walk.nodes,
        [agent.clone(), cred.clone(), tool.clone(), vault.clone()]
    );
    // The tool is reached first directly (witness), and later again under P = cred.
    assert_eq!(found.walk_to(&tool).unwrap().nodes, [agent, tool]);
}

#[test]
fn depth_cut_and_state_bounds_are_reported() {
    let mut g = G::new();
    let mut prev = g.node(NodeType::Agent, "n0");
    let seed = prev.clone();
    for i in 1..=5 {
        let next = g.node(NodeType::Tool, &format!("n{i}"));
        g.edge(&prev, EdgeType::Calls, &next, Gd::None);
        prev = next;
    }
    let graph = g.build();
    let index = Indexed::new(&graph);
    let cut = run(
        &index,
        &seed,
        SeedKind::PrincipalTakeover,
        View::Structural,
        3,
    );
    assert_eq!(cut.reached.len(), 3);
    assert!(cut.report.depth_cut);
    assert!(!cut.report.truncated);
    let full = run(
        &index,
        &seed,
        SeedKind::PrincipalTakeover,
        View::Structural,
        12,
    );
    assert_eq!(full.reached.len(), 5);
    assert!(!full.report.depth_cut);

    let mut budget = 5_000_000;
    let states = search(
        &index,
        &seed,
        initial_authority(SeedKind::PrincipalTakeover, &seed),
        View::Structural,
        Bounds {
            max_depth: 12,
            max_states: 2,
        },
        &mut budget,
        None,
    );
    assert_eq!(states.report.states_explored, 2);
    assert!(states.report.truncated);
    assert_eq!(states.report.stopped_by, Some(StopBound::MaxStates));

    let mut budget = 1;
    let total = search(
        &index,
        &seed,
        initial_authority(SeedKind::PrincipalTakeover, &seed),
        View::Structural,
        bounds(12),
        &mut budget,
        None,
    );
    assert_eq!(budget, 0);
    assert_eq!(total.report.stopped_by, Some(StopBound::MaxStatesTotal));
    assert_eq!(total.reached.len(), 1);
}

/// AD-07: among equally short walks, the witness is the first in adjacency
/// order `(target id, edge id)`; the input order of the arrays never matters.
#[test]
fn the_witness_is_the_first_shortest_walk_in_id_order() {
    let build = |reverse: bool| -> AttackGraphV2 {
        let mut g = G::new();
        let s = g.node(NodeType::Agent, "s");
        let a = g.node(NodeType::Tool, "a");
        let b = g.node(NodeType::Tool, "b");
        let t = g.node(NodeType::Resource, "t");
        let mut edges = vec![
            (s.clone(), b.clone()),
            (s.clone(), a.clone()),
            (b, t.clone()),
            (a, t),
        ];
        if reverse {
            edges.reverse();
        }
        for (x, y) in edges {
            g.edge(&x, EdgeType::Calls, &y, Gd::None);
        }
        g.build()
    };
    for reverse in [false, true] {
        let graph = build(reverse);
        let index = Indexed::new(&graph);
        let found = run(
            &index,
            "node:agent:s",
            SeedKind::PrincipalTakeover,
            View::Structural,
            8,
        );
        assert_eq!(
            found.walk_to("node:resource:t").unwrap().nodes,
            ["node:agent:s", "node:tool:a", "node:resource:t"]
        );
    }
}

/// The uncontained view skips exactly the edges whose every guard is PASS.
#[test]
fn the_uncontained_view_skips_only_held_edges() {
    for (guard, crossed) in [
        (Gd::Pass, false),
        (Gd::Fail, true),
        (Gd::Inconclusive, true),
        (Gd::Error, true),
        (Gd::None, true),
    ] {
        let mut g = G::new();
        let s = g.node(NodeType::Agent, "s");
        let t = g.node(NodeType::Resource, "t");
        let tenant = g.node(NodeType::Tenant, "x");
        g.edge(&s, EdgeType::CanReach, &t, guard);
        g.edge(&t, EdgeType::BelongsToTenant, &tenant, Gd::None);
        let graph = g.build();
        let index = Indexed::new(&graph);
        let structural = run(&index, &s, SeedKind::PrincipalTakeover, View::Structural, 8);
        let uncontained = run(
            &index,
            &s,
            SeedKind::PrincipalTakeover,
            View::Uncontained,
            8,
        );
        assert!(structural.reached.contains_key(t.as_str()));
        assert_eq!(
            uncontained.reached.contains_key(t.as_str()),
            crossed,
            "{guard:?}"
        );
        assert_eq!(uncontained.report.held_edges_skipped, u64::from(!crossed));
        assert_eq!(structural.report.held_edges_skipped, 0);
    }
    // A structural edge is never "held", whatever its guards (BQ-1 of 023).
    let mut g = G::new();
    let s = g.node(NodeType::Resource, "s");
    let tenant = g.node(NodeType::Tenant, "x");
    g.edge(&s, EdgeType::BelongsToTenant, &tenant, Gd::None);
    let graph = g.build();
    let index = Indexed::new(&graph);
    let found = run(&index, &s, SeedKind::ContentInjection, View::Uncontained, 8);
    assert!(found.reached.contains_key(tenant.as_str()));
}

#[test]
fn an_excluded_edge_is_treated_as_held() {
    let mut g = G::new();
    let s = g.node(NodeType::Agent, "s");
    let t = g.node(NodeType::Resource, "t");
    let edge = g.edge(&s, EdgeType::CanReach, &t, Gd::Fail);
    let graph = g.build();
    let index = Indexed::new(&graph);
    let mut budget = 100;
    let found = search(
        &index,
        &s,
        initial_authority(SeedKind::PrincipalTakeover, &s),
        View::Uncontained,
        bounds(8),
        &mut budget,
        Some(&edge),
    );
    assert!(found.reached.is_empty());
}
