//! Scale (task-018, O-08): 2 000 nodes, 10 000 edges and 64 seeds, both views
//! and the delta. Two fixed-seed graphs (REGRESSION R-6):
//!
//! - a **layered** graph shaped like the lab graphs (principals delegate to
//!   agents, agents invoke tools and use credentials, credentials and tools
//!   reach resources and data), which must finish in under 10 s in release;
//! - a **uniform** graph whose random edges make almost every authority state
//!   distinct, so it runs into the 5 000 000-state total budget. It checks
//!   that no bound is overshot and the truncation is reported; its time is
//!   printed, not asserted, since it measures the budget ceiling itself.
//!
//! Debug builds skip both: CI runs this file with `--release`.
mod support;

use std::time::{Duration, Instant};

use dare_attack_graph::{
    v2::{AttackGraphV2, EntryClass, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_blast_radius::{
    analyze::analyze_graph,
    limits::{MAX_DELTA_EDGES, MAX_STATES_PER_SEARCH, MAX_STATES_TOTAL},
    model::BlastRadiusDoc,
    scenario::entry_point_seeds,
    Options,
};
use support::{Gd, G};

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

const GUARDS: [Gd; 4] = [Gd::None, Gd::Pass, Gd::Fail, Gd::Inconclusive];

fn run(graph: &AttackGraphV2) -> (BlastRadiusDoc, Duration) {
    assert_eq!((graph.nodes.len(), graph.edges.len()), (2000, 10_000));
    let seeding = entry_point_seeds(graph).unwrap();
    assert_eq!(seeding.seeds.len(), 64);
    let start = Instant::now();
    let doc = analyze_graph(graph, &seeding, &Options::default()).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(doc.seeds.len(), 64);
    let mut states = 0;
    for seed in &doc.seeds {
        for report in [&seed.structural, &seed.uncontained] {
            assert!(report.states_explored <= MAX_STATES_PER_SEARCH);
            states += report.states_explored;
        }
    }
    assert!(states <= MAX_STATES_TOTAL);
    assert!(doc.remediation_delta.len() <= MAX_DELTA_EDGES);
    eprintln!(
        "scale: {states} states, {} exposed, {} contained, {} unknown, {} delta, truncated {}, {elapsed:?}",
        doc.totals.exposed,
        doc.totals.contained,
        doc.totals.containment_unknown,
        doc.remediation_delta.len(),
        doc.truncated,
    );
    (doc, elapsed)
}

/// Adds `count` distinct edges; `pick` returns `(source, type, target)`.
fn edges(
    g: &mut G,
    rng: &mut Rng,
    count: usize,
    mut pick: impl FnMut(&mut Rng) -> (String, EdgeType, String, Option<String>),
) {
    let mut seen = std::collections::HashSet::new();
    while seen.len() < count {
        let (s, t, d, principal) = pick(rng);
        let guard = GUARDS[rng.below(GUARDS.len())];
        if seen.insert((s.clone(), t as u8, d.clone(), principal.clone())) {
            g.edge_full(&s, t, &d, guard, principal.as_deref(), &[]);
        }
    }
}

fn layered() -> AttackGraphV2 {
    let mut rng = Rng(0x0DDB_1A5E_5BAD_5EED);
    let mut g = G::new();
    let tenant = |i: usize| G::tenant(["a", "b", "c"][i % 3]);
    let layer = |g: &mut G, t: NodeType, n: usize, name: &str, privileged: bool| {
        (0..n)
            .map(|i| {
                let security = NodeSecurity {
                    privileged: privileged && i % 5 == 0,
                    ..tenant(i)
                };
                g.node_with(t, &format!("{name}{i:04}"), security)
            })
            .collect::<Vec<_>>()
    };
    let humans = layer(&mut g, NodeType::Human, 64, "h", false);
    let agents = layer(&mut g, NodeType::Agent, 300, "a", false);
    let identities = layer(&mut g, NodeType::Identity, 136, "i", false);
    let credentials = layer(&mut g, NodeType::Credential, 300, "c", true);
    let tools = layer(&mut g, NodeType::Tool, 400, "t", false);
    let resources = layer(&mut g, NodeType::Resource, 400, "r", false);
    let data = layer(&mut g, NodeType::Data, 400, "d", false);
    let pick = |rng: &mut Rng, from: &[String]| from[rng.below(from.len())].clone();
    edges(&mut g, &mut rng, 10_000, |rng| {
        let (s, t, d) = match rng.below(10) {
            0 => (
                pick(rng, &humans),
                EdgeType::DelegatesTo,
                pick(rng, &agents),
            ),
            1 => (
                pick(rng, &agents),
                EdgeType::AuthenticatesAs,
                pick(rng, &identities),
            ),
            2 => (
                pick(rng, &agents),
                EdgeType::UsesCredential,
                pick(rng, &credentials),
            ),
            3 | 4 => (pick(rng, &agents), EdgeType::CanInvoke, pick(rng, &tools)),
            5 => (
                pick(rng, &credentials),
                EdgeType::CanReach,
                pick(rng, &resources),
            ),
            6 => (pick(rng, &tools), EdgeType::Reads, pick(rng, &data)),
            7 => (pick(rng, &tools), EdgeType::Writes, pick(rng, &resources)),
            8 => (pick(rng, &data), EdgeType::TransfersTo, pick(rng, &agents)),
            _ => (pick(rng, &agents), EdgeType::Calls, pick(rng, &agents)),
        };
        (s, t, d, None)
    });
    for h in &humans {
        g.entry(h, EntryClass::LowPrivilegePrincipal);
    }
    for r in &resources {
        g.target(r, TargetClass::SensitiveResource);
    }
    for (i, c) in credentials.iter().enumerate() {
        if i % 5 == 0 {
            g.target(c, TargetClass::PrivilegedCredential);
        }
    }
    g.build()
}

fn uniform() -> AttackGraphV2 {
    const TYPES: [NodeType; 7] = [
        NodeType::Human,
        NodeType::Agent,
        NodeType::Credential,
        NodeType::Tool,
        NodeType::Resource,
        NodeType::Data,
        NodeType::Identity,
    ];
    const EDGES: [EdgeType; 8] = [
        EdgeType::DelegatesTo,
        EdgeType::UsesCredential,
        EdgeType::CanInvoke,
        EdgeType::Calls,
        EdgeType::Reads,
        EdgeType::Writes,
        EdgeType::TransfersTo,
        EdgeType::CanReach,
    ];
    let mut rng = Rng(0x5DEE_CE66_D1CE_4E5B);
    let mut g = G::new();
    let ids: Vec<(NodeType, String)> = (0..2000)
        .map(|i| {
            let t = TYPES[i % TYPES.len()];
            let security = if t == NodeType::Resource || t == NodeType::Data {
                G::tenant(["a", "b", "c"][i % 3])
            } else {
                G::tenant("a")
            };
            (t, g.node_with(t, &format!("n{i:04}"), security))
        })
        .collect();
    edges(&mut g, &mut rng, 10_000, |rng| {
        let s = ids[rng.below(ids.len())].1.clone();
        let t = EDGES[rng.below(EDGES.len())];
        let d = ids[rng.below(ids.len())].1.clone();
        (s, t, d, None)
    });
    let mut seeds = 0;
    for (t, id) in &ids {
        match t {
            NodeType::Human if seeds < 64 => {
                g.entry(id, EntryClass::LowPrivilegePrincipal);
                seeds += 1;
            }
            NodeType::Resource => g.target(id, TargetClass::SensitiveResource),
            NodeType::Credential => g.target(id, TargetClass::PrivilegedCredential),
            _ => {}
        }
    }
    g.build()
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release only: cargo test --release --test scale"
)]
fn a_lab_shaped_graph_is_analysed_in_under_ten_seconds() {
    let (doc, elapsed) = run(&layered());
    assert!(doc.totals.exposed > 0 && doc.totals.contained > 0);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release only: cargo test --release --test scale"
)]
fn a_state_explosion_stops_at_the_total_budget_and_says_so() {
    let (doc, _) = run(&uniform());
    assert!(doc.truncated);
    assert!(doc.totals.containment_unknown > 0);
    assert!(doc.remediation_delta.iter().all(|d| d.partial));
}
