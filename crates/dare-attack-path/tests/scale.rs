//! O-09: a large synthetic graph is built and enumerated within the bounds
//! in under 10 s (CI runs this with `--release`).
mod support;

use std::time::Instant;

use dare_attack_graph::{
    v2::{validate_graph_v2, validate_paths_v2, EntryClass, GuardVerdict, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_attack_path::{paths::attack_paths, ConstructOptions};
use support::G;

/// A fixed-seed linear congruential generator: deterministic, dependency-free.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

#[test]
fn a_two_thousand_node_graph_is_built_and_enumerated_within_bounds() {
    let started = Instant::now();
    let mut rng = Lcg(0x0023_0023);
    let mut g = G::new();
    let ids: Vec<String> = (0..2_000)
        .map(|i| {
            let kind = match i % 4 {
                0 => NodeType::Agent,
                1 => NodeType::Tool,
                2 => NodeType::Data,
                _ => NodeType::Resource,
            };
            g.node(kind, &format!("n{i:04}"), NodeSecurity::default())
        })
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut made = 0;
    while made < 10_000 {
        let a = (rng.next() % 2_000) as usize;
        let b = (rng.next() % 2_000) as usize;
        if a == b || !seen.insert((a, b)) {
            continue;
        }
        let verdict = match rng.next() % 5 {
            0 => Some(GuardVerdict::Fail),
            1 => None,
            _ => Some(GuardVerdict::Pass),
        };
        g.edge(&ids[a], EdgeType::CanReach, &ids[b], verdict);
        made += 1;
    }
    for i in 0..50 {
        g.entry(&ids[i * 40], EntryClass::ExternalContent);
        g.target(&ids[i * 40 + 3], TargetClass::SensitiveResource);
    }
    let graph = g.build();
    assert_eq!(graph.nodes.len(), 2_000);
    assert_eq!(graph.edges.len(), 10_000);
    validate_graph_v2(&graph).unwrap();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    assert_eq!(doc.enumeration.pairs_total, 50 * 50);
    assert!(doc.paths.len() + doc.discontinuous_paths.len() <= 10_000);
    assert!(doc.enumeration.steps_used <= dare_attack_path::limits::MAX_STEPS + 1);
    let elapsed = started.elapsed();
    println!(
        "scale: {} paths, {} steps, truncated={}, {elapsed:?}",
        doc.paths.len(),
        doc.enumeration.steps_used,
        doc.enumeration.truncated
    );
    assert!(elapsed.as_secs() < 10, "{elapsed:?}");
}
