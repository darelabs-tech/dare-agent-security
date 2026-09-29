//! `analyze` end to end (task-017, BLUEPRINT §5.2, §6.8).
mod support;

use std::fs;

use dare_attack_graph::v2::graph_id_v2;
use dare_blast_radius::{
    analyze,
    analyze::analyze_graph,
    model::{Exposure, SeedKind},
    scenario::entry_point_seeds,
    BlastError, Options, Refusal, Seeding,
};
use serde_json::json;
use support::lab::lab;

fn write_graph(dir: &std::path::Path, graph: &impl serde::Serialize) -> std::path::PathBuf {
    let path = dir.join("attack-graph.json");
    fs::write(&path, serde_json::to_vec_pretty(graph).unwrap()).unwrap();
    path
}

#[test]
fn a_scenario_file_gives_a_valid_document_and_nothing_is_written() {
    let l = lab();
    let tmp = tempfile::tempdir().unwrap();
    let graph = write_graph(tmp.path(), &l.graph);
    let scenario = tmp.path().join("compromise.json");
    fs::write(
        &scenario,
        serde_json::to_vec(&json!({
            "schema_version": "1",
            "scenario_id": "admin-key-leak",
            "graph_id": l.graph.id,
            "seeds": [{"node_id": l.admin_key, "kind": "CREDENTIAL_LEAK"}],
        }))
        .unwrap(),
    )
    .unwrap();
    let before: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
    let a = analyze(&graph, Seeding::Scenario(&scenario), &Options::default()).unwrap();
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), before.len());
    assert_eq!(a.doc.scenario_id, "admin-key-leak");
    assert!(a
        .doc
        .scenario_digest
        .as_deref()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(a.doc.seeds.len(), 1);
    assert_eq!(a.doc.seeds[0].kind, SeedKind::CredentialLeak);
    let exposure = |n: &str| {
        a.doc.seeds[0]
            .targets
            .iter()
            .find(|t| t.node == n)
            .map(|t| t.exposure)
    };
    assert_eq!(exposure(&l.vault), Some(Exposure::Exposed));
    assert_eq!(exposure(&l.ledger), Some(Exposure::Contained));
    assert_eq!(a.graph.id, l.graph.id);
}

#[test]
fn entry_point_mode_seeds_every_fitting_entry() {
    let l = lab();
    let tmp = tempfile::tempdir().unwrap();
    let graph = write_graph(tmp.path(), &l.graph);
    let a = analyze(&graph, Seeding::EntryPoints, &Options::default()).unwrap();
    assert_eq!(a.doc.scenario_id, "entry-points");
    assert!(a.doc.scenario_digest.is_none());
    let seeds: Vec<(&str, SeedKind)> = a
        .doc
        .seeds
        .iter()
        .map(|s| (s.node.as_str(), s.kind))
        .collect();
    let mut want = vec![
        (l.doc.as_str(), SeedKind::ContentInjection),
        (l.user.as_str(), SeedKind::PrincipalTakeover),
    ];
    want.sort();
    assert_eq!(seeds, want);
}

#[test]
fn options_lower_the_bounds_and_are_refused_above_the_maximum() {
    let l = lab();
    let tmp = tempfile::tempdir().unwrap();
    let graph = write_graph(tmp.path(), &l.graph);
    let low = Options {
        max_depth: Some(1),
        max_states: Some(10),
    };
    let a = analyze(&graph, Seeding::EntryPoints, &low).unwrap();
    assert_eq!((a.doc.bounds.max_depth, a.doc.bounds.max_states), (1, 10));
    for (options, bound) in [
        (
            Options {
                max_depth: Some(13),
                max_states: None,
            },
            "max_depth",
        ),
        (
            Options {
                max_depth: None,
                max_states: Some(1_000_001),
            },
            "max_states",
        ),
    ] {
        match analyze(&graph, Seeding::EntryPoints, &options) {
            Err(BlastError::Refused(Refusal::BoundAboveMaximum { bound: b })) => {
                assert_eq!(b, bound)
            }
            other => panic!("{other:?}"),
        }
    }
    match analyze(
        &graph,
        Seeding::EntryPoints,
        &Options {
            max_depth: Some(0),
            max_states: None,
        },
    ) {
        Err(BlastError::Refused(Refusal::BoundZero { .. })) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_graph_that_fails_v2_validation_is_refused() {
    let l = lab();
    let tmp = tempfile::tempdir().unwrap();
    // Unsorted edges.
    let mut graph = l.graph.clone();
    graph.edges.reverse();
    let path = write_graph(tmp.path(), &graph);
    assert!(matches!(
        analyze(&path, Seeding::EntryPoints, &Options::default()),
        Err(BlastError::Refused(Refusal::InvalidGraph))
    ));
    // Not a graph at all.
    let path = write_graph(tmp.path(), &json!({"nodes": []}));
    assert!(matches!(
        analyze(&path, Seeding::EntryPoints, &Options::default()),
        Err(BlastError::Refused(Refusal::InvalidGraph))
    ));
    // A graph id that does not seal the graph.
    let mut graph = l.graph.clone();
    graph.id = format!("graph:{}", "0".repeat(64));
    let path = write_graph(tmp.path(), &graph);
    assert!(matches!(
        analyze(&path, Seeding::EntryPoints, &Options::default()),
        Err(BlastError::Refused(Refusal::InvalidGraph))
    ));
}

/// O-06: node, edge and seed order never change the document. A graph file
/// must be sorted to pass v2 validation, so the shuffles go to
/// `analyze_graph` directly (REGRESSION R-5).
#[test]
fn ten_shuffles_give_identical_documents() {
    let l = lab();
    let seeds = entry_point_seeds(&l.graph).unwrap();
    let baseline = analyze_graph(&l.graph, &seeds, &Options::default()).unwrap();
    let baseline = serde_json::to_value(&baseline).unwrap();
    let mut state = 0x243F_6A88_85A3_08D3u64;
    let mut next = |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % n as u64) as usize
    };
    for round in 0..10 {
        let mut graph = l.graph.clone();
        for i in (1..graph.nodes.len()).rev() {
            graph.nodes.swap(i, next(i + 1));
        }
        for i in (1..graph.edges.len()).rev() {
            graph.edges.swap(i, next(i + 1));
        }
        graph.targets.reverse();
        graph.id = graph_id_v2(&graph).unwrap();
        let mut shuffled = seeds.clone();
        shuffled.seeds.reverse();
        let doc = analyze_graph(&graph, &shuffled, &Options::default()).unwrap();
        let mut doc = serde_json::to_value(&doc).unwrap();
        doc["graph_id"] = json!(l.graph.id);
        assert_eq!(doc, baseline, "round {round}");
    }
}
