use std::path::PathBuf;

use dare_attack_graph::{
    build_attack_graph, derive_paths, load_facts_file, validate_graph, PathOptions, PathStatus,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/attack-graph")
        .join(name)
}

#[test]
fn all_synthetic_fixtures_build_validate_and_derive_paths() {
    for name in [
        "safe-read.json",
        "confused-deputy.json",
        "inferred-credential.json",
        "blocked-destructive.json",
        "auth-mutation.json",
    ] {
        let facts = load_facts_file(&fixture(name)).unwrap();
        let mut graph = build_attack_graph(&facts).unwrap();
        graph.paths = derive_paths(&graph, &PathOptions::default()).unwrap();
        assert!(!graph.paths.is_empty(), "{name}");
        validate_graph(&graph).unwrap();
    }
}

#[test]
fn weakest_edge_and_impact_semantics_are_visible() {
    let safe = build_attack_graph(&load_facts_file(&fixture("safe-read.json")).unwrap()).unwrap();
    assert_eq!(
        derive_paths(&safe, &PathOptions::default()).unwrap()[0].status,
        PathStatus::Proven
    );
    let blocked =
        build_attack_graph(&load_facts_file(&fixture("blocked-destructive.json")).unwrap())
            .unwrap();
    let path = &derive_paths(&blocked, &PathOptions::default()).unwrap()[0];
    assert_eq!(path.status, PathStatus::NotTested);
    assert!(path.impact_factors.contains_destructive_capability);
}
