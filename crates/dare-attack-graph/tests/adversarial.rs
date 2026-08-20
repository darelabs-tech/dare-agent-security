use dare_attack_graph::{
    build_attack_graph, derive_paths, GraphError, GraphFactsInput, PathOptions,
};

fn safe_facts() -> GraphFactsInput {
    serde_json::from_str(include_str!(
        "../../../fixtures/attack-graph/safe-read.json"
    ))
    .unwrap()
}

#[test]
fn hostile_secret_label_is_rejected_without_echo() {
    let mut facts = safe_facts();
    facts.nodes[0].display_name = "Bearer synthetic-canary".into();
    let error = build_attack_graph(&facts).unwrap_err().to_string();
    assert!(!error.contains("synthetic-canary"));
}

#[test]
fn duplicate_nodes_and_missing_references_fail() {
    let mut duplicate = safe_facts();
    duplicate.nodes.push(duplicate.nodes[0].clone());
    assert!(build_attack_graph(&duplicate).is_err());

    let mut missing = safe_facts();
    missing.edges[0].target_local_id = "absent".into();
    assert!(build_attack_graph(&missing).is_err());
}

#[test]
fn traversal_is_bounded_and_refuses_huge_depth() {
    let graph = build_attack_graph(&safe_facts()).unwrap();
    let paths = derive_paths(
        &graph,
        &PathOptions {
            max_paths: 1,
            ..PathOptions::default()
        },
    )
    .unwrap();
    assert_eq!(paths.len(), 1);
    let error = derive_paths(
        &graph,
        &PathOptions {
            max_depth: 65,
            ..PathOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(error, GraphError::SafetyRefusal(_)));
}

#[test]
fn unbounded_zero_options_are_refused() {
    let graph = build_attack_graph(&safe_facts()).unwrap();
    assert!(derive_paths(
        &graph,
        &PathOptions {
            max_depth: 0,
            max_paths: 0,
            source_filter: None,
            target_filter: None,
        }
    )
    .is_err());
}
