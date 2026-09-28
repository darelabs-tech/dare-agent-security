//! Path engine v2: enumeration, classification and chokepoints (tasks 033–035).
mod support;

use dare_attack_graph::{
    v2::{
        path_id, validate_graph_v2, validate_paths_v2, ControlState, EntryClass, Feasibility,
        GuardVerdict, StopBound, TargetClass,
    },
    AuthorityContext, EdgeType, NodeSecurity, NodeType,
};
use dare_attack_path::{
    enumerate::{enumerate, Bounds, PairSpec},
    paths::attack_paths,
    ConstructOptions,
};
use support::G;

fn plain() -> NodeSecurity {
    NodeSecurity::default()
}

fn opts(max_path_edges: u32, max_paths: u32, per_pair: u32) -> ConstructOptions {
    ConstructOptions {
        max_path_edges,
        max_paths,
        max_paths_per_pair: per_pair,
    }
}

/// entry → a → b → target and entry → target, plus a cycle a ⇄ b.
fn diamond() -> dare_attack_graph::v2::AttackGraphV2 {
    let mut g = G::new();
    let entry = g.node(NodeType::Data, "entry", plain());
    let agent = g.node(NodeType::Agent, "agent", plain());
    let tool = g.node(NodeType::Tool, "tool", plain());
    let target = g.node(
        NodeType::Resource,
        "target",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    g.edge(
        &entry,
        EdgeType::TransfersTo,
        &agent,
        Some(GuardVerdict::Fail),
    );
    g.edge(&agent, EdgeType::Calls, &tool, Some(GuardVerdict::Pass));
    g.edge(&tool, EdgeType::Calls, &agent, Some(GuardVerdict::Pass));
    g.edge(&tool, EdgeType::Reads, &target, Some(GuardVerdict::Pass));
    g.edge(&agent, EdgeType::Reads, &target, None);
    g.entry(&entry, EntryClass::ExternalContent);
    g.target(&target, TargetClass::SensitiveResource);
    g.build()
}

#[test]
fn paths_are_shortest_first_simple_and_validated() {
    let graph = diamond();
    validate_graph_v2(&graph).unwrap();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    let lengths: Vec<usize> = doc.paths.iter().map(|p| p.edges.len()).collect();
    assert_eq!(
        lengths,
        vec![2, 3],
        "entry→agent→target, then entry→agent→tool→target"
    );
    for path in &doc.paths {
        assert_eq!(
            path.id,
            path_id(&path.nodes, &path.edges).unwrap(),
            "the v1 id formula"
        );
        assert_eq!(path.feasibility, Feasibility::Feasible);
        assert_eq!(
            path.control_state,
            ControlState::ControlFailed,
            "the entry edge FAILs"
        );
    }
    assert!(!doc.enumeration.truncated);
    assert_eq!(doc.enumeration.pairs_exhausted, 1);
}

#[test]
fn an_unguarded_edge_leaves_the_path_undecided_and_a_held_path_is_held() {
    let mut g = G::new();
    let entry = g.node(NodeType::Data, "e", plain());
    let agent = g.node(NodeType::Agent, "a", plain());
    let target = g.node(
        NodeType::Resource,
        "t",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    let tenant = g.node(NodeType::Tenant, "x", plain());
    g.edge(
        &entry,
        EdgeType::TransfersTo,
        &agent,
        Some(GuardVerdict::Pass),
    );
    g.edge(&agent, EdgeType::Reads, &target, Some(GuardVerdict::Pass));
    g.edge(&target, EdgeType::BelongsToTenant, &tenant, None);
    g.entry(&entry, EntryClass::ExternalContent);
    g.target(&target, TargetClass::SensitiveResource);
    g.target(&tenant, TargetClass::SensitiveResource);
    let graph = g.build();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    let held: Vec<_> = doc
        .paths
        .iter()
        .filter(|p| p.control_state == ControlState::ControlsHeld)
        .collect();
    assert_eq!(held.len(), 2, "BQ-1: the tenant edge needs no guard");
    let mut g2 = G::new();
    let entry = g2.node(NodeType::Data, "e", plain());
    let agent = g2.node(NodeType::Agent, "a", plain());
    let target = g2.node(
        NodeType::Resource,
        "t",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    g2.edge(
        &entry,
        EdgeType::TransfersTo,
        &agent,
        Some(GuardVerdict::Pass),
    );
    g2.edge(&agent, EdgeType::Reads, &target, None);
    g2.entry(&entry, EntryClass::ExternalContent);
    g2.target(&target, TargetClass::SensitiveResource);
    let graph = g2.build();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    assert_eq!(doc.paths[0].control_state, ControlState::ControlUndecided);
    assert_eq!(doc.paths[0].undecided_edges.len(), 1);
}

#[test]
fn discontinuous_paths_are_listed_apart() {
    let mut g = G::new();
    let entry = g.node(NodeType::Human, "user", plain());
    let agent = g.node(NodeType::Agent, "agent", plain());
    let other = g.node(NodeType::Agent, "other", plain());
    let target = g.node(
        NodeType::Resource,
        "records",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    g.edge(
        &entry,
        EdgeType::DelegatesTo,
        &agent,
        Some(GuardVerdict::Pass),
    );
    let authority = AuthorityContext {
        principal: Some(other.clone()),
        ..AuthorityContext::default()
    };
    g.edge_with(
        &agent,
        EdgeType::Reads,
        &target,
        Some(("AGENT.TOOL.CHAIN_BOUNDARY", GuardVerdict::Pass)),
        authority,
        false,
    );
    g.entry(&entry, EntryClass::LowPrivilegePrincipal);
    g.target(&target, TargetClass::SensitiveResource);
    let graph = g.build();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    assert!(doc.paths.is_empty());
    assert_eq!(doc.discontinuous_paths.len(), 1);
    assert_eq!(doc.discontinuous_paths[0].discontinuity_at, Some(1));
    assert!(
        doc.chokepoints.is_empty(),
        "discontinuous paths give no chokepoint"
    );
}

/// A complete directed graph on `n` nodes.
fn complete(n: usize) -> dare_attack_graph::v2::AttackGraphV2 {
    let mut g = G::new();
    let ids: Vec<String> = (0..n)
        .map(|i| g.node(NodeType::Agent, &format!("n{i:02}"), plain()))
        .collect();
    for a in &ids {
        for b in &ids {
            if a != b {
                g.edge(a, EdgeType::Calls, b, Some(GuardVerdict::Pass));
            }
        }
    }
    g.entry(&ids[0], EntryClass::PeerAgent);
    g.target(&ids[n - 1], TargetClass::SensitiveResource);
    g.build()
}

#[test]
fn the_per_pair_cap_is_reported_and_keeps_the_shortest() {
    let graph = complete(6);
    let doc = attack_paths(&graph, &opts(5, 10_000, 3)).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    assert_eq!(doc.paths.len(), 3);
    assert_eq!(doc.paths[0].edges.len(), 1, "the direct edge first");
    assert!(doc.enumeration.truncated);
    assert_eq!(doc.enumeration.stopped_by, vec![StopBound::MaxPathsPerPair]);
    assert_eq!(doc.enumeration.pairs_truncated_count, 1);
    assert_eq!(doc.enumeration.pairs_truncated.len(), 1);
}

#[test]
fn the_global_cap_and_the_step_bound_are_reported() {
    let graph = complete(6);
    let doc = attack_paths(&graph, &opts(5, 2, 64)).unwrap();
    assert_eq!(doc.paths.len(), 2);
    assert!(doc.enumeration.stopped_by.contains(&StopBound::MaxPaths));
    let pair = PairSpec {
        entry: graph.entry_points[0].node.clone(),
        target: graph.targets[0].node.clone(),
        entry_class: EntryClass::PeerAgent,
        target_class: TargetClass::SensitiveResource,
    };
    // K₁₁ plus a target nothing reaches: the search must exhaust every
    // simple path, which only the step bound can stop.
    let mut g = G::new();
    let ids: Vec<String> = (0..11)
        .map(|i| g.node(NodeType::Agent, &format!("n{i:02}"), plain()))
        .collect();
    for a in &ids {
        for b in &ids {
            if a != b {
                g.edge(a, EdgeType::Calls, b, Some(GuardVerdict::Pass));
            }
        }
    }
    let unreachable = g.node(NodeType::Resource, "vault", plain());
    let dense = g.build();
    let pair = PairSpec {
        entry: ids[0].clone(),
        target: unreachable,
        ..pair
    };
    let bounds = Bounds {
        max_path_edges: 12,
        max_paths: 10_000,
        max_paths_per_pair: 64,
        max_steps: 1_000,
    };
    let (found, enumeration) = enumerate(&dense, std::slice::from_ref(&pair), &bounds);
    assert_eq!(
        enumeration.stopped_by,
        vec![StopBound::MaxSteps],
        "{enumeration:?}"
    );
    assert_eq!(
        enumeration.steps_used, 1_001,
        "stopped on the first step past the bound"
    );
    assert!(found.is_empty());
    let real = Bounds {
        max_steps: dare_attack_path::limits::MAX_STEPS,
        ..bounds
    };
    let (_, enumeration) = enumerate(&dense, &[pair], &real);
    assert_eq!(enumeration.stopped_by, vec![StopBound::MaxSteps]);
    assert_eq!(
        enumeration.steps_used,
        dare_attack_path::limits::MAX_STEPS + 1
    );
}

#[test]
fn cycles_and_self_loops_do_not_repeat_nodes() {
    let mut g = G::new();
    let a = g.node(NodeType::Agent, "a", plain());
    let b = g.node(NodeType::Agent, "b", plain());
    let t = g.node(
        NodeType::Resource,
        "t",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    g.edge(&a, EdgeType::Calls, &a, Some(GuardVerdict::Pass));
    g.edge(&a, EdgeType::Calls, &b, Some(GuardVerdict::Pass));
    g.edge(&b, EdgeType::Calls, &a, Some(GuardVerdict::Pass));
    g.edge(&b, EdgeType::Reads, &t, Some(GuardVerdict::Pass));
    g.entry(&a, EntryClass::PeerAgent);
    g.target(&t, TargetClass::SensitiveResource);
    let graph = g.build();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &doc).unwrap();
    assert_eq!(doc.paths.len(), 1);
    assert_eq!(doc.paths[0].nodes.len(), 3);
}

#[test]
fn ids_and_order_do_not_depend_on_input_order() {
    let graph = diamond();
    let reference =
        serde_json::to_vec(&attack_paths(&graph, &ConstructOptions::default()).unwrap()).unwrap();
    for rotation in 0..10 {
        let mut shuffled = graph.clone();
        let n = shuffled.nodes.len();
        shuffled.nodes.rotate_left(rotation % n);
        let m = shuffled.edges.len();
        shuffled.edges.rotate_left((rotation * 3) % m);
        if rotation % 2 == 1 {
            shuffled.edges.reverse();
        }
        let doc = attack_paths(&shuffled, &ConstructOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_vec(&doc).unwrap(),
            reference,
            "rotation {rotation}"
        );
    }
}

#[test]
fn chokepoints_are_the_edges_every_failed_path_shares() {
    let graph = diamond();
    let doc = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    // Both failed paths share only the entry edge (the other edges differ).
    assert_eq!(doc.chokepoints.len(), 1);
    let choke = &doc.chokepoints[0];
    assert_eq!(choke.failed_paths, 2);
    assert!(!choke.partial);
    assert_eq!(
        choke.properties,
        vec!["AGENT.TOOL.CHAIN_BOUNDARY".to_owned()]
    );
    let entry_edge = graph
        .edges
        .iter()
        .find(|e| e.edge_type == EdgeType::TransfersTo)
        .unwrap();
    assert_eq!(choke.edge, entry_edge.id);
    // Truncation marks chokepoints partial.
    let doc = attack_paths(&graph, &opts(8, 10_000, 1)).unwrap();
    assert!(doc.chokepoints.iter().all(|c| c.partial));
}

#[test]
fn a_single_failed_path_makes_every_non_structural_edge_a_chokepoint_and_disjoint_paths_none() {
    let mut g = G::new();
    let e = g.node(NodeType::Data, "e", plain());
    let a = g.node(NodeType::Agent, "a", plain());
    let b = g.node(NodeType::Agent, "b", plain());
    let t = g.node(
        NodeType::Resource,
        "t",
        NodeSecurity {
            sensitive: true,
            ..plain()
        },
    );
    g.edge(&e, EdgeType::TransfersTo, &a, Some(GuardVerdict::Fail));
    g.edge(&e, EdgeType::TransfersTo, &b, Some(GuardVerdict::Fail));
    g.edge(&a, EdgeType::Reads, &t, Some(GuardVerdict::Pass));
    g.edge(&b, EdgeType::Reads, &t, Some(GuardVerdict::Pass));
    g.entry(&e, EntryClass::ExternalContent);
    g.target(&t, TargetClass::SensitiveResource);
    let doc = attack_paths(&g.build(), &ConstructOptions::default()).unwrap();
    assert_eq!(doc.paths.len(), 2);
    assert!(
        doc.chokepoints.is_empty(),
        "disjoint failed paths share no edge"
    );
}

#[test]
fn a_cross_tenant_resource_is_a_target_for_an_entry_of_another_tenant() {
    let mut g = G::new();
    let user = g.node(
        NodeType::Human,
        "user",
        NodeSecurity {
            tenant: Some("a".into()),
            ..plain()
        },
    );
    let doc = g.node(
        NodeType::Data,
        "doc",
        NodeSecurity {
            tenant: Some("b".into()),
            ..plain()
        },
    );
    g.edge(&user, EdgeType::Reads, &doc, Some(GuardVerdict::Fail));
    g.entry(&user, EntryClass::LowPrivilegePrincipal);
    let graph = g.build();
    let result = attack_paths(&graph, &ConstructOptions::default()).unwrap();
    validate_paths_v2(&graph, &result).unwrap();
    assert_eq!(result.paths.len(), 1);
    assert_eq!(
        result.paths[0].target_class,
        TargetClass::CrossTenantResource
    );
}

/// The six v1 impact factors, computed by v2 over the same nodes and edges,
/// equal v1's on every path of the five v1 fixtures (BLUEPRINT §7.6). v1
/// carries a FAIL in `edge.security.verdict`; v2 carries it as a FAIL guard.
#[test]
fn v2_impact_factors_equal_v1_on_the_v1_fixtures() {
    use dare_attack_graph::{
        build_attack_graph, derive_paths,
        v2::{impact_factors, EdgeV2, Guard, GuardScope, NodeV2, Provenance},
        GraphFactsInput, PathOptions,
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/attack-graph");
    let mut compared = 0;
    for name in [
        "auth-mutation",
        "blocked-destructive",
        "confused-deputy",
        "inferred-credential",
        "safe-read",
    ] {
        let facts: GraphFactsInput =
            serde_json::from_slice(&std::fs::read(root.join(format!("{name}.json"))).unwrap())
                .unwrap();
        let graph = build_attack_graph(&facts).unwrap();
        let paths = derive_paths(&graph, &PathOptions::default()).unwrap();
        let prov = vec![Provenance {
            artifact_index: None,
            original_kind: "v1".into(),
            locator: "/".into(),
        }];
        let nodes: Vec<NodeV2> = graph
            .nodes
            .iter()
            .map(|n| NodeV2 {
                id: n.id.clone(),
                node_type: n.node_type,
                display_name: n.display_name.clone(),
                security: n.security.clone(),
                provenance: prov.clone(),
            })
            .collect();
        let edges: Vec<EdgeV2> = graph
            .edges
            .iter()
            .map(|e| EdgeV2 {
                id: e.id.clone(),
                edge_type: e.edge_type,
                source: e.source.clone(),
                target: e.target.clone(),
                authority: e.authority.clone(),
                evidence: e.evidence.clone(),
                guards: (e.security.verdict.as_deref() == Some("FAIL"))
                    .then(|| Guard {
                        property: e.security.property.clone().unwrap_or_default(),
                        verdict: GuardVerdict::Fail,
                        evidence_ids: vec![],
                        scope: GuardScope::Run,
                        artifact_index: 0,
                    })
                    .into_iter()
                    .collect(),
                authority_mutation: e.security.authority_mutation,
                crosses_trust_boundary: vec![],
                provenance: prov.clone(),
            })
            .collect();
        for path in &paths {
            let path_nodes: Vec<&NodeV2> = path
                .nodes
                .iter()
                .map(|id| nodes.iter().find(|n| &n.id == id).unwrap())
                .collect();
            let path_edges: Vec<&EdgeV2> = path
                .edges
                .iter()
                .map(|id| edges.iter().find(|e| &e.id == id).unwrap())
                .collect();
            let v2 = impact_factors(&path_nodes, &path_edges);
            assert_eq!(v2.v1, path.impact_factors, "{name} {}", path.id);
            assert!(!v2.crosses_trust_boundary);
            compared += 1;
        }
    }
    assert!(compared >= 5, "{compared}");
}
