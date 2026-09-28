//! Cycle 023 tasks 003–006: the v2 contract, its invariants and its views.
use dare_attack_graph::{
    build_edge_id,
    v2::{
        graph_id_v2, impact_factors, path_control, path_id, path_status, to_dot_v2, to_mermaid_v2,
        validate_graph_v2, validate_paths_v2, validate_projection_report, AliasReport,
        ArtifactReport, ArtifactSource, AttackGraphV2, AttackPathsDoc, ControlState,
        DesignationOrigin, EdgeV2, EntryClass, EntryDesignation, Enumeration, FactCounts,
        Feasibility, Guard, GuardScope, GuardVerdict, NodeV2, PathV2, ProjectionReport, Provenance,
        SourcesV2, TargetClass, TargetDesignation, ATTACK_GRAPH_SCHEMA_V2_JSON,
        ATTACK_PATHS_SCHEMA_V2_JSON, DOCUMENT_SCHEMA_VERSION, GRAPH_SCHEMA_ID_V2,
        GRAPH_SCHEMA_VERSION_V2, PATHS_SCHEMA_ID_V2, PROJECTION_REPORT_SCHEMA_V2_JSON,
        REPORT_SCHEMA_ID_V2,
    },
    AuthorityContext, EdgeEvidence, EdgeEvidenceStatus, EdgeType, GraphEngine, NodeSecurity,
    NodeType, SchemaRef,
};

fn provenance(locator: &str) -> Vec<Provenance> {
    vec![Provenance {
        artifact_index: Some(0),
        original_kind: "test".into(),
        locator: locator.into(),
    }]
}

fn node(id: &str, node_type: NodeType, security: NodeSecurity) -> NodeV2 {
    NodeV2 {
        id: id.into(),
        node_type,
        display_name: id.rsplit(':').next().unwrap().into(),
        security,
        provenance: provenance("/nodes"),
    }
}

fn observed() -> EdgeEvidence {
    EdgeEvidence {
        status: EdgeEvidenceStatus::Observed,
        evidence_ids: vec!["urn:dare:test:evidence:1".into()],
        rationale: None,
        source_facts: vec![],
        reason: None,
    }
}

fn guard(property: &str, verdict: GuardVerdict) -> Guard {
    Guard {
        property: property.into(),
        verdict,
        evidence_ids: vec!["urn:dare:test:evidence:1".into()],
        scope: GuardScope::Run,
        artifact_index: 0,
    }
}

fn edge(
    source: &str,
    edge_type: EdgeType,
    target: &str,
    tenant: Option<&str>,
    guards: Vec<Guard>,
) -> EdgeV2 {
    let authority = AuthorityContext {
        tenant: tenant.map(str::to_owned),
        ..AuthorityContext::default()
    };
    EdgeV2 {
        id: build_edge_id(source, edge_type, target, &authority).unwrap(),
        edge_type,
        source: source.into(),
        target: target.into(),
        authority,
        evidence: observed(),
        guards,
        authority_mutation: false,
        crosses_trust_boundary: vec![],
        provenance: provenance("/edges"),
    }
}

const USER: &str = "node:human:user-a";
const AGENT: &str = "node:agent:support";
const TOOL: &str = "node:tool:tool:0123456789ab:export";
const RECORDS: &str = "node:resource:records-b";
const TENANT: &str = "node:tenant:tenant-b";

/// A small valid graph: user → agent → tool → records, records ∈ tenant-b.
fn golden_graph() -> AttackGraphV2 {
    let sensitive = NodeSecurity {
        tenant: Some("tenant-b".into()),
        sensitive: true,
        ..NodeSecurity::default()
    };
    let mut nodes = vec![
        node(USER, NodeType::Human, NodeSecurity::default()),
        node(AGENT, NodeType::Agent, NodeSecurity::default()),
        node(TOOL, NodeType::Tool, NodeSecurity::default()),
        node(RECORDS, NodeType::Resource, sensitive),
        node(TENANT, NodeType::Tenant, NodeSecurity::default()),
    ];
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    let mut edges = vec![
        edge(
            USER,
            EdgeType::DelegatesTo,
            AGENT,
            Some("tenant-a"),
            vec![guard(
                "AGENT.IDENTITY.DELEGATION_INTEGRITY",
                GuardVerdict::Pass,
            )],
        ),
        edge(
            AGENT,
            EdgeType::Calls,
            TOOL,
            None,
            vec![
                guard("AGENT.TOOL.AUTHORIZATION_BOUNDARY", GuardVerdict::Pass),
                guard("AGENT.TOOL.CHAIN_BOUNDARY", GuardVerdict::Fail),
            ],
        ),
        edge(TOOL, EdgeType::Reads, RECORDS, Some("tenant-b"), vec![]),
        edge(RECORDS, EdgeType::BelongsToTenant, TENANT, None, vec![]),
    ];
    edges.sort_by(|a, b| a.id.cmp(&b.id));
    let mut graph = AttackGraphV2 {
        schema: SchemaRef {
            id: GRAPH_SCHEMA_ID_V2.into(),
            version: GRAPH_SCHEMA_VERSION_V2.into(),
        },
        id: String::new(),
        target_id: "support-agent".into(),
        target_version: "v1".into(),
        sources: SourcesV2 {
            model_digest: None,
            artifacts: vec![ArtifactSource {
                index: 0,
                engine: "identity".into(),
                run: "0123456789ab".into(),
                mode: "REPLAY".into(),
                synthetic: true,
                dynamic_authorized: false,
                result_digest: format!("sha256:{}", "a".repeat(64)),
                evidence_digest: format!("sha256:{}", "b".repeat(64)),
                input_digests: vec![format!("sha256:{}", "c".repeat(64))],
            }],
        },
        engine: GraphEngine {
            name: "dare-attack-path".into(),
            version: "test".into(),
            commit: "local".into(),
        },
        nodes,
        edges,
        entry_points: vec![EntryDesignation {
            node: USER.into(),
            class: EntryClass::LowPrivilegePrincipal,
            origin: DesignationOrigin::Default,
        }],
        targets: vec![TargetDesignation {
            node: RECORDS.into(),
            class: TargetClass::SensitiveResource,
            origin: DesignationOrigin::Default,
        }],
    };
    graph.id = graph_id_v2(&graph).unwrap();
    graph
}

fn golden_path(graph: &AttackGraphV2) -> PathV2 {
    let nodes: Vec<String> = [USER, AGENT, TOOL, RECORDS].map(str::to_owned).to_vec();
    let edges: Vec<&EdgeV2> = nodes
        .windows(2)
        .map(|pair| {
            graph
                .edges
                .iter()
                .find(|e| e.source == pair[0] && e.target == pair[1])
                .unwrap()
        })
        .collect();
    let node_refs: Vec<&NodeV2> = nodes
        .iter()
        .map(|id| graph.nodes.iter().find(|n| &n.id == id).unwrap())
        .collect();
    let edge_ids: Vec<String> = edges.iter().map(|e| e.id.clone()).collect();
    let (control_state, failed_guards, undecided_edges) = path_control(&edges);
    PathV2 {
        id: path_id(&nodes, &edge_ids).unwrap(),
        status: path_status(&edges),
        feasibility: Feasibility::Feasible,
        discontinuity_at: None,
        control_state,
        failed_guards,
        undecided_edges,
        entry: USER.into(),
        entry_class: EntryClass::LowPrivilegePrincipal,
        target: RECORDS.into(),
        target_class: TargetClass::SensitiveResource,
        impact_factors: impact_factors(&node_refs, &edges),
        nodes,
        edges: edge_ids,
    }
}

fn golden_paths(graph: &AttackGraphV2) -> AttackPathsDoc {
    AttackPathsDoc {
        schema_id: PATHS_SCHEMA_ID_V2.into(),
        schema_version: DOCUMENT_SCHEMA_VERSION.into(),
        graph_id: graph.id.clone(),
        paths: vec![golden_path(graph)],
        discontinuous_paths: vec![],
        chokepoints: vec![],
        enumeration: Enumeration {
            max_path_edges: 8,
            max_paths: 10_000,
            max_paths_per_pair: 64,
            max_steps: 5_000_000,
            steps_used: 12,
            truncated: false,
            stopped_by: vec![],
            pairs_total: 1,
            pairs_exhausted: 1,
            pairs_truncated_count: 0,
            pairs_truncated: vec![],
        },
    }
}

#[test]
fn the_embedded_schemas_compile() {
    for raw in [
        ATTACK_GRAPH_SCHEMA_V2_JSON,
        ATTACK_PATHS_SCHEMA_V2_JSON,
        PROJECTION_REPORT_SCHEMA_V2_JSON,
    ] {
        let schema: serde_json::Value = serde_json::from_str(raw).unwrap();
        jsonschema::options().build(&schema).unwrap();
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    }
}

#[test]
fn the_golden_example_validates_and_round_trips() {
    let graph = golden_graph();
    validate_graph_v2(&graph).unwrap();
    let doc = golden_paths(&graph);
    validate_paths_v2(&graph, &doc).unwrap();
    let path = &doc.paths[0];
    assert_eq!(path.control_state, ControlState::ControlFailed);
    assert_eq!(path.failed_guards.len(), 1);
    assert_eq!(path.failed_guards[0].property, "AGENT.TOOL.CHAIN_BOUNDARY");
    assert_eq!(path.undecided_edges.len(), 1, "the unguarded READS edge");
    assert!(path.impact_factors.v1.cross_tenant);
    assert!(path.impact_factors.v1.reaches_sensitive_resource);
    let text = serde_json::to_string(&graph).unwrap();
    let back: AttackGraphV2 = serde_json::from_str(&text).unwrap();
    assert_eq!(back, graph);
    let text = serde_json::to_string(&doc).unwrap();
    let back: AttackPathsDoc = serde_json::from_str(&text).unwrap();
    assert_eq!(back, doc);
}

fn rejected(graph: &AttackGraphV2) -> bool {
    validate_graph_v2(graph).is_err()
}

fn reseal(graph: &mut AttackGraphV2) {
    graph.id = graph_id_v2(graph).unwrap();
}

#[test]
fn invariant_1_edge_evidence_rules_hold() {
    let mut graph = golden_graph();
    graph.edges[0].evidence.evidence_ids.clear();
    reseal(&mut graph);
    assert!(rejected(&graph));
}

#[test]
fn invariant_2_edge_ids_are_recomputed() {
    let mut graph = golden_graph();
    graph.edges[0].authority.tenant = Some("tenant-z".into());
    reseal(&mut graph);
    assert!(rejected(&graph));
}

#[test]
fn invariant_3_references_resolve() {
    let mut graph = golden_graph();
    graph.targets[0].node = "node:resource:absent".into();
    reseal(&mut graph);
    assert!(rejected(&graph));
    let graph = golden_graph();
    let mut doc = golden_paths(&graph);
    doc.paths[0].edges[1] = format!("edge:{}", "0".repeat(64));
    assert!(validate_paths_v2(&graph, &doc).is_err());
}

#[test]
fn invariant_4_guard_verdicts_are_closed() {
    let mut value = serde_json::to_value(golden_graph()).unwrap();
    let edges = value["edges"].as_array_mut().unwrap();
    let with_guard = edges
        .iter_mut()
        .find(|e| !e["guards"].as_array().unwrap().is_empty())
        .unwrap();
    with_guard["guards"][0]["verdict"] = "SECURE".into();
    assert!(serde_json::from_value::<AttackGraphV2>(value).is_err());
}

#[test]
fn invariant_5_provenance_and_guards_name_known_artifacts() {
    let mut graph = golden_graph();
    graph.nodes[0].provenance[0].artifact_index = Some(7);
    reseal(&mut graph);
    assert!(rejected(&graph));
    let mut graph = golden_graph();
    let index = graph
        .edges
        .iter()
        .position(|e| !e.guards.is_empty())
        .unwrap();
    graph.edges[index].guards[0].artifact_index = 9;
    reseal(&mut graph);
    assert!(rejected(&graph));
}

#[test]
fn invariant_6_a_doctored_control_state_is_refused() {
    let graph = golden_graph();
    let mut doc = golden_paths(&graph);
    doc.paths[0].control_state = ControlState::ControlsHeld;
    doc.paths[0].failed_guards.clear();
    doc.paths[0].undecided_edges.clear();
    assert!(validate_paths_v2(&graph, &doc).is_err());
    let mut doc = golden_paths(&graph);
    doc.paths[0].status = dare_attack_graph::PathStatus::Proven;
    doc.paths[0].impact_factors.v1.cross_tenant = false;
    assert!(validate_paths_v2(&graph, &doc).is_err());
}

#[test]
fn invariant_7_lists_are_sorted_and_the_graph_id_is_sealed() {
    let mut graph = golden_graph();
    graph.nodes.swap(0, 1);
    reseal(&mut graph);
    assert!(rejected(&graph));
    let mut graph = golden_graph();
    graph.target_version = "v2".into();
    assert!(rejected(&graph), "id no longer matches the content");
}

#[test]
fn a_path_must_be_in_the_list_of_its_feasibility() {
    let graph = golden_graph();
    let mut doc = golden_paths(&graph);
    let mut path = doc.paths.remove(0);
    path.feasibility = Feasibility::Discontinuous;
    doc.paths.push(path);
    assert!(validate_paths_v2(&graph, &doc).is_err());
}

#[test]
fn the_projection_report_is_bound_to_its_graph() {
    let graph = golden_graph();
    let report = ProjectionReport {
        schema_id: REPORT_SCHEMA_ID_V2.into(),
        schema_version: DOCUMENT_SCHEMA_VERSION.into(),
        graph_id: graph.id.clone(),
        model_digest: None,
        artifacts: vec![ArtifactReport {
            index: 0,
            engine: "identity".into(),
            run: "0123456789ab".into(),
            mode: "REPLAY".into(),
            synthetic: true,
            dynamic_authorized: false,
            result_digest: graph.sources.artifacts[0].result_digest.clone(),
            evidence_digest: graph.sources.artifacts[0].evidence_digest.clone(),
            verified_inputs: vec!["scenario".into()],
            facts: FactCounts::default(),
            unprojected: Default::default(),
        }],
        aliases_used: vec![],
        aliases_unused: vec![AliasReport {
            engine: "tool".into(),
            local_id: "sut".into(),
            run: None,
            entity_id: "support".into(),
            matched_nodes: 0,
        }],
    };
    validate_projection_report(&graph, &report).unwrap();
    let mut other = report.clone();
    other.graph_id = format!("graph:{}", "f".repeat(64));
    assert!(validate_projection_report(&graph, &other).is_err());
}

#[test]
fn views_label_state_in_text_and_escape_hostile_labels() {
    let mut graph = golden_graph();
    let index = graph.nodes.iter().position(|n| n.id == AGENT).unwrap();
    graph.nodes[index].display_name = "evil\"]; click n0 --> <script>".into();
    reseal(&mut graph);
    let mermaid = to_mermaid_v2(&graph).unwrap();
    let dot = to_dot_v2(&graph).unwrap();
    for view in [&mermaid, &dot] {
        assert!(
            view.contains("evil\\\"]; click n0 --&gt; &lt;script&gt;"),
            "{view}"
        );
        assert!(!view.contains("<script>"));
        assert!(
            view.contains("{FAIL}")
                && view.contains("{UNASSESSED}")
                && view.contains("{STRUCTURAL}")
        );
        assert!(view.contains("[Observed]"));
    }
}

#[test]
fn a_secret_like_label_is_refused_by_the_views() {
    let mut graph = golden_graph();
    graph.nodes[0].display_name = "Bearer abc".into();
    reseal(&mut graph);
    assert!(to_mermaid_v2(&graph).is_err());
}
