//! Schemas (tasks 008, 009) and seed resolution (task-010, BLUEPRINT §4.3, §6.1).
mod support;

use dare_attack_graph::{
    v2::{EntryClass, TargetClass},
    EdgeType, NodeType,
};
use dare_blast_radius::{
    model::{
        BlastRadiusDoc, SeedKind, BLAST_RADIUS_SCHEMA_ID, BLAST_RADIUS_SCHEMA_JSON,
        COMPROMISE_SCHEMA_JSON,
    },
    scenario::{entry_point_seeds, kind_fits, scenario_from_value},
    BlastError, Refusal,
};
use serde_json::{json, Value};
use support::{Gd, G};

fn refusal<T: std::fmt::Debug>(result: Result<T, BlastError>) -> Refusal {
    match result {
        Err(BlastError::Refused(r)) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Every object schema, at any depth, closes its properties.
fn assert_closed(value: &Value, at: &str) {
    match value {
        Value::Object(map) => {
            if map.get("type") == Some(&Value::String("object".into()))
                && map.contains_key("properties")
            {
                assert_eq!(
                    map.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{at} is open"
                );
            }
            for (key, child) in map {
                assert_closed(child, &format!("{at}/{key}"));
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                assert_closed(child, &format!("{at}/{i}"));
            }
        }
        _ => {}
    }
}

/// Every property name any object schema declares.
fn property_names(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if map.get("type") == Some(&Value::String("object".into())) {
                if let Some(Value::Object(props)) = map.get("properties") {
                    out.extend(props.keys().cloned());
                }
            }
            map.values().for_each(|child| property_names(child, out));
        }
        Value::Array(items) => items.iter().for_each(|child| property_names(child, out)),
        _ => {}
    }
}

fn compile(schema: &str) -> jsonschema::Validator {
    jsonschema::options()
        .build(&serde_json::from_str(schema).unwrap())
        .unwrap()
}

#[test]
fn both_schemas_compile_and_are_closed() {
    for schema in [COMPROMISE_SCHEMA_JSON, BLAST_RADIUS_SCHEMA_JSON] {
        compile(schema);
        assert_closed(&serde_json::from_str(schema).unwrap(), "#");
    }
}

fn graph() -> dare_attack_graph::v2::AttackGraphV2 {
    let mut g = G::new();
    let alice = g.node_with(NodeType::Human, "alice", G::tenant("tenant-a"));
    let cred = g.node(NodeType::Credential, "cred");
    let doc = g.node(NodeType::Data, "doc");
    let tool = g.node(NodeType::Tool, "tool");
    let _run = g.node(NodeType::Human, "memory:0123456789ab:alice");
    g.edge(&alice, EdgeType::UsesCredential, &cred, Gd::Pass);
    g.edge(&doc, EdgeType::TransfersTo, &alice, Gd::None);
    g.edge(&alice, EdgeType::Calls, &tool, Gd::Fail);
    g.entry(&alice, EntryClass::LowPrivilegePrincipal);
    g.entry(&doc, EntryClass::RetrievedDocument);
    g.entry(&doc, EntryClass::PeerAgent);
    g.target(&cred, TargetClass::PrivilegedCredential);
    g.build()
}

fn scenario(graph_id: &str, seeds: Value) -> Value {
    json!({"schema_version": "1", "scenario_id": "s-1", "graph_id": graph_id, "seeds": seeds})
}

#[test]
fn the_compromise_schema_enforces_its_shape() {
    let v = compile(COMPROMISE_SCHEMA_JSON);
    let id = format!("graph:{}", "0".repeat(64));
    let ok = scenario(
        &id,
        json!([{"entity_id": "alice", "kind": "PRINCIPAL_TAKEOVER"}]),
    );
    assert!(v.is_valid(&ok));
    for bad in [
        scenario(&id, json!([])),
        scenario(&id, json!([{"kind": "CREDENTIAL_LEAK"}])),
        scenario(
            &id,
            json!([{"entity_id": "a", "node_id": "node:human:a", "kind": "CREDENTIAL_LEAK"}]),
        ),
        scenario(&id, json!([{"entity_id": "a", "kind": "WORM"}])),
        scenario(
            &id,
            json!([{"entity_id": "A:B", "kind": "CREDENTIAL_LEAK"}]),
        ),
        scenario(
            "graph:xyz",
            json!([{"entity_id": "a", "kind": "CREDENTIAL_LEAK"}]),
        ),
        scenario(
            &id,
            json!((0..65)
                .map(|i| json!({"entity_id": format!("e{i}"), "kind": "CREDENTIAL_LEAK"}))
                .collect::<Vec<_>>()),
        ),
    ] {
        assert!(!v.is_valid(&bad), "{bad}");
    }
    let mut extra = ok.clone();
    extra["score"] = json!(1);
    assert!(!v.is_valid(&extra));
    let mut depth = ok.clone();
    depth["max_depth"] = json!(13);
    assert!(!v.is_valid(&depth));
    depth["max_depth"] = json!(12);
    assert!(v.is_valid(&depth));
}

/// A hand-built document round-trips and validates; no key anywhere in the
/// schema names a score, probability, likelihood or weight (RS-07).
#[test]
fn the_result_document_round_trips_and_carries_no_score() {
    let doc = json!({
        "schema_id": BLAST_RADIUS_SCHEMA_ID, "schema_version": "1.0.0",
        "graph_id": format!("graph:{}", "1".repeat(64)), "scenario_id": "s-1",
        "scenario_digest": format!("sha256:{}", "2".repeat(64)),
        "bounds": {"max_depth": 8, "max_states": 1000000, "max_states_total": 5000000, "max_delta_edges": 64},
        "seeds": [{
            "node": "node:credential:cred", "kind": "CREDENTIAL_LEAK",
            "structural": {"states_explored": 2, "nodes_reached": 2, "refused_steps": 0, "held_edges_skipped": 0, "depth_cut": false, "truncated": false},
            "uncontained": {"states_explored": 1, "nodes_reached": 1, "refused_steps": 0, "held_edges_skipped": 1, "depth_cut": false, "truncated": false},
            "targets": [{
                "node": "node:resource:r", "class": "SENSITIVE_RESOURCE", "exposure": "CONTAINED",
                "structural_route": {"nodes": ["node:credential:cred", "node:resource:r"], "edges": [format!("edge:{}", "3".repeat(64))],
                    "control_state": "CONTROLS_HELD", "failed_guards": [], "undecided_edges": []},
                "frontier": [format!("edge:{}", "3".repeat(64))]}],
            "impact": {"structural": {"targets_by_class": {"SENSITIVE_RESOURCE": 1}, "tenants_reached": [], "trust_boundaries_crossed": [], "privileged_credentials_acquired": []},
                       "uncontained": {"targets_by_class": {}, "tenants_reached": [], "trust_boundaries_crossed": [], "privileged_credentials_acquired": []}}
        }],
        "seeds_skipped": 0, "seeds_omitted": 0,
        "totals": {"exposed": 0, "contained": 1, "containment_unknown": 0, "exposed_by_class": {}},
        "frontier": [{"edge": format!("edge:{}", "3".repeat(64)), "properties": ["AGENT.TOOL.CHAIN_BOUNDARY"], "evidence_ids": ["urn:ev"], "contained_targets": 1}],
        "remediation_delta": [], "truncated": false, "stopped_by": []
    });
    let v = compile(BLAST_RADIUS_SCHEMA_JSON);
    assert!(
        v.is_valid(&doc),
        "{:?}",
        v.iter_errors(&doc)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
    let typed: BlastRadiusDoc = serde_json::from_value(doc.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), doc);
    let mut names = Vec::new();
    property_names(
        &serde_json::from_str(BLAST_RADIUS_SCHEMA_JSON).unwrap(),
        &mut names,
    );
    assert!(names.len() > 40, "{names:?}");
    for name in &names {
        for word in ["score", "probab", "likelihood", "weight", "risk", "rank"] {
            assert!(!name.to_ascii_lowercase().contains(word), "{name}");
        }
    }
}

#[test]
fn seeds_resolve_by_node_or_entity_and_sort() {
    let g = graph();
    let s = scenario(
        &g.id,
        json!([
            {"entity_id": "tool", "kind": "COMPONENT_COMPROMISE"},
            {"node_id": "node:human:alice", "kind": "PRINCIPAL_TAKEOVER", "note": "phished"}
        ]),
    );
    let seeding = scenario_from_value(&s, &g).unwrap();
    let nodes: Vec<&str> = seeding.seeds.iter().map(|s| s.node.as_str()).collect();
    assert_eq!(nodes, ["node:human:alice", "node:tool:tool"]);
    assert_eq!(seeding.seeds[0].tenant.as_deref(), Some("tenant-a"));
    assert!(seeding.scenario_digest.unwrap().starts_with("sha256:"));
    // A run-scoped id is never matched by entity id.
    let run_scoped = scenario(
        &g.id,
        json!([{"entity_id": "0123456789ab", "kind": "PRINCIPAL_TAKEOVER"}]),
    );
    assert_eq!(
        refusal(scenario_from_value(&run_scoped, &g)),
        Refusal::UnknownSeed { seed: 0 }
    );
}

#[test]
fn every_seed_rule_refuses_with_its_variant() {
    let g = graph();
    let one = |seed: Value| scenario(&g.id, json!([seed]));
    assert_eq!(
        refusal(scenario_from_value(
            &scenario(
                &format!("graph:{}", "f".repeat(64)),
                json!([{"entity_id": "alice", "kind": "PRINCIPAL_TAKEOVER"}])
            ),
            &g
        )),
        Refusal::GraphMismatch
    );
    assert_eq!(
        refusal(scenario_from_value(
            &one(json!({"entity_id": "nobody", "kind": "PRINCIPAL_TAKEOVER"})),
            &g
        )),
        Refusal::UnknownSeed { seed: 0 }
    );
    assert_eq!(
        refusal(scenario_from_value(
            &one(json!({"node_id": "node:human:nobody", "kind": "PRINCIPAL_TAKEOVER"})),
            &g
        )),
        Refusal::UnknownSeed { seed: 0 }
    );
    assert_eq!(
        refusal(scenario_from_value(
            &one(json!({"entity_id": "cred", "kind": "PRINCIPAL_TAKEOVER"})),
            &g
        )),
        Refusal::SeedKindMismatch { seed: 0 }
    );
    let dup = scenario(
        &g.id,
        json!([
            {"entity_id": "cred", "kind": "CREDENTIAL_LEAK"},
            {"entity_id": "doc", "kind": "CONTENT_INJECTION"},
            {"node_id": "node:credential:cred", "kind": "CREDENTIAL_LEAK"}
        ]),
    );
    assert_eq!(
        refusal(scenario_from_value(&dup, &g)),
        Refusal::DuplicateSeed {
            first: 0,
            second: 2
        }
    );
    assert_eq!(
        refusal(scenario_from_value(&json!({"schema_version": "1"}), &g)),
        Refusal::InvalidDocument { file: "scenario" }
    );
    // Two nodes of different types sharing one entity id cannot come from a
    // system model; if a graph carries them anyway, the seed is refused.
    let mut two = G::new();
    two.node(NodeType::Tool, "x");
    two.node(NodeType::Data, "x");
    let two = two.build();
    assert_eq!(
        refusal(scenario_from_value(
            &scenario(
                &two.id,
                json!([{"entity_id": "x", "kind": "CONTENT_INJECTION"}])
            ),
            &two
        )),
        Refusal::AmbiguousSeed { seed: 0 }
    );
}

#[test]
fn the_kind_table_is_complete() {
    use NodeType::*;
    let all = [
        Human,
        Agent,
        Identity,
        DelegatedAuthority,
        McpServer,
        Capability,
        Tool,
        Credential,
        DownstreamService,
        Resource,
        Data,
        Tenant,
        PolicyDecisionPoint,
        PolicyEnforcementPoint,
    ];
    let expect = |kind: SeedKind| -> Vec<NodeType> {
        match kind {
            SeedKind::PrincipalTakeover => vec![Human, Agent, Identity],
            SeedKind::CredentialLeak => vec![Credential],
            SeedKind::ContentInjection => vec![Data],
            SeedKind::ComponentCompromise => vec![McpServer, Capability, Tool, DownstreamService],
        }
    };
    for kind in [
        SeedKind::PrincipalTakeover,
        SeedKind::CredentialLeak,
        SeedKind::ContentInjection,
        SeedKind::ComponentCompromise,
    ] {
        let fits: Vec<NodeType> = all
            .iter()
            .copied()
            .filter(|t| kind_fits(kind, *t))
            .collect();
        assert_eq!(fits, expect(kind), "{kind:?}");
    }
}

#[test]
fn entry_points_become_seeds_and_misfits_are_skipped() {
    let g = graph();
    let seeding = entry_point_seeds(&g).unwrap();
    let seeds: Vec<(&str, SeedKind)> = seeding
        .seeds
        .iter()
        .map(|s| (s.node.as_str(), s.kind))
        .collect();
    assert_eq!(
        seeds,
        [
            ("node:data:doc", SeedKind::ContentInjection),
            ("node:human:alice", SeedKind::PrincipalTakeover)
        ]
    );
    assert_eq!(seeding.skipped, 1, "a PEER_AGENT entry on a DATA node");
    assert_eq!(seeding.omitted, 0);
    assert_eq!(seeding.scenario_id, "entry-points");
    let empty = G::new();
    let mut e = empty;
    e.node(NodeType::Tool, "t");
    assert_eq!(refusal(entry_point_seeds(&e.build())), Refusal::NoSeeds);
}
