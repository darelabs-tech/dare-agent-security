//! Merge, designation and construction (tasks 029–031).
use std::{collections::BTreeMap, path::Path};

use dare_attack_graph::{
    v2::{DesignationOrigin, EntryClass, GuardScope, GuardVerdict, TargetClass},
    EdgeEvidence, EdgeEvidenceStatus, EdgeType, NodeSecurity, NodeType,
};
use dare_attack_path::{
    designate,
    facts::{FactAuthority, FactEdge, FactGuard, FactNode, NodeRef, RunFacts},
    ids::{EngineSlug, RunTag},
    merge::merge,
    model::admit_model_bytes,
    run::{build_graph, project_all},
    AttackPathError, ModelRefusal, Refusal,
};
use serde_json::json;

fn run(index: u32, engine: EngineSlug, tag: &str) -> RunFacts {
    RunFacts {
        artifact_index: index,
        engine,
        run: RunTag::from_result_bytes(tag.as_bytes()),
        mode: "REPLAY".into(),
        synthetic: true,
        dynamic_authorized: false,
        result_digest: format!(
            "sha256:{}",
            format!("{index:x}")
                .repeat(64)
                .chars()
                .take(64)
                .collect::<String>()
        ),
        evidence_digest: format!("sha256:{}", "e".repeat(64)),
        input_digests: vec![],
        verified_inputs: vec![],
        nodes: vec![],
        edges: vec![],
        designations: vec![],
        unprojected: BTreeMap::new(),
    }
}

fn node(facts: &mut RunFacts, node_type: NodeType, id: &str, security: NodeSecurity) -> NodeRef {
    let node = NodeRef::new(node_type, id);
    facts.nodes.push(FactNode {
        node: node.clone(),
        raw_label: id.into(),
        security,
        original_kind: "test".into(),
        locator: "/".into(),
    });
    node
}

fn evidence(status: EdgeEvidenceStatus, ids: &[&str]) -> EdgeEvidence {
    EdgeEvidence {
        status,
        evidence_ids: ids.iter().map(|s| (*s).to_owned()).collect(),
        rationale: None,
        source_facts: vec![],
        reason: None,
    }
}

fn link(
    facts: &mut RunFacts,
    source: &NodeRef,
    edge_type: EdgeType,
    target: &NodeRef,
    ev: EdgeEvidence,
    guards: Vec<FactGuard>,
) {
    facts.edges.push(FactEdge {
        edge_type,
        source: source.clone(),
        target: target.clone(),
        authority: FactAuthority::default(),
        evidence: ev,
        guards,
        authority_mutation: false,
        original_kind: "test".into(),
        locator: "/".into(),
    });
}

fn model(value: serde_json::Value) -> dare_attack_path::model::AdmittedModel {
    admit_model_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn tenant(t: &str) -> NodeSecurity {
    NodeSecurity {
        tenant: Some(t.into()),
        ..NodeSecurity::default()
    }
}

#[test]
fn the_same_local_id_in_two_runs_stays_two_nodes_without_an_alias() {
    let mut a = run(0, EngineSlug::Tool, "a");
    let mut b = run(1, EngineSlug::Tool, "b");
    node(&mut a, NodeType::Tool, "search", NodeSecurity::default());
    node(&mut b, NodeType::Tool, "search", NodeSecurity::default());
    let merged = merge(&[a.clone(), b.clone()], None).unwrap();
    assert_eq!(merged.nodes.len(), 2, "run-scoped ids (BQ-2)");
    let aliased = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "crm-search", "type": "TOOL", "display_name": "CRM search"}],
        "aliases": [{"engine": "tool", "local_id": "search", "entity_id": "crm-search"}]
    }));
    let merged = merge(&[a, b], Some(&aliased)).unwrap();
    assert_eq!(merged.nodes.len(), 1, "one explicit alias merges both");
    assert!(merged.nodes.contains_key("node:tool:crm-search"));
    assert_eq!(merged.alias_hits.get(&0), Some(&2));
}

#[test]
fn an_alias_to_an_entity_of_another_type_is_refused() {
    let mut a = run(0, EngineSlug::Identity, "a");
    node(&mut a, NodeType::Identity, "svc", NodeSecurity::default());
    let m = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "svc", "type": "AGENT", "display_name": "service"}],
        "aliases": [{"engine": "identity", "local_id": "svc", "entity_id": "svc"}]
    }));
    assert!(matches!(
        merge(&[a], Some(&m)),
        Err(AttackPathError::Refused(Refusal::Model(
            ModelRefusal::TypeClash { alias: 0 }
        )))
    ));
}

#[test]
fn merged_nodes_that_disagree_on_their_tenant_are_refused() {
    let mut a = run(0, EngineSlug::Rag, "a");
    let mut b = run(1, EngineSlug::Memory, "b");
    node(&mut a, NodeType::Data, "doc", tenant("tenant-a"));
    node(&mut b, NodeType::Data, "item", tenant("tenant-b"));
    let m = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "shared", "type": "DATA", "display_name": "shared"}],
        "aliases": [
            {"engine": "rag", "local_id": "doc", "entity_id": "shared"},
            {"engine": "memory", "local_id": "item", "entity_id": "shared"}
        ]
    }));
    assert!(matches!(
        merge(&[a, b], Some(&m)),
        Err(AttackPathError::Refused(Refusal::Model(
            ModelRefusal::TenantClash { .. }
        )))
    ));
}

#[test]
fn identical_edges_merge_by_the_stronger_evidence_and_unioned_guards() {
    let mut a = run(0, EngineSlug::Tool, "a");
    let mut b = run(1, EngineSlug::Tool, "b");
    let m = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [
            {"entity_id": "agent", "type": "AGENT", "display_name": "agent"},
            {"entity_id": "export", "type": "TOOL", "display_name": "export"}
        ],
        "aliases": [
            {"engine": "tool", "local_id": "sut", "entity_id": "agent"},
            {"engine": "tool", "local_id": "export", "entity_id": "export"}
        ]
    }));
    let guard = |verdict| FactGuard {
        property: "AGENT.TOOL.CHAIN_BOUNDARY".into(),
        verdict,
        evidence_ids: vec!["g".into()],
        scope: GuardScope::Run,
    };
    for (facts, status, id, verdict) in [
        (
            &mut a,
            EdgeEvidenceStatus::StaticallyProven,
            "input:tool:aa",
            GuardVerdict::Pass,
        ),
        (
            &mut b,
            EdgeEvidenceStatus::Observed,
            "urn:ev:1",
            GuardVerdict::Fail,
        ),
    ] {
        let s = node(facts, NodeType::Agent, "sut", NodeSecurity::default());
        let t = node(facts, NodeType::Tool, "export", NodeSecurity::default());
        link(
            facts,
            &s,
            EdgeType::Calls,
            &t,
            evidence(status, &[id]),
            vec![guard(verdict)],
        );
    }
    let merged = merge(&[a, b], Some(&m)).unwrap();
    assert_eq!(merged.edges.len(), 1);
    let edge = merged.edges.values().next().unwrap();
    assert_eq!(edge.evidence.status, EdgeEvidenceStatus::Observed);
    assert_eq!(
        edge.evidence.evidence_ids,
        vec!["input:tool:aa".to_owned(), "urn:ev:1".to_owned()]
    );
    assert_eq!(edge.guards.len(), 2, "one guard per run");
    assert_eq!(edge.provenance.len(), 2);
}

#[test]
fn authority_names_nodes_or_an_opaque_external_subject() {
    let mut a = run(0, EngineSlug::A2a, "a");
    let peer = node(&mut a, NodeType::Agent, "planner", NodeSecurity::default());
    let sut = node(&mut a, NodeType::Agent, "sut", NodeSecurity::default());
    a.edges.push(FactEdge {
        edge_type: EdgeType::Calls,
        source: peer.clone(),
        target: sut.clone(),
        authority: FactAuthority {
            principal: Some(NodeRef::new(NodeType::Identity, "user alice")),
            credential: Some(NodeRef::new(NodeType::Credential, "absent")),
            ..FactAuthority::default()
        },
        evidence: evidence(EdgeEvidenceStatus::Observed, &["e"]),
        guards: vec![],
        authority_mutation: false,
        original_kind: "test".into(),
        locator: "/".into(),
    });
    link(
        &mut a,
        &sut,
        EdgeType::Calls,
        &peer,
        evidence(EdgeEvidenceStatus::Observed, &["e"]),
        vec![],
    );
    a.edges[1].authority.principal = Some(sut.clone());
    let merged = merge(&[a], None).unwrap();
    let principals: Vec<_> = merged
        .edges
        .values()
        .map(|e| e.authority.principal.clone().unwrap())
        .collect();
    assert!(
        principals.iter().any(|p| p.starts_with("ext:x-")),
        "{principals:?}"
    );
    assert!(
        principals.iter().any(|p| p.starts_with("node:agent:a2a:")),
        "{principals:?}"
    );
    assert!(
        merged
            .edges
            .values()
            .all(|e| e.authority.credential.is_none()),
        "an unknown credential is dropped"
    );
}

#[test]
fn declared_edges_and_trust_boundaries_come_from_the_model() {
    let m = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [
            {"entity_id": "agent", "type": "AGENT", "display_name": "agent"},
            {"entity_id": "token", "type": "CREDENTIAL", "display_name": "token"},
            {"entity_id": "vault", "type": "RESOURCE", "display_name": "vault"}
        ],
        "trust_boundaries": [{"boundary_id": "secrets", "entity_ids": ["token", "vault"]}],
        "declared_edges": [
            {"type": "USES_CREDENTIAL", "source": "agent", "target": "token",
             "authority": {"principal": "agent", "credential": "token"},
             "status": "INFERRED", "rationale": "mounted by the deployment"},
            {"type": "READS", "source": "token", "target": "vault", "status": "NOT_TESTED", "reason": "no engine covers the vault"}
        ]
    }));
    let merged = merge(&[], Some(&m)).unwrap();
    assert_eq!(merged.nodes.len(), 3);
    let inferred = merged
        .edges
        .values()
        .find(|e| e.edge_type == EdgeType::UsesCredential)
        .unwrap();
    assert_eq!(inferred.evidence.status, EdgeEvidenceStatus::Inferred);
    assert!(inferred.evidence.source_facts[0].starts_with("system-model:"));
    assert_eq!(
        inferred.authority.principal.as_deref(),
        Some("node:agent:agent")
    );
    assert_eq!(
        inferred.authority.credential.as_deref(),
        Some("node:credential:token")
    );
    assert_eq!(inferred.crosses_trust_boundary, vec!["secrets".to_owned()]);
    let untested = merged
        .edges
        .values()
        .find(|e| e.edge_type == EdgeType::Reads)
        .unwrap();
    assert_eq!(untested.evidence.status, EdgeEvidenceStatus::NotTested);
    assert!(
        untested.crosses_trust_boundary.is_empty(),
        "both ends inside the boundary"
    );
    assert!(untested
        .provenance
        .iter()
        .all(|p| p.artifact_index.is_none()));
}

#[test]
fn designations_follow_flags_then_the_model() {
    let mut a = run(0, EngineSlug::Identity, "a");
    node(
        &mut a,
        NodeType::Credential,
        "admin",
        NodeSecurity {
            privileged: true,
            ..NodeSecurity::default()
        },
    );
    node(
        &mut a,
        NodeType::Resource,
        "records",
        NodeSecurity {
            sensitive: true,
            tenant: Some("b".into()),
            ..NodeSecurity::default()
        },
    );
    node(
        &mut a,
        NodeType::Tool,
        "wipe",
        NodeSecurity {
            destructive: true,
            ..NodeSecurity::default()
        },
    );
    let user = node(&mut a, NodeType::Human, "user", tenant("a"));
    let mut merged = merge(&[a], None).unwrap();
    designate::apply_defaults(&mut merged);
    let classes: Vec<TargetClass> = merged.targets.iter().map(|t| t.class).collect();
    for class in [
        TargetClass::PrivilegedCredential,
        TargetClass::SensitiveResource,
        TargetClass::DestructiveCapability,
    ] {
        assert!(classes.contains(&class), "{class:?}");
    }
    let user_id = merged
        .nodes
        .keys()
        .find(|k| k.contains(":user"))
        .unwrap()
        .clone();
    let m = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "x", "type": "DATA", "display_name": "x"}],
        "entry_points": [{"node_id": user_id, "class": "LOW_PRIVILEGE_PRINCIPAL"}],
        "targets": [{"node_id": merged.nodes.keys().find(|k| k.contains(":wipe")).unwrap(), "class": "DESTRUCTIVE_CAPABILITY", "exclude": true}]
    }));
    let mut with_model = merge(
        &[{
            let mut again = run(0, EngineSlug::Identity, "a");
            again.nodes = merged
                .nodes
                .values()
                .map(|n| FactNode {
                    node: NodeRef::new(n.node_type, n.id.rsplit(':').next().unwrap()),
                    raw_label: n.display_name.clone(),
                    security: n.security.clone(),
                    original_kind: "test".into(),
                    locator: "/".into(),
                })
                .collect();
            again
        }],
        Some(&m),
    )
    .unwrap();
    designate::apply_defaults(&mut with_model);
    designate::apply_model(&mut with_model, &m).unwrap();
    assert!(with_model
        .entries
        .iter()
        .any(|e| e.class == EntryClass::LowPrivilegePrincipal
            && e.origin == DesignationOrigin::Model));
    assert!(
        !with_model
            .targets
            .iter()
            .any(|t| t.class == TargetClass::DestructiveCapability),
        "excluded"
    );
    let bad = model(json!({
        "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "x", "type": "DATA", "display_name": "x"}],
        "entry_points": [{"node_id": "node:human:nobody", "class": "UNTRUSTED_INPUT"}]
    }));
    assert!(matches!(
        designate::apply_model(&mut with_model, &bad),
        Err(AttackPathError::Refused(Refusal::Model(
            ModelRefusal::UnknownDesignationTarget { designation: 0 }
        )))
    ));
    // Cross-tenant targets depend on the entry.
    let user_node = merged
        .nodes
        .values()
        .find(|n| n.id.ends_with(&user.local_id))
        .unwrap();
    let cross = designate::cross_tenant_targets(user_node, merged.nodes.values());
    assert_eq!(cross.len(), 1);
    assert!(cross[0].ends_with(":records"));
}

fn fixture_dirs(names: &[&str]) -> Vec<std::path::PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bundles");
    names.iter().map(|n| root.join(n)).collect()
}

#[test]
fn the_same_artifacts_in_any_order_build_byte_identical_output() {
    let names = [
        "tool",
        "identity",
        "memory",
        "rag",
        "mcp",
        "static-sc",
        "static-a2a",
        "pi",
        "mt",
        "remote",
    ];
    let reference = {
        let runs = project_all(&fixture_dirs(&names)).unwrap();
        let (graph, report) = build_graph(&runs, None).unwrap();
        (
            serde_json::to_vec(&graph).unwrap(),
            serde_json::to_vec(&report).unwrap(),
        )
    };
    let mut order: Vec<&str> = names.to_vec();
    for round in 0..10 {
        // A deterministic permutation per round.
        order.rotate_left(3);
        if round % 2 == 0 {
            order.reverse();
        }
        let runs = project_all(&fixture_dirs(&order)).unwrap();
        let (graph, report) = build_graph(&runs, None).unwrap();
        assert_eq!(
            serde_json::to_vec(&graph).unwrap(),
            reference.0,
            "round {round}"
        );
        assert_eq!(
            serde_json::to_vec(&report).unwrap(),
            reference.1,
            "round {round}"
        );
    }
    let text = String::from_utf8(reference.0).unwrap();
    assert!(
        !text.contains("generated_at"),
        "no wall-clock value (AD-11)"
    );
}

#[test]
fn the_same_result_given_twice_is_refused_with_both_positions() {
    let dirs = fixture_dirs(&["tool", "rag", "tool"]);
    assert!(matches!(
        project_all(&dirs),
        Err(AttackPathError::Refused(Refusal::DuplicateRun {
            first: 0,
            second: 2
        }))
    ));
    assert!(matches!(
        project_all(&[]),
        Err(AttackPathError::Refused(Refusal::NoArtifacts))
    ));
    let many = vec![fixture_dirs(&["tool"])[0].clone(); 65];
    assert!(matches!(
        project_all(&many),
        Err(AttackPathError::Refused(Refusal::TooManyArtifacts {
            given: 65
        }))
    ));
}
