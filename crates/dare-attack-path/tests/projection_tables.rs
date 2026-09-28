//! Projection tables (BLUEPRINT §6, tasks 018–028).
//!
//! Each fixture bundle is real engine output (see
//! `tests/fixtures/static-inputs/README.md`); these tests assert what each
//! projector's closed table must produce from it.
use std::path::Path;

use dare_attack_graph::{
    v2::{EntryClass, GuardScope, GuardVerdict, TargetClass},
    EdgeEvidenceStatus, EdgeType, NodeType,
};
use dare_attack_path::{
    bundle::load_bundle,
    facts::{Designation, FactEdge, NodeRef, RunFacts},
    project::{project, supply_chain},
};

fn facts(name: &str) -> RunFacts {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bundles")
        .join(name);
    project(&load_bundle(0, &dir).unwrap()).unwrap()
}

fn edges(facts: &RunFacts, edge_type: EdgeType) -> Vec<&FactEdge> {
    facts
        .edges
        .iter()
        .filter(|e| e.edge_type == edge_type)
        .collect()
}

fn has_node(facts: &RunFacts, node_type: NodeType) -> bool {
    facts.nodes.iter().any(|n| n.node.node_type == node_type)
}

fn designated(facts: &RunFacts, designation: Designation) -> Vec<&NodeRef> {
    facts
        .designations
        .iter()
        .filter(|d| d.designation == designation)
        .map(|d| &d.node)
        .collect()
}

fn all_have_evidence(facts: &RunFacts) {
    for edge in &facts.edges {
        assert!(!edge.evidence.evidence_ids.is_empty(), "{edge:?}");
        match edge.evidence.status {
            EdgeEvidenceStatus::Observed => assert!(edge
                .evidence
                .evidence_ids
                .iter()
                .all(|id| !id.starts_with("input:"))),
            EdgeEvidenceStatus::StaticallyProven => assert!(edge
                .evidence
                .evidence_ids
                .iter()
                .all(|id| id.starts_with(&format!("input:{}:", facts.engine.as_str())))),
            other => panic!("a projector emitted {other:?}"),
        }
        assert!(!edge.locator.is_empty() && !edge.original_kind.is_empty());
    }
}

#[test]
fn tool_rows() {
    let f = facts("tool");
    all_have_evidence(&f);
    assert!(has_node(&f, NodeType::McpServer), "surface → MCP_SERVER");
    let tools = f
        .nodes
        .iter()
        .filter(|n| n.node.node_type == NodeType::Tool)
        .count();
    assert!(tools >= 1);
    assert_eq!(
        edges(&f, EdgeType::CanReach).len(),
        edges(&f, EdgeType::CanInvoke).len(),
        "server CAN_REACH and SUT CAN_INVOKE per surface entry"
    );
    for invoke in edges(&f, EdgeType::CanInvoke) {
        assert_eq!(invoke.source, NodeRef::new(NodeType::Agent, "sut"));
        assert_eq!(invoke.evidence.status, EdgeEvidenceStatus::StaticallyProven);
        assert!(invoke
            .guards
            .iter()
            .all(|g| g.property == "AGENT.TOOL.METADATA_TRUST_BOUNDARY"));
    }
    let calls = edges(&f, EdgeType::Calls);
    assert!(!calls.is_empty(), "ToolRequested → SUT CALLS tool");
    assert!(calls
        .iter()
        .all(|c| c.evidence.status == EdgeEvidenceStatus::Observed
            && c.original_kind.contains("request, not execution")));
    let outputs: Vec<_> = f
        .nodes
        .iter()
        .filter(|n| n.node.local_id.starts_with("output."))
        .collect();
    assert!(!outputs.is_empty(), "ToolOutputObserved → DATA output node");
    assert!(edges(&f, EdgeType::TransfersTo)
        .iter()
        .any(|e| e.target == NodeRef::new(NodeType::Agent, "sut")));
    assert!(f
        .unprojected
        .keys()
        .all(|k| k.starts_with("ToolObservationEvent::")));
}

#[test]
fn tool_security_flags_follow_the_declared_operation_class() {
    use dare_tool_security::model::ToolEntry;
    let entry = |json: serde_json::Value| -> ToolEntry { serde_json::from_value(json).unwrap() };
    let base = serde_json::json!({"tool_id": "t", "tool_name": "t", "description": "d"});
    let mut delete = base.clone();
    delete["security_metadata"] = serde_json::json!({"declared_operation_class": "DELETE"});
    assert!(supply_chain_free_tool_flags(&entry(delete)).destructive);
    let mut hinted = base.clone();
    hinted["annotations"] = serde_json::json!({"destructive_hint": true});
    assert!(supply_chain_free_tool_flags(&entry(hinted)).destructive);
    let mut sensitive = base.clone();
    sensitive["security_metadata"] = serde_json::json!({"declared_sensitivity": "HIGH"});
    let flags = supply_chain_free_tool_flags(&entry(sensitive));
    assert!(flags.sensitive && !flags.destructive);
    assert_eq!(
        supply_chain_free_tool_flags(&entry(base)),
        Default::default()
    );
}

fn supply_chain_free_tool_flags(
    entry: &dare_tool_security::model::ToolEntry,
) -> dare_attack_graph::NodeSecurity {
    dare_attack_path::project::tool::tool_security(entry)
}

#[test]
fn identity_rows() {
    let f = facts("identity");
    all_have_evidence(&f);
    assert!(
        has_node(&f, NodeType::Human)
            || has_node(&f, NodeType::Agent)
            || has_node(&f, NodeType::Identity)
    );
    let delegations = edges(&f, EdgeType::DelegatesTo);
    assert!(!delegations.is_empty());
    for d in &delegations {
        assert!(d.authority.delegated && d.authority.principal.is_some());
    }
    assert!(
        delegations
            .iter()
            .any(|d| d.evidence.status == EdgeEvidenceStatus::Observed),
        "a DELEGATION_EDGE event upgrades the declared edge to OBSERVED"
    );
    assert!(!f
        .unprojected
        .contains_key("IdentityObservationEvent::DELEGATION_EDGE"));
    assert!(
        !edges(&f, EdgeType::AuthenticatesAs).is_empty(),
        "credential owner AUTHENTICATES_AS"
    );
    assert!(
        !edges(&f, EdgeType::UsesCredential).is_empty(),
        "CredentialContext → USES_CREDENTIAL"
    );
    assert!(
        !edges(&f, EdgeType::BelongsToTenant).is_empty(),
        "resource BELONGS_TO_TENANT"
    );
    let reaches: Vec<_> = edges(&f, EdgeType::CanReach)
        .into_iter()
        .filter(|e| e.original_kind.starts_with("FinalOperation"))
        .collect();
    assert!(
        !reaches.is_empty(),
        "FinalOperation → subject CAN_REACH resource"
    );
    assert!(
        reaches
            .iter()
            .all(|e| e.authority.tenant.is_some() && !e.authority_mutation),
        "no mutation when the binding properties did not FAIL"
    );
    assert!(!designated(&f, Designation::Entry(EntryClass::LowPrivilegePrincipal)).is_empty());
}

#[test]
fn identity_principal_kinds_map_to_node_types() {
    use dare_attack_path::project::identity::principal_type;
    use dare_identity_security::source::PrincipalKind as K;
    for (kind, node) in [
        (K::Human, NodeType::Human),
        (K::Agent, NodeType::Agent),
        (K::Workload, NodeType::Identity),
        (K::Service, NodeType::Identity),
    ] {
        assert_eq!(principal_type(kind), node);
    }
}

#[test]
fn memory_rows() {
    let f = facts("memory");
    all_have_evidence(&f);
    assert!(has_node(&f, NodeType::Data), "memory items are DATA");
    let writes = edges(&f, EdgeType::Writes);
    assert!(
        writes
            .iter()
            .any(|w| w.evidence.status == EdgeEvidenceStatus::StaticallyProven),
        "owner WRITES item (declared)"
    );
    assert!(
        writes
            .iter()
            .any(|w| w.evidence.status == EdgeEvidenceStatus::Observed),
        "MemoryWriteObserved"
    );
    assert!(writes.iter().all(|w| w
        .guards
        .iter()
        .all(|g| g.property == "AGENT.MEMORY.WRITE_TRUST_BOUNDARY"
            || g.property == "AGENT.MEMORY.PROVENANCE_INTEGRITY")));
    let reads = edges(&f, EdgeType::Reads);
    assert!(
        !reads.is_empty(),
        "MemoryRecallObserved → requester READS item"
    );
    let back: Vec<_> = edges(&f, EdgeType::TransfersTo);
    assert_eq!(
        reads.len(),
        back.iter()
            .filter(|e| e.original_kind == "MemoryRecallObserved")
            .count(),
        "each recall also flows the item back"
    );
    assert!(!designated(&f, Designation::Entry(EntryClass::MemoryWrite)).is_empty());
    assert!(!f
        .unprojected
        .contains_key("MemoryObservationEvent::MEMORY_INFLUENCE_OBSERVED"));
}

#[test]
fn rag_rows() {
    let f = facts("rag");
    all_have_evidence(&f);
    let reads = edges(&f, EdgeType::Reads);
    let flows = edges(&f, EdgeType::TransfersTo);
    assert!(
        !reads.is_empty() && reads.len() == flows.len(),
        "every retrieval gives READS and TRANSFERS_TO"
    );
    const ACCESS: [&str; 4] = [
        "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
        "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
        "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
        "AGENT.RAG.RESULT_SET_INTEGRITY",
    ];
    assert!(reads.iter().all(|e| e
        .guards
        .iter()
        .all(|g| ACCESS.contains(&g.property.as_str()))));
    assert!(flows.iter().all(|e| e
        .guards
        .iter()
        .all(|g| !ACCESS.contains(&g.property.as_str()))));
    let tenants = edges(&f, EdgeType::BelongsToTenant);
    assert!(!tenants.is_empty() && tenants.iter().all(|e| e.guards.is_empty()));
    assert!(f
        .nodes
        .iter()
        .filter(|n| n.node.node_type == NodeType::Data)
        .all(|n| n.original_kind.starts_with("Document (collection")));
}

#[test]
fn mcp_auth_rows() {
    let f = facts("mcp");
    all_have_evidence(&f);
    assert!(has_node(&f, NodeType::McpServer));
    let upstream: Vec<_> = f
        .nodes
        .iter()
        .filter(|n| n.original_kind == "CredentialRef (upstream)")
        .collect();
    for credential in &upstream {
        assert!(credential.security.privileged);
        assert!(
            designated(&f, Designation::Target(TargetClass::PrivilegedCredential))
                .contains(&&credential.node)
        );
    }
    assert!(!edges(&f, EdgeType::UsesCredential).is_empty());
    for edge in &f.edges {
        assert!(
            edge.guards.iter().all(|g| g.scope == GuardScope::Run),
            "every 018 guard is RUN scope"
        );
    }
    let reaches = edges(&f, EdgeType::CanReach);
    assert!(
        reaches
            .iter()
            .any(|e| e.evidence.status == EdgeEvidenceStatus::Observed),
        "observed credential flow re-emits the edges with trial evidence"
    );
}

#[test]
fn supply_chain_tables_are_exhaustive() {
    use dare_supply_chain_security::{relationship::RelationType as R, source::ComponentType as C};
    let components = [
        C::Agent,
        C::Model,
        C::EmbeddingModel,
        C::Dataset,
        C::Framework,
        C::Tool,
        C::SkillPlugin,
        C::McpServer,
        C::ServiceApi,
        C::Package,
        C::ContainerImage,
        C::PromptPolicyAsset,
        C::Guardrail,
        C::ExternalAgent,
    ];
    // Compile-time check that the list above names every variant.
    for c in components {
        match c {
            C::Agent
            | C::Model
            | C::EmbeddingModel
            | C::Dataset
            | C::Framework
            | C::Tool
            | C::SkillPlugin
            | C::McpServer
            | C::ServiceApi
            | C::Package
            | C::ContainerImage
            | C::PromptPolicyAsset
            | C::Guardrail
            | C::ExternalAgent => {}
        }
        let _ = supply_chain::node_type(c);
    }
    assert_eq!(
        supply_chain::node_type(C::Model),
        NodeType::DownstreamService
    );
    assert_eq!(
        supply_chain::node_type(C::Guardrail),
        NodeType::PolicyEnforcementPoint
    );
    assert_eq!(supply_chain::node_type(C::Package), NodeType::Capability);
    let relations = [
        R::DependsOn,
        R::Uses,
        R::Calls,
        R::Loads,
        R::ProvidedBy,
        R::BuiltFrom,
        R::TrainedFrom,
        R::FineTunedFrom,
        R::EmbedsWith,
        R::ExposesTool,
        R::ConnectsTo,
        R::AttestedBy,
        R::SignedBy,
    ];
    let mut projected = 0;
    for r in relations {
        match r {
            R::DependsOn
            | R::Uses
            | R::Calls
            | R::Loads
            | R::ProvidedBy
            | R::BuiltFrom
            | R::TrainedFrom
            | R::FineTunedFrom
            | R::EmbedsWith
            | R::ExposesTool
            | R::ConnectsTo
            | R::AttestedBy
            | R::SignedBy => {}
        }
        if let Some((edge_type, reversed, _)) = supply_chain::edge_for(r, false) {
            projected += 1;
            assert_eq!(
                reversed,
                edge_type == EdgeType::TransfersTo,
                "dependency edges point from dependency to dependent"
            );
        }
    }
    assert_eq!(
        projected, 10,
        "PROVIDED_BY, ATTESTED_BY and SIGNED_BY are not projected"
    );
    let (_, _, role) = supply_chain::edge_for(R::TrainedFrom, true).unwrap();
    assert_eq!(
        role,
        dare_attack_path::guard_table::Role::SupplyDatasetLineage
    );
}

#[test]
fn supply_chain_rows_and_entity_narrowing() {
    let f = facts("static-sc");
    all_have_evidence(&f);
    let flows = edges(&f, EdgeType::TransfersTo);
    assert_eq!(flows.len(), 1, "support-agent DEPENDS_ON left-pad");
    let flow = flows[0];
    assert_eq!(
        flow.source.local_id, "left-pad",
        "from dependency to dependent"
    );
    assert_eq!(flow.target.local_id, "support-agent");
    assert!(
        flow.evidence.evidence_ids.len() >= 2,
        "cites the BOM and evidence_digest"
    );
    assert_eq!(flow.guards.len(), 7);
    let bom = flow
        .guards
        .iter()
        .find(|g| g.property == "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS")
        .unwrap();
    assert_eq!(
        (bom.verdict, bom.scope),
        (GuardVerdict::Fail, GuardScope::Entity),
        "the violation names a component on this edge"
    );
    assert!(!designated(&f, Designation::Entry(EntryClass::SupplyChainComponent)).is_empty());
}

#[test]
fn a2a_rows() {
    for name in ["a2a", "static-a2a"] {
        let f = facts(name);
        all_have_evidence(&f);
        let peers = designated(&f, Designation::Entry(EntryClass::PeerAgent));
        assert!(
            !peers.is_empty(),
            "{name}: every peer is a PEER_AGENT entry"
        );
        let calls = edges(&f, EdgeType::Calls);
        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call.target, NodeRef::new(NodeType::Agent, "sut"));
            assert!(call
                .guards
                .iter()
                .all(|g| g.property != "AGENT.A2A.AUTHORITY_PROPAGATION"));
        }
        let delegations = edges(&f, EdgeType::DelegatesTo);
        assert!(!delegations.is_empty(), "{name}: delegation hops");
        for d in &delegations {
            assert!(d
                .guards
                .iter()
                .all(|g| g.property == "AGENT.A2A.AUTHORITY_PROPAGATION"));
            assert!(d.authority.delegated);
        }
    }
}

#[test]
fn prompt_injection_rows() {
    let f = facts("pi");
    all_have_evidence(&f);
    let channels: Vec<_> = f
        .nodes
        .iter()
        .filter(|n| n.node.local_id.starts_with("channel."))
        .collect();
    assert_eq!(channels.len(), 1);
    let entries = designated(&f, Designation::Entry(EntryClass::UntrustedInput)).len()
        + designated(&f, Designation::Entry(EntryClass::ExternalContent)).len();
    assert_eq!(entries, 1, "the direction picks exactly one entry class");
    let flow = edges(&f, EdgeType::TransfersTo);
    assert!(flow
        .iter()
        .all(|e| e.guards.len() == 1 && e.guards[0].property.starts_with("AGENT.GOAL.")));
    assert!(edges(&f, EdgeType::CanInvoke)
        .iter()
        .all(|e| e.original_kind.contains("request, not execution")));
}

#[test]
fn multi_turn_rows() {
    let f = facts("mt");
    all_have_evidence(&f);
    let channels: Vec<_> = f
        .nodes
        .iter()
        .filter(|n| n.node.local_id.starts_with("channel."))
        .collect();
    assert!(!channels.is_empty());
    assert!(
        channels
            .iter()
            .all(|c| c.node.local_id != "channel.approval"),
        "APPROVAL is not an entry"
    );
    for edge in edges(&f, EdgeType::TransfersTo) {
        assert_eq!(
            edge.guards.len(),
            7,
            "the seven 021 invariants guard each channel"
        );
    }
}

#[test]
fn remote_multi_turn_runs_are_counted_not_guessed() {
    let f = facts("remote");
    assert!(f.nodes.is_empty() && f.edges.is_empty());
    assert_eq!(f.unprojected.get("MULTI_TURN_RESULT_ONLY"), Some(&1));
    assert!(f.dynamic_authorized);
}
