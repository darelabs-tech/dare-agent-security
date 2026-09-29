//! Small, valid v2 graphs for the blast-radius tests.
#![allow(dead_code)]

use dare_attack_graph::{
    build_edge_id,
    model::{GraphEngine, SchemaRef},
    v2::{
        graph_id_v2, validate_graph_v2, ArtifactSource, AttackGraphV2, DesignationOrigin, EdgeV2,
        EntryClass, EntryDesignation, Guard, GuardScope, GuardVerdict, NodeV2, Provenance,
        SourcesV2, TargetClass, TargetDesignation, GRAPH_SCHEMA_ID_V2, GRAPH_SCHEMA_VERSION_V2,
    },
    AuthorityContext, EdgeEvidence, EdgeEvidenceStatus, EdgeType, NodeSecurity, NodeType,
};

pub struct G {
    pub nodes: Vec<NodeV2>,
    pub edges: Vec<EdgeV2>,
    pub entries: Vec<EntryDesignation>,
    pub targets: Vec<TargetDesignation>,
}

fn prov() -> Vec<Provenance> {
    vec![Provenance {
        artifact_index: Some(0),
        original_kind: "test".into(),
        locator: "/".into(),
    }]
}

/// Guard state of a test edge.
#[derive(Clone, Copy, Debug)]
pub enum Gd {
    None,
    Pass,
    Fail,
    Inconclusive,
    Error,
}

pub const PROP: &str = "AGENT.TOOL.CHAIN_BOUNDARY";

impl Default for G {
    fn default() -> Self {
        Self::new()
    }
}

impl G {
    pub fn new() -> Self {
        Self {
            nodes: vec![],
            edges: vec![],
            entries: vec![],
            targets: vec![],
        }
    }

    pub fn node(&mut self, t: NodeType, local: &str) -> String {
        self.node_with(t, local, NodeSecurity::default())
    }

    pub fn node_with(&mut self, t: NodeType, local: &str, security: NodeSecurity) -> String {
        let id = format!("node:{}:{local}", t.slug());
        self.nodes.push(NodeV2 {
            id: id.clone(),
            node_type: t,
            display_name: local.into(),
            security,
            provenance: prov(),
        });
        id
    }

    pub fn tenant(tenant: &str) -> NodeSecurity {
        NodeSecurity {
            tenant: Some(tenant.into()),
            ..NodeSecurity::default()
        }
    }

    pub fn edge(&mut self, s: &str, t: EdgeType, d: &str, guard: Gd) -> String {
        self.edge_full(s, t, d, guard, None, &[])
    }

    pub fn edge_full(
        &mut self,
        s: &str,
        t: EdgeType,
        d: &str,
        guard: Gd,
        principal: Option<&str>,
        boundaries: &[&str],
    ) -> String {
        let authority = AuthorityContext {
            principal: principal.map(str::to_owned),
            ..AuthorityContext::default()
        };
        let id = build_edge_id(s, t, d, &authority).unwrap();
        let verdict = match guard {
            Gd::None => None,
            Gd::Pass => Some(GuardVerdict::Pass),
            Gd::Fail => Some(GuardVerdict::Fail),
            Gd::Inconclusive => Some(GuardVerdict::Inconclusive),
            Gd::Error => Some(GuardVerdict::Error),
        };
        self.edges.push(EdgeV2 {
            id: id.clone(),
            edge_type: t,
            source: s.into(),
            target: d.into(),
            authority,
            evidence: EdgeEvidence {
                status: EdgeEvidenceStatus::Observed,
                evidence_ids: vec!["urn:ev".into()],
                rationale: None,
                source_facts: vec![],
                reason: None,
            },
            guards: verdict
                .map(|verdict| Guard {
                    property: PROP.into(),
                    verdict,
                    evidence_ids: vec!["urn:ev:guard".into()],
                    scope: GuardScope::Run,
                    artifact_index: 0,
                })
                .into_iter()
                .collect(),
            authority_mutation: false,
            crosses_trust_boundary: boundaries.iter().map(|b| (*b).to_owned()).collect(),
            provenance: prov(),
        });
        id
    }

    pub fn entry(&mut self, node: &str, class: EntryClass) {
        self.entries.push(EntryDesignation {
            node: node.into(),
            class,
            origin: DesignationOrigin::Default,
        });
    }

    pub fn target(&mut self, node: &str, class: TargetClass) {
        self.targets.push(TargetDesignation {
            node: node.into(),
            class,
            origin: DesignationOrigin::Default,
        });
    }

    pub fn build(mut self) -> AttackGraphV2 {
        self.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        self.edges.sort_by(|a, b| a.id.cmp(&b.id));
        self.edges.dedup_by(|a, b| a.id == b.id);
        self.entries.sort();
        self.targets.sort();
        let mut graph = AttackGraphV2 {
            schema: SchemaRef {
                id: GRAPH_SCHEMA_ID_V2.into(),
                version: GRAPH_SCHEMA_VERSION_V2.into(),
            },
            id: String::new(),
            target_id: "test".into(),
            target_version: "1".into(),
            sources: SourcesV2 {
                model_digest: None,
                artifacts: vec![ArtifactSource {
                    index: 0,
                    engine: "tool".into(),
                    run: "0123456789ab".into(),
                    mode: "REPLAY".into(),
                    synthetic: true,
                    dynamic_authorized: false,
                    result_digest: format!("sha256:{}", "a".repeat(64)),
                    evidence_digest: format!("sha256:{}", "b".repeat(64)),
                    input_digests: vec![],
                }],
            },
            engine: GraphEngine {
                name: "test".into(),
                version: "0".into(),
                commit: "none".into(),
            },
            nodes: self.nodes,
            edges: self.edges,
            entry_points: self.entries,
            targets: self.targets,
        };
        graph.id = graph_id_v2(&graph).unwrap();
        validate_graph_v2(&graph).expect("test graph is valid v2");
        graph
    }
}
