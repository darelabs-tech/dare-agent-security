use std::collections::BTreeSet;

use crate::{
    edge::build_edge_id,
    error::{GraphError, Result},
    evidence::validate_edge_evidence,
    facts::GraphFactsInput,
    model::{AttackGraph, Edge, GraphEngine, Node, SchemaRef},
    node::build_node_id,
    provenance::graph_digest,
    validate::{validate_graph, validate_safe_label},
};

pub const SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/attack-graph/v1/attack-graph.schema.json";

pub fn build_attack_graph(facts: &GraphFactsInput) -> Result<AttackGraph> {
    let mut nodes = Vec::with_capacity(facts.nodes.len());
    let mut ids = BTreeSet::new();
    for fact in &facts.nodes {
        validate_safe_label(&fact.display_name)?;
        let id = build_node_id(fact.node_type, &fact.local_id)?;
        if !ids.insert(id.clone()) {
            return Err(GraphError::Invalid("duplicate node id".into()));
        }
        nodes.push(Node {
            id,
            node_type: fact.node_type,
            display_name: fact.display_name.clone(),
            security: fact.security.clone(),
        });
    }
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut edges = Vec::with_capacity(facts.edges.len());
    let mut edge_ids = BTreeSet::new();
    for fact in &facts.edges {
        validate_edge_evidence(&fact.evidence)?;
        let source = build_node_id(fact.source_type, &fact.source_local_id)?;
        let target = build_node_id(fact.target_type, &fact.target_local_id)?;
        if !ids.contains(&source) || !ids.contains(&target) {
            return Err(GraphError::Invalid("edge references missing node".into()));
        }
        if let Some(credential) = &fact.authority.credential {
            if !credential.starts_with("node:credential:") {
                return Err(GraphError::Invalid(
                    "credential authority must be a logical node id".into(),
                ));
            }
        }
        let id = build_edge_id(&source, fact.edge_type, &target, &fact.authority)?;
        if !edge_ids.insert(id.clone()) {
            return Err(GraphError::Invalid("duplicate edge id".into()));
        }
        edges.push(Edge {
            id,
            edge_type: fact.edge_type,
            source,
            target,
            authority: fact.authority.clone(),
            evidence: fact.evidence.clone(),
            security: fact.security.clone(),
        });
    }
    edges.sort_by(|a, b| a.id.cmp(&b.id));
    let mut graph = AttackGraph {
        schema: SchemaRef {
            id: SCHEMA_ID.into(),
            version: "1.0.0".into(),
        },
        id: String::new(),
        target_id: facts.target_id.clone(),
        target_version: facts.target_version.clone(),
        generated_at: facts.generated_at.clone(),
        sources: facts.sources.clone(),
        engine: GraphEngine {
            name: "dare-attack-graph".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            commit: facts.engine_commit.clone(),
        },
        nodes,
        edges,
        paths: vec![],
    };
    graph.id = format!("graph:{}", graph_digest(&graph)?);
    validate_graph(&graph)?;
    Ok(graph)
}
