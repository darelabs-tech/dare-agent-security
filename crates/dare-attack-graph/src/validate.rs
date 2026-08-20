use std::collections::BTreeSet;

use crate::{
    builder::SCHEMA_ID,
    edge::build_edge_id,
    error::{GraphError, Result},
    evidence::validate_edge_evidence,
    model::AttackGraph,
};

pub const ATTACK_GRAPH_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/attack-graph/v1/attack-graph.schema.json");

pub fn validate_safe_label(label: &str) -> Result<()> {
    let trimmed = label.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.is_empty()
        || trimmed.len() > 160
        || lower.contains("token=")
        || lower.contains("bearer ")
        || lower.contains("password")
        || lower.contains("sk-")
        || lower.contains('\n')
        || lower.contains('\r')
    {
        return Err(GraphError::Invalid(
            "unsafe or secret-like graph label rejected".into(),
        ));
    }
    Ok(())
}

pub fn validate_graph(graph: &AttackGraph) -> Result<()> {
    if graph.schema.id != SCHEMA_ID {
        return Err(GraphError::Invalid("unexpected graph schema id".into()));
    }
    let node_ids: BTreeSet<_> = graph.nodes.iter().map(|node| node.id.as_str()).collect();
    if node_ids.len() != graph.nodes.len() {
        return Err(GraphError::Invalid("duplicate node id".into()));
    }
    for node in &graph.nodes {
        validate_safe_label(&node.display_name)?;
    }
    let mut edge_ids = BTreeSet::new();
    for edge in &graph.edges {
        if !node_ids.contains(edge.source.as_str()) || !node_ids.contains(edge.target.as_str()) {
            return Err(GraphError::Invalid("edge references missing node".into()));
        }
        validate_edge_evidence(&edge.evidence)?;
        let expected = build_edge_id(&edge.source, edge.edge_type, &edge.target, &edge.authority)?;
        if edge.id != expected || !edge_ids.insert(edge.id.as_str()) {
            return Err(GraphError::Invalid(
                "invalid or duplicate deterministic edge id".into(),
            ));
        }
    }
    let instance = serde_json::to_value(graph)?;
    let schema: serde_json::Value = serde_json::from_str(ATTACK_GRAPH_SCHEMA_V1_JSON)?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| GraphError::Invalid(format!("invalid embedded schema: {error}")))?;
    if let Some(error) = validator.iter_errors(&instance).next() {
        return Err(GraphError::Invalid(format!(
            "schema validation failed at {}: {error}",
            error.instance_path()
        )));
    }
    Ok(())
}
