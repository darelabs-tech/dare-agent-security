//! v2 validation (BLUEPRINT §4.7 invariants 1–7).
//!
//! Beyond the JSON schemas, the validators recompute everything a document
//! could misstate: edge ids, the graph id, path ids, path evidence status,
//! control state and impact factors. A v2 document therefore cannot claim a
//! better control state or a weaker evidence status than its edges support.
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonical::digest_value,
    edge::build_edge_id,
    error::{GraphError, Result},
    evidence::{validate_edge_evidence, EdgeEvidenceStatus},
    model::{ImpactFactors, PathStatus},
    node::NodeType,
    validate::validate_safe_label,
};

use super::{
    control::path_control,
    model::{
        AttackGraphV2, AttackPathsDoc, EdgeV2, Feasibility, GuardVerdict, ImpactFactorsV2, NodeV2,
        PathV2, ProjectionReport, TargetClass, DOCUMENT_SCHEMA_VERSION, GRAPH_SCHEMA_ID_V2,
        GRAPH_SCHEMA_VERSION_V2, PATHS_SCHEMA_ID_V2, REPORT_SCHEMA_ID_V2,
    },
};

pub const ATTACK_GRAPH_SCHEMA_V2_JSON: &str =
    include_str!("../../../../schemas/attack-graph/v2/attack-graph.schema.json");
pub const ATTACK_PATHS_SCHEMA_V2_JSON: &str =
    include_str!("../../../../schemas/attack-graph/v2/attack-paths.schema.json");
pub const PROJECTION_REPORT_SCHEMA_V2_JSON: &str =
    include_str!("../../../../schemas/attack-graph/v2/projection-report.schema.json");

fn invalid(message: &str) -> GraphError {
    GraphError::Invalid(message.to_owned())
}

fn check_schema(schema_json: &str, instance: &serde_json::Value) -> Result<()> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| GraphError::Invalid(format!("invalid embedded schema: {error}")))?;
    if let Some(error) = validator.iter_errors(instance).next() {
        return Err(GraphError::Invalid(format!(
            "schema validation failed at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

fn strictly_sorted<'a>(ids: impl Iterator<Item = &'a str>) -> bool {
    let mut previous: Option<&str> = None;
    for id in ids {
        if previous.is_some_and(|p| p >= id) {
            return false;
        }
        previous = Some(id);
    }
    true
}

/// `graph:` + the canonical digest of the graph with its id cleared.
pub fn graph_id_v2(graph: &AttackGraphV2) -> Result<String> {
    let mut normalized = graph.clone();
    normalized.id.clear();
    Ok(format!(
        "graph:{}",
        digest_value(&serde_json::to_value(normalized)?)?
    ))
}

/// The v1 path-id formula, so a path keeps its id across v1 and v2 (AD-10).
pub fn path_id(nodes: &[String], edges: &[String]) -> Result<String> {
    let value = serde_json::json!({"edges": edges, "nodes": nodes});
    Ok(format!("path:{}", digest_value(&value)?))
}

/// The Cycle 008 weakest-edge rule.
pub fn path_status(edges: &[&EdgeV2]) -> PathStatus {
    if edges
        .iter()
        .any(|edge| edge.evidence.status == EdgeEvidenceStatus::NotTested)
    {
        PathStatus::NotTested
    } else if edges
        .iter()
        .any(|edge| edge.evidence.status == EdgeEvidenceStatus::Inferred)
    {
        PathStatus::Inferred
    } else {
        PathStatus::Proven
    }
}

/// The six v1 factors, computed over v2 nodes and edges the way v1
/// `make_path` computes them, plus `crosses_trust_boundary` (BLUEPRINT §7.6).
/// v2 carries verdicts in guards, so "contains a failed security property"
/// means any FAIL guard on the path.
pub fn impact_factors(nodes: &[&NodeV2], edges: &[&EdgeV2]) -> ImpactFactorsV2 {
    let tenants: BTreeSet<&str> = edges
        .iter()
        .filter_map(|edge| edge.authority.tenant.as_deref())
        .collect();
    ImpactFactorsV2 {
        v1: ImpactFactors {
            cross_tenant: tenants.len() > 1,
            uses_privileged_credential: nodes
                .iter()
                .any(|node| node.node_type == NodeType::Credential && node.security.privileged),
            reaches_sensitive_resource: nodes.iter().any(|node| node.security.sensitive),
            contains_destructive_capability: nodes.iter().any(|node| node.security.destructive),
            contains_failed_security_property: edges.iter().any(|edge| {
                edge.guards
                    .iter()
                    .any(|guard| guard.verdict == GuardVerdict::Fail)
            }),
            contains_authorization_mutation: edges.iter().any(|edge| edge.authority_mutation),
        },
        crosses_trust_boundary: edges
            .iter()
            .any(|edge| !edge.crosses_trust_boundary.is_empty()),
    }
}

pub fn validate_graph_v2(graph: &AttackGraphV2) -> Result<()> {
    if graph.schema.id != GRAPH_SCHEMA_ID_V2 || graph.schema.version != GRAPH_SCHEMA_VERSION_V2 {
        return Err(invalid("unexpected v2 graph schema"));
    }
    let artifact_indices: BTreeSet<u32> = graph.sources.artifacts.iter().map(|a| a.index).collect();
    let provenance_ok = |index: Option<u32>| index.is_none_or(|i| artifact_indices.contains(&i));

    // Invariant 7: every list sorted by id, no duplicates.
    if !strictly_sorted(graph.nodes.iter().map(|n| n.id.as_str())) {
        return Err(invalid("nodes are not sorted by unique id"));
    }
    if !strictly_sorted(graph.edges.iter().map(|e| e.id.as_str())) {
        return Err(invalid("edges are not sorted by unique id"));
    }
    let nodes: BTreeSet<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    for node in &graph.nodes {
        validate_safe_label(&node.display_name)?;
        if node.provenance.is_empty()
            || !node
                .provenance
                .iter()
                .all(|p| provenance_ok(p.artifact_index))
        {
            return Err(invalid(
                "node provenance is empty or names an unknown artifact",
            ));
        }
    }
    for edge in &graph.edges {
        // Invariant 3: referenced nodes exist.
        if !nodes.contains(edge.source.as_str()) || !nodes.contains(edge.target.as_str()) {
            return Err(invalid("edge references missing node"));
        }
        // Invariant 1: v1 edge-evidence invariants.
        validate_edge_evidence(&edge.evidence)?;
        // Invariant 2: deterministic edge id.
        if edge.id != build_edge_id(&edge.source, edge.edge_type, &edge.target, &edge.authority)? {
            return Err(invalid("invalid deterministic edge id"));
        }
        if let Some(credential) = &edge.authority.credential {
            if !credential.starts_with("node:credential:") {
                return Err(invalid("credential authority must be a credential node id"));
            }
        }
        // Invariant 5: provenance and guards name known artifacts.
        if edge.provenance.is_empty()
            || !edge
                .provenance
                .iter()
                .all(|p| provenance_ok(p.artifact_index))
        {
            return Err(invalid(
                "edge provenance is empty or names an unknown artifact",
            ));
        }
        if !edge
            .guards
            .iter()
            .all(|g| artifact_indices.contains(&g.artifact_index))
        {
            return Err(invalid("guard names an unknown artifact"));
        }
        if edge.guards.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("guards are not sorted and unique"));
        }
    }
    for designation in &graph.entry_points {
        if !nodes.contains(designation.node.as_str()) {
            return Err(invalid("entry point references missing node"));
        }
    }
    for designation in &graph.targets {
        if !nodes.contains(designation.node.as_str()) {
            return Err(invalid("target references missing node"));
        }
    }
    if graph.entry_points.windows(2).any(|pair| pair[0] >= pair[1])
        || graph.targets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("designations are not sorted and unique"));
    }
    if graph.id != graph_id_v2(graph)? {
        return Err(invalid("graph id does not match its content"));
    }
    check_schema(ATTACK_GRAPH_SCHEMA_V2_JSON, &serde_json::to_value(graph)?)
}

fn validate_path(
    graph: &AttackGraphV2,
    nodes: &BTreeMap<&str, &NodeV2>,
    edges: &BTreeMap<&str, &EdgeV2>,
    path: &PathV2,
) -> Result<()> {
    if path.nodes.len() != path.edges.len() + 1 || path.edges.is_empty() {
        return Err(invalid("path node and edge counts disagree"));
    }
    let path_edges = path
        .edges
        .iter()
        .map(|id| {
            edges
                .get(id.as_str())
                .copied()
                .ok_or_else(|| invalid("path references missing edge"))
        })
        .collect::<Result<Vec<_>>>()?;
    let path_nodes = path
        .nodes
        .iter()
        .map(|id| {
            nodes
                .get(id.as_str())
                .copied()
                .ok_or_else(|| invalid("path references missing node"))
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, edge) in path_edges.iter().enumerate() {
        if edge.source != path.nodes[index] || edge.target != path.nodes[index + 1] {
            return Err(invalid("path edges do not connect its nodes"));
        }
    }
    let distinct: BTreeSet<&str> = path.nodes.iter().map(String::as_str).collect();
    if distinct.len() != path.nodes.len() {
        return Err(invalid("path is not simple"));
    }
    if path.entry != path.nodes[0] || Some(&path.target) != path.nodes.last() {
        return Err(invalid("path entry or target does not match its ends"));
    }
    if path.id != path_id(&path.nodes, &path.edges)? {
        return Err(invalid("path id does not match its content"));
    }
    if path.status != path_status(&path_edges) {
        return Err(invalid("path evidence status does not match its edges"));
    }
    // Invariant 6: control state recomputed.
    let (state, failed, undecided) = path_control(&path_edges);
    if path.control_state != state
        || path.failed_guards != failed
        || path.undecided_edges != undecided
    {
        return Err(invalid("path control state does not match its guards"));
    }
    if path.impact_factors != impact_factors(&path_nodes, &path_edges) {
        return Err(invalid(
            "path impact factors do not match its nodes and edges",
        ));
    }
    if !graph
        .entry_points
        .iter()
        .any(|d| d.node == path.entry && d.class == path.entry_class)
    {
        return Err(invalid("path entry is not a designated entry point"));
    }
    if path.target_class != TargetClass::CrossTenantResource
        && !graph
            .targets
            .iter()
            .any(|d| d.node == path.target && d.class == path.target_class)
    {
        return Err(invalid("path target is not a designated target"));
    }
    Ok(())
}

pub fn validate_paths_v2(graph: &AttackGraphV2, doc: &AttackPathsDoc) -> Result<()> {
    if doc.schema_id != PATHS_SCHEMA_ID_V2 || doc.schema_version != DOCUMENT_SCHEMA_VERSION {
        return Err(invalid("unexpected v2 paths schema"));
    }
    if doc.graph_id != graph.id {
        return Err(invalid("paths document names another graph"));
    }
    let nodes: BTreeMap<&str, &NodeV2> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let edges: BTreeMap<&str, &EdgeV2> = graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut ids = BTreeSet::new();
    for path in doc.paths.iter().chain(&doc.discontinuous_paths) {
        validate_path(graph, &nodes, &edges, path)?;
        if !ids.insert(path.id.as_str()) {
            return Err(invalid("duplicate path id"));
        }
    }
    if doc
        .paths
        .iter()
        .any(|p| p.feasibility != Feasibility::Feasible || p.discontinuity_at.is_some())
        || doc
            .discontinuous_paths
            .iter()
            .any(|p| p.feasibility != Feasibility::Discontinuous || p.discontinuity_at.is_none())
    {
        return Err(invalid("path is in the wrong feasibility list"));
    }
    for chokepoint in &doc.chokepoints {
        if !nodes.contains_key(chokepoint.target.as_str())
            || !edges.contains_key(chokepoint.edge.as_str())
        {
            return Err(invalid("chokepoint references missing node or edge"));
        }
    }
    if doc.enumeration.truncated == doc.enumeration.stopped_by.is_empty() {
        return Err(invalid(
            "truncation flag disagrees with the bounds that fired",
        ));
    }
    check_schema(ATTACK_PATHS_SCHEMA_V2_JSON, &serde_json::to_value(doc)?)
}

pub fn validate_projection_report(graph: &AttackGraphV2, report: &ProjectionReport) -> Result<()> {
    if report.schema_id != REPORT_SCHEMA_ID_V2 || report.schema_version != DOCUMENT_SCHEMA_VERSION {
        return Err(invalid("unexpected projection report schema"));
    }
    if report.graph_id != graph.id || report.model_digest != graph.sources.model_digest {
        return Err(invalid("projection report names another graph"));
    }
    let listed: Vec<u32> = report.artifacts.iter().map(|a| a.index).collect();
    let sources: Vec<u32> = graph.sources.artifacts.iter().map(|a| a.index).collect();
    if listed != sources {
        return Err(invalid(
            "projection report artifacts differ from the graph sources",
        ));
    }
    check_schema(
        PROJECTION_REPORT_SCHEMA_V2_JSON,
        &serde_json::to_value(report)?,
    )
}
