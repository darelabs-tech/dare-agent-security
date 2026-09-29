//! Reach views (BLUEPRINT §5.3). JSON stays canonical; these are views only.
//!
//! Only the reached subgraph is drawn: the seeds and every structural
//! witness route. Exposure and control state are written as text, never
//! conveyed by colour alone, and every label goes through `escape_label`.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::{
    escape_label,
    v2::{edge_control, AttackGraphV2, EdgeControl, GuardVerdict},
};
use serde::Serialize;

use crate::{
    error::{BlastError, Result},
    model::{BlastRadiusDoc, Exposure},
    reach::Indexed,
};

/// The SCREAMING_SNAKE_CASE wire name of an enum value.
pub fn wire(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn escaped(label: &str) -> Result<String> {
    escape_label(label).map_err(|_| BlastError::Internal("unsafe label"))
}

struct Subgraph<'d> {
    nodes: Vec<&'d str>,
    edges: Vec<&'d str>,
    tags: BTreeMap<&'d str, Vec<String>>,
}

fn subgraph(doc: &BlastRadiusDoc) -> Subgraph<'_> {
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeSet::new();
    let mut seeds: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut exposure: BTreeMap<&str, BTreeSet<Exposure>> = BTreeMap::new();
    for seed in &doc.seeds {
        nodes.insert(seed.node.as_str());
        seeds
            .entry(seed.node.as_str())
            .or_default()
            .push(format!("[seed {}]", wire(&seed.kind)));
        for target in &seed.targets {
            nodes.extend(target.structural_route.nodes.iter().map(String::as_str));
            edges.extend(target.structural_route.edges.iter().map(String::as_str));
            exposure
                .entry(target.node.as_str())
                .or_default()
                .insert(target.exposure);
        }
    }
    let tags = nodes
        .iter()
        .map(|&node| {
            let mut tags = seeds.remove(node).unwrap_or_default();
            for state in exposure.remove(node).unwrap_or_default() {
                tags.push(
                    match state {
                        Exposure::Exposed => "[exposed]",
                        Exposure::Contained => "[contained]",
                        Exposure::ContainmentUnknown => "[unknown]",
                    }
                    .to_owned(),
                );
            }
            (node, tags)
        })
        .collect();
    Subgraph {
        nodes: nodes.into_iter().collect(),
        edges: edges.into_iter().collect(),
        tags,
    }
}

fn node_label(index: &Indexed<'_>, sub: &Subgraph<'_>, id: &str) -> Result<String> {
    let node = index
        .node(id)
        .ok_or(BlastError::Internal("view names an unknown node"))?;
    let mut text = format!("{} ({:?})", escaped(&node.display_name)?, node.node_type);
    for tag in sub.tags.get(id).into_iter().flatten() {
        text.push(' ');
        text.push_str(tag);
    }
    Ok(text)
}

fn edge_label(index: &Indexed<'_>, id: &str) -> Result<String> {
    let edge = index
        .edge(id)
        .ok_or(BlastError::Internal("view names an unknown edge"))?;
    let mut text = wire(&edge.edge_type);
    match edge_control(edge) {
        EdgeControl::Decided(GuardVerdict::Pass) => text.push_str(" held"),
        EdgeControl::Decided(GuardVerdict::Fail) => {
            let failed: BTreeSet<&str> = edge
                .guards
                .iter()
                .filter(|g| g.verdict == GuardVerdict::Fail)
                .map(|g| g.property.as_str())
                .collect();
            text.push_str(" FAIL ");
            text.push_str(&failed.into_iter().collect::<Vec<_>>().join(", "));
        }
        _ => {}
    }
    escaped(&text)
}

/// Positional symbols: two ids that differ only in punctuation never share
/// one.
fn symbols<'d>(sub: &Subgraph<'d>) -> BTreeMap<&'d str, String> {
    sub.nodes
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, format!("n{i}")))
        .collect()
}

fn ends<'g>(index: &Indexed<'g>, id: &str) -> Result<(&'g str, &'g str)> {
    let edge = index
        .edge(id)
        .ok_or(BlastError::Internal("view names an unknown edge"))?;
    Ok((edge.source.as_str(), edge.target.as_str()))
}

pub fn to_mermaid(graph: &AttackGraphV2, doc: &BlastRadiusDoc) -> Result<String> {
    let index = Indexed::new(graph);
    let sub = subgraph(doc);
    let symbol = symbols(&sub);
    let mut out = String::from("flowchart LR\n");
    for id in &sub.nodes {
        out.push_str(&format!(
            "  {}[\"{}\"]\n",
            symbol[id],
            node_label(&index, &sub, id)?
        ));
    }
    for id in &sub.edges {
        let (source, target) = ends(&index, id)?;
        out.push_str(&format!(
            "  {} -->|\"{}\"| {}\n",
            symbol[source],
            edge_label(&index, id)?,
            symbol[target]
        ));
    }
    Ok(out)
}

pub fn to_dot(graph: &AttackGraphV2, doc: &BlastRadiusDoc) -> Result<String> {
    let index = Indexed::new(graph);
    let sub = subgraph(doc);
    let symbol = symbols(&sub);
    let mut out = String::from("digraph blast_radius {\n  rankdir=LR;\n");
    for id in &sub.nodes {
        out.push_str(&format!(
            "  {} [label=\"{}\"];\n",
            symbol[id],
            node_label(&index, &sub, id)?
        ));
    }
    for (i, id) in sub.edges.iter().enumerate() {
        let (source, target) = ends(&index, id)?;
        out.push_str(&format!(
            "  {} -> {} [id=\"e{i}\", label=\"{}\"];\n",
            symbol[source],
            symbol[target],
            edge_label(&index, id)?
        ));
    }
    out.push_str("}\n");
    Ok(out)
}
