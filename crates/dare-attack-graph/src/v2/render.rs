//! v2 derived views. JSON stays canonical; these are views only.
//!
//! Labels are escaped exactly as in v1. Node symbols are positional (`n0`,
//! `n1`, …) instead of v1's alphanumeric filter, so two ids that differ only
//! in punctuation can never collapse into one symbol. Evidence and control
//! state are written as text, never conveyed by colour alone.
use std::collections::BTreeMap;

use crate::{error::Result, render::escape_label};

use super::{
    control::{edge_control, EdgeControl},
    model::{AttackGraphV2, GuardVerdict},
    validate::validate_graph_v2,
};

fn control_label(control: EdgeControl) -> &'static str {
    match control {
        EdgeControl::Exempt => "STRUCTURAL",
        EdgeControl::Unassessed => "UNASSESSED",
        EdgeControl::Decided(GuardVerdict::Pass) => "PASS",
        EdgeControl::Decided(GuardVerdict::Fail) => "FAIL",
        EdgeControl::Decided(GuardVerdict::Inconclusive) => "INCONCLUSIVE",
        EdgeControl::Decided(GuardVerdict::Error) => "ERROR",
    }
}

fn symbols(graph: &AttackGraphV2) -> BTreeMap<&str, String> {
    graph
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), format!("n{index}")))
        .collect()
}

fn edge_label(graph: &AttackGraphV2, index: usize) -> Result<String> {
    let edge = &graph.edges[index];
    let text = format!(
        "{:?} [{:?}] {{{}}}",
        edge.edge_type,
        edge.evidence.status,
        control_label(edge_control(edge))
    );
    escape_label(&text)
}

pub fn to_mermaid_v2(graph: &AttackGraphV2) -> Result<String> {
    validate_graph_v2(graph)?;
    let symbol = symbols(graph);
    let mut output = String::from("flowchart LR\n");
    for node in &graph.nodes {
        output.push_str(&format!(
            "  {}[\"{} ({:?})\"]\n",
            symbol[node.id.as_str()],
            escape_label(&node.display_name)?,
            node.node_type
        ));
    }
    for (index, edge) in graph.edges.iter().enumerate() {
        output.push_str(&format!(
            "  {} -->|\"{}\"| {}\n",
            symbol[edge.source.as_str()],
            edge_label(graph, index)?,
            symbol[edge.target.as_str()]
        ));
    }
    Ok(output)
}

pub fn to_dot_v2(graph: &AttackGraphV2) -> Result<String> {
    validate_graph_v2(graph)?;
    let symbol = symbols(graph);
    let mut output = String::from("digraph attack_graph_v2 {\n");
    for node in &graph.nodes {
        output.push_str(&format!(
            "  {} [label=\"{} ({:?})\"];\n",
            symbol[node.id.as_str()],
            escape_label(&node.display_name)?,
            node.node_type
        ));
    }
    for (index, edge) in graph.edges.iter().enumerate() {
        output.push_str(&format!(
            "  {} -> {} [label=\"{}\"];\n",
            symbol[edge.source.as_str()],
            symbol[edge.target.as_str()],
            edge_label(graph, index)?
        ));
    }
    output.push_str("}\n");
    Ok(output)
}
