use crate::{
    error::Result,
    model::AttackGraph,
    validate::{validate_graph, validate_safe_label},
};

fn safe_label(label: &str) -> Result<String> {
    validate_safe_label(label)?;
    let capped: String = label.chars().take(80).collect();
    Ok(capped
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

fn symbol(id: &str) -> String {
    format!(
        "n_{}",
        id.chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect::<String>()
    )
}

pub fn to_mermaid(graph: &AttackGraph) -> Result<String> {
    validate_graph(graph)?;
    let mut output = String::from("flowchart LR\n");
    for node in &graph.nodes {
        output.push_str(&format!(
            "  {}[\"{}\"]\n",
            symbol(&node.id),
            safe_label(&node.display_name)?
        ));
    }
    for edge in &graph.edges {
        output.push_str(&format!(
            "  {} -->|\"{:?} [{:?}]\"| {}\n",
            symbol(&edge.source),
            edge.edge_type,
            edge.evidence.status,
            symbol(&edge.target)
        ));
    }
    Ok(output)
}

pub fn to_dot(graph: &AttackGraph) -> Result<String> {
    validate_graph(graph)?;
    let mut output = String::from("digraph attack_graph {\n");
    for node in &graph.nodes {
        output.push_str(&format!(
            "  {} [label=\"{}\"];\n",
            symbol(&node.id),
            safe_label(&node.display_name)?
        ));
    }
    for edge in &graph.edges {
        output.push_str(&format!(
            "  {} -> {} [label=\"{:?} [{:?}]\"];\n",
            symbol(&edge.source),
            symbol(&edge.target),
            edge.edge_type,
            edge.evidence.status
        ));
    }
    output.push_str("}\n");
    Ok(output)
}
