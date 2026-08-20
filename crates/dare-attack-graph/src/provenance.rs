use crate::{canonical::digest_value, error::Result, model::AttackGraph};

pub fn graph_digest(graph: &AttackGraph) -> Result<String> {
    let mut normalized = graph.clone();
    normalized.id.clear();
    normalized.nodes.sort_by(|a, b| a.id.cmp(&b.id));
    normalized.edges.sort_by(|a, b| a.id.cmp(&b.id));
    normalized.paths.sort_by(|a, b| a.id.cmp(&b.id));
    digest_value(&serde_json::to_value(normalized)?)
}

#[cfg(test)]
mod tests {
    use crate::{build_attack_graph, GraphFactsInput};

    #[test]
    fn identical_facts_have_identical_digest() {
        let raw = include_str!("../../../fixtures/attack-graph/safe-read.json");
        let facts: GraphFactsInput = serde_json::from_str(raw).unwrap();
        let a = build_attack_graph(&facts).unwrap();
        let b = build_attack_graph(&facts).unwrap();
        assert_eq!(
            super::graph_digest(&a).unwrap(),
            super::graph_digest(&b).unwrap()
        );
    }
}
