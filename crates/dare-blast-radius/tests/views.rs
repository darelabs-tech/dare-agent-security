//! Reach views and the summary (tasks 019-020, BLUEPRINT §5.3-§5.4).
mod support;

use dare_attack_graph::{
    v2::{AttackGraphV2, EntryClass, TargetClass},
    EdgeType, NodeType,
};
use dare_blast_radius::{
    analyze::analyze_graph,
    model::BlastRadiusDoc,
    render::{to_dot, to_mermaid},
    scenario::entry_point_seeds,
    summary::{summary, NOT_CLAIMED, TARGETS_PER_SEED},
    Options,
};
use support::{Gd, G, PROP};

const HOSTILE: [&str; 4] = [
    "\"]; click n0 call x()",
    "a --> b",
    "<script>x</script>",
    "p|q`r`",
];

fn doc_for(graph: &AttackGraphV2) -> BlastRadiusDoc {
    let seeds = entry_point_seeds(graph).unwrap();
    analyze_graph(graph, &seeds, &Options::default()).unwrap()
}

/// Two seeds share one target: an open edge from one, a held edge from the
/// other. Display names are hostile; one node is never reached.
fn shared() -> AttackGraphV2 {
    let mut g = G::new();
    let a = g.node(NodeType::Human, "a");
    let b = g.node(NodeType::Human, "b");
    let t = g.node(NodeType::Resource, "t");
    let x = g.node(NodeType::Resource, "x");
    let island = g.node(NodeType::Resource, "island");
    for (node, name) in g.nodes.iter_mut().zip(HOSTILE) {
        node.display_name = name.into();
    }
    g.edge(&a, EdgeType::Reads, &t, Gd::Fail);
    g.edge(&b, EdgeType::Reads, &t, Gd::Pass);
    g.edge(&a, EdgeType::Writes, &x, Gd::None);
    g.entry(&a, EntryClass::LowPrivilegePrincipal);
    g.entry(&b, EntryClass::LowPrivilegePrincipal);
    for n in [&t, &x, &island] {
        g.target(n, TargetClass::SensitiveResource);
    }
    g.build()
}

/// A quoted label holds no unescaped quote and no raw angle bracket.
fn label_is_escaped(label: &str) {
    let mut escaped = false;
    for c in label.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' | '<' | '>' => panic!("unescaped {c:?} in {label}"),
            _ => {}
        }
    }
}

fn quoted(line: &str) -> Vec<&str> {
    // Every label sits between the first `"` after `[`/`|`/`label=` and the
    // last `"` of its group.
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut start = None;
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], start) {
            (b'\\', Some(_)) => i += 1,
            (b'"', None) => start = Some(i + 1),
            (b'"', Some(s)) => {
                out.push(&line[s..i]);
                start = None;
            }
            _ => {}
        }
        i += 1;
    }
    assert!(start.is_none(), "unterminated label in {line}");
    out
}

#[test]
fn hostile_labels_render_escaped_in_both_views() {
    let graph = shared();
    let doc = doc_for(&graph);
    let mermaid = to_mermaid(&graph, &doc).unwrap();
    let dot = to_dot(&graph, &doc).unwrap();
    for line in mermaid.lines().chain(dot.lines()).skip(1) {
        for label in quoted(line) {
            label_is_escaped(label);
        }
    }
    assert!(mermaid.contains("&lt;script&gt;"));
    assert!(mermaid.contains("\\\"]; click"));
    assert!(!mermaid.contains("<script>") && !dot.contains("<script>"));
    // Symbols are positional; the graph's ids never appear.
    assert!(!mermaid.contains("node:") && !dot.contains("node:"));
    assert!(mermaid.starts_with("flowchart LR\n"));
    assert!(dot.starts_with("digraph blast_radius {\n") && dot.ends_with("}\n"));
}

#[test]
fn views_draw_only_the_reached_subgraph_with_text_tags() {
    let graph = shared();
    let doc = doc_for(&graph);
    let mermaid = to_mermaid(&graph, &doc).unwrap();
    let node_lines: Vec<&str> = mermaid.lines().filter(|l| l.contains("[\"")).collect();
    // a, b, t and x; the island is never reached.
    assert_eq!(node_lines.len(), 4, "{mermaid}");
    assert!(!mermaid.contains("island"));
    let line_of = |needle: &str| {
        *node_lines
            .iter()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle} in {mermaid}"))
    };
    assert!(line_of("click").ends_with("[seed PRINCIPAL_TAKEOVER]\"]"));
    assert!(line_of("a --&gt; b").contains("[seed PRINCIPAL_TAKEOVER]"));
    // Exposed for one seed and contained for the other: both, in order.
    assert!(line_of("script").ends_with("(Resource) [exposed] [contained]\"]"));
    // Edge labels carry control state as text.
    assert!(mermaid.contains(&format!("READS FAIL {PROP}")));
    assert!(mermaid.contains("READS held"));
    assert!(mermaid.contains("|\"WRITES\"|"));
    let dot = to_dot(&graph, &doc).unwrap();
    assert!(dot.contains("[id=\"e0\", label="));
}

#[test]
fn the_summary_counts_routes_and_ends_with_what_it_does_not_claim() {
    let graph = shared();
    let doc = doc_for(&graph);
    let text = summary(&graph, &doc).unwrap();
    assert!(text.starts_with("# DARE Blast Radius\n"));
    assert!(text.contains(&format!("Graph: `{}`", graph.id)));
    assert!(text.contains("Scenario: entry-points"));
    assert!(text.contains("2 EXPOSED, 1 CONTAINED, 0 CONTAINMENT_UNKNOWN"));
    assert!(text.contains("## Frontier") && text.contains("## Remediation delta"));
    assert!(text.contains("a count, not a ranking"));
    // A pipe in a display name cannot break a table cell.
    assert!(!text.contains("p|q"));
    let tail: Vec<&str> = text.trim_end().lines().rev().take(4).collect();
    let want: Vec<String> = NOT_CLAIMED.iter().rev().map(|l| format!("- {l}")).collect();
    assert_eq!(tail, want);
    assert!(text.contains("## What this does not claim"));
    // No time stamp.
    assert!(!text.contains("2026") && !text.contains("UTC"));
}

#[test]
fn the_summary_lists_at_most_fifty_targets_per_seed() {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    for i in 0..(TARGETS_PER_SEED + 7) {
        let r = g.node(NodeType::Resource, &format!("r{i:03}"));
        g.edge(&user, EdgeType::Reads, &r, Gd::Fail);
        g.target(&r, TargetClass::SensitiveResource);
    }
    g.entry(&user, EntryClass::LowPrivilegePrincipal);
    let graph = g.build();
    let doc = doc_for(&graph);
    let text = summary(&graph, &doc).unwrap();
    assert!(text.contains("\n7 more in blast-radius.json.\n"));
    assert_eq!(text.matches("| SENSITIVE_RESOURCE | EXPOSED |").count(), 50);
}

#[test]
fn every_summary_ends_with_the_four_statements_even_with_no_reach() {
    let mut g = G::new();
    let user = g.node(NodeType::Human, "user");
    g.node(NodeType::Resource, "r");
    g.entry(&user, EntryClass::LowPrivilegePrincipal);
    let graph = g.build();
    let doc = doc_for(&graph);
    let text = summary(&graph, &doc).unwrap();
    assert!(text.contains("No target reached within the bounds."));
    for line in NOT_CLAIMED {
        assert!(text.contains(line));
    }
    assert!(text.trim_end().ends_with(NOT_CLAIMED[3]));
    let mermaid = to_mermaid(&graph, &doc).unwrap();
    assert_eq!(mermaid.lines().count(), 2, "only the seed");
}
