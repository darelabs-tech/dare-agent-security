//! `summary.md` (BLUEPRINT §5.4): counts, routes and the not-claimed
//! statements. No time stamp.
use std::collections::BTreeMap;

use dare_attack_graph::v2::{AttackGraphV2, TargetClass};

use crate::{
    error::Result,
    model::{BlastRadiusDoc, Exposure},
    reach::Indexed,
    render::wire,
};

/// Targets listed per seed before the rest are left to the JSON.
pub const TARGETS_PER_SEED: usize = 50;

pub const NOT_CLAIMED: [&str; 4] = [
    "CONTAINED means only that every route to the target within max_depth crosses a control observed to hold in the supplied runs. It does not mean \"safe\".",
    "Unreached is not unreachable: a relationship no artifact or model line states is not in the graph.",
    "No reach was executed.",
    "The remediation delta counts what one edge's controls would contain if they held. It is not a ranking of risk.",
];

/// A display name safe inside a Markdown table cell.
fn cell(index: &Indexed<'_>, id: &str) -> String {
    md(index.node(id).map_or(id, |n| n.display_name.as_str()))
}

/// Text safe inside a Markdown table cell: no cell break, markup or code
/// span, at most 80 characters.
fn md(text: &str) -> String {
    text.chars()
        .take(80)
        .flat_map(|c| match c {
            '|' => vec!['\\', '|'],
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '`' => vec!['\''],
            '\n' | '\r' => vec![' '],
            c => vec![c],
        })
        .collect()
}

fn exposure_counts(targets: &[crate::model::TargetReach]) -> [usize; 3] {
    let count = |e| targets.iter().filter(|t| t.exposure == e).count();
    [
        count(Exposure::Exposed),
        count(Exposure::Contained),
        count(Exposure::ContainmentUnknown),
    ]
}

pub fn summary(graph: &AttackGraphV2, doc: &BlastRadiusDoc) -> Result<String> {
    let index = Indexed::new(graph);
    let mut out = String::from("# DARE Blast Radius\n\n");
    out.push_str(&format!(
        "Graph: `{}`\nScenario: {}\nSeeds: {} ({} skipped, {} omitted)\nBounds: max_depth {}, max_states {} per search, {} in total\n\n",
        doc.graph_id,
        md(&doc.scenario_id),
        doc.seeds.len(),
        doc.seeds_skipped,
        doc.seeds_omitted,
        doc.bounds.max_depth,
        doc.bounds.max_states,
        doc.bounds.max_states_total,
    ));
    let t = &doc.totals;
    out.push_str(&format!(
        "Targets over (seed, target) pairs: {} EXPOSED, {} CONTAINED, {} CONTAINMENT_UNKNOWN.\n",
        t.exposed, t.contained, t.containment_unknown
    ));

    out.push_str("\n## Seeds\n\n| Seed | Kind | EXPOSED | CONTAINED | CONTAINMENT_UNKNOWN | Truncated |\n|---|---|---|---|---|---|\n");
    for seed in &doc.seeds {
        let [e, c, u] = exposure_counts(&seed.targets);
        out.push_str(&format!(
            "| {} | {} | {e} | {c} | {u} | {} |\n",
            cell(&index, &seed.node),
            wire(&seed.kind),
            seed.structural.truncated || seed.uncontained.truncated,
        ));
    }

    out.push_str("\n## Exposed targets by class\n\n| Class | EXPOSED pairs |\n|---|---|\n");
    let classes: BTreeMap<TargetClass, u32> = t.exposed_by_class.clone();
    if classes.is_empty() {
        out.push_str("| (none) | 0 |\n");
    }
    for (class, n) in &classes {
        out.push_str(&format!("| {} | {n} |\n", wire(class)));
    }

    for seed in &doc.seeds {
        out.push_str(&format!(
            "\n## Reach of {} ({})\n\n",
            cell(&index, &seed.node),
            wire(&seed.kind)
        ));
        if seed.targets.is_empty() {
            out.push_str("No target reached within the bounds.\n");
            continue;
        }
        out.push_str(
            "| Target | Class | Exposure | Route edges | Control |\n|---|---|---|---|---|\n",
        );
        for target in seed.targets.iter().take(TARGETS_PER_SEED) {
            let route = target
                .uncontained_route
                .as_ref()
                .unwrap_or(&target.structural_route);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                cell(&index, &target.node),
                wire(&target.class),
                wire(&target.exposure),
                route.edges.len(),
                wire(&route.control_state),
            ));
        }
        if seed.targets.len() > TARGETS_PER_SEED {
            out.push_str(&format!(
                "\n{} more in blast-radius.json.\n",
                seed.targets.len() - TARGETS_PER_SEED
            ));
        }
    }

    if !doc.frontier.is_empty() {
        out.push_str("\n## Frontier\n\nHeld edges that contain at least one target: every guard on them was observed to PASS.\n\n| Edge | From | To | Properties | Contained pairs |\n|---|---|---|---|---|\n");
        for edge in &doc.frontier {
            let (from, to) = index
                .edge(&edge.edge)
                .map_or(("?".into(), "?".into()), |e| {
                    (cell(&index, &e.source), cell(&index, &e.target))
                });
            out.push_str(&format!(
                "| `{}` | {from} | {to} | {} | {} |\n",
                edge.edge,
                edge.properties.join(", "),
                edge.contained_targets
            ));
        }
    }

    if !doc.remediation_delta.is_empty() {
        out.push_str("\n## Remediation delta\n\nExposed targets each failed edge's seeds would no longer reach if this edge's controls held (a count, not a ranking).\n\n| Edge | From | To | Failed properties | Targets contained if held | Partial |\n|---|---|---|---|---|---|\n");
        for delta in &doc.remediation_delta {
            let (from, to) = index
                .edge(&delta.edge)
                .map_or(("?".into(), "?".into()), |e| {
                    (cell(&index, &e.source), cell(&index, &e.target))
                });
            out.push_str(&format!(
                "| `{}` | {from} | {to} | {} | {} | {} |\n",
                delta.edge,
                delta.properties.join(", "),
                delta.targets_contained_if_held,
                delta.partial
            ));
        }
    }

    let states: u64 = doc
        .seeds
        .iter()
        .map(|s| s.structural.states_explored + s.uncontained.states_explored)
        .sum();
    let refused: u64 = doc
        .seeds
        .iter()
        .map(|s| s.structural.refused_steps + s.uncontained.refused_steps)
        .sum();
    let depth_cut = doc
        .seeds
        .iter()
        .any(|s| s.structural.depth_cut || s.uncontained.depth_cut);
    out.push_str(&format!(
        "\n## Search\n\nStates explored: {states}. Steps no continuity rule explains: {refused}. Depth cut: {depth_cut}. Truncated: {}{}.\n",
        doc.truncated,
        if doc.truncated {
            let bounds: Vec<String> = doc.stopped_by.iter().map(wire).collect();
            format!(" (stopped by {})", bounds.join(", "))
        } else {
            String::new()
        }
    ));

    out.push_str("\n## What this does not claim\n\n");
    for line in NOT_CLAIMED {
        out.push_str("- ");
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}
