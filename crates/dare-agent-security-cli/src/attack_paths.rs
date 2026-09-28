//! `validate attack-paths`: evidence-derived attack-path construction
//! (Cycle 023). Analysis only; it reads local files and never executes,
//! sends or schedules anything.
use std::{fs, path::PathBuf};

use clap::Args;
use dare_attack_graph::v2::{to_dot_v2, to_mermaid_v2, ControlState};
use dare_attack_path::{
    construct,
    limits::{DEFAULT_PATH_EDGES, MAX_PATHS, MAX_PATHS_PER_PAIR},
    sweep::sweep,
    AttackPathError, ConstructOptions, Construction, Refusal,
};

use crate::{
    ci_output::validate_output_dir,
    exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET},
};

pub const ATTACK_PATHS_AFTER_HELP: &str = "\
Exit codes (`validate attack-paths`):
  0  every feasible path is CONTROLS_HELD (or there is none) and nothing was truncated
  1  internal error
  2  a feasible path is CONTROL_FAILED or CONTROL_UNDECIDED, or enumeration was truncated
  3  refusal (invalid or unbound input, bound above its maximum); nothing is written

CONTROLS_HELD means only that every control guarding an enumerated path was
observed to hold. It does not mean the system is secure: relationships no
artifact or model states, and paths longer than --max-path-edges, are not covered.";

#[derive(Debug, Args)]
pub struct AttackPathsArgs {
    /// An engine artifact directory (result, evidence and `inputs/`). Repeatable, 1 to 64.
    #[arg(long, value_name = "DIR", required = true)]
    pub artifacts: Vec<PathBuf>,
    /// The system model: entities, aliases, entry points, targets, trust boundaries.
    #[arg(long, value_name = "FILE")]
    pub system_model: Option<PathBuf>,
    /// Directory for the six output files.
    #[arg(long, value_name = "DIR")]
    pub output_dir: PathBuf,
    /// Longest path, in edges (1 to 12).
    #[arg(long, default_value_t = DEFAULT_PATH_EDGES)]
    pub max_path_edges: u32,
    /// Most paths reported (1 to 10000).
    #[arg(long, default_value_t = MAX_PATHS)]
    pub max_paths: u32,
    /// Most paths per (entry, target) pair (1 to 64).
    #[arg(long, default_value_t = MAX_PATHS_PER_PAIR)]
    pub max_paths_per_pair: u32,
    /// Also print `attack-paths.json` to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_attack_paths(args: AttackPathsArgs) -> i32 {
    match run_inner(&args) {
        Ok(code) => code,
        Err(AttackPathError::Refused(refusal)) => {
            eprintln!("refused: {refusal}");
            UNSUPPORTED_TARGET
        }
        Err(AttackPathError::Internal(message)) => {
            eprintln!("internal error: {message}");
            SCANNER_ERROR
        }
    }
}

fn json(value: &impl serde::Serialize) -> Result<Vec<u8>, AttackPathError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| AttackPathError::Internal("serialization"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn run_inner(args: &AttackPathsArgs) -> Result<i32, AttackPathError> {
    validate_output_dir(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    let options = ConstructOptions {
        max_path_edges: args.max_path_edges,
        max_paths: args.max_paths,
        max_paths_per_pair: args.max_paths_per_pair,
    };
    let construction = construct(&args.artifacts, args.system_model.as_deref(), &options)?;
    // Every file is rendered and checked before the first one is written.
    let files: Vec<(&'static str, Vec<u8>)> = vec![
        ("projection-report.json", json(&construction.report)?),
        ("attack-graph.json", json(&construction.graph)?),
        ("attack-paths.json", json(&construction.paths)?),
        (
            "graph.mmd",
            to_mermaid_v2(&construction.graph)
                .map_err(|_| AttackPathError::Internal("mermaid view"))?
                .into_bytes(),
        ),
        (
            "graph.dot",
            to_dot_v2(&construction.graph)
                .map_err(|_| AttackPathError::Internal("dot view"))?
                .into_bytes(),
        ),
        ("summary.md", summary(&construction, &options).into_bytes()),
    ];
    for (name, bytes) in &files {
        sweep(name, bytes)?;
    }
    fs::create_dir_all(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    for (name, bytes) in &files {
        fs::write(args.output_dir.join(name), bytes)
            .map_err(|_| AttackPathError::Internal("write"))?;
    }
    if args.json {
        print!("{}", String::from_utf8_lossy(&files[2].1));
    }
    let paths = &construction.paths;
    let failed = count(paths, ControlState::ControlFailed);
    let undecided = count(paths, ControlState::ControlUndecided);
    println!(
        "{} feasible paths ({failed} CONTROL_FAILED, {undecided} CONTROL_UNDECIDED), {} discontinuous{}",
        paths.paths.len(),
        paths.discontinuous_paths.len(),
        if paths.enumeration.truncated { ", enumeration truncated" } else { "" }
    );
    Ok(
        if failed > 0 || undecided > 0 || paths.enumeration.truncated {
            PARTIAL
        } else {
            SUCCESS
        },
    )
}

fn count(paths: &dare_attack_graph::v2::AttackPathsDoc, state: ControlState) -> usize {
    paths
        .paths
        .iter()
        .filter(|p| p.control_state == state)
        .count()
}

/// The wire name of a unit enum, as it appears in the JSON artifacts.
fn wire(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn label<'a>(construction: &'a Construction, id: &'a str) -> &'a str {
    construction
        .graph
        .nodes
        .iter()
        .find(|n| n.id == id)
        .map_or(id, |n| n.display_name.as_str())
}

fn summary(c: &Construction, options: &ConstructOptions) -> String {
    let paths = &c.paths;
    let e = &paths.enumeration;
    let mut out = String::from("# DARE Attack Paths\n\n");
    out.push_str(&format!(
        "Target: {} ({})\nArtifacts: {}{}\nNodes: {}  Edges: {}  Entry points: {}  Targets: {}\n\n",
        c.graph.target_id,
        c.graph.target_version,
        c.graph.sources.artifacts.len(),
        if c.graph.sources.model_digest.is_some() {
            ", with a system model"
        } else {
            ", no system model (runs are not joined)"
        },
        c.graph.nodes.len(),
        c.graph.edges.len(),
        c.graph.entry_points.len(),
        c.graph.targets.len(),
    ));
    out.push_str("| Control state | Feasible paths |\n|---|---|\n");
    for state in [
        ControlState::ControlFailed,
        ControlState::ControlUndecided,
        ControlState::ControlsHeld,
    ] {
        out.push_str(&format!("| {} | {} |\n", wire(&state), count(paths, state)));
    }
    out.push_str(&format!(
        "\nDiscontinuous paths (reported apart): {}\n",
        paths.discontinuous_paths.len()
    ));
    if !paths.paths.is_empty() {
        out.push_str("\n## Paths\n\n| Entry | Target | Edges | Evidence | Control |\n|---|---|---|---|---|\n");
        for path in paths.paths.iter().take(50) {
            out.push_str(&format!(
                "| {} ({}) | {} ({}) | {} | {} | {} |\n",
                label(c, &path.entry),
                wire(&path.entry_class),
                label(c, &path.target),
                wire(&path.target_class),
                path.edges.len(),
                wire(&path.status),
                wire(&path.control_state),
            ));
        }
        if paths.paths.len() > 50 {
            out.push_str(&format!(
                "\n{} more paths are in attack-paths.json.\n",
                paths.paths.len() - 50
            ));
        }
    }
    if !paths.chokepoints.is_empty() {
        out.push_str("\n## Chokepoints\n\nEdges every failed path to a target shares (counts over the enumerated paths, not a score).\n\n| Target | Failed paths | Properties | Partial |\n|---|---|---|---|\n");
        for choke in &paths.chokepoints {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                label(c, &choke.target),
                choke.failed_paths,
                choke.properties.join(", "),
                choke.partial
            ));
        }
    }
    out.push_str(&format!(
        "\n## Enumeration\n\nPairs: {} total, {} exhausted, {} truncated. Steps: {}. Truncated: {}{}.\n",
        e.pairs_total,
        e.pairs_exhausted,
        e.pairs_truncated_count,
        e.steps_used,
        e.truncated,
        if e.truncated {
            let bounds: Vec<String> = e.stopped_by.iter().map(wire).collect();
            format!(" (stopped by {})", bounds.join(", "))
        } else {
            String::new()
        },
    ));
    let synthetic = c
        .graph
        .sources
        .artifacts
        .iter()
        .filter(|a| a.synthetic)
        .count();
    let dynamic = c
        .graph
        .sources
        .artifacts
        .iter()
        .filter(|a| a.dynamic_authorized)
        .count();
    out.push_str(&format!(
        "\n## What this does not claim\n\n\
- CONTROLS_HELD is not \"secure\": it means every control guarding an enumerated path was observed to hold.\n\
- Paths longer than {} edges, and relationships that no artifact or system-model line states, are not covered.\n\
- No path was executed. {synthetic} of the artifacts came from synthetic runs and {dynamic} from authorized remote runs.\n",
        options.max_path_edges
    ));
    out
}
