//! `validate attack-graph`: deterministic analysis only; never executes paths.
use std::{fs, path::PathBuf};

use clap::Args;
use dare_attack_graph::{
    build_attack_graph, derive_paths, graph_digest, load_facts_file, to_dot, to_mermaid,
    validate_graph, GraphError, PathOptions,
};

use crate::{
    ci_output::{assert_summary_secret_safe, validate_output_dir},
    exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET},
};

#[derive(Debug, Args)]
pub struct AttackGraphArgs {
    /// Normalized graph fact JSON file.
    #[arg(long, value_name = "PATH")]
    pub facts: PathBuf,
    /// Directory for attack-graph.json, paths.json, graph.mmd, graph.dot, and summary.md.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Maximum edges per derived path (hard limit 64).
    #[arg(long, default_value_t = 8)]
    pub max_depth: usize,
    /// Maximum paths emitted (hard limit 10000).
    #[arg(long, default_value_t = 64)]
    pub max_paths: usize,
    /// Write the canonical graph JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_attack_graph(args: AttackGraphArgs) -> i32 {
    match run_attack_graph_inner(args) {
        Ok(()) => SUCCESS,
        Err(GraphError::SafetyRefusal(message)) => {
            eprintln!("{message}");
            UNSUPPORTED_TARGET
        }
        Err(GraphError::Invalid(message)) => {
            eprintln!("{message}");
            PARTIAL
        }
        Err(GraphError::Json(error)) => {
            eprintln!("{error}");
            PARTIAL
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_attack_graph_inner(args: AttackGraphArgs) -> dare_attack_graph::Result<()> {
    validate_output_dir(&args.output_dir).map_err(GraphError::Invalid)?;
    let facts = load_facts_file(&args.facts)?;
    let mut graph = build_attack_graph(&facts)?;
    graph.paths = derive_paths(
        &graph,
        &PathOptions {
            max_depth: args.max_depth,
            max_paths: args.max_paths,
            source_filter: None,
            target_filter: None,
        },
    )?;
    graph.id = format!("graph:{}", graph_digest(&graph)?);
    validate_graph(&graph)?;
    fs::create_dir_all(&args.output_dir)?;
    fs::write(
        args.output_dir.join("attack-graph.json"),
        serde_json::to_vec_pretty(&graph)?,
    )?;
    fs::write(
        args.output_dir.join("paths.json"),
        serde_json::to_vec_pretty(&graph.paths)?,
    )?;
    fs::write(args.output_dir.join("graph.mmd"), to_mermaid(&graph)?)?;
    fs::write(args.output_dir.join("graph.dot"), to_dot(&graph)?)?;
    let summary = format!(
        "# DARE Agent Attack Graph\n\nTarget: {}\nNodes: {}\nEdges: {}\nPaths: {}\n\nAnalysis only; no exploit path was executed.\n",
        graph.target_id,
        graph.nodes.len(),
        graph.edges.len(),
        graph.paths.len()
    );
    assert_summary_secret_safe(&summary).map_err(GraphError::Invalid)?;
    fs::write(args.output_dir.join("summary.md"), summary)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&graph)?);
    }
    Ok(())
}
