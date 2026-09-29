//! `validate blast-radius`: what a compromise reaches over an attack graph
//! (Cycle 024). Analysis only; it reads local files and never executes,
//! sends or schedules anything.
use std::{fs, path::PathBuf};

use clap::Args;
use dare_attack_graph::v2::sweep::is_sensitive;
use dare_blast_radius::{
    analyze,
    limits::{DEFAULT_DEPTH, MAX_STATES_PER_SEARCH},
    render::{to_dot, to_mermaid},
    summary::summary,
    validate::check_schema,
    BlastError, Options, Refusal, Seeding,
};

use crate::{
    ci_output::validate_output_dir,
    exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET},
};

pub const BLAST_RADIUS_AFTER_HELP: &str = "\
Exit codes (`validate blast-radius`):
  0  no target is EXPOSED and nothing was truncated
  1  internal error
  2  a target is EXPOSED, or a search was truncated
  3  refusal (invalid graph or scenario, unknown seed, bound out of range); nothing is written

CONTAINED means only that every route to the target within --max-depth crosses a
control observed to hold in the supplied runs; it does not mean safe. Unreached is
not unreachable: relationships no artifact or model line states are not in the graph.
No reach is executed, and the remediation delta is a count, not a ranking of risk.";

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("seeding")
        .required(true)
        .args(["compromise", "seed_entry_points"])
))]
pub struct BlastRadiusArgs {
    /// The v2 attack graph written by `validate attack-paths` (attack-graph.json).
    #[arg(long, value_name = "FILE")]
    pub graph: PathBuf,
    /// A compromise scenario naming the seeds.
    #[arg(long, value_name = "FILE")]
    pub compromise: Option<PathBuf>,
    /// Seed every entry point of the graph instead of a scenario.
    #[arg(long)]
    pub seed_entry_points: bool,
    /// Directory for the four output files.
    #[arg(long, value_name = "DIR")]
    pub output_dir: PathBuf,
    /// Longest walk, in edges (1 to 12); lowers the scenario's value.
    #[arg(long, default_value_t = DEFAULT_DEPTH)]
    pub max_depth: u32,
    /// Most states per search (1 to 1000000); lowers the scenario's value.
    #[arg(long, default_value_t = MAX_STATES_PER_SEARCH)]
    pub max_states: u64,
    /// Also print `blast-radius.json` to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_blast_radius(args: BlastRadiusArgs) -> i32 {
    match run_inner(&args) {
        Ok(code) => code,
        Err(BlastError::Refused(refusal)) => {
            eprintln!("refused: {refusal}");
            UNSUPPORTED_TARGET
        }
        Err(BlastError::Internal(message)) => {
            eprintln!("internal error: {message}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: &BlastRadiusArgs) -> Result<i32, BlastError> {
    validate_output_dir(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    let seeding = match &args.compromise {
        Some(path) => Seeding::Scenario(path),
        None => Seeding::EntryPoints,
    };
    let options = Options {
        max_depth: Some(args.max_depth),
        max_states: Some(args.max_states),
    };
    let analysis = analyze(&args.graph, seeding, &options)?;
    let doc = &analysis.doc;
    check_schema(doc)?;
    let mut document =
        serde_json::to_vec_pretty(doc).map_err(|_| BlastError::Internal("serialization"))?;
    document.push(b'\n');
    // Every file is rendered and checked before the first one is written.
    let files: [(&'static str, Vec<u8>); 4] = [
        ("blast-radius.json", document),
        ("summary.md", summary(&analysis.graph, doc)?.into_bytes()),
        ("graph.mmd", to_mermaid(&analysis.graph, doc)?.into_bytes()),
        ("graph.dot", to_dot(&analysis.graph, doc)?.into_bytes()),
    ];
    for (file, bytes) in &files {
        if is_sensitive(bytes) {
            return Err(Refusal::UnsafeArtifact { file }.into());
        }
    }
    fs::create_dir_all(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    for (file, bytes) in &files {
        fs::write(args.output_dir.join(file), bytes).map_err(|_| BlastError::Internal("write"))?;
    }
    if args.json {
        print!("{}", String::from_utf8_lossy(&files[0].1));
    }
    let t = &doc.totals;
    println!(
        "{} seeds: {} EXPOSED, {} CONTAINED, {} CONTAINMENT_UNKNOWN targets{}",
        doc.seeds.len(),
        t.exposed,
        t.contained,
        t.containment_unknown,
        if doc.truncated { ", truncated" } else { "" }
    );
    Ok(if t.exposed > 0 || doc.truncated {
        PARTIAL
    } else {
        SUCCESS
    })
}
