//! `dare-agent-security assess`

use std::path::PathBuf;

use clap::Args;
use dare_mcp_discovery::sanitize_stream;
use dare_product::{run_assessment, AssessOptions, GateResult};

use crate::exit_code::{PARTIAL, SUCCESS};
use crate::product::map_product_error;

#[derive(Debug, Args)]
pub struct AssessCliArgs {
    /// Path to project or demo fixture root.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,

    /// Explicit product config path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Enable confidential classification and fail-closed privacy.
    #[arg(long)]
    pub confidential: bool,

    /// Deny network/telemetry egress (fail-closed).
    #[arg(long)]
    pub offline: bool,

    /// Optional stable run id (safe path segment).
    #[arg(long, value_name = "ID")]
    pub run: Option<String>,

    /// Emit summary JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_assess(args: AssessCliArgs) -> i32 {
    match run_assessment(&AssessOptions {
        target: args.path,
        config_path: args.config,
        confidential: args.confidential,
        offline: args.offline,
        run_id: args.run,
    }) {
        Ok(outcome) => {
            if args.json {
                match serde_json::to_string_pretty(&outcome.view_model.summary) {
                    Ok(body) => println!("{body}"),
                    Err(err) => {
                        eprintln!("{}", sanitize_stream(&err.to_string()));
                        return crate::exit_code::SCANNER_ERROR;
                    }
                }
            } else {
                println!(
                    "Assessment complete: run={} gate={:?} duration_ms={}",
                    outcome.run_id, outcome.gate, outcome.duration_ms
                );
                println!("Artifacts: {}", outcome.run_dir.display());
                println!(
                    "Reports: {}/reports/executive.html",
                    outcome.run_dir.display()
                );
            }
            match outcome.gate {
                GateResult::Pass => SUCCESS,
                GateResult::Fail
                | GateResult::Partial
                | GateResult::Blocked
                | GateResult::Inconclusive => PARTIAL,
            }
        }
        Err(err) => {
            eprintln!("{}", sanitize_stream(&err.actionable_message()));
            map_product_error(&err)
        }
    }
}
