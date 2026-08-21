//! `dare-agent-security doctor`

use std::path::PathBuf;

use clap::Args;
use dare_mcp_discovery::sanitize_stream;
use dare_product::run_doctor;

use crate::exit_code::{PARTIAL, SUCCESS};
use crate::product::map_product_error;

#[derive(Debug, Args)]
pub struct DoctorCliArgs {
    /// Project root to diagnose (default: current directory).
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

pub fn run_doctor_cmd(args: DoctorCliArgs) -> i32 {
    match run_doctor(&args.path) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(body) => println!("{body}"),
                    Err(err) => {
                        eprintln!("{}", sanitize_stream(&err.to_string()));
                        return crate::exit_code::SCANNER_ERROR;
                    }
                }
            } else {
                for check in &report.checks {
                    println!("[{:?}] {}: {}", check.status, check.id, check.message);
                }
                if report.ok {
                    println!("doctor: OK");
                } else {
                    println!("doctor: FAILED — fix failing checks above");
                }
            }
            if report.ok {
                SUCCESS
            } else {
                PARTIAL
            }
        }
        Err(err) => {
            eprintln!("{}", sanitize_stream(&err.actionable_message()));
            map_product_error(&err)
        }
    }
}
