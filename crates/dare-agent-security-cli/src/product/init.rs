//! `dare-agent-security init`

use std::path::PathBuf;

use clap::Args;
use dare_mcp_discovery::sanitize_stream;
use dare_product::{init_project, InitOptions};

use crate::exit_code::{SUCCESS, UNSUPPORTED_TARGET};
use crate::product::map_product_error;

#[derive(Debug, Args)]
pub struct InitCliArgs {
    /// Project root to initialize (default: current directory).
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,

    /// Overwrite an existing config.
    #[arg(long)]
    pub force: bool,

    /// Project name override.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Initialize with confidential/offline fail-closed defaults.
    #[arg(long)]
    pub confidential: bool,
}

pub fn run_init(args: InitCliArgs) -> i32 {
    match init_project(
        &args.path,
        &InitOptions {
            force: args.force,
            project_name: args.name,
            confidential: args.confidential,
        },
    ) {
        Ok(cfg) => {
            println!(
                "Initialized DARE Agent Security product config for `{}` (profile={}).",
                cfg.project.name, cfg.assessment.profile
            );
            println!("Next: dare-agent-security doctor");
            println!("Then: dare-agent-security assess {}", args.path.display());
            SUCCESS
        }
        Err(err) => {
            eprintln!("{}", sanitize_stream(&err.actionable_message()));
            map_product_error(&err)
        }
    }
}

#[allow(dead_code)]
fn _usage_hint() -> i32 {
    UNSUPPORTED_TARGET
}
