//! `dare-agent-security ci` — CI adapter helpers (no domain security logic).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use dare_mcp_discovery::sanitize_stream;

use crate::ci_output::CiAutomation;
use crate::ci_result::ActionMode;
use crate::exit_code::SCANNER_ERROR;

/// CI automation helpers for GitHub Actions and fixture harnesses.
#[derive(Debug, Subcommand)]
pub enum CiSubcommand {
    /// Write aggregate ci-result.json from the current evidence directory (or empty for INCONCLUSIVE).
    WriteResult(WriteResultArgs),
}

/// Arguments for `ci write-result`.
#[derive(Debug, Args)]
pub struct WriteResultArgs {
    #[arg(long, value_enum)]
    pub mode: ActionModeArg,

    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,

    #[arg(long, default_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub fail_on_inconclusive: bool,

    /// Safe target label included in the job summary (never raw credentials).
    #[arg(long, value_name = "LABEL")]
    pub target_label: Option<String>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ActionModeArg {
    Discover,
    Validate,
}

impl From<ActionModeArg> for ActionMode {
    fn from(value: ActionModeArg) -> Self {
        match value {
            ActionModeArg::Discover => ActionMode::Discover,
            ActionModeArg::Validate => ActionMode::Validate,
        }
    }
}

pub fn run_ci(sub: CiSubcommand) -> i32 {
    match sub {
        CiSubcommand::WriteResult(args) => run_write_result(args),
    }
}

fn run_write_result(args: WriteResultArgs) -> i32 {
    let mode = ActionMode::from(args.mode);
    let Some(automation) = CiAutomation::from_flags(
        Some(args.output_dir.clone()),
        Some(args.output_dir.join("evidence")),
        args.fail_on_inconclusive,
    ) else {
        diagnostic("output-dir is required");
        return SCANNER_ERROR;
    };

    if let Err(message) = automation.prepare() {
        diagnostic(&message);
        return SCANNER_ERROR;
    }

    match automation.write_ci_result_with_summary(
        mode,
        crate::exit_code::SUCCESS,
        args.target_label.as_deref(),
    ) {
        Ok(exit) => exit,
        Err(message) => {
            diagnostic(&message);
            SCANNER_ERROR
        }
    }
}

fn diagnostic(message: &str) {
    let text = sanitize_stream(message);
    eprintln!("{text}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn write_result_emits_inconclusive_without_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = WriteResultArgs {
            mode: ActionModeArg::Validate,
            output_dir: dir.path().to_path_buf(),
            fail_on_inconclusive: true,
            target_label: Some("fixture-inconclusive".to_owned()),
        };
        let exit = run_write_result(args);
        assert_eq!(exit, 2);
        assert!(dir.path().join("ci-result.json").is_file());
        assert!(dir.path().join("github-output.env").is_file());
        let summary = fs::read_to_string(dir.path().join("summary.md")).unwrap();
        assert!(summary.contains("INCONCLUSIVE"));
        assert!(!summary.contains("Bearer "));
    }
}
