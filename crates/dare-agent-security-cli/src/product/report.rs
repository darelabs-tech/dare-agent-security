//! `dare-agent-security report`

use std::fs;
use std::path::PathBuf;

use clap::Args;
use dare_mcp_discovery::sanitize_stream;
use dare_product::{
    latest_run_id, render_executive_html, render_technical_html, resolve_run_dir, Finding,
    ProductSummary, ProductViewModel, RunArtifactPaths,
};

use crate::exit_code::SUCCESS;
use crate::product::map_product_error;

#[derive(Debug, Args)]
pub struct ReportCliArgs {
    /// Project root containing `.dare-security/runs`.
    #[arg(long = "path", value_name = "PATH", default_value = ".")]
    pub path: PathBuf,

    /// Specific run id (default: latest).
    #[arg(long, value_name = "ID")]
    pub run: Option<String>,

    /// Re-render HTML from stored JSON.
    #[arg(long)]
    pub refresh: bool,

    /// Print paths only.
    #[arg(long)]
    pub json: bool,
}

pub fn run_report(args: ReportCliArgs) -> i32 {
    match run_report_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", sanitize_stream(&err.actionable_message()));
            map_product_error(&err)
        }
    }
}

fn run_report_inner(args: ReportCliArgs) -> Result<i32, dare_product::ProductError> {
    let run_dir = resolve_run_dir(&args.path, args.run.as_deref())?;
    let run_id = run_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_owned();
    let paths = RunArtifactPaths::for_run(&args.path, &run_id)?;

    if args.refresh {
        let summary: ProductSummary = read_json(&paths.summary)?;
        let findings: Vec<Finding> = read_json(&paths.findings)?;
        let coverage = read_json_value(&paths.coverage)?;
        let attack_graph = read_json_value(&paths.attack_graph)?;
        let validation = read_json_value(&paths.validation)?;
        let drift = read_json_value(&paths.drift)?;
        let vm = ProductViewModel {
            summary,
            findings,
            coverage,
            attack_graph,
            validation,
            drift,
        };
        let executive = render_executive_html(&vm)?;
        let technical = render_technical_html(&vm)?;
        fs::create_dir_all(paths.run_dir.join("reports"))?;
        fs::write(&paths.executive_html, executive)?;
        fs::write(&paths.technical_html, technical)?;
    }

    if args.json {
        let payload = serde_json::json!({
            "run_id": run_id,
            "summary": paths.summary,
            "findings": paths.findings,
            "executive_html": paths.executive_html,
            "technical_html": paths.technical_html,
            "latest": latest_run_id(&args.path)?,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Run: {run_id}");
        println!("Summary: {}", paths.summary.display());
        println!("Findings: {}", paths.findings.display());
        println!("Executive: {}", paths.executive_html.display());
        println!("Technical: {}", paths.technical_html.display());
    }
    Ok(SUCCESS)
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &PathBuf,
) -> Result<T, dare_product::ProductError> {
    let raw = fs::read_to_string(path).map_err(|e| {
        dare_product::ProductError::environment(format!("read {}: {e}", path.display()))
    })?;
    Ok(serde_json::from_str(
        raw.strip_prefix('\u{feff}').unwrap_or(&raw),
    )?)
}

fn read_json_value(path: &PathBuf) -> Result<serde_json::Value, dare_product::ProductError> {
    if !path.is_file() {
        return Ok(serde_json::json!({}));
    }
    read_json(path)
}
