//! `dare-agent-security validate coverage` — profile/coverage gate, not a second engine.

use std::fs;
use std::path::PathBuf;

use clap::Args;
use dare_coverage::{
    derive_risk_family_coverage, registry_for_profile, resolve_profile, run_assessment,
    AssessmentFacts, CoveragePolicy, PropertyExecution,
};
use dare_mcp_discovery::sanitize_stream;

use crate::ci_output::{assert_summary_secret_safe, validate_output_dir};
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Args)]
pub struct CoverageArgs {
    /// Built-in profile id (`mcp-security-baseline` or `agentic-security-baseline-2026`) or a profile JSON path.
    #[arg(long, value_name = "ID-OR-PATH")]
    pub profile: String,

    /// Typed assessment facts JSON (not an expression language).
    #[arg(long, value_name = "PATH")]
    pub facts: PathBuf,

    /// Optional property execution JSON array (verdict + Cycle 001 evidence ids).
    #[arg(long, value_name = "PATH")]
    pub executions: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub output_dir: Option<PathBuf>,

    /// Fail when required coverage is below this ratio (0.0–1.0).
    #[arg(long, default_value_t = 0.0)]
    pub min_required_coverage: f64,

    #[arg(long, default_value_t = false)]
    pub fail_on_required_blocked: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run_coverage(args: CoverageArgs) -> i32 {
    match run_coverage_inner(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{}", sanitize_stream(&message));
            if message.contains("usage") || message.contains("unknown") {
                UNSUPPORTED_TARGET
            } else {
                SCANNER_ERROR
            }
        }
    }
}

fn run_coverage_inner(args: CoverageArgs) -> Result<i32, String> {
    if !(0.0..=1.0).contains(&args.min_required_coverage) {
        return Err("usage: min-required-coverage must be between 0 and 1".to_owned());
    }
    let profile = resolve_profile(&args.profile).map_err(|e| e.to_string())?;
    let registry = registry_for_profile(&profile).map_err(|e| e.to_string())?;
    let facts_raw = fs::read_to_string(&args.facts).map_err(|e| e.to_string())?;
    let facts: AssessmentFacts =
        serde_json::from_str(facts_raw.strip_prefix('\u{feff}').unwrap_or(&facts_raw))
            .map_err(|e| format!("facts parse: {e}"))?;
    let executions = match args.executions {
        Some(path) => {
            let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            serde_json::from_str(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
                .map_err(|e| format!("executions parse: {e}"))?
        }
        None => Vec::<PropertyExecution>::new(),
    };
    let policy = CoveragePolicy {
        min_required_coverage: args.min_required_coverage,
        fail_on_required_blocked: args.fail_on_required_blocked,
    };
    let report = run_assessment(&profile, &registry, &facts, &executions, policy)
        .map_err(|e| e.to_string())?;

    if args.json {
        let body = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        println!("{body}");
    }

    if let Some(output_dir) = args.output_dir.as_ref() {
        validate_output_dir(output_dir)?;
        fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
        let report_path = output_dir.join("coverage-report.json");
        let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
        fs::write(&report_path, bytes).map_err(|e| e.to_string())?;

        if profile.id == "agentic-security-baseline-2026"
            || profile
                .properties
                .iter()
                .any(|entry| entry.id.starts_with("AGENT."))
        {
            let family_view = derive_risk_family_coverage(&report, &registry);
            let family_bytes =
                serde_json::to_vec_pretty(&family_view).map_err(|e| e.to_string())?;
            fs::write(output_dir.join("risk-family-coverage.json"), family_bytes)
                .map_err(|e| e.to_string())?;
        }

        let appendix = report.summary_markdown();
        assert_summary_secret_safe(&appendix)?;
        let summary_path = output_dir.join("summary.md");
        if summary_path.is_file() {
            let mut existing = fs::read_to_string(&summary_path).map_err(|e| e.to_string())?;
            existing.push_str(&appendix);
            fs::write(&summary_path, existing).map_err(|e| e.to_string())?;
        } else {
            fs::write(&summary_path, format!("# DARE Agent Security\n{appendix}"))
                .map_err(|e| e.to_string())?;
        }
    }

    if report.gate.ok {
        Ok(SUCCESS)
    } else {
        if !args.json {
            for reason in &report.gate.reasons {
                eprintln!("{}", sanitize_stream(reason));
            }
        }
        Ok(PARTIAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn coverage_cli_writes_report_and_passes_default_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let facts = dir.path().join("facts.json");
        fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/coverage/fixture-a-tools-static-roe.json"),
            &facts,
        )
        .unwrap();
        let out = dir.path().join("out");
        let code = run_coverage(CoverageArgs {
            profile: "mcp-security-baseline".to_owned(),
            facts,
            executions: None,
            output_dir: Some(out.clone()),
            min_required_coverage: 0.0,
            fail_on_required_blocked: false,
            json: false,
        });
        assert_eq!(code, SUCCESS);
        assert!(out.join("coverage-report.json").is_file());
        assert!(!out.join("risk-family-coverage.json").exists());
        let summary = fs::read_to_string(out.join("summary.md")).unwrap();
        assert!(summary.contains("mcp-security-baseline"));
        assert!(!summary.contains("Bearer "));
    }

    #[test]
    fn agentic_coverage_cli_selects_builtin_registry_and_writes_family_view() {
        let dir = tempfile::tempdir().unwrap();
        let facts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/coverage/agentic-all-capabilities.json");
        let out = dir.path().join("out");
        let code = run_coverage(CoverageArgs {
            profile: "agentic-security-baseline-2026".to_owned(),
            facts,
            executions: None,
            output_dir: Some(out.clone()),
            min_required_coverage: 0.0,
            fail_on_required_blocked: false,
            json: false,
        });
        assert_eq!(code, SUCCESS);
        assert!(out.join("coverage-report.json").is_file());
        assert!(out.join("risk-family-coverage.json").is_file());
        let family = fs::read_to_string(out.join("risk-family-coverage.json")).unwrap();
        assert!(family.contains("AGENT_GOAL_HIJACKING"));
        assert!(family.contains("UNASSESSED"));
        assert!(!family.contains("\"assessment_state\": \"SECURE\""));
    }

    #[test]
    fn unknown_builtin_profile_preserves_unsupported_exit_semantics() {
        let code = run_coverage(CoverageArgs {
            profile: "not-a-real-profile".to_owned(),
            facts: PathBuf::from("unused.json"),
            executions: None,
            output_dir: None,
            min_required_coverage: 0.0,
            fail_on_required_blocked: false,
            json: false,
        });
        assert_eq!(code, UNSUPPORTED_TARGET);
    }

    #[test]
    fn coverage_cli_fails_closed_on_high_required_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let facts = dir.path().join("facts.json");
        let mut f = fs::File::create(&facts).unwrap();
        f.write_all(
            fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/coverage/fixture-c-dynamic-blocked.json"),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        let code = run_coverage(CoverageArgs {
            profile: "mcp-security-baseline".to_owned(),
            facts,
            executions: None,
            output_dir: None,
            min_required_coverage: 1.0,
            fail_on_required_blocked: true,
            json: false,
        });
        assert_eq!(code, PARTIAL);
    }
}
