use std::{fs, path::PathBuf};

use clap::{Args, ValueEnum};
use dare_continuous::{
    analyze, detect_changes, load_fixture, ContinuousError, ContinuousValidationPolicy,
    GateDecision, RunMode, SecurityStateSnapshot,
};

use crate::{
    ci_output::validate_output_dir,
    exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ContinuousModeArg {
    PlanOnly,
    Revalidate,
}

impl From<ContinuousModeArg> for RunMode {
    fn from(value: ContinuousModeArg) -> Self {
        match value {
            ContinuousModeArg::PlanOnly => Self::PlanOnly,
            ContinuousModeArg::Revalidate => Self::Revalidate,
        }
    }
}

#[derive(Debug, Args)]
pub struct ContinuousArgs {
    /// Explicit trusted baseline snapshot.
    #[arg(
        long,
        value_name = "PATH",
        requires = "candidate",
        conflicts_with = "fixture"
    )]
    pub baseline: Option<PathBuf>,
    /// Candidate snapshot to compare with the explicit baseline.
    #[arg(
        long,
        value_name = "PATH",
        requires = "baseline",
        conflicts_with = "fixture"
    )]
    pub candidate: Option<PathBuf>,
    /// Self-contained local baseline/candidate fixture bundle.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "candidate"])]
    pub fixture: Option<PathBuf>,
    /// Versioned continuous-validation policy; built-in fail-safe policy by default.
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,
    /// Output directory for changeset, plan and report artifacts.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Plan only, or mark selected offline validations as revalidated.
    #[arg(long, value_enum, default_value = "plan-only")]
    pub mode: ContinuousModeArg,
    /// Write the continuous report JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_continuous(args: ContinuousArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(ContinuousError::SafetyRefusal(message)) => {
            eprintln!("{message}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: ContinuousArgs) -> dare_continuous::Result<i32> {
    validate_output_dir(&args.output_dir).map_err(ContinuousError::Invalid)?;
    let (baseline, candidate, fixture_policy) = if let Some(path) = args.fixture {
        let bundle = load_fixture(&path)?;
        (
            bundle.baseline_snapshot,
            bundle.candidate_snapshot,
            bundle.policy,
        )
    } else {
        let baseline_path = args.baseline.ok_or_else(|| {
            ContinuousError::SafetyRefusal(
                "an explicit --baseline with --candidate, or --fixture, is required".to_owned(),
            )
        })?;
        let candidate_path = args.candidate.ok_or_else(|| {
            ContinuousError::SafetyRefusal(
                "an explicit --candidate with --baseline, or --fixture, is required".to_owned(),
            )
        })?;
        (
            SecurityStateSnapshot::load(&baseline_path)?,
            SecurityStateSnapshot::load(&candidate_path)?,
            None,
        )
    };
    let policy = match args.policy {
        Some(path) => ContinuousValidationPolicy::load(&path)?,
        None => fixture_policy.unwrap_or_default(),
    };
    let changes = detect_changes(&baseline, &candidate);
    let report = analyze(&baseline, &candidate, &policy, args.mode.into())?;
    fs::create_dir_all(&args.output_dir)?;
    fs::write(
        args.output_dir.join("security-changeset.json"),
        serde_json::to_vec_pretty(&changes)?,
    )?;
    fs::write(
        args.output_dir.join("revalidation-plan.json"),
        serde_json::to_vec_pretty(&report.plan)?,
    )?;
    fs::write(
        args.output_dir.join("continuous-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(match report.gate.decision {
        GateDecision::Fail | GateDecision::Review => PARTIAL,
        GateDecision::Pass | GateDecision::Warn => SUCCESS,
    })
}
