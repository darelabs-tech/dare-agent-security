use std::{fs, path::PathBuf};

use clap::{Args, ValueEnum};
use dare_adversarial::{
    load_bundle, roe::load_roe, AdversarialError, ControlledRunner, ResultStatus, ValidationMode,
    Verdict,
};

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdversarialModeArg {
    PlanOnly,
    Simulated,
    LocalSynthetic,
    AuthorizedDynamic,
}

impl From<AdversarialModeArg> for ValidationMode {
    fn from(value: AdversarialModeArg) -> Self {
        match value {
            AdversarialModeArg::PlanOnly => Self::PlanOnly,
            AdversarialModeArg::Simulated => Self::Simulated,
            AdversarialModeArg::LocalSynthetic => Self::LocalSynthetic,
            AdversarialModeArg::AuthorizedDynamic => Self::AuthorizedDynamic,
        }
    }
}

#[derive(Debug, Args)]
pub struct AdversarialArgs {
    /// Approved JSON bundle. In MVP, --plan accepts the same self-contained bundle format.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "fixture",
        required_unless_present = "fixture"
    )]
    pub plan: Option<PathBuf>,
    /// Controlled local fixture bundle.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "plan",
        required_unless_present = "plan"
    )]
    pub fixture: Option<PathBuf>,
    /// Execution mode. Defaults to validation-only with zero operations.
    #[arg(long, value_enum, default_value = "plan-only")]
    pub mode: AdversarialModeArg,
    /// Rules of Engagement document; mandatory for authorized-dynamic.
    #[arg(
        long,
        value_name = "PATH",
        required_if_eq("mode", "authorized-dynamic")
    )]
    pub roe: Option<PathBuf>,
    /// Directory for validation-result.json and evidence.json.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Write validation-result JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_adversarial(args: AdversarialArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(AdversarialError::SafetyRefusal(message)) => {
            eprintln!("{message}");
            UNSUPPORTED_TARGET
        }
        Err(AdversarialError::Invalid(message) | AdversarialError::Schema(message)) => {
            eprintln!("{message}");
            PARTIAL
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: AdversarialArgs) -> dare_adversarial::Result<i32> {
    let input = args
        .fixture
        .or(args.plan)
        .ok_or_else(|| AdversarialError::Invalid("plan or fixture is required".to_owned()))?;
    let mut bundle = load_bundle(&input)?;
    if let Some(path) = args.roe {
        bundle.roe = Some(load_roe(&path)?);
    }
    let result = ControlledRunner::new(args.mode.into()).run(&bundle)?;
    validate_output_dir(&args.output_dir).map_err(AdversarialError::Invalid)?;
    fs::create_dir_all(&args.output_dir)?;
    fs::write(
        args.output_dir.join("validation-result.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    fs::write(
        args.output_dir.join("evidence.json"),
        serde_json::to_vec_pretty(&result.evidence)?,
    )?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    let code = match (result.status, result.verdict) {
        (ResultStatus::Planned, _) | (ResultStatus::Completed, Some(Verdict::Pass)) => SUCCESS,
        _ => PARTIAL,
    };
    Ok(code)
}
