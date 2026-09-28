//! `validate remote` and `validate replay-capture` (Cycle 022).
//!
//! The only subcommands that reach a network. There is no flag that names a
//! URL, header, token, proxy, certificate or model: the target, the
//! credential's variable, the methods and the limits all come from a
//! verified authorization, and the operator must retype the origin.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use dare_remote_validation::audit::AuditRecord;
use dare_remote_validation::authorization::Authorization;
use dare_remote_validation::capture::Capture;
use dare_remote_validation::engines::Sources;
use dare_remote_validation::gateway::TrustRoots;
use dare_remote_validation::limits::{Limits, MAX_CAPTURE_BYTES};
use dare_remote_validation::plan::RemotePlan;
use dare_remote_validation::runner::{replay_capture, run_remote_lowered, RemoteRun};
use dare_remote_validation::schema::DocumentKind;
use dare_remote_validation::source::{admit_file, read_bounded};
use dare_remote_validation::RemoteError;
use dare_security_evidence::Verdict;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// `dare-agent-security validate remote` options.
#[derive(Debug, Clone, Args)]
pub struct RemoteArgs {
    /// Owner-issued authorization (remote-validation authorization v1).
    #[arg(long, value_name = "FILE")]
    pub authorization: PathBuf,
    /// Plan bound to the authorization by digest.
    #[arg(long, value_name = "FILE")]
    pub plan: PathBuf,
    /// The plan's origin, retyped by the operator (`https://host[:port]`).
    #[arg(long = "confirm-origin", value_name = "ORIGIN")]
    pub confirm_origin: String,
    /// Directory holding the A2A policy files the plan names.
    #[arg(long = "policy-dir", value_name = "DIR")]
    pub policy_dir: Option<PathBuf>,
    /// Where the five artifacts are written.
    #[arg(long = "output-dir", value_name = "DIR")]
    pub output_dir: PathBuf,
    /// Lower the request ceiling (never raises it).
    #[arg(long = "max-requests", value_name = "N")]
    pub max_requests: Option<u32>,
    /// Lower the request rate (never raises it).
    #[arg(long = "max-rps", value_name = "N")]
    pub max_rps: Option<u32>,
    /// Lower the run duration in seconds (never raises it).
    #[arg(long = "max-duration", value_name = "SECONDS")]
    pub max_duration: Option<u64>,
    /// Lower the response size ceiling in bytes (never raises it).
    #[arg(long = "max-response-bytes", value_name = "BYTES")]
    pub max_response_bytes: Option<u64>,
    /// Print the result JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

/// `dare-agent-security validate replay-capture` options.
#[derive(Debug, Clone, Args)]
pub struct ReplayCaptureArgs {
    #[arg(long, value_name = "FILE")]
    pub capture: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub audit: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub authorization: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub plan: PathBuf,
    #[arg(long = "policy-dir", value_name = "DIR")]
    pub policy_dir: Option<PathBuf>,
    #[arg(long = "output-dir", value_name = "DIR")]
    pub output_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub const REMOTE_AFTER_HELP: &str = "\
Sends only the closed, read-only methods a verified authorization grants, to
its single origin, over HTTPS with certificate verification, no proxy and no
redirects, within its window and limits. Nothing leaves the machine when the
authorization, plan or confirmation is refused (exit 3). Verdicts are decided
offline from the capture; `validate replay-capture` reproduces them byte for
byte without a network.

A PASS is scoped to the listed scenarios, this origin and the observed window,
and relies on any target-reported fields the summary lists. It is not a claim
that the target is secure.";

fn is_refusal(error: &RemoteError) -> bool {
    matches!(
        error,
        RemoteError::Refused(_)
            | RemoteError::Schema { .. }
            | RemoteError::Authorization(_)
            | RemoteError::BoundRaised { .. }
            | RemoteError::BoundZero { .. }
            | RemoteError::ForbiddenCharacter { .. }
            | RemoteError::InvalidIdentifier { .. }
            | RemoteError::CaptureTampered(_)
    )
}

fn exit_for(error: &RemoteError) -> i32 {
    if is_refusal(error) {
        UNSUPPORTED_TARGET
    } else {
        SCANNER_ERROR
    }
}

fn exit_for_verdict(verdict: Verdict) -> i32 {
    match verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Error => SCANNER_ERROR,
        Verdict::Fail | Verdict::Inconclusive => PARTIAL,
    }
}

fn sources() -> Sources {
    Sources {
        root: PathBuf::from("."),
    }
}

fn write(dir: &Path, run: &RemoteRun, json: bool) -> Result<i32, RemoteError> {
    let artifacts = run.artifacts()?;
    fs::create_dir_all(dir)?;
    for artifact in &artifacts {
        fs::write(dir.join(artifact.name), &artifact.bytes)?;
    }
    if json {
        let result = artifacts
            .iter()
            .find(|a| a.name == dare_remote_validation::result::RESULT_FILE)
            .map(|a| a.bytes.clone())
            .unwrap_or_default();
        print!("{}", String::from_utf8_lossy(&result));
    } else {
        println!(
            "remote-result verdict {} ({} request(s), stop {})",
            verdict_word(run.result.verdict),
            run.result.requests,
            run.result.stop_reason.as_str()
        );
    }
    Ok(exit_for_verdict(run.result.verdict))
}

fn verdict_word(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::Error => "ERROR",
    }
}

fn check_output_dir(dir: &Path) -> Result<(), RemoteError> {
    validate_output_dir(dir).map_err(|_| {
        RemoteError::Refused(
            "the output directory is not a plain relative or absolute path without `..`",
        )
    })
}

pub fn run_remote_validation(args: RemoteArgs) -> i32 {
    match remote_inner(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("validate remote: {error}");
            exit_for(&error)
        }
    }
}

fn remote_inner(args: &RemoteArgs) -> Result<i32, RemoteError> {
    check_output_dir(&args.output_dir)?;
    let auth: Authorization = admit_file(&args.authorization, DocumentKind::Authorization)?;
    let plan: RemotePlan = admit_file(&args.plan, DocumentKind::Plan)?;
    let lower = Limits {
        max_requests: args.max_requests,
        max_rps: args.max_rps,
        max_duration_s: args.max_duration,
        max_request_bytes: None,
        max_response_bytes: args.max_response_bytes,
    };
    let handle = tokio::runtime::Handle::try_current()
        .map_err(|_| RemoteError::Refused("no async runtime"))?;
    let run = run_remote_lowered(
        &auth,
        &plan,
        &args.confirm_origin,
        args.policy_dir.as_deref(),
        OffsetDateTime::now_utc(),
        TrustRoots::BuiltIn,
        handle,
        &sources(),
        &args.output_dir,
        &lower,
    )?;
    write(&args.output_dir, &run, args.json)
}

pub fn run_replay_capture(args: ReplayCaptureArgs) -> i32 {
    match replay_inner(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("validate replay-capture: {error}");
            exit_for(&error)
        }
    }
}

fn replay_inner(args: &ReplayCaptureArgs) -> Result<i32, RemoteError> {
    check_output_dir(&args.output_dir)?;
    let auth: Authorization = admit_file(&args.authorization, DocumentKind::Authorization)?;
    let plan: RemotePlan = admit_file(&args.plan, DocumentKind::Plan)?;
    let capture = Capture::admit(&read_bounded(&args.capture, MAX_CAPTURE_BYTES)?)?;
    let audit = AuditRecord::admit(&read_bounded(&args.audit, MAX_CAPTURE_BYTES)?)?;
    let run = replay_capture(
        &auth,
        &plan,
        &capture,
        &audit,
        args.policy_dir.as_deref(),
        &sources(),
        &args.output_dir,
    )?;
    write(&args.output_dir, &run, args.json)
}
