//! `validate runtime-telemetry` (Cycle 025): offline security analysis of
//! OpenTelemetry trace exports against an optional runtime policy.
//!
//! Files in, files out. The command never listens, never connects to a
//! collector and never runs the system under test: there is deliberately no
//! endpoint, port, header, token or exec flag (`tests/runtime_telemetry_cli.rs`).
use std::{fs, path::PathBuf};

use clap::Args;
use dare_attack_graph::v2::sweep::is_sensitive;
use dare_runtime_telemetry::{
    limits::{Bounds, MAX_SPANS},
    policy::load_policy,
    render::{artifacts, RESULT_FILE},
    result::{analyze, read_trace_paths, Mode},
    semconv::Mapping,
    Refusal, TelemetryError,
};
use dare_security_evidence::Verdict;

use crate::{
    ci_output::validate_output_dir,
    exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET},
};

pub const RUNTIME_TELEMETRY_AFTER_HELP: &str = "\
Exit codes (`validate runtime-telemetry`):
  0  every judged property is PASS; the rest are NOT_APPLICABLE or NOT_TESTED
  1  internal error
  2  a property is FAIL or INCONCLUSIVE, or nothing could be judged
  3  refusal (admission, trace or policy schema, bound out of range, output
     directory, unsafe artifact); nothing is written

The traces are self-reported by the system under test and unsigned; no
authenticity is claimed. A property passes only on traces proven complete for
it, and an absent span is never evidence of an absent action. No attribute
value, prompt, completion or tool argument is written: only keys, ids, rule
codes and digests.";

#[derive(Debug, Args)]
pub struct RuntimeTelemetryArgs {
    /// An OTLP/JSON trace export (1 to 64; repeat the flag).
    #[arg(long = "traces", value_name = "FILE", required = true)]
    pub traces: Vec<PathBuf>,
    /// A runtime policy. Without one, only the telemetry rules are judged.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    pub output_dir: PathBuf,
    /// Lower the span bound (never raise it).
    #[arg(long, default_value_t = MAX_SPANS)]
    pub max_spans: u64,
    /// Also print the result document to stdout.
    #[arg(long)]
    pub json: bool,
}

pub fn run_runtime_telemetry(args: RuntimeTelemetryArgs) -> i32 {
    match run_inner(&args) {
        Ok(code) => code,
        Err(TelemetryError::Refused(refusal)) => {
            eprintln!("refused: {refusal}");
            UNSUPPORTED_TARGET
        }
        Err(TelemetryError::Internal(message)) => {
            eprintln!("internal error: {message}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: &RuntimeTelemetryArgs) -> Result<i32, TelemetryError> {
    validate_output_dir(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    let bounds = Bounds {
        max_spans: args.max_spans,
    };
    bounds.validate()?;
    let mapping = Mapping::embedded()?;
    let policy = match &args.policy {
        Some(path) => Some(load_policy(path, &mapping)?),
        None => None,
    };
    let files = read_trace_paths(&args.traces)?;
    let mut run = analyze(&files, policy.as_ref(), &mapping, bounds, Mode::Replay)?;
    let files = artifacts(&mut run, policy.as_ref())?;
    // Every artifact is swept before the first byte is written.
    for (file, bytes) in &files {
        if is_sensitive(bytes) {
            return Err(Refusal::UnsafeArtifact { file }.into());
        }
    }
    fs::create_dir_all(&args.output_dir).map_err(|_| Refusal::UnsafeOutputDir)?;
    for (file, bytes) in &files {
        fs::write(args.output_dir.join(file), bytes)
            .map_err(|_| TelemetryError::Internal("write"))?;
    }
    if args.json {
        if let Some((_, bytes)) = files.iter().find(|(f, _)| *f == RESULT_FILE) {
            print!("{}", String::from_utf8_lossy(bytes));
        }
    }
    let r = &run.result;
    let judged = r.properties.iter().filter(|p| p.verdict.is_some()).count();
    println!(
        "{} trace(s), {} span(s): {} ({}); {judged} of {} properties judged{}",
        r.traces.count,
        r.traces.spans,
        match r.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::Error => "ERROR",
        },
        r.reason,
        r.properties.len(),
        if r.stop_reason.is_some() {
            ", span bound reached"
        } else {
            ""
        }
    );
    Ok(if r.verdict == Verdict::Pass {
        SUCCESS
    } else {
        PARTIAL
    })
}
