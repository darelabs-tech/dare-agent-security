//! `validate coaz-integrity` command implementation.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use dare_coaz_integrity::{
    emit_integrity_evidence, execute_vector, load_builtin_vector, validate_result, EmitOptions,
    IntegrityVerdict, ReferencePepMode, RunOptions, VectorDefinition, VectorResult,
    BUILTIN_VECTOR_IDS,
};
use dare_mcp_discovery::sanitize_stream;

use crate::args::{CoazIntegrityArgs, ReferenceModeArg};
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Run `validate coaz-integrity` and write stdout/stderr. Returns a documented exit code.
pub fn run_coaz_integrity(args: CoazIntegrityArgs) -> i32 {
    match validate_coaz_integrity(args) {
        Ok(outcome) => {
            if let Err(err) = write_stdout(&outcome.stdout) {
                diagnostic(&err);
                return SCANNER_ERROR;
            }
            outcome.exit
        }
        Err(err) => {
            diagnostic(&err.message);
            err.code
        }
    }
}

struct CoazIntegritySuccess {
    stdout: String,
    exit: i32,
}

struct CoazIntegrityFailure {
    code: i32,
    message: String,
}

fn validate_coaz_integrity(
    args: CoazIntegrityArgs,
) -> Result<CoazIntegritySuccess, CoazIntegrityFailure> {
    let vector_ids = resolve_vector_ids(&args)?;
    let mut results = Vec::with_capacity(vector_ids.len());

    for vector_id in vector_ids {
        let vector = load_builtin_vector(&vector_id).map_err(|err| CoazIntegrityFailure {
            code: UNSUPPORTED_TARGET,
            message: sanitize_stream(&format!("unknown or invalid fixture `{vector_id}`: {err}")),
        })?;
        let options = build_run_options(&args, &vector)?;
        let result = execute_vector(&vector, &options).map_err(map_run_error)?;
        validate_result(&result).map_err(|err| CoazIntegrityFailure {
            code: SCANNER_ERROR,
            message: sanitize_stream(&format!(
                "result validation failed for `{vector_id}`: {err}"
            )),
        })?;
        write_artifacts(args.evidence_dir.as_deref(), &result)?;
        results.push(result);
    }

    let stdout = render_stdout(&args, &results)?;
    Ok(CoazIntegritySuccess {
        stdout,
        exit: aggregate_exit(&results),
    })
}

fn resolve_vector_ids(args: &CoazIntegrityArgs) -> Result<Vec<String>, CoazIntegrityFailure> {
    match (&args.all, &args.fixture) {
        (true, Some(_fixture)) => Err(usage(
            "`--all` and `--fixture` are mutually exclusive; choose one",
        )),
        (false, None) => Err(usage(
            "a fixture selector is required: `--all` or `--fixture <COAZ-INTEGRITY-NNN>`",
        )),
        (true, None) => Ok(BUILTIN_VECTOR_IDS
            .iter()
            .map(|id| (*id).to_owned())
            .collect()),
        (false, Some(fixture)) => {
            let fixture = fixture.trim();
            if fixture.is_empty() {
                return Err(usage("fixture id must not be empty"));
            }
            if !BUILTIN_VECTOR_IDS.contains(&fixture) {
                return Err(usage(&format!(
                    "unknown built-in fixture `{fixture}`; supported ids: {}",
                    BUILTIN_VECTOR_IDS.join(", ")
                )));
            }
            Ok(vec![fixture.to_owned()])
        }
    }
}

fn build_run_options(
    args: &CoazIntegrityArgs,
    vector: &VectorDefinition,
) -> Result<RunOptions, CoazIntegrityFailure> {
    let mut options = RunOptions::from_vector(vector);
    if let Some(mode) = args.reference_mode {
        if mode == ReferenceModeArg::Vulnerable && !vector.safety.synthetic_only {
            return Err(CoazIntegrityFailure {
                code: UNSUPPORTED_TARGET,
                message: sanitize_stream(
                    "vulnerable reference mode requires built-in synthetic-only fixtures",
                ),
            });
        }
        options = options.with_reference_mode(match mode {
            ReferenceModeArg::Secure => ReferencePepMode::SecureReevaluate,
            ReferenceModeArg::Vulnerable => ReferencePepMode::VulnerableReuse,
        });
    }
    Ok(options)
}

fn render_stdout(
    args: &CoazIntegrityArgs,
    results: &[VectorResult],
) -> Result<String, CoazIntegrityFailure> {
    if args.json {
        if results.len() == 1 {
            serde_json::to_string_pretty(&results[0]).map_err(|_| CoazIntegrityFailure {
                code: SCANNER_ERROR,
                message: "failed to serialize result json".to_owned(),
            })
        } else {
            serde_json::to_string_pretty(results).map_err(|_| CoazIntegrityFailure {
                code: SCANNER_ERROR,
                message: "failed to serialize results json".to_owned(),
            })
        }
    } else {
        Ok(human_summary(results))
    }
}

fn human_summary(results: &[VectorResult]) -> String {
    let mut out = String::from("DARE Agent Security — COAZ Authorization Integrity\n\n");
    for result in results {
        let verdict = verdict_label(result.verdict);
        let _ = writeln!(out, "{:<24}{verdict}", result.vector_id);
    }
    out
}

fn verdict_label(verdict: IntegrityVerdict) -> &'static str {
    match verdict {
        IntegrityVerdict::Pass => "PASS",
        IntegrityVerdict::Fail => "FAIL",
        IntegrityVerdict::Inconclusive => "INCONCLUSIVE",
        IntegrityVerdict::Error => "ERROR",
    }
}

fn aggregate_exit(results: &[VectorResult]) -> i32 {
    let mut exit = SUCCESS;
    for result in results {
        exit = merge_exit(exit, verdict_exit(result.verdict));
    }
    exit
}

fn merge_exit(current: i32, next: i32) -> i32 {
    match (current, next) {
        (SCANNER_ERROR, _) | (_, SCANNER_ERROR) => SCANNER_ERROR,
        (UNSUPPORTED_TARGET, _) | (_, UNSUPPORTED_TARGET) => UNSUPPORTED_TARGET,
        (PARTIAL, _) | (_, PARTIAL) => PARTIAL,
        _ => SUCCESS,
    }
}

fn verdict_exit(verdict: IntegrityVerdict) -> i32 {
    match verdict {
        IntegrityVerdict::Pass => SUCCESS,
        IntegrityVerdict::Fail | IntegrityVerdict::Inconclusive => PARTIAL,
        IntegrityVerdict::Error => SCANNER_ERROR,
    }
}

fn write_artifacts(dir: Option<&Path>, result: &VectorResult) -> Result<(), CoazIntegrityFailure> {
    let Some(dir) = dir else {
        return Ok(());
    };
    if let Err(err) = fs::create_dir_all(dir) {
        diagnostic(&format!(
            "evidence directory unavailable ({})",
            sanitize_stream(&err.to_string())
        ));
        return Ok(());
    }

    let result_path = dir.join(format!("{}.result.json", result.vector_id));
    let result_artifact = format!("{}.result.json", result.vector_id);
    match serde_json::to_vec_pretty(result) {
        Ok(bytes) => {
            if let Err(err) = fs::write(&result_path, bytes) {
                diagnostic(&format!(
                    "result write failed ({})",
                    sanitize_stream(&err.to_string())
                ));
            }
        }
        Err(_) => diagnostic("result serialization failed"),
    }

    let options =
        EmitOptions::deterministic_for_result(result).with_result_artifact_path(result_artifact);
    match emit_integrity_evidence(result, &options) {
        Ok(evidence) => {
            let evidence_path = dir.join(format!("{}.evidence.json", result.vector_id));
            match serde_json::to_vec_pretty(&evidence) {
                Ok(bytes) => {
                    if let Err(err) = fs::write(&evidence_path, bytes) {
                        diagnostic(&format!(
                            "evidence write failed ({})",
                            sanitize_stream(&err.to_string())
                        ));
                    }
                }
                Err(_) => diagnostic("evidence serialization failed"),
            }
        }
        Err(err) => diagnostic(&format!(
            "evidence emission failed ({})",
            sanitize_stream(&err.to_string())
        )),
    }
    Ok(())
}

fn map_run_error(err: dare_coaz_integrity::RunError) -> CoazIntegrityFailure {
    CoazIntegrityFailure {
        code: SCANNER_ERROR,
        message: sanitize_stream(&format!("vector execution failed: {err}")),
    }
}

fn usage(message: &str) -> CoazIntegrityFailure {
    CoazIntegrityFailure {
        code: UNSUPPORTED_TARGET,
        message: sanitize_stream(message),
    }
}

fn diagnostic(message: &str) {
    let text = sanitize_stream(message);
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{text}");
}

fn write_stdout(text: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|_| {
            if text.ends_with('\n') {
                Ok(())
            } else {
                stdout.write_all(b"\n")
            }
        })
        .and_then(|_| stdout.flush())
        .map_err(|err| sanitize_stream(&err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{CoazIntegrityArgs, ReferenceModeArg};

    #[test]
    fn aggregate_exit_prefers_harness_error() {
        assert_eq!(
            aggregate_exit(&[
                sample_result(IntegrityVerdict::Pass),
                sample_result(IntegrityVerdict::Error),
            ]),
            SCANNER_ERROR
        );
    }

    #[test]
    fn aggregate_exit_marks_fail_as_partial() {
        assert_eq!(
            aggregate_exit(&[
                sample_result(IntegrityVerdict::Pass),
                sample_result(IntegrityVerdict::Fail),
            ]),
            PARTIAL
        );
    }

    #[test]
    fn vulnerable_mode_refuses_non_synthetic_fixture() {
        let mut vector = dare_coaz_integrity::sample_vector_definition();
        vector.safety.synthetic_only = false;
        let args = CoazIntegrityArgs {
            all: false,
            fixture: Some(vector.vector_id.clone()),
            json: false,
            reference_mode: Some(ReferenceModeArg::Vulnerable),
            evidence_dir: None,
        };
        let err = build_run_options(&args, &vector).expect_err("must refuse non-synthetic");
        assert_eq!(err.code, UNSUPPORTED_TARGET);
        assert!(err.message.contains("synthetic-only"));
    }

    fn sample_result(verdict: IntegrityVerdict) -> VectorResult {
        let mut result = dare_coaz_integrity::sample_vector_result_pass();
        result.verdict = verdict;
        result
    }
}
