//! GitHub Action outputs for the Cycle 023–025 engines (no domain security logic).
//!
//! `validate attack-paths`, `validate blast-radius` and `validate runtime-telemetry`
//! write their own artifacts and summary but no `github-output.env`. This module
//! restates an engine's exit code and result document as the three Action outputs
//! (`verdict`, `evidence-path`, `summary-path`). It re-judges nothing: it reads
//! the verdict the engine already wrote, and a run whose exit code and document
//! disagree is reported as ERROR.

use std::fs;
use std::path::Path;

use clap::ValueEnum;
use dare_security_evidence::Verdict;
use serde_json::Value;

use crate::ci_output::{assert_summary_secret_safe, validate_output_dir};
use crate::ci_result::{GITHUB_OUTPUT_FILENAME, SUMMARY_FILENAME};
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Engines whose run the Action can restate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Engine {
    RuntimeTelemetry,
    AttackPaths,
    BlastRadius,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeTelemetry => "runtime-telemetry",
            Self::AttackPaths => "attack-paths",
            Self::BlastRadius => "blast-radius",
        }
    }

    /// The document the verdict is read from, which is also the evidence output.
    pub fn result_file(self) -> &'static str {
        match self {
            Self::RuntimeTelemetry => "runtime-telemetry-result.json",
            Self::AttackPaths => "attack-paths.json",
            Self::BlastRadius => "blast-radius.json",
        }
    }

    /// The file named by the `evidence-path` output.
    pub fn evidence_file(self) -> &'static str {
        match self {
            Self::RuntimeTelemetry => "runtime-telemetry-evidence.json",
            Self::AttackPaths => "attack-paths.json",
            Self::BlastRadius => "blast-radius.json",
        }
    }
}

/// The Action's view of one engine run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOutcome {
    pub verdict: Verdict,
    /// Why the verdict is ERROR, when it is; a fixed token, never engine text.
    pub error: Option<&'static str>,
}

impl EngineOutcome {
    fn verdict(verdict: Verdict) -> Self {
        Self {
            verdict,
            error: None,
        }
    }

    fn error(reason: &'static str) -> Self {
        Self {
            verdict: Verdict::Error,
            error: Some(reason),
        }
    }
}

/// Restate an engine's exit code and result document as one verdict.
///
/// Exit 0 must come with a PASS document, exit 2 with a FAIL or INCONCLUSIVE
/// one; exit 1 and 3 are ERROR (the engine wrote nothing on a refusal). Any
/// other pairing is ERROR: the Action never guesses.
pub fn engine_outcome(engine: Engine, engine_exit: i32, output_dir: &Path) -> EngineOutcome {
    match engine_exit {
        SCANNER_ERROR => return EngineOutcome::error("engine_internal_error"),
        UNSUPPORTED_TARGET => return EngineOutcome::error("engine_refused_input"),
        SUCCESS | PARTIAL => {}
        _ => return EngineOutcome::error("unknown_engine_exit"),
    }
    let Some(document) = read_document(&output_dir.join(engine.result_file())) else {
        return EngineOutcome::error("result_document_unreadable");
    };
    let Some(verdict) = document_verdict(engine, &document) else {
        return EngineOutcome::error("result_document_unrecognised");
    };
    match (engine_exit, verdict) {
        (SUCCESS, Verdict::Pass) => EngineOutcome::verdict(Verdict::Pass),
        (PARTIAL, Verdict::Fail | Verdict::Inconclusive) => EngineOutcome::verdict(verdict),
        _ => EngineOutcome::error("exit_code_contradicts_result"),
    }
}

fn read_document(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The verdict a result document states, in the engine's own vocabulary.
fn document_verdict(engine: Engine, document: &Value) -> Option<Verdict> {
    match engine {
        Engine::RuntimeTelemetry => match document.get("verdict")?.as_str()? {
            "PASS" => Some(Verdict::Pass),
            "FAIL" => Some(Verdict::Fail),
            "INCONCLUSIVE" => Some(Verdict::Inconclusive),
            _ => None,
        },
        Engine::AttackPaths => {
            let paths = document.get("paths")?.as_array()?;
            let truncated = document.get("enumeration")?.get("truncated")?.as_bool()?;
            let mut undecided = false;
            for path in paths {
                if path.get("feasibility")?.as_str()? != "FEASIBLE" {
                    continue;
                }
                match path.get("control_state")?.as_str()? {
                    "CONTROL_FAILED" => return Some(Verdict::Fail),
                    "CONTROL_UNDECIDED" => undecided = true,
                    "CONTROLS_HELD" => {}
                    _ => return None,
                }
            }
            Some(if undecided || truncated {
                Verdict::Inconclusive
            } else {
                Verdict::Pass
            })
        }
        Engine::BlastRadius => {
            let exposed = document.get("totals")?.get("exposed")?.as_u64()?;
            let truncated = document.get("truncated")?.as_bool()?;
            Some(if exposed > 0 {
                Verdict::Fail
            } else if truncated {
                Verdict::Inconclusive
            } else {
                Verdict::Pass
            })
        }
    }
}

/// The process exit the Action step ends with.
pub fn action_exit(outcome: &EngineOutcome, engine_exit: i32, fail_on_inconclusive: bool) -> i32 {
    match outcome.verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Fail => PARTIAL,
        Verdict::Inconclusive if fail_on_inconclusive => PARTIAL,
        Verdict::Inconclusive => SUCCESS,
        Verdict::Error if engine_exit == UNSUPPORTED_TARGET => UNSUPPORTED_TARGET,
        Verdict::Error => SCANNER_ERROR,
    }
}

/// Write `github-output.env` (and, on ERROR, a summary) for one engine run.
/// Returns the exit code the Action step should end with.
pub fn write_engine_outputs(
    engine: Engine,
    engine_exit: i32,
    output_dir: &Path,
    fail_on_inconclusive: bool,
) -> Result<i32, String> {
    validate_output_dir(output_dir)?;
    fs::create_dir_all(output_dir).map_err(|_| "output directory unavailable".to_owned())?;
    let outcome = engine_outcome(engine, engine_exit, output_dir);
    let dir = output_dir.to_string_lossy();
    let summary_path = format!("{dir}/{SUMMARY_FILENAME}");
    let evidence_path = match outcome.verdict {
        Verdict::Error => format!("{dir}/.none"),
        _ => format!("{dir}/{}", engine.evidence_file()),
    };
    let summary_file = output_dir.join(SUMMARY_FILENAME);
    let engine_summary = match outcome.error {
        None => fs::read_to_string(&summary_file).ok(),
        // A refusal writes nothing, and a stale summary from an earlier run
        // must not stand in for this one.
        Some(_) => None,
    };
    let summary_safe = engine_summary
        .as_deref()
        .is_some_and(|text| assert_summary_secret_safe(text).is_ok());
    if !summary_safe {
        let summary = error_summary(engine, &outcome);
        assert_summary_secret_safe(&summary)?;
        fs::write(&summary_file, summary.as_bytes())
            .map_err(|_| "summary write failed".to_owned())?;
    }
    let body = format!(
        "verdict={}\nevidence-path={evidence_path}\nsummary-path={summary_path}\n",
        outcome.verdict.as_str()
    );
    assert_summary_secret_safe(&body)?;
    fs::write(output_dir.join(GITHUB_OUTPUT_FILENAME), body.as_bytes())
        .map_err(|_| "github output write failed".to_owned())?;
    Ok(action_exit(&outcome, engine_exit, fail_on_inconclusive))
}

fn error_summary(engine: Engine, outcome: &EngineOutcome) -> String {
    format!(
        "# DARE Agent Security\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Version | {} |\n\
         | Mode | {} |\n\
         | Verdict | {} |\n\
         | Reason | {} |\n\n\
         The engine's own diagnostic is in the step log; no artifact is claimed.\n",
        env!("CARGO_PKG_VERSION"),
        engine.as_str(),
        outcome.verdict.as_str(),
        outcome.error.unwrap_or("engine_summary_withheld"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(engine: Engine, exit: i32, document: Option<Value>) -> (EngineOutcome, String, i32) {
        let dir = tempfile::tempdir().expect("tempdir");
        if let Some(document) = document {
            fs::write(dir.path().join(engine.result_file()), document.to_string()).unwrap();
            fs::write(dir.path().join(SUMMARY_FILENAME), "# engine summary\n").unwrap();
        }
        let outcome = engine_outcome(engine, exit, dir.path());
        let code = write_engine_outputs(engine, exit, dir.path(), true).unwrap();
        let env = fs::read_to_string(dir.path().join(GITHUB_OUTPUT_FILENAME)).unwrap();
        (outcome, env, code)
    }

    fn path(state: &str) -> Value {
        json!({"feasibility": "FEASIBLE", "control_state": state})
    }

    fn paths(states: &[&str], truncated: bool) -> Value {
        json!({
            "paths": states.iter().map(|s| path(s)).collect::<Vec<_>>(),
            "enumeration": {"truncated": truncated},
        })
    }

    #[test]
    fn runtime_telemetry_restates_the_document_verdict() {
        for (exit, verdict, expected) in [
            (0, "PASS", Verdict::Pass),
            (2, "FAIL", Verdict::Fail),
            (2, "INCONCLUSIVE", Verdict::Inconclusive),
        ] {
            let (outcome, env, _) = run(
                Engine::RuntimeTelemetry,
                exit,
                Some(json!({"verdict": verdict})),
            );
            assert_eq!(outcome.verdict, expected);
            assert!(env.contains(&format!("verdict={}", expected.as_str())));
            assert!(env.contains("runtime-telemetry-evidence.json"));
        }
    }

    #[test]
    fn attack_paths_fail_on_a_failed_control_and_are_inconclusive_when_undecided() {
        let cases = [
            (0, paths(&["CONTROLS_HELD"], false), Verdict::Pass),
            (0, paths(&[], false), Verdict::Pass),
            (
                2,
                paths(&["CONTROL_UNDECIDED", "CONTROL_FAILED"], false),
                Verdict::Fail,
            ),
            (
                2,
                paths(&["CONTROL_UNDECIDED"], false),
                Verdict::Inconclusive,
            ),
            (2, paths(&["CONTROLS_HELD"], true), Verdict::Inconclusive),
        ];
        for (exit, document, expected) in cases {
            let (outcome, _, _) = run(Engine::AttackPaths, exit, Some(document));
            assert_eq!(outcome.verdict, expected);
        }
    }

    #[test]
    fn blast_radius_fails_on_exposure_and_is_inconclusive_when_truncated() {
        let doc = |exposed: u64, truncated: bool| json!({"totals": {"exposed": exposed}, "truncated": truncated});
        assert_eq!(
            run(Engine::BlastRadius, 0, Some(doc(0, false))).0.verdict,
            Verdict::Pass
        );
        assert_eq!(
            run(Engine::BlastRadius, 2, Some(doc(1, false))).0.verdict,
            Verdict::Fail
        );
        assert_eq!(
            run(Engine::BlastRadius, 2, Some(doc(0, true))).0.verdict,
            Verdict::Inconclusive
        );
    }

    #[test]
    fn refusals_and_contradictions_are_errors_with_no_evidence() {
        let (outcome, env, code) = run(Engine::RuntimeTelemetry, 3, None);
        assert_eq!(outcome.error, Some("engine_refused_input"));
        assert!(env.contains("verdict=ERROR") && env.contains("/.none"));
        assert_eq!(code, UNSUPPORTED_TARGET);

        // Exit 0 with a failing document, exit 2 with a passing one.
        let (outcome, _, code) = run(
            Engine::RuntimeTelemetry,
            0,
            Some(json!({"verdict": "FAIL"})),
        );
        assert_eq!(outcome.error, Some("exit_code_contradicts_result"));
        assert_eq!(code, SCANNER_ERROR);
        let (outcome, _, _) = run(
            Engine::BlastRadius,
            2,
            Some(json!({"totals": {"exposed": 0}, "truncated": false})),
        );
        assert_eq!(outcome.verdict, Verdict::Error);

        // Missing or foreign documents, and unknown exits.
        assert_eq!(run(Engine::AttackPaths, 0, None).0.verdict, Verdict::Error);
        assert_eq!(
            run(
                Engine::AttackPaths,
                2,
                Some(
                    json!({"paths": [path("SOMETHING_ELSE")], "enumeration": {"truncated": false}})
                )
            )
            .0
            .error,
            Some("result_document_unrecognised")
        );
        assert_eq!(
            run(
                Engine::RuntimeTelemetry,
                7,
                Some(json!({"verdict": "PASS"}))
            )
            .0
            .error,
            Some("unknown_engine_exit")
        );
    }

    #[test]
    fn inconclusive_follows_fail_on_inconclusive() {
        let outcome = EngineOutcome::verdict(Verdict::Inconclusive);
        assert_eq!(action_exit(&outcome, 2, true), PARTIAL);
        assert_eq!(action_exit(&outcome, 2, false), SUCCESS);
    }

    #[test]
    fn an_error_replaces_a_stale_summary_and_keeps_the_engine_one_otherwise() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(SUMMARY_FILENAME), "# stale PASS\n").unwrap();
        write_engine_outputs(Engine::BlastRadius, 3, dir.path(), true).unwrap();
        let summary = fs::read_to_string(dir.path().join(SUMMARY_FILENAME)).unwrap();
        assert!(!summary.contains("stale") && summary.contains("engine_refused_input"));

        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("runtime-telemetry-result.json"),
            r#"{"verdict":"PASS"}"#,
        )
        .unwrap();
        fs::write(dir.path().join(SUMMARY_FILENAME), "# engine summary\n").unwrap();
        write_engine_outputs(Engine::RuntimeTelemetry, 0, dir.path(), true).unwrap();
        let summary = fs::read_to_string(dir.path().join(SUMMARY_FILENAME)).unwrap();
        assert_eq!(summary, "# engine summary\n");
    }

    #[test]
    fn a_secret_like_engine_summary_is_withheld() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("runtime-telemetry-result.json"),
            r#"{"verdict":"PASS"}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join(SUMMARY_FILENAME),
            "Authorization: Bearer x\n",
        )
        .unwrap();
        write_engine_outputs(Engine::RuntimeTelemetry, 0, dir.path(), true).unwrap();
        let summary = fs::read_to_string(dir.path().join(SUMMARY_FILENAME)).unwrap();
        assert!(!summary.contains("Bearer") && summary.contains("engine_summary_withheld"));
    }

    #[test]
    fn parent_traversal_is_refused() {
        assert!(write_engine_outputs(Engine::AttackPaths, 0, Path::new("../x"), true).is_err());
    }
}
