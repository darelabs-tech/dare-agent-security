//! End-to-end tests for `dare-agent-security validate tool-security`.
//!
//! These invoke the built binary against the shipped scenario fixtures. Nothing
//! here reaches the network, starts a server, or performs a tool call; the
//! command has no code path that could.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    output_dir: PathBuf,
}

impl Run {
    fn result(&self) -> Value {
        let raw = std::fs::read(self.output_dir.join("tool-security-result.json"))
            .expect("result artifact written");
        serde_json::from_slice(&raw).expect("result is valid JSON")
    }

    fn summary(&self) -> String {
        std::fs::read_to_string(self.output_dir.join("summary.md")).expect("summary written")
    }
}

fn run(name: &str, args: &[&str]) -> Run {
    let output_dir = std::env::temp_dir()
        .join("dare-tool-security-cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&output_dir);

    let mut command = Command::new(binary());
    command
        .current_dir(repo_root())
        .args(["validate", "tool-security"])
        .args(args)
        .arg("--output-dir")
        .arg(&output_dir);

    let output = command.output().expect("the binary runs");
    Run {
        code: output.status.code().expect("an exit code"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        output_dir,
    }
}

#[test]
fn a_benign_scenario_passes_and_writes_the_four_artifacts() {
    let run = run("benign", &["--scenario", "TOOL-LAB-001"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    for artifact in [
        "tool-security-result.json",
        "tool-security-trials.json",
        "tool-security-evidence.json",
        "summary.md",
    ] {
        assert!(
            run.output_dir.join(artifact).is_file(),
            "{artifact} was not written"
        );
    }

    let result = run.result();
    assert_eq!(result["verdict"], "PASS");
    assert_eq!(result["scenario_id"], "TOOL-LAB-001");
    assert_eq!(result["mode"], "SIMULATED");
    assert_eq!(result["synthetic"], true);
}

#[test]
fn every_shipped_scenario_produces_the_outcome_its_design_calls_for() {
    // The whole TOOL-LAB matrix, exercised through the real binary.
    // TOOL-LAB-016 and 017 are excluded here: their point is that loading is
    // refused, and they are covered by their own test below.
    let expected: [(&str, &str, i32); 18] = [
        ("TOOL-LAB-001", "PASS", 0),
        ("TOOL-LAB-002", "FAIL", 2),
        ("TOOL-LAB-003", "PASS", 0),
        ("TOOL-LAB-004", "FAIL", 2),
        ("TOOL-LAB-005", "PASS", 0),
        ("TOOL-LAB-006", "FAIL", 2),
        ("TOOL-LAB-007", "PASS", 0),
        ("TOOL-LAB-008", "FAIL", 2),
        ("TOOL-LAB-009", "PASS", 0),
        ("TOOL-LAB-010", "FAIL", 2),
        ("TOOL-LAB-011", "PASS", 0),
        ("TOOL-LAB-012", "FAIL", 2),
        ("TOOL-LAB-013", "FAIL", 2),
        ("TOOL-LAB-014", "FAIL", 2),
        ("TOOL-LAB-015", "INCONCLUSIVE", 2),
        ("TOOL-LAB-018", "PASS", 0),
        ("TOOL-LAB-019", "FAIL", 2),
        ("TOOL-LAB-020", "FAIL", 2),
    ];

    for (scenario, verdict, code) in expected {
        let run = run(scenario, &["--scenario", scenario]);
        assert_eq!(run.code, code, "{scenario} stderr: {}", run.stderr);
        assert_eq!(
            run.result()["verdict"],
            verdict,
            "{scenario} produced the wrong verdict"
        );
    }
}

#[test]
fn a_poisoned_or_substituted_corpus_is_refused_before_anything_runs() {
    // TOOL-LAB-017: a vector carrying an executable field.
    let executable = run(
        "executable-field",
        &[
            "--scenario",
            "TOOL-LAB-017",
            "--corpus",
            "fixtures/tool-security/lab-corpora/executable-field-corpus",
        ],
    );
    assert_eq!(executable.code, 3, "a refusal must exit 3");
    assert!(
        executable
            .stderr
            .contains("forbidden executable/credential field"),
        "stderr: {}",
        executable.stderr
    );
    assert!(
        !executable.output_dir.exists(),
        "a refused run must write no artifact"
    );

    // TOOL-LAB-016: an intact vector under a substituted digest.
    let substituted = run(
        "substituted-digest",
        &[
            "--scenario",
            "TOOL-LAB-016",
            "--corpus",
            "fixtures/tool-security/lab-corpora/malformed-corpus",
        ],
    );
    assert_eq!(substituted.code, 3);
    assert!(
        substituted.stderr.contains("digest"),
        "stderr: {}",
        substituted.stderr
    );
    assert!(!substituted.output_dir.exists());
}

#[test]
fn replay_mode_evaluates_a_local_trace_offline() {
    let compliant = run(
        "replay-compliant",
        &[
            "--scenario",
            "TOOL-LAB-005",
            "--mode",
            "replay",
            "--trace",
            "fixtures/tool-security/traces/TOOL-LAB-005.json",
        ],
    );
    assert_eq!(compliant.code, 0, "stderr: {}", compliant.stderr);
    let result = compliant.result();
    assert_eq!(result["verdict"], "PASS");
    assert_eq!(result["mode"], "REPLAY");
    assert_eq!(
        result["synthetic"], false,
        "a recorded trace is not synthetic"
    );

    let violating = run(
        "replay-violating",
        &[
            "--scenario",
            "TOOL-LAB-006",
            "--mode",
            "replay",
            "--trace",
            "fixtures/tool-security/traces/TOOL-LAB-006.json",
        ],
    );
    assert_eq!(violating.code, 2);
    assert_eq!(violating.result()["verdict"], "FAIL");
}

#[test]
fn a_trace_recorded_for_a_different_scenario_is_refused() {
    let run = run(
        "replay-mismatched",
        &[
            "--scenario",
            "TOOL-LAB-005",
            "--mode",
            "replay",
            "--trace",
            "fixtures/tool-security/traces/TOOL-LAB-006.json",
        ],
    );
    assert_eq!(run.code, 3);
    assert!(
        run.stderr.contains("recorded for scenario"),
        "stderr: {}",
        run.stderr
    );
}

#[test]
fn local_synthetic_mode_runs_under_the_cycle_009_controls() {
    let run = run(
        "local-synthetic",
        &["--scenario", "TOOL-LAB-001", "--mode", "local-synthetic"],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let result = run.result();
    assert_eq!(result["mode"], "LOCAL_SYNTHETIC");
    assert_eq!(result["budget"]["state_changes"], 0);
    assert_eq!(result["budget"]["external_egress_bytes"], 0);
}

#[test]
fn the_trial_flag_is_bounded_by_the_approved_maximum() {
    let ok = run(
        "trials-ten",
        &["--scenario", "TOOL-LAB-001", "--trials", "10"],
    );
    assert_eq!(ok.code, 0, "stderr: {}", ok.stderr);
    assert_eq!(ok.result()["trials_planned"], 10);

    // Above the hard maximum, clap refuses before the engine is reached.
    let refused = run(
        "trials-eleven",
        &["--scenario", "TOOL-LAB-001", "--trials", "11"],
    );
    assert_ne!(refused.code, 0);
    assert!(!refused.output_dir.exists());
}

#[test]
fn the_summary_separates_poisoning_from_misuse_and_names_untested_surfaces() {
    let poisoning = run("summary-poisoning", &["--scenario", "TOOL-LAB-001"]);
    let summary = poisoning.summary();
    // Exact table rows, not substring hunting: a row must say what it says.
    assert!(summary.contains("| TOOL_POISONING | TESTED |"));
    assert!(summary.contains("| TOOL_MISUSE | NOT TESTED |"));
    assert!(summary.contains("| Poisoning: description | TESTED |"));
    assert!(summary.contains("| Poisoning: output | NOT TESTED |"));
    assert!(summary.contains("| Misuse: selection | NOT APPLICABLE |"));

    let misuse = run("summary-misuse", &["--scenario", "TOOL-LAB-008"]);
    let summary = misuse.summary();
    assert!(summary.contains("| TOOL_POISONING | NOT TESTED |"));
    assert!(summary.contains("| TOOL_MISUSE | TESTED |"));
    assert!(summary.contains("| Misuse: selection | TESTED |"));
    assert!(summary.contains("| Poisoning: description | NOT APPLICABLE |"));
}

#[test]
fn the_summary_reports_the_counts_the_approval_requires() {
    let run = run("summary-counts", &["--scenario", "TOOL-LAB-014"]);
    let summary = run.summary();
    for row in [
        "| Scenarios | 1 |",
        "| Trials planned |",
        "| Trials executed |",
        "| Tool requests observed |",
        "| Maximum chain depth observed |",
        "| Violations observed |",
        "| Inconclusive trials |",
        "| State changes | 0 |",
        "| External egress bytes | 0 |",
    ] {
        assert!(summary.contains(row), "summary is missing `{row}`");
    }
}

#[test]
fn no_summary_ever_renders_an_unbounded_security_claim() {
    // Exact token matching over the whole rendered document, applied to every
    // shipped scenario — the Cycle 013 lesson about loose substring assertions
    // cuts both ways, so the banned phrases are checked as written.
    for entry in std::fs::read_dir(repo_root().join("fixtures/tool-security/scenarios"))
        .expect("scenario directory")
    {
        let path = entry.expect("entry").path();
        let scenario = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("scenario id");
        if matches!(scenario, "TOOL-LAB-016" | "TOOL-LAB-017") {
            continue; // These refuse before a summary exists.
        }

        let run = run(&format!("claim-{scenario}"), &["--scenario", scenario]);
        let lowered = run.summary().to_lowercase();
        for banned in [
            "tool secure",
            "tools are secure",
            "safe tools",
            "immune",
            "fully protected",
            "guaranteed secure",
            "cannot be poisoned",
            "cannot be misused",
        ] {
            assert!(
                !lowered.contains(banned),
                "{scenario} rendered the banned claim `{banned}`"
            );
        }
        assert!(
            lowered.contains("no result here should be read as a claim of universal tool security"),
            "{scenario} is missing the scope note"
        );
    }
}

#[test]
fn the_preferred_bounded_wording_is_used_verbatim_on_a_pass() {
    let run = run("bounded-wording", &["--scenario", "TOOL-LAB-001"]);
    assert!(
        run.summary().contains(
            "No tool-security invariant violation was observed for the tested vectors under the \
             recorded conditions"
        ),
        "the approved wording must appear verbatim"
    );
}

#[test]
fn no_artifact_or_stream_carries_a_canary_or_credential() {
    // TOOL-LAB-018 is the redaction-hygiene vector: its payload contains a
    // synthetic canary, so this is the run most likely to leak one.
    let run = run("redaction", &["--scenario", "TOOL-LAB-018", "--json"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let mut inspected = 0;
    for entry in std::fs::read_dir(&run.output_dir).expect("artifacts") {
        let path = entry.expect("entry").path();
        let text = std::fs::read_to_string(&path).expect("readable");
        assert_leak_free(&text, &path.display().to_string());
        inspected += 1;
    }
    assert_eq!(inspected, 4, "every artifact must be inspected");

    assert_leak_free(&run.stdout, "stdout");
    assert_leak_free(&run.stderr, "stderr");
    assert!(run.stdout.contains("[REDACTED]"), "the canary was masked");
}

fn assert_leak_free(text: &str, where_found: &str) {
    for marker in [
        "DARE-SYNTHETIC-CANARY-TOOL01",
        "sk-live-",
        "-----BEGIN",
        "ghp_",
        "xoxb-",
    ] {
        assert!(!text.contains(marker), "{where_found} leaked `{marker}`");
    }
}

#[test]
fn no_artifact_ever_records_a_dispatched_tool_request() {
    // The dangerous-operation vector: it must fail deterministically while the
    // delete it describes never happens.
    let run = run("no-dispatch", &["--scenario", "TOOL-LAB-010"]);
    assert_eq!(run.code, 2);
    let result = run.result();
    assert_eq!(result["verdict"], "FAIL");

    let mut requests = 0;
    for trial in result["trials"].as_array().expect("trials") {
        for event in trial["events"].as_array().expect("events") {
            if event["type"] == "TOOL_REQUESTED" {
                requests += 1;
                assert_eq!(
                    event["dispatched"], false,
                    "a request was recorded as dispatched"
                );
            }
        }
    }
    assert!(requests > 0, "the vector must actually request something");
}

#[test]
fn a_scenario_id_cannot_become_a_path_expression() {
    for spec in ["../../etc/passwd", "..", "TOOL/LAB", "tool-lab-001"] {
        let run = run("traversal", &["--scenario", spec]);
        assert_ne!(run.code, 0, "`{spec}` must not be accepted");
        assert!(!run.output_dir.exists());
    }
}

#[test]
fn the_help_text_advertises_no_remote_or_credential_capability() {
    let output = Command::new(binary())
        .current_dir(repo_root())
        .args(["validate", "tool-security", "--help"])
        .output()
        .expect("help runs");
    let help = String::from_utf8_lossy(&output.stdout);

    for flag in [
        "--url",
        "--endpoint",
        "--api-key",
        "--token",
        "--provider",
        "--remote",
        "--command",
        "--mcp-server",
    ] {
        assert!(!help.contains(flag), "help advertises `{flag}`");
    }
    assert!(help.contains("--scenario"));
    assert!(help.contains("--mode"));
    assert!(help.contains("--trace"));
    assert!(help.contains("--corpus"));
    assert!(help.contains("--trials"));
    assert!(help.contains("--output-dir"));
    assert!(help.contains("observed, never dispatched"));
}

#[test]
fn results_are_byte_identical_across_repeated_runs() {
    let first = run("determinism-a", &["--scenario", "TOOL-LAB-012"]);
    let second = run("determinism-b", &["--scenario", "TOOL-LAB-012"]);
    assert_eq!(first.code, second.code);

    // The result and trial artifacts are pure functions of the inputs. Evidence
    // carries timestamps, so it is compared with those removed.
    for artifact in ["tool-security-result.json", "tool-security-trials.json"] {
        assert_eq!(
            read(&first.output_dir, artifact),
            read(&second.output_dir, artifact),
            "{artifact} differed between runs"
        );
    }
    assert_eq!(first.summary(), second.summary());
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).expect("artifact readable")
}
