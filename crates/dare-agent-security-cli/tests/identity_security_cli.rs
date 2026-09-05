//! End-to-end tests for `dare-agent-security validate identity-security`.
//!
//! These invoke the built binary against the shipped IDENTITY-LAB fixtures.
//! Nothing here reaches the network, contacts an identity provider or
//! authorization server, parses a token, or performs an operation; the command
//! has no code path that could.

use std::path::PathBuf;
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
        let raw = std::fs::read(self.output_dir.join("identity-security-result.json"))
            .expect("result artifact written");
        serde_json::from_slice(&raw).expect("result is valid JSON")
    }

    fn evidence(&self) -> Value {
        let raw = std::fs::read(self.output_dir.join("identity-security-evidence.json"))
            .expect("evidence artifact written");
        serde_json::from_slice(&raw).expect("evidence is valid JSON")
    }

    fn trials(&self) -> Value {
        let raw = std::fs::read(self.output_dir.join("identity-security-trials.json"))
            .expect("trials artifact written");
        serde_json::from_slice(&raw).expect("trials is valid JSON")
    }

    fn summary(&self) -> String {
        std::fs::read_to_string(self.output_dir.join("summary.md")).expect("summary written")
    }
}

fn run(name: &str, args: &[&str]) -> Run {
    let output_dir = std::env::temp_dir()
        .join("dare-identity-security-cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&output_dir);

    let mut command = Command::new(binary());
    command
        .current_dir(repo_root())
        .args(["validate", "identity-security"])
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
fn a_compliant_lab_exits_zero_and_writes_every_artifact() {
    let run = run("lab-001", &["--scenario", "IDENTITY-LAB-001"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["scenario_id"], "IDENTITY-LAB-001");
    assert_eq!(result["verdict"], "PASS");
    assert_eq!(result["mode"], "SIMULATED");
    assert_eq!(result["synthetic"], true);
    assert_eq!(result["redaction_state"], "REDACTED");

    assert!(!run.trials().as_array().expect("array").is_empty());
    assert!(!run.evidence().as_array().expect("array").is_empty());
    assert!(run
        .summary()
        .contains("# DARE Identity, Privilege and Delegation Validation"));
}

#[test]
fn an_observed_violation_exits_two_and_names_the_invariant() {
    let run = run("lab-002", &["--scenario", "IDENTITY-LAB-002"]);
    assert_eq!(run.code, 2, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["verdict"], "FAIL");
    assert_eq!(
        result["invariant"],
        "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER"
    );
    let violations = result["trials"][0]["violations"]
        .as_array()
        .expect("violations array");
    assert!(!violations.is_empty());
}

#[test]
fn a_run_with_no_relevant_observation_is_inconclusive_and_never_passes() {
    let run = run("lab-016", &["--scenario", "IDENTITY-LAB-016"]);
    assert_eq!(run.code, 2, "stderr: {}", run.stderr);
    assert_eq!(run.result()["verdict"], "INCONCLUSIVE");
}

#[test]
fn a_scenario_the_engine_refuses_exits_three_without_writing_a_verdict() {
    // LAB-018 names a principal the scenario never declares.
    let run = run("lab-018", &["--scenario", "IDENTITY-LAB-018"]);
    assert_eq!(run.code, 3, "stderr: {}", run.stderr);
    assert!(!run
        .output_dir
        .join("identity-security-result.json")
        .exists());
    for banned in ["PASS", "FAIL", "INCONCLUSIVE"] {
        assert!(
            !run.stderr.contains(banned),
            "`{banned}` in `{}`",
            run.stderr
        );
    }
}

#[test]
fn the_local_synthetic_mode_runs_under_the_cycle_009_controls() {
    let run = run(
        "lab-001-local",
        &[
            "--scenario",
            "IDENTITY-LAB-001",
            "--mode",
            "local-synthetic",
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let result = run.result();
    assert_eq!(result["mode"], "LOCAL_SYNTHETIC");
    assert_eq!(result["budget"]["state_changes"], 0);
    assert_eq!(result["budget"]["external_egress_bytes"], 0);
}

#[test]
fn json_output_goes_to_stdout_and_diagnostics_do_not() {
    let run = run(
        "lab-001-json",
        &["--scenario", "IDENTITY-LAB-001", "--json"],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let parsed: Value = serde_json::from_str(&run.stdout).expect("stdout is the result JSON");
    assert_eq!(parsed["scenario_id"], "IDENTITY-LAB-001");
}

#[test]
fn every_artifact_is_deterministic_across_runs() {
    let first = run("determinism-a", &["--scenario", "IDENTITY-LAB-003"]);
    let second = run("determinism-b", &["--scenario", "IDENTITY-LAB-003"]);
    assert_eq!(first.code, second.code);
    assert_eq!(first.result(), second.result());
    assert_eq!(first.trials(), second.trials());
    assert_eq!(first.summary(), second.summary());

    // Evidence carries a timestamp, so identity is checked on the stable parts.
    let strip = |value: &Value| -> Vec<Value> {
        value
            .as_array()
            .expect("array")
            .iter()
            .map(|record| {
                let mut record = record.clone();
                record.as_object_mut().expect("object").remove("timestamps");
                record
            })
            .collect()
    };
    assert_eq!(strip(&first.evidence()), strip(&second.evidence()));
}

#[test]
fn no_artifact_carries_a_credential_a_canary_or_a_provider() {
    for lab in ["IDENTITY-LAB-001", "IDENTITY-LAB-006", "IDENTITY-LAB-019"] {
        let run = run(&format!("hygiene-{lab}"), &["--scenario", lab]);
        assert!(run.code == 0 || run.code == 2, "stderr: {}", run.stderr);

        for artifact in [
            "identity-security-result.json",
            "identity-security-trials.json",
            "identity-security-evidence.json",
            "summary.md",
        ] {
            let text = std::fs::read_to_string(run.output_dir.join(artifact))
                .unwrap_or_else(|err| panic!("{lab}/{artifact}: {err}"))
                .to_lowercase();
            for marker in [
                "dare-synthetic-canary-",
                "sk-live-",
                "-----begin",
                "ghp_",
                "xoxb-",
                "eyjhbgci",
                "idp.example",
                "pdp.example",
            ] {
                assert!(!text.contains(marker), "{lab}/{artifact} contains {marker}");
            }
        }
    }
}

#[test]
fn the_summary_reports_each_surface_separately_and_never_overclaims() {
    let run = run("surfaces", &["--scenario", "IDENTITY-LAB-007"]);
    let summary = run.summary();

    // The tested surface is named, and the other four are reported as untested
    // rather than quietly counted as holding.
    assert!(summary.contains("| TENANT_RESOURCE | TESTED |"));
    assert!(summary.contains("| PRINCIPAL_BINDING | NOT TESTED |"));
    assert!(summary.contains("| DELEGATION | NOT TESTED |"));
    assert!(summary.contains("| PRIVILEGE | NOT TESTED |"));
    assert!(summary.contains("| AUTHORIZATION_BINDING | NOT TESTED |"));

    assert!(summary.contains(
        "No identity-security invariant violation was observed for the tested vectors under the \
         recorded conditions"
    ));
    assert!(summary.contains("| State changes | 0 |"));
    assert!(summary.contains("| External egress bytes | 0 |"));
    assert!(summary.contains("effective authority must stay within the delegated or source"));
    assert!(summary.contains("capability availability, not delegated authority"));

    let lowered = summary.to_lowercase();
    for banned in [
        "identity secure",
        "authorization secure",
        "no privilege escalation possible",
        "fully protected",
        "immune",
        "authzen compliant",
        "coaz compliant",
    ] {
        assert!(!lowered.contains(banned), "`{banned}` in the summary");
    }
}

#[test]
fn a_forbidden_flag_is_rejected_by_the_parser() {
    for flag in [
        "--url",
        "--endpoint",
        "--issuer",
        "--jwks",
        "--token",
        "--bearer",
        "--client-secret",
        "--api-key",
        "--pdp-url",
        "--authzen-url",
        "--remote",
        "--command",
    ] {
        let output = Command::new(binary())
            .current_dir(repo_root())
            .args([
                "validate",
                "identity-security",
                "--scenario",
                "IDENTITY-LAB-001",
            ])
            .arg(flag)
            .arg("value")
            .arg("--output-dir")
            .arg(std::env::temp_dir().join("dare-identity-security-cli/forbidden"))
            .output()
            .expect("the binary runs");
        assert!(
            !output.status.success(),
            "{flag} was accepted; it must not exist"
        );
    }
}

#[test]
fn the_help_text_states_the_boundary() {
    let output = Command::new(binary())
        .current_dir(repo_root())
        .args(["validate", "identity-security", "--help"])
        .output()
        .expect("the binary runs");
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(help.contains("local and offline"));
    assert!(help.contains("observed, never dispatched"));
    assert!(help.contains("no identity provider"));
    assert!(help.contains("Tokens are never parsed or validated"));
}
