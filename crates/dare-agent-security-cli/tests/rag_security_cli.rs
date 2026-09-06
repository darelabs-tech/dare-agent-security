//! End-to-end tests for `dare-agent-security validate rag-security`.
//!
//! These invoke the built binary against the shipped RAG-LAB fixtures. Nothing
//! here reaches the network, connects to a vector database or search provider,
//! indexes a document or computes an embedding; the command has no code path
//! that could.

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
    fn artifact(&self, name: &str) -> Value {
        let raw = std::fs::read(self.output_dir.join(name))
            .unwrap_or_else(|err| panic!("{name} was not written: {err}"));
        serde_json::from_slice(&raw).expect("artifact is valid JSON")
    }

    fn result(&self) -> Value {
        self.artifact("rag-security-result.json")
    }

    fn evidence(&self) -> Value {
        self.artifact("rag-security-evidence.json")
    }

    fn trials(&self) -> Value {
        self.artifact("rag-security-trials.json")
    }

    fn summary(&self) -> String {
        std::fs::read_to_string(self.output_dir.join("summary.md")).expect("summary written")
    }

    fn wrote_a_result(&self) -> bool {
        self.output_dir.join("rag-security-result.json").exists()
    }
}

fn run(name: &str, args: &[&str]) -> Run {
    let output_dir = std::env::temp_dir()
        .join("dare-rag-security-cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&output_dir);

    let mut command = Command::new(binary());
    command
        .current_dir(repo_root())
        .args(["validate", "rag-security"])
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
    let run = run("lab-001", &["--scenario", "RAG-LAB-001"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["scenario_id"], "RAG-LAB-001");
    assert_eq!(result["verdict"], "PASS");
    assert_eq!(result["mode"], "SIMULATED");
    assert_eq!(result["synthetic"], true);
    assert_eq!(result["redaction_state"], "REDACTED");

    assert!(!run.trials().as_array().expect("array").is_empty());
    assert!(!run.evidence().as_array().expect("array").is_empty());
    assert!(run.summary().contains("RAG-LAB-001"));
}

#[test]
fn an_observed_violation_exits_two_and_names_the_invariant() {
    let run = run("lab-002", &["--scenario", "RAG-LAB-002"]);
    assert_eq!(run.code, 2, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["verdict"], "FAIL");
    assert_eq!(result["invariant"], "RETRIEVAL_TENANT_BOUNDARY_PRESERVED");

    // A finding must say what decided it, not merely that something failed.
    let trials = run.trials();
    let violations = trials.as_array().expect("array")[0]["violations"]
        .as_array()
        .expect("violations");
    assert!(!violations.is_empty());
    assert!(!violations[0]["deciding_event_digests"]
        .as_array()
        .expect("digests")
        .is_empty());
}

#[test]
fn a_high_scoring_protected_document_still_fails() {
    // The cycle's thesis at the command level: the disclosed document is ranked
    // first, and the run still exits non-zero.
    let run = run("lab-016", &["--scenario", "RAG-LAB-016"]);
    assert_eq!(run.code, 2, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["verdict"], "FAIL");
    assert_eq!(result["invariant"], "PROTECTED_DOCUMENT_NOT_RETRIEVED");
    // The reason explains the boundary, not the ranking.
    let reason = result["reason"].as_str().expect("a reason");
    assert!(reason.contains("protected"), "reason: {reason}");
    assert!(!reason.contains("score"), "reason: {reason}");
}

#[test]
fn a_run_with_no_relevant_observation_is_inconclusive_and_never_passes() {
    let run = run("lab-021", &["--scenario", "RAG-LAB-021"]);
    assert_eq!(run.code, 2, "stderr: {}", run.stderr);
    assert_eq!(run.result()["verdict"], "INCONCLUSIVE");
    // Exit 2 covers both a violation and an undecided run: neither is a pass,
    // and CI must not treat either as one.
    assert_ne!(run.code, 0);
}

#[test]
fn a_scenario_the_engine_refuses_exits_three_without_writing_a_verdict() {
    let run = run("lab-024", &["--scenario", "RAG-LAB-024"]);
    assert_eq!(run.code, 3, "stderr: {}", run.stderr);
    assert!(!run.wrote_a_result());

    // The refusal must not echo what it refused.
    assert!(!run.stderr.contains("sk-live-"));
    assert!(!run.stderr.contains("example.invalid"));
    for banned in ["PASS", "FAIL", "INCONCLUSIVE"] {
        assert!(!run.stderr.contains(banned), "stderr: {}", run.stderr);
    }
}

#[test]
fn an_over_bound_corpus_is_refused_rather_than_trimmed() {
    let run = run("lab-023", &["--scenario", "RAG-LAB-023"]);
    assert_eq!(run.code, 3, "stderr: {}", run.stderr);
    assert!(!run.wrote_a_result());
}

#[test]
fn the_local_synthetic_mode_runs_under_the_cycle_009_controls() {
    let run = run(
        "lab-001-local",
        &["--scenario", "RAG-LAB-001", "--mode", "local-synthetic"],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["mode"], "LOCAL_SYNTHETIC");
    assert_eq!(result["budget"]["state_changes"], 0);
    assert_eq!(result["budget"]["external_egress_bytes"], 0);
}

#[test]
fn a_recorded_trace_replays_without_reaching_anything() {
    let run = run(
        "lab-001-replay",
        &[
            "--scenario",
            "RAG-LAB-001",
            "--mode",
            "replay",
            "--trace",
            "crates/dare-rag-security/tests/fixtures/traces/rag-lab-001.json",
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let result = run.result();
    assert_eq!(result["mode"], "REPLAY");
    assert_eq!(result["verdict"], "PASS");
    // A replayed observation is still synthetic; a report must not present it
    // as production evidence.
    assert_eq!(result["synthetic"], true);
}

#[test]
fn a_trace_recorded_against_another_scenario_is_refused() {
    let run = run(
        "lab-mismatch",
        &[
            "--scenario",
            "RAG-LAB-002",
            "--mode",
            "replay",
            "--trace",
            "crates/dare-rag-security/tests/fixtures/traces/rag-lab-001.json",
        ],
    );
    assert_ne!(run.code, 0);
    assert!(!run.wrote_a_result());
}

#[test]
fn a_trace_without_replay_mode_is_a_usage_error() {
    let run = run(
        "lab-trace-wrong-mode",
        &[
            "--scenario",
            "RAG-LAB-001",
            "--mode",
            "simulated",
            "--trace",
            "crates/dare-rag-security/tests/fixtures/traces/rag-lab-001.json",
        ],
    );
    assert_eq!(run.code, 3, "stderr: {}", run.stderr);
}

#[test]
fn json_output_goes_to_stdout_and_diagnostics_do_not() {
    let run = run("lab-001-json", &["--scenario", "RAG-LAB-001", "--json"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let parsed: Value = serde_json::from_str(&run.stdout).expect("stdout is only JSON");
    assert_eq!(parsed["scenario_id"], "RAG-LAB-001");
}

#[test]
fn every_artifact_is_deterministic_across_runs() {
    // Determinism is what makes the recorded digests worth anything: two runs
    // of the same fixture that differed would mean the digest identified the
    // run rather than the thing under test.
    let first = run("determinism-a", &["--scenario", "RAG-LAB-001"]);
    let second = run("determinism-b", &["--scenario", "RAG-LAB-001"]);
    assert_eq!(first.code, 0);
    assert_eq!(second.code, 0);

    assert_eq!(first.result(), second.result());
    assert_eq!(first.trials(), second.trials());
    assert_eq!(first.summary(), second.summary());

    // Evidence carries a timestamp, so only the identity-bearing fields are
    // compared.
    let ids = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .expect("array")
            .iter()
            .map(|record| record["id"].as_str().expect("id").to_owned())
            .collect()
    };
    assert_eq!(ids(&first.evidence()), ids(&second.evidence()));
}

#[test]
fn no_artifact_carries_a_credential_a_canary_or_a_reachable_target() {
    // Two different things are checked here, and only one of them is about
    // words.
    //
    // Secrets and canaries must never appear at all. Store *names* may: the
    // evidence and the summary both carry an honest note saying which stores
    // this cycle never contacts, and banning the word would ban the sentence
    // that documents the boundary. What must never appear is something
    // reachable — a scheme, a host or a connection string. So every `://` in
    // every artifact has to belong to the schema identifiers, which name a
    // contract and are never resolved.
    for lab in [
        "RAG-LAB-001",
        "RAG-LAB-002",
        "RAG-LAB-014",
        "RAG-LAB-016",
        "RAG-LAB-022",
    ] {
        let run = run(&format!("hygiene-{lab}"), &["--scenario", lab]);
        assert!(run.code == 0 || run.code == 2, "stderr: {}", run.stderr);

        for artifact in [
            "rag-security-result.json",
            "rag-security-trials.json",
            "rag-security-evidence.json",
            "summary.md",
        ] {
            let text = std::fs::read_to_string(run.output_dir.join(artifact))
                .unwrap_or_else(|err| panic!("{lab}/{artifact}: {err}"));

            for marker in [
                "DARE-SYNTHETIC-CANARY-",
                "sk-live-",
                "-----BEGIN",
                "Bearer ey",
                "example.invalid",
            ] {
                assert!(
                    !text.contains(marker),
                    "{lab}/{artifact} carried `{marker}`"
                );
            }

            for (index, _) in text.match_indices("://") {
                let from = text[..index].rfind(|c: char| c.is_whitespace() || c == '"');
                let occurrence = &text[from.map_or(0, |at| at + 1)..];
                assert!(
                    occurrence.starts_with("https://darelabs.tech/schemas/"),
                    "{lab}/{artifact} carries a reachable target: {}",
                    &occurrence[..occurrence.len().min(80)]
                );
            }
        }
    }
}

#[test]
fn the_summary_reports_each_surface_separately_and_never_overclaims() {
    let run = run("summary", &["--scenario", "RAG-LAB-001"]);
    let summary = run.summary();

    for surface in [
        "RETRIEVAL_AUTHORIZATION",
        "DOCUMENT_ISOLATION",
        "PROVENANCE",
        "RESULT_INTEGRITY",
        "CONTENT_TRUST",
        "PROTECTED_NONDISCLOSURE",
    ] {
        assert!(summary.contains(surface), "{surface} missing");
    }
    assert!(summary.contains("NOT TESTED"));

    let lowered = summary.to_lowercase();
    for banned in [
        "rag secure",
        "vector database secure",
        "no leakage possible",
        "fully protected",
        "no retrieval attack possible",
    ] {
        assert!(!lowered.contains(banned), "summary claims `{banned}`");
    }
    assert!(summary.contains(
        "No RAG/retrieval-security invariant violation was observed for the tested vectors"
    ));
}

#[test]
fn the_summary_records_that_nothing_was_indexed_embedded_or_sent() {
    let run = run("summary-counts", &["--scenario", "RAG-LAB-001"]);
    let summary = run.summary();
    assert!(summary.contains("| Documents indexed | 0 |"));
    assert!(summary.contains("| Embeddings computed | 0 |"));
    assert!(summary.contains("| State changes | 0 |"));
    assert!(summary.contains("| External egress bytes | 0 |"));
}

#[test]
fn a_forbidden_flag_is_rejected_by_the_parser() {
    // Every store, provider and credential flag the approval forbids. A flag
    // that parsed would imply a code path able to use it.
    for flag in [
        "--url",
        "--endpoint",
        "--pinecone",
        "--weaviate",
        "--qdrant",
        "--redis",
        "--postgres",
        "--opensearch",
        "--elasticsearch",
        "--api-key",
        "--token",
        "--connection-string",
        "--remote",
        "--command",
    ] {
        let run = run(
            &format!("flag{}", flag.replace('-', "")),
            &["--scenario", "RAG-LAB-001", flag, "value"],
        );
        assert_ne!(run.code, 0, "`{flag}` was accepted");
        assert!(!run.wrote_a_result());
    }
}

#[test]
fn the_help_text_states_the_boundary() {
    let output = Command::new(binary())
        .current_dir(repo_root())
        .args(["validate", "rag-security", "--help"])
        .output()
        .expect("the binary runs");
    let help = String::from_utf8_lossy(&output.stdout);

    for expected in [
        "Pinecone",
        "Weaviate",
        "Qdrant",
        "Elasticsearch",
        "customer corpus",
        "relevance is not authorization",
        "Cycle 013",
        "Cycle 016",
        "never a claim that RAG is secure",
    ] {
        assert!(help.contains(expected), "the help omits `{expected}`");
    }
}
