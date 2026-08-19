//! CLI contract tests for `dare-agent-security validate coaz-integrity`.

use std::path::PathBuf;
use std::process::{Command, Output};

use dare_coaz_integrity::{validate_result, IntegrityVerdict, VectorResult, BUILTIN_VECTOR_IDS};
use serde_json::Value;

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn run(args: &[&str]) -> Output {
    Command::new(cli_bin())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn CLI: {err}"))
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exit code")
}

#[test]
fn help_documents_fixture_flags_and_exit_codes() {
    let output = run(&["validate", "coaz-integrity", "--help"]);
    assert_eq!(code(&output), 0);
    let help = format!("{}{}", stdout_str(&output), stderr_str(&output));
    assert!(help.contains("--all"));
    assert!(help.contains("--fixture"));
    assert!(help.contains("--json"));
    assert!(help.contains("--reference-mode"));
    assert!(help.contains("--evidence-dir"));
    assert!(help.contains("Exit codes"));
    assert!(help.contains("vulnerable"));
    assert!(!help.contains("--url"));
    assert!(!help.contains("--stdio"));
}

#[test]
fn missing_selector_exits_usage() {
    let output = run(&["validate", "coaz-integrity"]);
    assert_eq!(code(&output), 3);
    assert!(stdout_str(&output).trim().is_empty());
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("fixture selector is required"),
        "stderr={stderr}"
    );
}

#[test]
fn all_and_fixture_conflict_exits_usage() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--all",
        "--fixture",
        "COAZ-INTEGRITY-001",
    ]);
    assert_ne!(code(&output), 0);
    assert_eq!(code(&output), 3);
    assert!(stdout_str(&output).trim().is_empty());
}

#[test]
fn unknown_fixture_exits_usage() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--fixture",
        "COAZ-INTEGRITY-999",
    ]);
    assert_eq!(code(&output), 3);
    assert!(stdout_str(&output).trim().is_empty());
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("unknown built-in fixture"),
        "stderr={stderr}"
    );
}

#[test]
fn single_fixture_secure_pass_exits_zero() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--fixture",
        "COAZ-INTEGRITY-003",
    ]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    assert!(stdout.contains("COAZ-INTEGRITY-003"));
    assert!(stdout.contains("PASS"));
}

#[test]
fn all_fixtures_secure_pass_exits_zero() {
    let output = run(&["validate", "coaz-integrity", "--all"]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    for vector_id in BUILTIN_VECTOR_IDS {
        assert!(stdout.contains(vector_id), "missing {vector_id} in summary");
    }
}

#[test]
fn single_fixture_json_stdout_is_only_json_object() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--fixture",
        "COAZ-INTEGRITY-003",
        "--json",
    ]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{'),
        "stdout must be a JSON object: {stdout}"
    );
    let result: VectorResult = serde_json::from_str(trimmed).expect("parse vector result");
    validate_result(&result).expect("result contract");
    assert_eq!(result.vector_id, "COAZ-INTEGRITY-003");
    assert_eq!(result.verdict, IntegrityVerdict::Pass);
}

#[test]
fn all_fixtures_json_stdout_is_only_json_array() {
    let output = run(&["validate", "coaz-integrity", "--all", "--json"]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('['),
        "stdout must be a JSON array: {stdout}"
    );
    let results: Vec<VectorResult> = serde_json::from_str(trimmed).expect("parse vector results");
    assert_eq!(results.len(), BUILTIN_VECTOR_IDS.len());
    for (index, vector_id) in BUILTIN_VECTOR_IDS.iter().enumerate() {
        assert_eq!(results[index].vector_id, *vector_id);
        validate_result(&results[index]).expect("result contract");
    }
}

#[test]
fn json_failure_keeps_stdout_clean_and_diagnostics_on_stderr() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--json",
        "--fixture",
        "COAZ-INTEGRITY-404",
    ]);
    assert_eq!(code(&output), 3);
    assert!(
        stdout_str(&output).trim().is_empty(),
        "json mode must not mix diagnostics into stdout"
    );
    assert!(!stderr_str(&output).trim().is_empty());
}

#[test]
fn vulnerable_mode_mutation_fixture_exits_partial() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--fixture",
        "COAZ-INTEGRITY-003",
        "--reference-mode",
        "vulnerable",
        "--json",
    ]);
    assert_eq!(code(&output), 2, "stderr={}", stderr_str(&output));
    let result: VectorResult =
        serde_json::from_str(stdout_str(&output).trim()).expect("parse vector result");
    assert_eq!(result.verdict, IntegrityVerdict::Fail);
}

#[test]
fn vulnerable_mode_all_exits_partial() {
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--all",
        "--reference-mode",
        "vulnerable",
    ]);
    assert_eq!(code(&output), 2, "stderr={}", stderr_str(&output));
}

#[test]
fn evidence_dir_writes_result_and_evidence_artifacts() {
    let dir = std::env::temp_dir().join(format!("dare-coaz-validate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let output = run(&[
        "validate",
        "coaz-integrity",
        "--fixture",
        "COAZ-INTEGRITY-001",
        "--evidence-dir",
        dir.to_str().expect("temp path utf8"),
    ]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let result_path = dir.join("COAZ-INTEGRITY-001.result.json");
    let evidence_path = dir.join("COAZ-INTEGRITY-001.evidence.json");
    assert!(result_path.is_file(), "missing {}", result_path.display());
    assert!(
        evidence_path.is_file(),
        "missing {}",
        evidence_path.display()
    );
    let result: VectorResult =
        serde_json::from_str(&std::fs::read_to_string(result_path).expect("read result")).unwrap();
    validate_result(&result).expect("result contract");
    let evidence: Value =
        serde_json::from_str(&std::fs::read_to_string(evidence_path).expect("read evidence"))
            .unwrap();
    assert_eq!(evidence["verdict"], Value::String("PASS".to_owned()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn discover_subcommand_still_works() {
    let output = run(&["discover", "--help"]);
    assert_eq!(code(&output), 0);
    let help = format!("{}{}", stdout_str(&output), stderr_str(&output));
    assert!(help.contains("--stdio"));
    assert!(help.contains("--url"));
}

#[test]
fn coaz_exit_docs_exist() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("EXIT.md");
    let docs = std::fs::read_to_string(path).expect("read EXIT.md");
    assert!(docs.contains("validate coaz-integrity"));
    assert!(docs.contains("Harness error"));
    assert!(docs.contains("safety refusal"));
}

#[test]
fn cycle_003_operator_docs_exist() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let required = [
        "docs/coaz-integrity.md",
        "docs/coaz-integrity-policy.md",
        "docs/coaz-integrity-vectors.md",
        "docs/coaz-integrity-cli.md",
        "docs/coaz-integrity-standards.md",
        "crates/dare-coaz-integrity/README.md",
        "DARE/cycles/003-coaz-authorization-integrity/PROOF.md",
        "DARE/cycles/003-coaz-authorization-integrity/upstream/README.md",
        "examples/coaz-integrity/cycle003-standards-v1.json",
    ];
    for rel in required {
        let path = repo_root.join(rel);
        assert!(
            path.is_file(),
            "missing Cycle 003 operator doc: {}",
            path.display()
        );
        let content = std::fs::read_to_string(&path).expect("read doc");
        assert!(
            !content.trim().is_empty(),
            "empty Cycle 003 operator doc: {}",
            path.display()
        );
    }
    let readme = std::fs::read_to_string(repo_root.join("README.md")).expect("read README");
    assert!(readme.contains("validate coaz-integrity"));
    assert!(readme.contains("docs/coaz-integrity.md"));
}
