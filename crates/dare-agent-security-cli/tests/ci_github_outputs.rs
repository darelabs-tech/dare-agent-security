//! Cycle 004 task-006: GitHub outputs and job summary integration.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use dare_agent_security::ci_result::GITHUB_OUTPUT_FILENAME;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

#[test]
fn validate_emits_github_output_env_and_summary_without_secrets() {
    let output_dir = tempfile::tempdir().expect("tempdir");
    let output = output_dir.path().to_string_lossy();
    let status = Command::new(cli_bin())
        .current_dir(repo_root())
        .args([
            "validate",
            "coaz-integrity",
            "--fixture",
            "COAZ-INTEGRITY-001",
            "--output-dir",
            &output,
        ])
        .status()
        .expect("spawn");
    assert!(status.success());

    let github =
        fs::read_to_string(output_dir.path().join(GITHUB_OUTPUT_FILENAME)).expect("github");
    assert!(github.contains("verdict=PASS"));
    assert!(github.contains("evidence-path="));
    assert!(github.contains("summary-path="));
    assert!(!github.contains("Bearer "));
    assert!(!github.contains("sk-live-"));

    let summary = fs::read_to_string(output_dir.path().join("summary.md")).expect("summary");
    assert!(summary.contains("DARE Agent Security"));
    assert!(summary.contains("NOT TESTED"));
    assert!(summary.contains("Aggregate verdict"));
}

#[test]
fn ci_write_result_emits_github_output_for_inconclusive() {
    let output_dir = tempfile::tempdir().expect("tempdir");
    let output = output_dir.path().to_string_lossy();
    let status = Command::new(cli_bin())
        .current_dir(repo_root())
        .args([
            "ci",
            "write-result",
            "--mode",
            "validate",
            "--output-dir",
            &output,
            "--target-label",
            "inconclusive-empty",
        ])
        .status()
        .expect("spawn");
    assert_eq!(status.code(), Some(2));
    let github = fs::read_to_string(output_dir.path().join(GITHUB_OUTPUT_FILENAME)).unwrap();
    assert!(github.contains("verdict=INCONCLUSIVE"));
}
