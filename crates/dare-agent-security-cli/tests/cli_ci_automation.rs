//! Cycle 004 task-004: headless CLI automation with --output-dir.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

#[test]
fn validate_coaz_integrity_writes_ci_result_headlessly() {
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
            "--json",
        ])
        .status()
        .expect("spawn cli");
    assert!(status.success(), "expected PASS fixture exit 0");
    let ci_result = output_dir.path().join("ci-result.json");
    assert!(ci_result.is_file(), "ci-result.json must exist");
    let raw = fs::read_to_string(&ci_result).expect("read ci-result");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse ci-result");
    assert_eq!(value["aggregate_verdict"], "PASS");
    assert_eq!(value["mode"], "validate");
    assert!(output_dir.path().join("summary.md").is_file());
    let evidence_dir = output_dir.path().join("evidence");
    assert!(evidence_dir.is_dir());
    assert!(evidence_dir
        .read_dir()
        .unwrap()
        .flatten()
        .any(|e| e.path().extension().is_some()));
}

#[test]
fn validate_fail_fixture_exits_nonzero_with_ci_result() {
    let output_dir = tempfile::tempdir().expect("tempdir");
    let output = output_dir.path().to_string_lossy();
    let status = Command::new(cli_bin())
        .current_dir(repo_root())
        .args([
            "validate",
            "coaz-integrity",
            "--fixture",
            "COAZ-INTEGRITY-003",
            "--reference-mode",
            "vulnerable",
            "--output-dir",
            &output,
        ])
        .status()
        .expect("spawn cli");
    assert_eq!(status.code(), Some(2));
    let raw = fs::read_to_string(output_dir.path().join("ci-result.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["aggregate_verdict"], "FAIL");
}

#[test]
fn output_dir_rejects_parent_traversal() {
    let status = Command::new(cli_bin())
        .current_dir(repo_root())
        .args([
            "validate",
            "coaz-integrity",
            "--fixture",
            "COAZ-INTEGRITY-001",
            "--output-dir",
            "../escape-ci-output",
        ])
        .status()
        .expect("spawn cli");
    assert_eq!(status.code(), Some(1));
}

#[test]
fn coaz_integrity_without_output_dir_preserves_legacy_exit() {
    let status = Command::new(cli_bin())
        .current_dir(repo_root())
        .args([
            "validate",
            "coaz-integrity",
            "--fixture",
            "COAZ-INTEGRITY-001",
        ])
        .status()
        .expect("spawn cli");
    assert!(status.success());
}
