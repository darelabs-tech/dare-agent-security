//! Cycle 004 task-005: Action adapter contains no domain logic.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn action_metadata_exists_with_bounded_mode_input() {
    let action = fs::read_to_string(repo_root().join("action.yml")).expect("action.yml");
    assert!(action.contains("using: docker"));
    assert!(action.contains("image: Dockerfile"));
    assert!(!action.contains("image: action/Dockerfile"));
    assert!(action.contains("mode:"));
    assert!(action.contains("target:"));
    assert!(action.contains("output-dir:"));
    assert!(action.contains("fail-on-inconclusive:"));
    assert!(action.contains("verdict:"));
    assert!(!action.contains("eval"));
}

#[test]
fn entrypoint_invokes_cli_without_eval_or_shell_c() {
    let entry = fs::read_to_string(repo_root().join("action/entrypoint.sh")).expect("entrypoint");
    assert!(entry.contains("dare-agent-security"));
    assert!(!entry.contains("eval "));
    assert!(!entry.contains("sh -c"));
    for token in ["discover", "validate", "coaz-integrity", "--output-dir"] {
        assert!(entry.contains(token), "missing token: {token}");
    }
}

#[test]
fn dockerfile_builds_cli_from_repository() {
    let dockerfile = fs::read_to_string(repo_root().join("Dockerfile")).expect("root Dockerfile");
    assert!(dockerfile.contains("cargo build --release -p dare-agent-security"));
    assert!(dockerfile.contains("entrypoint.sh"));
    assert!(dockerfile.contains("/src/vectors"));
    assert!(!dockerfile.contains("curl"));
    assert!(!dockerfile.contains("wget"));
}

#[test]
fn entrypoint_preserves_outputs_after_nonzero_cli_exit() {
    let entry = fs::read_to_string(repo_root().join("action/entrypoint.sh")).expect("entrypoint");
    assert!(entry.contains("set +e"));
    assert!(entry.contains("write_github_outputs"));
    assert!(entry.contains("EXIT=$?"));
}
