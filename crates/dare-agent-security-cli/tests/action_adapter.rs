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

#[test]
fn engine_modes_are_bounded_and_restated_by_the_cli() {
    let root = repo_root();
    let action = fs::read_to_string(root.join("action.yml")).expect("action.yml");
    for input in [
        "traces:",
        "policy:",
        "artifacts:",
        "system-model:",
        "graph:",
        "compromise:",
        "INPUT_TRACES: ${{ inputs.traces }}",
        "INPUT_COMPROMISE: ${{ inputs.compromise }}",
    ] {
        assert!(action.contains(input), "action.yml missing {input}");
    }
    let entry = fs::read_to_string(root.join("action/entrypoint.sh")).expect("entrypoint");
    assert!(entry.contains("discover|validate|runtime-telemetry|attack-paths|blast-radius) ;;"));
    // The verdict mapping is the CLI's, not the shell's.
    assert!(entry.contains("ci engine-outputs"));
    assert!(entry.contains("--engine-exit \"$ENGINE_EXIT\""));
    // Lists are split without globbing, each path one argv element.
    assert!(entry.contains("set -f"));
    assert!(entry.contains("set -- \"$@\" --traces \"$item\""));
    assert!(entry.contains("set -- \"$@\" --artifacts \"$item\""));
    assert!(entry.contains("/*|-*|*..*)"));
    assert!(
        !entry.contains("--traces \"$TRACES\"") && !entry.contains("--artifacts \"$ARTIFACTS\""),
        "a list must not reach the CLI as one string"
    );
}

#[test]
fn e2e_runs_every_engine_mode_through_the_action() {
    let e2e = fs::read_to_string(repo_root().join(".github/workflows/action-e2e.yml"))
        .expect("action-e2e.yml");
    for needle in [
        "mode: runtime-telemetry",
        "mode: attack-paths",
        "mode: blast-radius",
        "OTL-001",
        "OTL-002",
        "OTL-055",
        "fail-on-inconclusive: \"false\"",
        "/ap-fail/attack-graph.json",
        "id: hostile",
    ] {
        assert!(e2e.contains(needle), "action-e2e.yml missing {needle}");
    }
}
