//! Cycle 004 task-009: hostile-input tests for the Action/CLI adapter surface.

use std::path::Path;

use dare_agent_security::ci_output::{assert_summary_secret_safe, validate_output_dir};

#[test]
fn output_dir_rejects_parent_traversal_variants() {
    for path in ["../escape", "foo/../../bar", ".."] {
        assert!(
            validate_output_dir(Path::new(path)).is_err(),
            "should reject {path}"
        );
    }
}

#[test]
fn shell_metacharacters_in_relative_path_are_data_not_traversal() {
    assert!(validate_output_dir(Path::new(".dare-agent-security")).is_ok());
    assert!(validate_output_dir(Path::new(".dare;rm")).is_ok());
}

#[test]
fn secret_canaries_rejected_in_github_output_body() {
    for canary in [
        "Bearer eyJhbGciOiJIUzI1NiIs",
        "Authorization: Basic abc",
        "sk-live-abcdef",
        "password=hunter2",
    ] {
        assert!(
            assert_summary_secret_safe(canary).is_err(),
            "canary should be blocked: {canary}"
        );
    }
}

#[test]
fn markdown_control_characters_allowed_when_not_secrets() {
    let content = "Target | `; rm -rf /` | **bold** | INCONCLUSIVE";
    assert!(assert_summary_secret_safe(content).is_ok());
}

#[test]
fn entrypoint_documents_rejection_of_unknown_mode() {
    let entry = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../action/entrypoint.sh"),
    )
    .expect("entrypoint");
    assert!(entry.contains("unsupported mode"));
    assert!(entry.contains("unsupported reference-mode"));
}
