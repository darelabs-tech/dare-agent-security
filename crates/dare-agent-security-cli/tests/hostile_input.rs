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
    assert!(entry.contains(r#"REFERENCE_MODE="${INPUT_REFERENCE_MODE:-secure}""#));
}

/// Runs the real entrypoint with a stub CLI on PATH that records its argv.
#[cfg(unix)]
fn run_entrypoint_with_stub(env: &[(&str, &str)]) -> (i32, String, String) {
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.path().join("argv.log");
    let stub = bin.join("dare-agent-security");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\" >> '{}'; done\necho >> '{}'\nexit 3\n",
            log.display(),
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = std::process::Command::new("sh");
    cmd.arg(root.join("action/entrypoint.sh"))
        .env_clear()
        .env("PATH", path)
        .env("GITHUB_WORKSPACE", dir.path())
        .env("INPUT_OUTPUT_DIR", "out");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run entrypoint");
    let argv = std::fs::read_to_string(&log).unwrap_or_default();
    (
        out.status.code().unwrap_or(-1),
        argv,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[cfg(unix)]
#[test]
fn engine_mode_paths_are_rejected_before_the_cli_runs() {
    for (key, value) in [
        ("INPUT_ARTIFACTS", "bundles/../../etc"),
        ("INPUT_ARTIFACTS", "/etc"),
        ("INPUT_ARTIFACTS", "--help"),
        ("INPUT_ARTIFACTS", "ok -x"),
    ] {
        let (code, argv, stderr) =
            run_entrypoint_with_stub(&[("INPUT_MODE", "attack-paths"), (key, value)]);
        assert_eq!(code, 1, "{value}: {stderr}");
        assert!(argv.is_empty(), "{value}: the CLI ran with {argv}");
        assert!(stderr.contains("rejected"), "{value}: {stderr}");
    }
    let (code, argv, _) = run_entrypoint_with_stub(&[("INPUT_MODE", "blast-radius")]);
    assert_eq!(code, 1);
    assert!(argv.is_empty());
}

#[cfg(unix)]
#[test]
fn engine_mode_lists_become_one_argv_element_per_path_without_globbing() {
    let (_, argv, _) = run_entrypoint_with_stub(&[
        ("INPUT_MODE", "runtime-telemetry"),
        ("INPUT_TRACES", "a.json\n  b;id.json\t*"),
        ("INPUT_POLICY", "p.json"),
        ("INPUT_FAIL_ON_INCONCLUSIVE", "false"),
    ]);
    let mut lines = argv.lines();
    assert_eq!(
        lines.next(),
        Some(
            "[validate][runtime-telemetry][--output-dir][out][--traces][a.json][--traces][b;id.json][--traces][*][--policy][p.json]"
        )
    );
    assert_eq!(
        lines.next(),
        Some(
            "[ci][engine-outputs][--engine][runtime-telemetry][--output-dir][out][--engine-exit][3][--fail-on-inconclusive][false]"
        )
    );
}
