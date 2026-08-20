//! Cycle 005 task-001: deterministic reconciliation with merged Cycle 004 baseline.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_repo_file(rel: &str) {
    let path = repo_root().join(rel);
    assert!(path.is_file(), "missing baseline artifact: {rel}");
}

fn assert_repo_dir(rel: &str) {
    let path = repo_root().join(rel);
    assert!(path.is_dir(), "missing baseline directory: {rel}");
}

#[test]
fn cycle004_acceptance_proof_exists_on_main() {
    assert_repo_file("DARE/cycles/004-ci-security-gate/PROOF.md");
    assert_repo_file("action.yml");
    assert_repo_file("Dockerfile");
    assert_repo_file("action/entrypoint.sh");
    assert_repo_file("schemas/ci/v1/ci-result.schema.json");
    assert_repo_file("docs/ci-gate.md");
    assert_repo_file(".github/workflows/action-e2e.yml");
}

#[test]
fn cycles_001_002_003_baseline_present() {
    assert_repo_file("schemas/evidence/v1/evidence.schema.json");
    assert_repo_dir("crates/dare-security-evidence");
    assert_repo_dir("crates/dare-mcp-discovery");
    assert_repo_dir("crates/dare-coaz-integrity");
    assert_repo_file("vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json");
    assert_repo_dir("labs/synthetic-mcp");
}

#[test]
fn cli_exposes_discover_validate_and_ci_commands() {
    assert!(std::env::var("CARGO_BIN_EXE_dare-agent-security").is_ok());
    assert_repo_file("crates/dare-agent-security-cli/src/coaz_integrity.rs");
    assert_repo_file("crates/dare-agent-security-cli/src/ci.rs");
    assert_repo_file("crates/dare-agent-security-cli/src/ci_result.rs");
    assert_repo_file("crates/dare-agent-security-cli/EXIT.md");
}

#[test]
fn action_yml_uses_root_dockerfile_and_bounded_modes() {
    let action = std::fs::read_to_string(repo_root().join("action.yml")).expect("action.yml");
    assert!(action.contains("using: docker"));
    assert!(action.contains("image: Dockerfile"));
    assert!(!action.contains("image: action/Dockerfile"));
    assert!(action.contains("fail-on-inconclusive"));
    assert!(action.contains("reference-mode"));
}

#[test]
fn synthetic_mcp_lab_and_docs_present() {
    assert_repo_file("labs/synthetic-mcp/Cargo.toml");
    assert_repo_file("labs/synthetic-mcp/src/server.rs");
    assert_repo_file("docs/synthetic-lab.md");
}

#[test]
fn cycle005_implementation_notes_exist() {
    assert_repo_file("DARE/cycles/005-synthetic-mcp-security-lab/IMPLEMENTATION-NOTES.md");
    assert_repo_file("DARE/cycles/005-synthetic-mcp-security-lab/APPROVAL.md");
}

#[test]
fn workspace_msrv_and_rmcp_pinned() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    assert!(
        manifest.contains("rust-version = \"1.88\""),
        "expected MSRV 1.88"
    );
    assert!(
        manifest.contains("rmcp = { version = \"3.1.3\""),
        "expected rmcp 3.1.3"
    );
}

#[test]
fn ci_workflows_include_workspace_and_action_e2e() {
    let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
    for gate in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
    ] {
        assert!(ci.contains(gate), "CI missing gate: {gate}");
    }
    let e2e = std::fs::read_to_string(repo_root().join(".github/workflows/action-e2e.yml"))
        .expect("action-e2e.yml");
    assert!(e2e.contains("uses: ./"));
}
