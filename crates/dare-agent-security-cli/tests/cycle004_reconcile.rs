//! Cycle 004 task-001: deterministic reconciliation with merged Cycle 003 baseline.

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
fn cycle003_acceptance_proof_exists_on_main() {
    assert_repo_file("DARE/cycles/003-coaz-authorization-integrity/PROOF.md");
    assert_repo_dir("crates/dare-coaz-integrity");
    assert_repo_file("vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json");
    assert_repo_file("docs/coaz-integrity.md");
}

#[test]
fn cycle002_discovery_baseline_present() {
    assert_repo_dir("crates/dare-mcp-discovery");
    assert_repo_dir("labs/synthetic-mcp");
    assert_repo_file("schemas/discovery/v1/inventory.schema.json");
}

#[test]
fn cycle001_evidence_schema_present() {
    assert_repo_file("schemas/evidence/v1/evidence.schema.json");
    assert_repo_dir("crates/dare-security-evidence");
}

#[test]
fn cli_binary_and_validate_subcommand_exist() {
    assert!(std::env::var("CARGO_BIN_EXE_dare-agent-security").is_ok());
    assert_repo_file("crates/dare-agent-security-cli/src/coaz_integrity.rs");
    assert_repo_file("crates/dare-agent-security-cli/EXIT.md");
}

#[test]
fn cycle004_implementation_notes_exist() {
    assert_repo_file("DARE/cycles/004-ci-security-gate/IMPLEMENTATION-NOTES.md");
}

#[test]
fn workspace_msrv_is_pinned() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    assert!(
        manifest.contains("rust-version = \"1.88\""),
        "expected MSRV 1.88 in workspace Cargo.toml"
    );
}

#[test]
fn ci_workflow_runs_workspace_gates() {
    let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
    for gate in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
    ] {
        assert!(ci.contains(gate), "CI missing gate: {gate}");
    }
}
