//! Cycle 008 task-001: reconcile Cycles 001–007 on main.

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
fn cycles_001_through_007_present() {
    assert_repo_file("schemas/evidence/v1/evidence.schema.json");
    assert_repo_dir("crates/dare-security-evidence");
    assert_repo_dir("crates/dare-mcp-discovery");
    assert_repo_dir("crates/dare-coaz-integrity");
    assert_repo_file("action.yml");
    assert_repo_file("schemas/ci/v1/ci-result.schema.json");
    assert_repo_dir("crates/dare-mcp-lab");
    assert_repo_file("schemas/lab/v1/scenario.schema.json");
    assert_repo_dir("crates/dare-coverage");
    assert_repo_file("schemas/coverage/v1/registry.json");
    assert_repo_file("profiles/mcp-security-baseline.json");
    assert_repo_dir("crates/dare-benchmark");
    assert_repo_file("schemas/benchmark/v1/benchmark-record.schema.json");
    assert_repo_file("DARE/cycles/007-mcp-security-benchmark-corpus-methodology/PROOF.md");
}

#[test]
fn cycle008_approval_and_notes_exist() {
    assert_repo_file("DARE/cycles/008-agent-attack-graph-mvp/APPROVAL.md");
    assert_repo_file("DARE/cycles/008-agent-attack-graph-mvp/IMPLEMENTATION-NOTES.md");
}

#[test]
fn ci_result_schema_remains_closed() {
    let schema = std::fs::read_to_string(repo_root().join("schemas/ci/v1/ci-result.schema.json"))
        .expect("ci schema");
    assert!(schema.contains("\"additionalProperties\": false"));
}

#[test]
fn workspace_msrv_and_rmcp_pinned() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    assert!(manifest.contains("rust-version = \"1.88\""));
    assert!(manifest.contains("rmcp = { version = \"3.1.3\""));
}

#[test]
fn no_second_engine_planned_in_notes() {
    let notes = std::fs::read_to_string(
        repo_root().join("DARE/cycles/008-agent-attack-graph-mvp/IMPLEMENTATION-NOTES.md"),
    )
    .expect("notes");
    assert!(notes.contains("must not invent a second evidence"));
    assert!(notes.contains("Edge evidence ≠ verdict") || notes.contains("edge evidence"));
}
