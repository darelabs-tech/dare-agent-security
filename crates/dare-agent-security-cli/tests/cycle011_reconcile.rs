//! Cycle 011 task-001: reconcile Cycles 001–010 on main.

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
fn cycles_001_through_010_present() {
    assert_repo_file("schemas/evidence/v1/evidence.schema.json");
    assert_repo_dir("crates/dare-security-evidence");
    assert_repo_dir("crates/dare-mcp-discovery");
    assert_repo_dir("crates/dare-coaz-integrity");
    assert_repo_file("action.yml");
    assert_repo_file("schemas/ci/v1/ci-result.schema.json");
    assert_repo_dir("crates/dare-mcp-lab");
    assert_repo_dir("crates/dare-coverage");
    assert_repo_file("schemas/coverage/v1/registry.json");
    assert_repo_dir("crates/dare-benchmark");
    assert_repo_dir("crates/dare-attack-graph");
    assert_repo_dir("crates/dare-adversarial");
    assert_repo_file("schemas/adversarial/v1/validation-plan.schema.json");
    assert_repo_dir("crates/dare-continuous");
    assert_repo_file("schemas/continuous/v1/security-state-snapshot.schema.json");
    assert_repo_file("DARE/cycles/010-continuous-agent-security-validation/PROOF.md");
}

#[test]
fn cycle011_approval_and_notes_exist() {
    assert_repo_file("DARE/cycles/011-productization-v1-release-readiness/APPROVAL.md");
    assert_repo_file("DARE/cycles/011-productization-v1-release-readiness/IMPLEMENTATION-NOTES.md");
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
fn no_second_engine_and_freeze_preserved() {
    let notes = std::fs::read_to_string(
        repo_root()
            .join("DARE/cycles/011-productization-v1-release-readiness/IMPLEMENTATION-NOTES.md"),
    )
    .expect("notes");
    assert!(notes.contains("must not invent a second evidence"));
    assert!(notes.contains("CORE FEATURE FREEZE"));
    assert!(notes.contains("AUTHORIZED_DYNAMIC remains ROE-gated"));
    assert!(notes.contains("confidential/offline fail-closed"));

    let proof = std::fs::read_to_string(
        repo_root().join("DARE/cycles/010-continuous-agent-security-validation/PROOF.md"),
    )
    .expect("cycle 010 proof");
    assert!(proof.contains("CORE FEATURE FREEZE"));
}
