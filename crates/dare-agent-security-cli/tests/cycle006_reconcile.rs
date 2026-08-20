//! Cycle 006 task-001: deterministic reconciliation with Cycles 001–005 on main.

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
fn cycles_001_through_004_contracts_present() {
    assert_repo_file("schemas/evidence/v1/evidence.schema.json");
    assert_repo_dir("crates/dare-security-evidence");
    assert_repo_file("schemas/discovery/v1/inventory.schema.json");
    assert_repo_dir("crates/dare-mcp-discovery");
    assert_repo_dir("crates/dare-coaz-integrity");
    assert_repo_file("vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json");
    assert_repo_file("action.yml");
    assert_repo_file("Dockerfile");
    assert_repo_file("schemas/ci/v1/ci-result.schema.json");
    assert_repo_file("DARE/cycles/004-ci-security-gate/PROOF.md");
}

#[test]
fn cycle_005_is_merged_on_main_and_must_not_be_the_coverage_engine() {
    assert_repo_file("DARE/cycles/005-synthetic-mcp-security-lab/PROOF.md");
    assert_repo_dir("crates/dare-mcp-lab");
    assert_repo_file("schemas/lab/v1/scenario.schema.json");
    assert_repo_file("labs/scenarios/MCP-LAB-001/scenario.json");
    assert_repo_file("DARE/cycles/006-assessment-profiles-coverage-engine/APPROVAL.md");
    let approval = std::fs::read_to_string(
        repo_root().join("DARE/cycles/006-assessment-profiles-coverage-engine/APPROVAL.md"),
    )
    .expect("approval");
    assert!(approval.contains("task-013 is **APPLICABLE**"));
}

#[test]
fn ci_result_schema_is_closed_so_coverage_must_be_a_sibling_artifact() {
    let schema = std::fs::read_to_string(repo_root().join("schemas/ci/v1/ci-result.schema.json"))
        .expect("ci schema");
    assert!(schema.contains("\"additionalProperties\": false"));
}

#[test]
fn action_inputs_are_bounded_modes() {
    let action = std::fs::read_to_string(repo_root().join("action.yml")).expect("action.yml");
    assert!(action.contains("using: docker"));
    assert!(action.contains("image: Dockerfile"));
    assert!(action.contains("fail-on-inconclusive"));
    assert!(action.contains("reference-mode"));
}

#[test]
fn cli_commands_and_exit_docs_exist() {
    assert!(std::env::var("CARGO_BIN_EXE_dare-agent-security").is_ok());
    assert_repo_file("crates/dare-agent-security-cli/src/args.rs");
    assert_repo_file("crates/dare-agent-security-cli/EXIT.md");
}

#[test]
fn cycle006_implementation_notes_exist() {
    assert_repo_file("DARE/cycles/006-assessment-profiles-coverage-engine/IMPLEMENTATION-NOTES.md");
}

#[test]
fn workspace_msrv_and_rmcp_pinned() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    assert!(manifest.contains("rust-version = \"1.88\""));
    assert!(manifest.contains("rmcp = { version = \"3.1.3\""));
}
