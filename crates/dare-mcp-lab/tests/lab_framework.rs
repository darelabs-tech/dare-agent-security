//! Cycle 005 task-003: shared lab framework isolation tests.

use dare_mcp_lab::{LabCredential, LabIdentity, LabSession, PolicyFixture, VariantKind};

#[test]
fn fixture_runs_twice_without_cross_session_leakage() {
    for round in 0..2 {
        let mut session = LabSession::start("MCP-LAB-ISO", VariantKind::Secure)
            .unwrap()
            .with_identity(LabIdentity::human("human-001"))
            .with_identity(LabIdentity::agent("agent-001"))
            .with_credential(LabCredential::synthetic("issuer-lab", "subject-001"))
            .unwrap()
            .with_policy(PolicyFixture::permit(
                "invoke",
                "rental.quote",
                "subject-001",
            ));

        session.state.insert("round", format!("{round}"));
        let expected = format!("{round}");
        assert_eq!(session.state.get("round"), Some(expected.as_str()));
        assert!(session.endpoint.starts_with("lab://"));
        assert!(!session.endpoint.contains("http://"));
        assert!(!session.endpoint.contains("https://"));
        let leftover = session.teardown();
        assert!(leftover.is_empty());
    }
}

#[test]
fn secure_and_vulnerable_sessions_do_not_share_state() {
    let mut secure = LabSession::start("MCP-LAB-002", VariantKind::Secure).unwrap();
    let mut vulnerable = LabSession::start("MCP-LAB-002", VariantKind::Vulnerable).unwrap();
    secure.state.insert("secret-marker", "secure-only");
    vulnerable.state.insert("secret-marker", "vulnerable-only");
    assert_ne!(secure.session_id, vulnerable.session_id);
    assert_eq!(secure.state.get("secret-marker"), Some("secure-only"));
    assert_eq!(
        vulnerable.state.get("secret-marker"),
        Some("vulnerable-only")
    );
    secure.teardown();
    vulnerable.teardown();
}

#[test]
fn endpoint_addressing_is_stable_local_scheme() {
    let session = LabSession::start("MCP-LAB-003", VariantKind::Vulnerable).unwrap();
    assert!(session
        .endpoint
        .starts_with("lab://mcp-lab-003-vulnerable-"));
    session.teardown();
}
