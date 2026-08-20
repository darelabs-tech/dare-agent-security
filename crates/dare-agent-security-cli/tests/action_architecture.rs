//! Cycle 004 task-003: architecture decision and threat model acceptance.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn docker_container_action_decision_documented() {
    let arch = std::fs::read_to_string(repo_root().join("action/ARCHITECTURE.md"))
        .expect("ARCHITECTURE.md");
    assert!(arch.contains("Docker container Action"));
    assert!(arch.contains("dare-agent-security"));
    assert!(arch.contains("permissions"));
    assert!(arch.contains("contents: read"));
    for topic in [
        "Linux runner",
        "multi-stage",
        "entrypoint",
        "Immutable version",
        "Rejected",
    ] {
        assert!(arch.contains(topic), "missing architecture topic: {topic}");
    }
}

#[test]
fn threat_model_covers_required_surfaces() {
    let tm = std::fs::read_to_string(repo_root().join("action/THREAT-MODEL.md"))
        .expect("THREAT-MODEL.md");
    for threat in [
        "Shell injection",
        "Path traversal",
        "Secret leakage",
        "Malicious MCP metadata",
        "Scope expansion",
        "Mutable dependency",
        "INCONCLUSIVE",
        "Markdown",
    ] {
        assert!(tm.contains(threat), "missing threat: {threat}");
    }
    assert!(tm.contains("eval"));
    assert!(tm.contains("pull_request_target"));
}
