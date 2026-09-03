use std::fs;

use dare_product::{run_assessment, AssessOptions};

#[test]
fn agentic_assessment_preserves_confidential_offline_guarantees() {
    let dir = tempfile::tempdir().expect("tempdir");

    fs::write(
        dir.path().join("dare-security.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": "1",
            "project": {"name": "agentic-offline-demo"},
            "assessment": {"profile": "agentic-security-baseline-2026"},
            "privacy": {
                "mode": "confidential",
                "telemetry": false,
                "network": "denied",
                "offline": true,
                "retention_days": 7
            },
            "reporting": {"formats": ["html", "json"]},
            "classification": {
                "level": "CONFIDENTIAL",
                "distribution": ["security-team"],
                "publication_allowed": false
            }
        }))
        .expect("config json"),
    )
    .expect("write config");

    fs::write(
        dir.path().join("assessment-fixture.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "coverage_facts": {
                "tools_count": 2,
                "resources_count": 1,
                "prompts_count": 1,
                "transport": "http",
                "authorization_present": true,
                "dynamic_authorization_allowed": false,
                "execution_integrity_supported": true,
                "confused_deputy_supported": true,
                "agent_present": true,
                "memory_present": true,
                "rag_present": false,
                "multi_agent_present": true,
                "code_execution_present": true,
                "human_approval_present": true,
                "delegated_identity_present": true,
                "external_components_present": true,
                "stateful_agent_present": true,
                "runtime_dynamic_allowed": false,
                "out_of_scope_property_ids": []
            },
            "coverage_executions": [],
            "limitations": ["Synthetic offline Cycle 012 regression fixture."]
        }))
        .expect("fixture json"),
    )
    .expect("write fixture");

    let outcome = run_assessment(&AssessOptions {
        target: dir.path().to_path_buf(),
        config_path: None,
        confidential: true,
        offline: true,
        run_id: Some("run-agentic-offline".to_owned()),
    })
    .expect("offline Agentic assessment");

    assert!(outcome.view_model.summary.offline);
    assert_eq!(outcome.view_model.summary.privacy_mode, "confidential");

    let metadata_path = outcome.run_dir.join("agentic-metadata.json");
    assert!(metadata_path.is_file());
    let metadata = fs::read_to_string(metadata_path).expect("agentic metadata");
    assert!(metadata.contains("UNASSESSED"));
    assert!(metadata.contains("NOT_TESTED"));
    assert!(!metadata.contains("\"assessment_state\": \"SECURE\""));

    let executive = fs::read_to_string(outcome.run_dir.join("reports/executive.html"))
        .expect("executive report");
    let technical = fs::read_to_string(outcome.run_dir.join("reports/technical.html"))
        .expect("technical report");
    for report in [&executive, &technical] {
        assert!(report.contains("Agentic Security Coverage"));
        assert!(report.contains("not treated as secure"));
        assert!(!report.contains("assessment state</th><th>SECURE"));
    }

    let privacy = fs::read_to_string(outcome.run_dir.join("evidence/privacy-mode.json"))
        .expect("privacy marker");
    let privacy: serde_json::Value = serde_json::from_str(&privacy).expect("privacy json");
    assert_eq!(privacy["telemetry"], false);
    assert_eq!(privacy["egress_denied"], true);
    assert_eq!(privacy["offline"], true);
}
