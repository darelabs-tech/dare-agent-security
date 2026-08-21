//! Product security hardening tests (redaction, offline egress, path traversal, HTML).

use dare_product::{
    assert_no_secrets, escape_html, redact_product_text, run_assessment, validate_safe_segment,
    AssessOptions, EgressGuard, NetworkClass, PrivacyPolicy,
};
use tempfile::tempdir;

#[test]
fn redaction_removes_secret_classes() {
    let samples = [
        "Authorization: Bearer sk-live-ABCDEFGHIJKLMNOPQRSTUVWX",
        "API_KEY=supersecretvalue0123456789",
        "password=hunter2hunter2hunter2",
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
        "COOKIE=session=abc; TOKEN=xyz",
    ];
    for sample in samples {
        let out = redact_product_text(sample);
        assert_no_secrets("redaction", &out)
            .unwrap_or_else(|e| panic!("{e} from {sample} -> {out}"));
        assert!(
            !out.to_ascii_lowercase()
                .contains("sk-live-abcdefghijklmnop"),
            "{out}"
        );
    }
}

#[test]
fn html_injection_is_escaped() {
    let evil = r#"<img src=x onerror="alert(1)">"#;
    let escaped = escape_html(evil);
    assert!(!escaped.contains("<img"));
    assert!(escaped.contains("&lt;img"));
}

#[test]
fn path_traversal_run_ids_rejected() {
    assert!(validate_safe_segment("../secret").is_err());
    assert!(validate_safe_segment("..\\secret").is_err());
    assert!(validate_safe_segment("a/b").is_err());
}

#[test]
fn offline_confidential_denies_egress_classes() {
    let mut policy = PrivacyPolicy::default();
    policy.apply_flags(true, true);
    assert!(policy.prohibits_egress());
    assert!(!policy.telemetry);
    let mut guard = EgressGuard::from_policy(&policy);
    assert!(guard.check(NetworkClass::Telemetry, "analytics").is_err());
    assert!(guard.check(NetworkClass::ModelApi, "llm").is_err());
    assert!(guard.check(NetworkClass::Public, "update").is_err());
}

#[test]
fn assess_confidential_writes_privacy_marker() {
    let dir = tempdir().unwrap();
    dare_product::init_project(dir.path(), &dare_product::InitOptions::default()).unwrap();
    let outcome = run_assessment(&AssessOptions {
        target: dir.path().to_path_buf(),
        config_path: None,
        confidential: true,
        offline: true,
        run_id: Some("run-sec-001".into()),
    })
    .unwrap();
    let marker =
        std::fs::read_to_string(outcome.run_dir.join("evidence/privacy-mode.json")).unwrap();
    assert!(marker.contains("\"telemetry\": false"));
    assert!(marker.contains("\"egress_denied\": true"));
    let html = std::fs::read_to_string(outcome.run_dir.join("reports/executive.html")).unwrap();
    assert!(html.contains("CONFIDENTIAL") || html.contains("Classification"));
    assert!(!html.to_ascii_lowercase().contains("<script"));
}
