use dare_coverage::{
    builtin_profile, builtin_registry, load_profile, profile_digest_sha256, validate_pair,
    validate_profile, AssessmentProfile, CoverageStatus, ProfileProperty, RequirementLevel,
};
use dare_security_evidence::Verdict;
use serde_json::json;

#[test]
fn property_injection_unknown_id_fails() {
    let registry = builtin_registry().unwrap();
    let mut profile = builtin_profile().unwrap();
    profile.properties.push(ProfileProperty {
        id: "MCP.INJECTED.PWN".to_owned(),
        requirement: RequirementLevel::Required,
    });
    assert!(validate_profile(&profile, &registry).is_err());
}

#[test]
fn duplicate_ids_in_profile_fail() {
    let mut profile = builtin_profile().unwrap();
    let first = profile.properties[0].clone();
    profile.properties.push(first);
    let registry = builtin_registry().unwrap();
    assert!(validate_profile(&profile, &registry).is_err());
}

#[test]
fn silent_property_deletion_changes_digest() {
    let profile = builtin_profile().unwrap();
    let before = profile_digest_sha256(&profile).unwrap();
    let mut deleted = profile.clone();
    deleted.properties.pop();
    let after = profile_digest_sha256(&deleted).unwrap();
    assert_ne!(before, after);
}

#[test]
fn status_relabel_blocked_as_not_applicable_is_invalid_if_verdict_present() {
    assert!(validate_pair(CoverageStatus::NotApplicable, Some(Verdict::Pass), true).is_err());
}

#[test]
fn denominator_cannot_include_not_applicable() {
    use dare_coverage::eligible_count;
    assert!(!eligible_count(CoverageStatus::NotApplicable, None));
}

#[test]
fn profile_schema_rejects_code_like_extra_fields() {
    let mut value = json!({
        "schema": {
            "id": "https://darelabs.tech/schemas/coverage/v1/profile.schema.json",
            "version": "1.0.0"
        },
        "id": "evil",
        "version": "1.0.0",
        "properties": [{ "id": "MCP.DISCOVERY.PASSIVE_BOUNDARY", "requirement": "REQUIRED" }],
        "script": "rm -rf /"
    });
    assert!(dare_coverage::load_profile(&value.to_string()).is_err());
    value.as_object_mut().unwrap().remove("script");
    let parsed: AssessmentProfile = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.id, "evil");
}

#[test]
fn load_profile_rejects_unknown_requirement() {
    let raw = r#"{
      "schema": {"id":"https://darelabs.tech/schemas/coverage/v1/profile.schema.json","version":"1.0.0"},
      "id": "x",
      "version": "1.0.0",
      "properties": [{"id":"MCP.DISCOVERY.PASSIVE_BOUNDARY","requirement":"WHATEVER"}]
    }"#;
    assert!(load_profile(raw).is_err());
}
