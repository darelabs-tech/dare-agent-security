use std::fs;
use std::path::PathBuf;

use dare_coverage::{
    agentic_profile, agentic_registry, load_registry, registry_for_profile, run_assessment,
    validate_agentic_assets, validate_profile, validate_property_instance_v2, AssessmentFacts,
    CoveragePolicy, RiskFamily,
};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/coverage")
        .join(name)
}

#[test]
fn agentic_assets_and_all_ten_families_validate_offline() {
    validate_agentic_assets().expect("agentic assets");
    let registry = agentic_registry().expect("registry");
    let profile = agentic_profile().expect("profile");
    validate_profile(&profile, &registry).expect("profile");

    let families: std::collections::HashSet<RiskFamily> = registry
        .properties
        .iter()
        .filter_map(|property| property.risk_family)
        .collect();
    assert_eq!(families.len(), 10);
    assert_eq!(profile.properties.len(), 10);
}

#[test]
fn agentic_baseline_is_consumable_by_existing_coverage_engine() {
    let raw = fs::read_to_string(fixture("agentic-all-capabilities.json")).expect("facts");
    let facts: AssessmentFacts = serde_json::from_str(&raw).expect("typed facts");
    let profile = agentic_profile().expect("profile");
    let registry = registry_for_profile(&profile).expect("registry");
    let report = run_assessment(&profile, &registry, &facts, &[], CoveragePolicy::default())
        .expect("coverage report");

    assert_eq!(report.profile_id, "agentic-security-baseline-2026");
    assert_eq!(report.properties.len(), 10);
    assert!(report.properties.iter().all(|row| {
        matches!(
            row.status,
            dare_coverage::CoverageStatus::NotTested
                | dare_coverage::CoverageStatus::Blocked
                | dare_coverage::CoverageStatus::NotApplicable
        )
    }));
}

#[test]
fn hostile_property_and_registry_fixtures_fail_closed() {
    let raw = fs::read_to_string(fixture("agentic-hostile-cases.json")).expect("hostile fixture");
    let cases: Value = serde_json::from_str(&raw).expect("hostile json");

    for case in cases["property_cases"].as_array().expect("property cases") {
        let name = case["name"].as_str().unwrap_or("unnamed");
        assert!(
            validate_property_instance_v2(&case["instance"]).is_err(),
            "property hostile case unexpectedly accepted: {name}"
        );
    }

    for case in cases["registry_cases"].as_array().expect("registry cases") {
        let name = case["name"].as_str().unwrap_or("unnamed");
        let registry = serde_json::to_string(&case["registry"]).expect("registry serialization");
        assert!(
            load_registry(&registry).is_err(),
            "registry hostile case unexpectedly accepted: {name}"
        );
    }
}
