use std::fs;
use std::path::PathBuf;

use dare_coverage::{
    build_assessment_plan, builtin_profile, builtin_registry, correlate, load_profile,
    run_assessment, AssessmentFacts, CoveragePolicy, CoverageStatus, PropertyExecution,
};
use dare_security_evidence::Verdict;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/coverage")
}

fn load_facts(name: &str) -> AssessmentFacts {
    let raw = fs::read_to_string(fixtures_dir().join(name)).expect("facts");
    serde_json::from_str(&raw).expect("facts json")
}

#[test]
fn fixture_a_tools_and_static_roe_keeps_per_operation_applicable() {
    let facts = load_facts("fixture-a-tools-static-roe.json");
    let profile = builtin_profile().unwrap();
    let registry = builtin_registry().unwrap();
    let plan = build_assessment_plan(&profile, &registry, &facts).unwrap();
    let per_op = plan
        .properties
        .iter()
        .find(|p| p.property_id == "MCP.AUTHZ.PER_OPERATION")
        .unwrap();
    assert_eq!(per_op.coverage_status, CoverageStatus::Applicable);
    let dynamic = plan
        .properties
        .iter()
        .find(|p| p.property_id == "MCP.AUTHZ.DYNAMIC_VALIDATION")
        .unwrap();
    assert_eq!(dynamic.coverage_status, CoverageStatus::Blocked);
    assert_ne!(dynamic.coverage_status, CoverageStatus::NotApplicable);
}

#[test]
fn fixture_b_stdio_marks_http_property_not_applicable() {
    let facts = load_facts("fixture-b-stdio.json");
    let profile = builtin_profile().unwrap();
    let registry = builtin_registry().unwrap();
    let plan = build_assessment_plan(&profile, &registry, &facts).unwrap();
    let http = plan
        .properties
        .iter()
        .find(|p| p.property_id == "MCP.DISCOVERY.STREAMABLE_HTTP")
        .unwrap();
    assert_eq!(http.coverage_status, CoverageStatus::NotApplicable);
}

#[test]
fn fixture_c_dynamic_roe_blocks_dynamic_property() {
    let facts = load_facts("fixture-c-dynamic-blocked.json");
    let profile = builtin_profile().unwrap();
    let registry = builtin_registry().unwrap();
    let plan = build_assessment_plan(&profile, &registry, &facts).unwrap();
    let dynamic = plan
        .properties
        .iter()
        .find(|p| p.property_id == "MCP.AUTHZ.DYNAMIC_VALIDATION")
        .unwrap();
    assert_eq!(dynamic.coverage_status, CoverageStatus::Blocked);
}

#[test]
fn missing_execution_finalizes_applicable_to_not_tested() {
    let facts = load_facts("fixture-a-tools-static-roe.json");
    let report = run_assessment(
        &builtin_profile().unwrap(),
        &builtin_registry().unwrap(),
        &facts,
        &[],
        CoveragePolicy::default(),
    )
    .unwrap();
    assert!(report
        .properties
        .iter()
        .any(|p| p.property_id == "MCP.DISCOVERY.PASSIVE_BOUNDARY"
            && p.coverage_status == CoverageStatus::NotTested));
}

#[test]
fn evidence_correlation_attaches_cycle001_ids() {
    let facts = load_facts("fixture-a-tools-static-roe.json");
    let profile = builtin_profile().unwrap();
    let registry = builtin_registry().unwrap();
    let plan = build_assessment_plan(&profile, &registry, &facts).unwrap();
    let executions = vec![PropertyExecution {
        property_id: "MCP.DISCOVERY.PASSIVE_BOUNDARY".to_owned(),
        verdict: Some(Verdict::Pass),
        evidence_ids: vec!["evidence-passive-1".to_owned()],
    }];
    let rows = correlate(&plan, &executions).unwrap();
    let row = rows
        .iter()
        .find(|r| r.property_id == "MCP.DISCOVERY.PASSIVE_BOUNDARY")
        .unwrap();
    assert_eq!(row.coverage_status, CoverageStatus::Applicable);
    assert_eq!(row.verdict, Some(Verdict::Pass));
    assert_eq!(row.evidence_ids, vec!["evidence-passive-1"]);
}

#[test]
fn profile_files_are_data_not_code() {
    let raw = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../profiles/mcp-security-baseline.json"),
    )
    .unwrap();
    assert!(!raw.contains("eval"));
    assert!(!raw.contains("{{"));
    load_profile(&raw).unwrap();
}
