use std::path::PathBuf;

use dare_continuous::{analyze, load_fixture, DriftDisposition, GateDecision, PlanAction, RunMode};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/continuous")
        .join(name)
}

#[test]
fn all_continuous_lab_fixtures_load_and_execute_offline() {
    for name in [
        "unrelated-change.json",
        "tool-change.json",
        "destructive-capability.json",
        "auth-fix.json",
        "coverage-degradation.json",
        "unknown-impact.json",
        "invalid-reuse.json",
        "dynamic-approval.json",
    ] {
        let bundle = load_fixture(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let policy = bundle.policy.unwrap_or_default();
        let report = analyze(
            &bundle.baseline_snapshot,
            &bundle.candidate_snapshot,
            &policy,
            RunMode::Revalidate,
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(!report.dynamic_approval_granted, "{name}");
    }
}

#[test]
fn fixture_expectations_match_security_semantics() {
    let unrelated = load_fixture(&fixture("unrelated-change.json")).unwrap();
    let report = analyze(
        &unrelated.baseline_snapshot,
        &unrelated.candidate_snapshot,
        &unrelated.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert_eq!(report.gate.decision, GateDecision::Pass);
    assert!(report
        .plan
        .items
        .iter()
        .all(|item| item.action == PlanAction::Reuse));

    let unknown = load_fixture(&fixture("unknown-impact.json")).unwrap();
    let report = analyze(
        &unknown.baseline_snapshot,
        &unknown.candidate_snapshot,
        &unknown.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert!(report.plan.full_fallback);

    let fixed = load_fixture(&fixture("auth-fix.json")).unwrap();
    let report = analyze(
        &fixed.baseline_snapshot,
        &fixed.candidate_snapshot,
        &fixed.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert_eq!(report.drift.disposition, DriftDisposition::Improved);

    let degraded = load_fixture(&fixture("coverage-degradation.json")).unwrap();
    let report = analyze(
        &degraded.baseline_snapshot,
        &degraded.candidate_snapshot,
        &degraded.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert_eq!(report.gate.decision, GateDecision::Fail);
}

#[test]
fn incremental_plan_is_smaller_than_full_fallback() {
    let tool = load_fixture(&fixture("tool-change.json")).unwrap();
    let incremental = analyze(
        &tool.baseline_snapshot,
        &tool.candidate_snapshot,
        &tool.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    let unknown = load_fixture(&fixture("unknown-impact.json")).unwrap();
    let full = analyze(
        &unknown.baseline_snapshot,
        &unknown.candidate_snapshot,
        &unknown.policy.unwrap(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert!(incremental.revalidate_count < full.revalidate_count);
}
