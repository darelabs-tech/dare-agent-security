use std::{collections::BTreeMap, path::PathBuf};

use dare_continuous::{
    analyze, can_reuse, load_fixture, CacheEntry, ContinuousValidationPolicy, GateDecision,
    ReuseCandidate, RunMode, ValidationCache, ValidationMode,
};
use dare_security_evidence::Verdict;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/continuous")
        .join(name)
}

#[test]
fn stale_baseline_substitution_is_denied() {
    let decision = can_reuse(&ReuseCandidate {
        baseline_snapshot_digest: "sha256:attacker".to_owned(),
        expected_baseline_snapshot_digest: "sha256:trusted".to_owned(),
        original_evidence_ids: vec!["evidence-1".to_owned()],
        baseline_dependencies: BTreeMap::new(),
        candidate_dependencies: BTreeMap::new(),
    });
    assert!(!decision.allowed);
}

#[test]
fn omitted_dependency_denies_reuse() {
    let baseline = BTreeMap::from([
        ("inventory".to_owned(), Some("digest-a".to_owned())),
        ("authorization".to_owned(), Some("digest-b".to_owned())),
    ]);
    let candidate = BTreeMap::from([("inventory".to_owned(), Some("digest-a".to_owned()))]);
    assert!(
        !can_reuse(&ReuseCandidate {
            baseline_snapshot_digest: "baseline".to_owned(),
            expected_baseline_snapshot_digest: "baseline".to_owned(),
            original_evidence_ids: vec!["evidence-1".to_owned()],
            baseline_dependencies: baseline,
            candidate_dependencies: candidate,
        })
        .allowed
    );
}

#[test]
fn cache_poisoning_key_mismatch_is_rejected() {
    let mut cache = ValidationCache::default();
    cache.insert(
        "property".to_owned(),
        CacheEntry {
            key_digest: "attacker-key".to_owned(),
            baseline_snapshot_digest: "trusted-baseline".to_owned(),
            verdict: Some(Verdict::Pass),
            evidence_ids: vec!["evidence-1".to_owned()],
            dependency_digests: BTreeMap::new(),
        },
    );
    assert!(cache
        .get(
            "property",
            "expected-key",
            "trusted-baseline",
            &BTreeMap::new()
        )
        .is_none());
}

#[test]
fn policy_downgrade_cannot_disable_unknown_fallback() {
    let policy = ContinuousValidationPolicy {
        fallback_full_on_unknown: false,
        ..ContinuousValidationPolicy::default()
    };
    assert!(policy.validate_safety().is_err());
}

#[test]
fn dynamic_approval_is_never_inferred() {
    let bundle = load_fixture(&fixture("dynamic-approval.json")).unwrap();
    let policy = bundle.policy.unwrap();
    assert!(!policy
        .dynamic
        .auto_modes
        .contains(&ValidationMode::AuthorizedDynamic));
    assert!(policy
        .dynamic
        .require_approval
        .contains(&ValidationMode::AuthorizedDynamic));
    let report = analyze(
        &bundle.baseline_snapshot,
        &bundle.candidate_snapshot,
        &policy,
        RunMode::Revalidate,
    )
    .unwrap();
    assert!(!report.dynamic_approval_granted);
}

#[test]
fn false_reuse_is_revalidated_and_regression_fails() {
    let invalid = load_fixture(&fixture("invalid-reuse.json")).unwrap();
    let report = analyze(
        &invalid.baseline_snapshot,
        &invalid.candidate_snapshot,
        &invalid.policy.unwrap(),
        RunMode::Revalidate,
    )
    .unwrap();
    let run = report.run.unwrap();
    assert!(run
        .records
        .iter()
        .any(|record| record.reason.contains("reuse denied")));

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
