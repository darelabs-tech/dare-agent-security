use std::collections::BTreeMap;

use dare_continuous::{
    can_reuse, canonical::digest_value, load_fixture, CacheEntry, ContinuousValidationPolicy,
    ReuseCandidate, RunMode, ValidationCache,
};
use dare_security_evidence::Verdict;
use serde_json::json;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/continuous")
        .join(name)
}

#[test]
fn canonical_digest_is_key_order_stable() {
    let left = json!({"z": 1, "a": {"y": 2, "b": 3}});
    let right: serde_json::Value = serde_json::from_str(r#"{"a":{"b":3,"y":2},"z":1}"#).unwrap();
    assert_eq!(digest_value(&left).unwrap(), digest_value(&right).unwrap());
}

#[test]
fn reuse_denies_unknown_dependency() {
    let mut dependencies = BTreeMap::new();
    dependencies.insert("authorization".to_owned(), None);
    let decision = can_reuse(&ReuseCandidate {
        baseline_snapshot_digest: "sha256:baseline".to_owned(),
        expected_baseline_snapshot_digest: "sha256:baseline".to_owned(),
        original_evidence_ids: vec!["evidence-1".to_owned()],
        baseline_dependencies: dependencies.clone(),
        candidate_dependencies: dependencies,
    });
    assert!(!decision.allowed);
}

#[test]
fn cache_cannot_invent_pass_without_evidence() {
    let mut cache = ValidationCache::default();
    cache.insert(
        "property".to_owned(),
        CacheEntry {
            key_digest: "key".to_owned(),
            baseline_snapshot_digest: "baseline".to_owned(),
            verdict: Some(Verdict::Pass),
            evidence_ids: Vec::new(),
            dependency_digests: BTreeMap::new(),
        },
    );
    assert!(cache
        .get("property", "key", "baseline", &BTreeMap::new())
        .is_none());
}

#[test]
fn unknown_impact_expands_to_full_fallback() {
    let bundle = load_fixture(&fixture("unknown-impact.json")).unwrap();
    let report = dare_continuous::analyze(
        &bundle.baseline_snapshot,
        &bundle.candidate_snapshot,
        &ContinuousValidationPolicy::default(),
        RunMode::PlanOnly,
    )
    .unwrap();
    assert!(report.plan.full_fallback);
    assert!(report.revalidate_count >= 10);
    assert_eq!(report.reuse_count, 0);
}
