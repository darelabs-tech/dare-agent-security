//! Cycle 003 standards snapshot fixture tests.

use dare_coaz_integrity::{
    cycle003_standards_snapshot, reference_key, required_reference_keys, StandardStatus,
    STANDARDS_SNAPSHOT_FIXTURE_ID,
};

#[test]
fn cycle003_standards_snapshot_contains_required_references() {
    let snapshot = cycle003_standards_snapshot();
    let keys: Vec<String> = snapshot.references.iter().map(reference_key).collect();

    for required in required_reference_keys() {
        assert!(
            keys.iter().any(|key| key == required),
            "missing required standards reference: {required}; got {keys:?}"
        );
    }

    assert_eq!(snapshot.executable_scope.mcp_method_scope, "tools/call");
    assert!(snapshot
        .executable_scope
        .lifecycle_skew_note
        .contains("lifecycle"));
}

#[test]
fn authzen_603_is_open_proposal_not_normative() {
    let snapshot = cycle003_standards_snapshot();
    let issue = snapshot
        .references
        .iter()
        .find(|reference| {
            reference
                .upstream_issue
                .as_deref()
                .is_some_and(|issue| issue == "openid/authzen#603")
        })
        .expect("authzen#603 reference");
    assert_eq!(issue.status, StandardStatus::OpenProposal);
}

#[test]
fn standards_snapshot_fixture_round_trips() {
    let snapshot = cycle003_standards_snapshot();
    let json = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
    let path = format!("../../examples/coaz-integrity/{STANDARDS_SNAPSHOT_FIXTURE_ID}.json");
    std::fs::write(&path, format!("{json}\n")).expect("refresh fixture");
    let fixture = std::fs::read_to_string(&path).expect("fixture file");
    let from_fixture: dare_coaz_integrity::StandardsSnapshot =
        serde_json::from_str(&fixture).expect("parse fixture");
    assert_eq!(from_fixture, snapshot);
    assert!(json.contains("openid/authzen#603"));
}
