//! Cycle 004 task-002: deterministic CI result contract acceptance tests.

use std::path::PathBuf;

use dare_agent_security::ci_result::{
    aggregate_verdict, build_ci_result, collect_evidence_verdicts, process_exit_code,
    validate_ci_result, ActionMode, EvidenceCounts, CI_RESULT_SCHEMA_V1_ID,
};
use dare_security_evidence::Verdict;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn evidence_fixture(name: &str) -> PathBuf {
    repo_root().join(format!("examples/evidence/{name}.json"))
}

#[test]
fn contract_pass_from_pass_evidence() {
    let paths = vec![evidence_fixture("pass")];
    let (counts, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Pass);
    assert_eq!(counts.pass, 1);
    assert_eq!(process_exit_code(aggregate, true), 0);
}

#[test]
fn contract_fail_from_fail_evidence() {
    let paths = vec![evidence_fixture("fail")];
    let (_, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Fail);
    assert_eq!(process_exit_code(aggregate, true), 2);
}

#[test]
fn contract_inconclusive_from_inconclusive_evidence() {
    let paths = vec![evidence_fixture("inconclusive")];
    let (_, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Inconclusive);
    assert_ne!(aggregate, Verdict::Pass);
    assert_eq!(process_exit_code(aggregate, true), 2);
    assert_eq!(process_exit_code(aggregate, false), 0);
}

#[test]
fn contract_error_from_error_evidence() {
    let paths = vec![evidence_fixture("error")];
    let (_, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Error);
    assert_eq!(process_exit_code(aggregate, true), 1);
}

#[test]
fn contract_mixed_evidence_uses_precedence() {
    let paths = vec![
        evidence_fixture("pass"),
        evidence_fixture("fail"),
        evidence_fixture("inconclusive"),
    ];
    let (counts, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Fail);
    assert_eq!(counts.pass, 1);
    assert_eq!(counts.fail, 1);
    assert_eq!(counts.inconclusive, 1);
}

#[test]
fn contract_no_evidence_is_inconclusive() {
    let result = build_ci_result(ActionMode::Discover, ".dare-agent-security", &[], true);
    assert_eq!(result.aggregate_verdict, Verdict::Inconclusive);
    assert_eq!(result.evidence_counts.total(), 0);
    assert_eq!(result.process_exit_code, 2);
    validate_ci_result(&result).expect("schema-valid no-evidence result");
}

#[test]
fn contract_malformed_evidence_yields_error_aggregate() {
    let bad = repo_root().join("examples/ci/malformed-evidence.json");
    let paths = vec![bad];
    let (counts, valid, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Error);
    assert_eq!(counts.error, 1);
    assert!(valid.is_empty());
}

#[test]
fn contract_built_result_matches_schema_and_github_outputs() {
    let paths = vec![evidence_fixture("pass")];
    let result = build_ci_result(ActionMode::Validate, ".dare-agent-security", &paths, true);
    validate_ci_result(&result).expect("valid ci result");
    assert_eq!(result.schema.id, CI_RESULT_SCHEMA_V1_ID);
    assert_eq!(result.github_outputs.verdict, Verdict::Pass);
    assert!(!result.github_outputs.summary_path.is_empty());
}

#[test]
fn contract_error_beats_pass_in_mixed_set() {
    let paths = vec![evidence_fixture("pass"), evidence_fixture("error")];
    let counts = EvidenceCounts {
        pass: 1,
        error: 1,
        ..Default::default()
    };
    assert_eq!(aggregate_verdict(&counts), Verdict::Error);
    let (_, _, aggregate) = collect_evidence_verdicts(&paths);
    assert_eq!(aggregate, Verdict::Error);
}

#[test]
fn contract_schema_artifact_exists() {
    let schema = repo_root().join("schemas/ci/v1/ci-result.schema.json");
    assert!(schema.is_file());
    let doc = repo_root().join("docs/ci-result-contract.md");
    assert!(doc.is_file());
}
