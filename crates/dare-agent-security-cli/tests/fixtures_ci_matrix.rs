//! Cycle 004 task-007: synthetic Action fixture matrix.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn fixture_matrix_documents_four_aggregate_classes() {
    let matrix_path = repo_root().join("fixtures/ci/matrix.json");
    let raw = fs::read_to_string(&matrix_path).expect("matrix.json");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let cases = value["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 4);
    let verdicts: Vec<_> = cases
        .iter()
        .filter_map(|c| c["expected_verdict"].as_str())
        .collect();
    for expected in ["PASS", "FAIL", "INCONCLUSIVE"] {
        assert!(
            verdicts.contains(&expected),
            "missing expected verdict {expected}"
        );
    }
}

#[test]
fn fixture_readme_and_entrypoint_aliases_align() {
    let readme = fs::read_to_string(repo_root().join("fixtures/ci/README.md")).expect("readme");
    let entry = fs::read_to_string(repo_root().join("action/entrypoint.sh")).expect("entrypoint");
    for alias in [
        "secure-pass",
        "fail-stale-permit",
        "inconclusive-empty",
        "synthetic-mcp",
    ] {
        assert!(readme.contains(alias), "readme missing {alias}");
        assert!(entry.contains(alias), "entrypoint missing {alias}");
    }
}
