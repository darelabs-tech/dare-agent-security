//! `validate remote` and `validate replay-capture` at the process boundary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/remote-replay")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(root())
        .env_remove("DARE_REMOTE_LAB_TOKEN")
        .output()
        .expect("runs")
}

const FORBIDDEN: [&str; 17] = [
    "--url",
    "--endpoint",
    "--header",
    "--token",
    "--api-key",
    "--bearer",
    "--proxy",
    "--insecure",
    "--no-verify",
    "--ca",
    "--follow-redirects",
    "--model",
    "--provider",
    "--seed",
    "--generate",
    "--shell",
    "--yes",
];

#[test]
fn the_help_offers_no_flag_that_could_widen_scope() {
    for sub in ["remote", "replay-capture"] {
        let help = String::from_utf8(run(&["validate", sub, "--help"]).stdout).unwrap();
        assert!(help.contains("--output-dir"), "{sub}");
        for flag in FORBIDDEN {
            assert!(
                !help.contains(&format!("{flag} ")) && !help.contains(&format!("{flag}\n")),
                "{sub} offers {flag}"
            );
            let out = run(&["validate", sub, flag, "x"]);
            assert_ne!(out.status.code(), Some(0), "{sub} accepted {flag}");
        }
    }
    let help = String::from_utf8(run(&["validate", "remote", "--help"]).stdout).unwrap();
    assert!(help.contains("not a claim") && help.contains("--confirm-origin"));
}

#[test]
fn a_refusal_exits_3_and_writes_nothing() {
    let out_dir = tempfile::tempdir().unwrap();
    let target = out_dir.path().join("out");
    // A confirmation for another origin (and no credential variable) is
    // refused by verification, before anything is sent.
    let out = run(&[
        "validate",
        "remote",
        "--authorization",
        fixture("authorization.json").to_str().unwrap(),
        "--plan",
        fixture("plan.json").to_str().unwrap(),
        "--confirm-origin",
        "https://127.0.0.1:1",
        "--output-dir",
        target.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!target.exists(), "nothing written");
    assert!(out.stdout.is_empty());
}

#[test]
fn a_raised_limit_is_refused() {
    let target = tempfile::tempdir().unwrap().path().join("out");
    let out = run(&[
        "validate",
        "remote",
        "--authorization",
        fixture("authorization.json").to_str().unwrap(),
        "--plan",
        fixture("plan.json").to_str().unwrap(),
        "--confirm-origin",
        "https://127.0.0.1:1",
        "--output-dir",
        target.to_str().unwrap(),
        "--max-rps",
        "0",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!target.exists());
}

#[test]
fn replay_capture_reproduces_the_committed_result_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out");
    let out = run(&[
        "validate",
        "replay-capture",
        "--capture",
        fixture("capture.json").to_str().unwrap(),
        "--audit",
        fixture("audit.json").to_str().unwrap(),
        "--authorization",
        fixture("authorization.json").to_str().unwrap(),
        "--plan",
        fixture("plan.json").to_str().unwrap(),
        "--output-dir",
        target.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "FAIL exits 2: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("remote-result verdict FAIL"));
    let mut names: Vec<String> = std::fs::read_dir(&target)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "remote-audit.json",
            "remote-capture.json",
            "remote-coverage.json",
            "remote-evidence.json",
            "remote-result.json",
            "summary.md"
        ]
    );
    assert_eq!(
        std::fs::read(target.join("remote-result.json")).unwrap(),
        std::fs::read(fixture("expected-result.json")).unwrap()
    );
}

#[test]
fn replay_capture_refuses_a_tampered_capture_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let tampered = dir.path().join("capture.json");
    let text = std::fs::read_to_string(fixture("capture.json")).unwrap();
    std::fs::write(
        &tampered,
        text.replacen("\"refusal\\\":true", "\"refusal\\\":false", 1)
            .replacen("\"elapsed_ms\": ", "\"elapsed_ms\": 1", 1),
    )
    .unwrap();
    let target = dir.path().join("out");
    let out = run(&[
        "validate",
        "replay-capture",
        "--capture",
        tampered.to_str().unwrap(),
        "--audit",
        fixture("audit.json").to_str().unwrap(),
        "--authorization",
        fixture("authorization.json").to_str().unwrap(),
        "--plan",
        fixture("plan.json").to_str().unwrap(),
        "--output-dir",
        target.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!target.exists());
}

fn replay_into(target: &Path) {
    let out = run(&[
        "validate",
        "replay-capture",
        "--capture",
        fixture("capture.json").to_str().unwrap(),
        "--audit",
        fixture("audit.json").to_str().unwrap(),
        "--authorization",
        fixture("authorization.json").to_str().unwrap(),
        "--plan",
        fixture("plan.json").to_str().unwrap(),
        "--output-dir",
        target.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
}

fn coverage(executions: &Path, facts: &Path, out: &Path) -> Output {
    run(&[
        "validate",
        "coverage",
        "--profile",
        "multi-turn-security-baseline-2026",
        "--facts",
        facts.to_str().unwrap(),
        "--executions",
        executions.to_str().unwrap(),
        "--output-dir",
        out.to_str().unwrap(),
    ])
}

#[test]
fn remote_evidence_feeds_the_coverage_report_as_dynamic() {
    let dir = tempfile::tempdir().unwrap();
    let replayed = dir.path().join("replayed");
    replay_into(&replayed);
    let report_dir = dir.path().join("coverage");
    let out = coverage(
        &replayed.join("remote-coverage.json"),
        &fixture("coverage-facts.json"),
        &report_dir,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report_dir.join("coverage-report.json")).unwrap())
            .unwrap();
    let evidence: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(replayed.join("remote-evidence.json")).unwrap())
            .unwrap();
    let ids: Vec<&str> = evidence.iter().map(|r| r["id"].as_str().unwrap()).collect();
    // Seven properties, all decided from the remote records; the eroded
    // refusal is the FAIL, and no property or denominator was added.
    assert_eq!(
        (report["eligible"].as_u64(), report["tested"].as_u64()),
        (Some(7), Some(7))
    );
    for row in report["properties"].as_array().unwrap() {
        let rationale = row["rationale"].as_str().unwrap();
        assert!(
            rationale.contains("dynamic evidence from remote run under authorization lab-auth-1"),
            "{rationale}"
        );
        for id in row["evidence_ids"].as_array().unwrap() {
            assert!(ids.contains(&id.as_str().unwrap()));
        }
        let expected = if row["property_id"] == "AGENT.GOAL.REFUSAL_PERSISTENCE" {
            "FAIL"
        } else {
            "INCONCLUSIVE"
        };
        assert_eq!(row["verdict"], expected, "{}", row["property_id"]);
    }
}

#[test]
fn remote_evidence_is_refused_against_facts_that_deny_dynamic_testing() {
    let dir = tempfile::tempdir().unwrap();
    let replayed = dir.path().join("replayed");
    replay_into(&replayed);
    let mut facts: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("coverage-facts.json")).unwrap()).unwrap();
    facts["dynamic_authorization_allowed"] = false.into();
    let facts_path = dir.path().join("facts.json");
    std::fs::write(&facts_path, facts.to_string()).unwrap();
    let report_dir = dir.path().join("coverage");
    let out = coverage(
        &replayed.join("remote-coverage.json"),
        &facts_path,
        &report_dir,
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "a contradiction is a usage error"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("deny dynamic authorization"));
    assert!(!report_dir.exists());
}
