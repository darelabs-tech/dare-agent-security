//! The `blast-radius-2026` CI job (Cycle 024 task-025): it keeps the workflow's
//! PR-open trigger, runs the lab, the refusal corpus and the release-mode
//! scale test, and references no secret and no network target.
use std::path::Path;

fn workflow() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml"),
    )
    .expect("ci.yml")
}

/// The job's lines, from its key to the next job key.
fn job(ci: &str, name: &str) -> String {
    let start = format!("  {name}:");
    let mut lines = ci.lines().skip_while(|l| *l != start);
    let mut out = vec![lines.next().expect("job present").to_owned()];
    out.extend(
        lines
            .take_while(|l| {
                !(l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':'))
            })
            .map(str::to_owned),
    );
    out.join("\n")
}

#[test]
fn the_workflow_keeps_its_pull_request_opened_trigger() {
    let ci = workflow();
    let head: Vec<&str> = ci.lines().take(8).collect();
    let head = head.join("\n");
    assert!(head.contains("pull_request:"), "{head}");
    assert!(head.contains("types: [opened]"), "{head}");
    assert!(
        ci.contains("  remote-validation-2026:") && ci.contains("  attack-path-2026:"),
        "earlier gates are kept"
    );
}

#[test]
fn the_job_runs_the_lab_the_refusal_corpus_and_scale_in_release() {
    let job = job(&workflow(), "blast-radius-2026");
    for step in [
        "cargo test -p dare-agent-security --test blast_radius_lab",
        "cargo test -p dare-agent-security --test blast_radius_cli",
        "cargo test -p dare-blast-radius --release --test scale",
        "cargo test -p dare-blast-radius --test classify",
        "cargo test -p dare-agent-security --test attack_path_goldens",
        "cargo test -p dare-agent-security --test attack_path_lab",
        "python scripts/k24/assert_no_real_credentials.py",
    ] {
        assert!(job.contains(step), "missing step: {step}");
    }
}

#[test]
fn the_job_references_no_secret_and_no_network_target() {
    let job = job(&workflow(), "blast-radius-2026");
    assert!(job.lines().count() > 20, "the job was found");
    for forbidden in [
        "secrets.",
        "http://",
        "https://",
        "curl ",
        "wget ",
        "--mode live",
        "validate remote ",
    ] {
        assert!(!job.contains(forbidden), "the job references `{forbidden}`");
    }
    // Every action it uses is pinned to a major version from the workflow's
    // existing set; no new third-party action.
    for line in job.lines().filter(|l| l.contains("uses:")) {
        assert!(
            line.contains("actions/checkout@v4") || line.contains("dtolnay/rust-toolchain@stable"),
            "{line}"
        );
    }
}
