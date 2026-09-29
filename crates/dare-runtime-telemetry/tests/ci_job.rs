//! The `runtime-telemetry-2026` CI job (Cycle 025 task-028): it keeps the
//! workflow's trigger, runs the lab, the refusal corpus, the release-mode
//! scale test, the coverage and BQ-1 pins and the Cycle 023/024 goldens and
//! labs, and references no secret, no network target and no collector.
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
fn the_workflow_keeps_its_pull_request_opened_trigger_and_earlier_gates() {
    let ci = workflow();
    let head = ci.lines().take(8).collect::<Vec<_>>().join("\n");
    assert!(head.contains("pull_request:"), "{head}");
    assert!(
        head.contains("types: [opened, synchronize, reopened]"),
        "{head}"
    );
    // R-9 (b) and the follow-up: pull-request events plus a manual run, and
    // no other trigger.
    let on = &ci[ci.find("\non:").expect("on:")..ci.find("\npermissions:").expect("permissions:")];
    assert!(on.contains("  workflow_dispatch:"), "{on}");
    for other in ["push:", "schedule:", "pull_request_target", "release:"] {
        assert!(!on.contains(other), "{other} in {on}");
    }
    for earlier in [
        "  remote-validation-2026:",
        "  attack-path-2026:",
        "  blast-radius-2026:",
    ] {
        assert!(ci.contains(earlier), "{earlier} was removed");
    }
}

#[test]
fn the_job_runs_every_cycle_025_gate() {
    let job = job(&workflow(), "runtime-telemetry-2026");
    for step in [
        "cargo test -p dare-runtime-telemetry --lib",
        "cargo test -p dare-runtime-telemetry --test otel_lab",
        "cargo test -p dare-runtime-telemetry --test no_value_leaves",
        "cargo test -p dare-runtime-telemetry --test determinism",
        "cargo test -p dare-runtime-telemetry --test hostile",
        "cargo test -p dare-runtime-telemetry --release --test scale",
        "cargo test -p dare-agent-security --test runtime_telemetry_cli",
        "cargo test -p dare-agent-security --test runtime_telemetry_refusals",
        "cargo test -p dare-coverage --test runtime_telemetry_properties",
        "cargo test -p dare-coverage --test runtime_telemetry_profile",
        "cargo test -p dare-remote-validation --test compatibility",
        "cargo test -p dare-agent-security --test attack_path_compatibility",
        "cargo test -p dare-attack-path --test projection_tables",
        "cargo test -p dare-agent-security --test attack_path_goldens",
        "cargo test -p dare-agent-security --test attack_path_lab",
        "cargo test -p dare-agent-security --test blast_radius_lab",
        "python scripts/k25/assert_no_real_credentials.py",
        "python scripts/k25/verify_proof_citations.py",
    ] {
        assert!(job.contains(step), "missing step: {step}");
    }
}

#[test]
fn the_job_references_no_secret_no_network_target_and_no_collector() {
    let job = job(&workflow(), "runtime-telemetry-2026");
    assert!(job.lines().count() > 30, "the job was found");
    for forbidden in [
        "secrets.",
        "http://",
        "https://",
        "curl ",
        "wget ",
        "OTEL_EXPORTER",
        "OTEL_",
        ":4317",
        ":4318",
        "--endpoint",
        "--collector",
        "otelcol",
        "services:",
    ] {
        assert!(!job.contains(forbidden), "the job references `{forbidden}`");
    }
    for line in job.lines().filter(|l| l.contains("uses:")) {
        assert!(
            line.contains("actions/checkout@v4") || line.contains("dtolnay/rust-toolchain@stable"),
            "{line}"
        );
    }
}
