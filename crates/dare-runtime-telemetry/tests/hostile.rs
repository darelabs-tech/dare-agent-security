//! RF-12 hostile corpus (task-025). Each fixture is refused or neutralized,
//! every run stays within its bounds, and no value is echoed.
mod support;

use std::{fs, io::Write};

use dare_attack_graph::v2::sweep::is_sensitive;
use dare_runtime_telemetry::{
    corpus::{lab_policy, run_case, span_id, write_files, LabCase, SimTrace},
    evaluate::Rule,
    limits::{Bounds, MAX_FILE_BYTES, MAX_SCANNED_VALUE_BYTES, MAX_TREE_DEPTH},
    render::artifacts,
    result::{analyze, read_trace_paths, Mode},
    Refusal, TelemetryError,
};
use dare_security_evidence::Verdict;
use support::*;

fn verdict_of(case: &LabCase, rule: Rule) -> Option<Verdict> {
    let run = run_case(case, Mode::Replay).expect("runs");
    run.result
        .properties
        .iter()
        .find(|p| p.rule == rule)
        .and_then(|p| p.verdict)
}

fn lab(traces: &[&SimTrace]) -> LabCase {
    LabCase {
        files: write_files(traces),
        policy: Some(lab_policy()),
    }
}

fn base(seed: &str) -> SimTrace {
    let mut t = SimTrace::new(seed);
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    t.tool("tool", "agent", "search").attr("user.id", "user-7");
    t
}

#[test]
fn an_oversize_file_and_deep_nesting_are_refused_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.json");
    let mut f = fs::File::create(&big).unwrap();
    f.write_all(b"{\"resourceSpans\":[]}").unwrap();
    f.set_len(MAX_FILE_BYTES + 1).unwrap();
    assert!(matches!(
        read_trace_paths(&[big]),
        Err(TelemetryError::Refused(Refusal::TooLarge { .. }))
    ));
    let deep = dir.path().join("deep.json");
    fs::write(&deep, format!("{}{}", "[".repeat(65), "]".repeat(65))).unwrap();
    assert!(matches!(
        read_trace_paths(&[deep]),
        Err(TelemetryError::Refused(Refusal::TooDeep { .. }))
    ));
    let bytes = dir.path().join("bytes.json");
    fs::write(&bytes, [0x7b, 0xff, 0xfe, 0x7d]).unwrap();
    assert!(matches!(
        read_trace_paths(&[bytes]),
        Err(TelemetryError::Refused(Refusal::InvalidTrace { .. }))
    ));
}

#[test]
fn a_span_flood_stops_at_the_bound_without_overshoot_or_pass() {
    let mut t = SimTrace::new("flood");
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    for i in 0..5_000 {
        t.tool(&format!("t{i}"), "agent", "search")
            .attr("user.id", "user-7");
    }
    let inputs: Vec<_> = write_files(&[&t])
        .into_iter()
        .map(|value| dare_runtime_telemetry::result::TraceInput {
            digest: dare_runtime_telemetry::canonical::digest(&value),
            value,
        })
        .collect();
    let run = analyze(
        &inputs,
        Some(&policy()),
        &mapping(),
        Bounds { max_spans: 1_000 },
        Mode::Replay,
    )
    .unwrap();
    assert_eq!(run.result.traces.spans, 1_000);
    assert_eq!(run.result.stop_reason, Some("max_spans"));
    assert!(run
        .result
        .properties
        .iter()
        .all(|p| p.verdict != Some(Verdict::Pass)));
    // A flood of attributes on one span is refused by position.
    let mut wide = SimTrace::new("wide");
    let span = wide.agent("agent", None, "assistant");
    for i in 0..=256 {
        span.attr(&format!("k{i}"), "v");
    }
    let case = lab(&[&wide]);
    assert!(matches!(
        run_case(&case, Mode::Replay),
        Err(TelemetryError::Refused(Refusal::InvalidTrace { .. }))
    ));
}

#[test]
fn id_collisions_are_deduplicated_or_marked_never_merged() {
    // Identical duplicate across files: deduplicated and counted.
    let mut same = base("same");
    same.duplicate("tool", 1);
    let run = run_case(&lab(&[&same]), Mode::Replay).unwrap();
    assert_eq!(run.result.traces.duplicates_removed, 1);
    assert_eq!(
        verdict_of(&lab(&[&same]), Rule::ToolAuthorization),
        Some(Verdict::Pass)
    );
    // Conflicting duplicate: the trace is undecided, whichever copy is right.
    let mut clash = base("clash");
    clash.duplicate("tool", 1).attr("user.id", "user-9");
    assert_eq!(
        verdict_of(&lab(&[&clash]), Rule::ToolAuthorization),
        Some(Verdict::Inconclusive)
    );
    assert_eq!(
        verdict_of(&lab(&[&clash]), Rule::Principal),
        Some(Verdict::Inconclusive)
    );
}

#[test]
fn parent_cycles_and_overdeep_trees_terminate_as_gaps() {
    let mut cycle = SimTrace::new("cycle");
    cycle
        .agent("agent", Some("tool"), "assistant")
        .attr("user.id", "user-7");
    cycle
        .tool("tool", "agent", "search")
        .attr("user.id", "user-7");
    assert_eq!(
        verdict_of(&lab(&[&cycle]), Rule::Completeness),
        Some(Verdict::Inconclusive)
    );
    let mut deep = SimTrace::new("deep");
    deep.agent("s0", None, "assistant")
        .attr("user.id", "user-7");
    for i in 1..=(MAX_TREE_DEPTH + 1) {
        deep.agent(&format!("s{i}"), Some(&format!("s{}", i - 1)), "assistant")
            .attr("user.id", "user-7");
    }
    deep.tool("tool", &format!("s{}", MAX_TREE_DEPTH + 1), "search")
        .attr("user.id", "user-7");
    assert_eq!(
        verdict_of(&lab(&[&deep]), Rule::ToolAuthorization),
        Some(Verdict::Inconclusive)
    );
}

#[test]
fn hostile_names_never_reach_the_summary_raw() {
    let mut t = base("names");
    let bidi = "\u{202e}\u{2066}exe.gnp\u{0007}<script>|`";
    t.model("model", "agent")
        .named(bidi)
        .attr("gen_ai.agent.name", bidi);
    t.agent("sub", Some("agent"), bidi)
        .attr("user.id", "user-7");
    let mut run = run_case(&lab(&[&t]), Mode::Replay).unwrap();
    for (name, bytes) in artifacts(&mut run, None).unwrap() {
        let text = String::from_utf8(bytes).unwrap();
        for c in ['\u{202e}', '\u{2066}', '\u{0007}'] {
            assert!(!text.contains(c), "{name} carries {c:?}");
        }
        assert!(!text.contains("<script>"), "{name}");
        assert!(!text.contains("exe.gnp"), "{name}");
    }
}

#[test]
fn secrets_in_values_fail_confidentiality_and_never_reach_an_artifact() {
    let secrets = [
        "Bearer DARE-SYNTHETIC-CANARY-hostile001",
        "DARE-SYNTHETIC-CANARY-hostile002",
        "-----BEGIN PRIVATE KEY----- DARE-SYNTHETIC-CANARY-hostile003",
    ];
    for (i, secret) in secrets.iter().enumerate() {
        let mut t = base(&format!("secret-{i}"));
        t.model("model", "agent").attr("app.debug", secret);
        let case = lab(&[&t]);
        let mut run = run_case(&case, Mode::Replay).unwrap();
        let t1 = run
            .result
            .properties
            .iter()
            .find(|p| p.rule == Rule::Confidentiality)
            .unwrap();
        assert_eq!(t1.verdict, Some(Verdict::Fail), "{i}");
        assert!(run.findings.iter().any(|o| o.rule == Rule::Confidentiality
            && o.violations.iter().any(|v| v
                .span_ids
                .contains(&span_id(&format!("secret-{i}"), "model")))));
        for (name, bytes) in artifacts(&mut run, None).unwrap() {
            assert!(!is_sensitive(&bytes), "{i}: {name} fails the sweep");
            assert!(
                !String::from_utf8_lossy(&bytes).contains("hostile00"),
                "{i}: {name}"
            );
        }
    }
}

#[test]
fn a_value_too_long_to_scan_is_never_a_confidentiality_pass() {
    let mut t = base("long");
    t.model("model", "agent")
        .attr("app.blob", &"a".repeat(MAX_SCANNED_VALUE_BYTES + 1));
    assert_eq!(
        verdict_of(&lab(&[&t]), Rule::Confidentiality),
        Some(Verdict::Inconclusive)
    );
}

#[test]
fn a_url_in_a_trace_is_never_dereferenced_or_echoed() {
    // RS-03: the egress rule reads the host of url.full; nothing fetches it.
    let mut t = base("url");
    t.http("egress", "agent")
        .attr("url.full", "http://169.254.169.254/latest/meta-data/iam");
    let mut run = run_case(&lab(&[&t]), Mode::Replay).unwrap();
    let b5 = run
        .result
        .properties
        .iter()
        .find(|p| p.rule == Rule::Egress)
        .unwrap();
    assert_eq!(b5.verdict, Some(Verdict::Fail));
    for (name, bytes) in artifacts(&mut run, None).unwrap() {
        assert!(
            !String::from_utf8_lossy(&bytes).contains("169.254"),
            "{name}"
        );
    }
}
