//! Scale (O-08, task-026): 100 000 spans in 64 files, with a policy, analysed
//! and rendered in under 10 s in release, with no bound overshoot.
//!
//! Debug builds skip it: CI runs this file with `--release`, as the Cycle 024
//! scale test does.
use std::time::{Duration, Instant};

use dare_runtime_telemetry::{
    canonical::digest_bytes,
    corpus::{file_bytes, lab_policy, write_files, SimTrace},
    limits::{Bounds, MAX_SPANS},
    policy::policy_from_value,
    render::artifacts,
    result::{analyze, Mode, TraceInput},
    semconv::Mapping,
};

const FILES: usize = 64;
const TRACES: usize = 2_000;
/// 1 agent, 45 tool calls, 3 HTTP calls and 1 retrieval per trace.
const SPANS_PER_TRACE: usize = 50;
const LIMIT: Duration = Duration::from_secs(10);

/// 2 000 traces of 50 spans, each spread over the 64 files.
fn inputs() -> Vec<TraceInput> {
    let traces: Vec<SimTrace> = (0..TRACES)
        .map(|n| {
            let mut t = SimTrace::new(&format!("scale-{n}"));
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7")
                .in_file(n % FILES);
            for i in 0..45 {
                t.tool(
                    &format!("tool-{i}"),
                    "agent",
                    if i % 3 == 0 { "lookup_order" } else { "search" },
                )
                .attr("user.id", "user-7")
                .in_file((n + i + 1) % FILES);
            }
            for i in 0..3 {
                t.http(&format!("http-{i}"), "agent")
                    .attr("server.address", "api.example.com")
                    .in_file((n + i) % FILES);
            }
            t.retrieval("docs", "agent")
                .attr("tenant.id", "tenant-a")
                .in_file(n % FILES);
            t
        })
        .collect();
    let refs: Vec<&SimTrace> = traces.iter().collect();
    write_files(&refs)
        .into_iter()
        .map(|value| TraceInput {
            digest: digest_bytes(&file_bytes(&value)),
            value,
        })
        .collect()
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release only: cargo test --release --test scale"
)]
fn a_hundred_thousand_spans_in_64_files_are_analysed_in_under_ten_seconds() {
    let files = inputs();
    assert_eq!(files.len(), FILES);
    let mapping = Mapping::embedded().unwrap();
    let policy = policy_from_value(&lab_policy(), &mapping).unwrap();

    let start = Instant::now();
    let mut run = analyze(
        &files,
        Some(&policy),
        &mapping,
        Bounds::default(),
        Mode::Replay,
    )
    .unwrap();
    let rendered = artifacts(&mut run, Some(&policy)).unwrap();
    let elapsed = start.elapsed();

    let r = &run.result;
    eprintln!(
        "scale: {} spans, {} traces, {} files, verdict {:?}, {elapsed:?}",
        r.traces.spans, r.traces.count, FILES, r.verdict
    );
    assert_eq!(r.traces.spans as usize, TRACES * SPANS_PER_TRACE);
    assert_eq!(r.traces.count as usize, TRACES);
    assert!(r.traces.spans <= MAX_SPANS);
    assert!(r.stop_reason.is_none());
    assert!(r.traces.incomplete.is_empty());
    assert_eq!(rendered.len(), 4);
    assert!(elapsed < LIMIT, "{elapsed:?}");
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release only: cargo test --release --test scale"
)]
fn the_span_bound_cuts_exactly_at_its_value() {
    let files = inputs();
    let mapping = Mapping::embedded().unwrap();
    let run = analyze(
        &files,
        None,
        &mapping,
        Bounds { max_spans: 12_345 },
        Mode::Replay,
    )
    .unwrap();
    assert_eq!(run.result.traces.spans, 12_345);
    assert_eq!(run.result.stop_reason, Some("max_spans"));
}
