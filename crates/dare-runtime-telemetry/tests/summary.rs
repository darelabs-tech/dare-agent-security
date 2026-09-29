//! `summary.md` (task-021).
mod support;

use dare_runtime_telemetry::{
    evidence_bridge::bind_evidence,
    limits::Bounds,
    result::{analyze, Mode},
    summary::{summary, NOT_CLAIMED},
};
use support::*;

fn render(files: &[Vec<Sp>], with_policy: bool) -> String {
    let inputs: Vec<_> = files.iter().map(|f| input(f)).collect();
    let p = policy();
    let mut run = analyze(
        &inputs,
        with_policy.then_some(&p),
        &mapping(),
        Bounds::default(),
        Mode::Replay,
    )
    .unwrap();
    bind_evidence(&mut run).unwrap();
    summary(&run)
}

fn failing(t: &str) -> Vec<Sp> {
    let mut bad = good_trace(t);
    bad[1] = Sp::tool(t, "b", "a", "delete_all")
        .s("user.id", "user-7")
        .at(20);
    bad
}

fn orphaned(t: &str) -> Vec<Sp> {
    let mut o = good_trace(t);
    o[1].parent = Some(sid("f"));
    o
}

#[test]
fn counts_verdicts_reasons_and_incomplete_traces_are_reported() {
    let md = render(&[good_trace("1"), failing("2"), orphaned("3")], true);
    assert!(md.starts_with("# DARE Runtime Telemetry\n"));
    assert!(md.contains("Verdict: **FAIL** (a_property_failed)"));
    assert!(md.contains("3 trace file(s), 3 trace(s), 9 span(s) analysed"));
    assert!(md.contains("Runtime policy: support-desk"));
    // Per-property rows carry the verdict, coverage and reason.
    assert!(md.contains(
        "| B-1 | AGENT.TOOL.AUTHORIZATION_BOUNDARY | FAIL | APPLICABLE | observed_violation | 1 / 1 / 1 / 0 |"
    ));
    // An orphan trace with no destructive call is undecided, not unexercised
    // (REGRESSION R-5): the missing parent could be the violation.
    assert!(md.contains(
        "| B-2 | AGENT.HUMAN_APPROVAL.INTENT_BINDING | INCONCLUSIVE | APPLICABLE | incomplete_traces | 0 / 1 / 0 / 2 |"
    ));
    // The incomplete trace is named with its gap.
    assert!(md.contains(&format!("| {} | orphan |", tid("3"))));
    // The failing trace is named with its reason code, never its tool.
    assert!(md.contains(&format!("| B-1 | {} | tool_not_allowed | 2 |", tid("2"))));
}

#[test]
fn no_value_and_no_time_stamp_appear() {
    let mut t = good_trace("1");
    t[0] = t[0]
        .clone()
        .s("note", "CANARY-SUMMARY-TEXT-7d1e")
        .s("auth", "Bearer DARE-SYNTHETIC-CANARY-summary99");
    let md = render(&[t, failing("2")], true);
    for planted in [
        "CANARY-SUMMARY-TEXT-7d1e",
        "DARE-SYNTHETIC-CANARY-summary99",
        "user-7",
        "delete_all",
        "search",
        "api.example.com",
        "assistant",
    ] {
        assert!(!md.contains(planted), "{planted} leaked");
    }
    for clock in ["1970", "2026", "UTC", "T00:"] {
        assert!(!md.contains(clock), "a time stamp ({clock}) appears");
    }
}

#[test]
fn it_ends_with_the_not_claimed_statements() {
    let md = render(&[good_trace("1")], false);
    let tail = md.split("## Not claimed").nth(1).expect("section");
    for line in NOT_CLAIMED {
        assert!(tail.contains(line));
    }
    assert!(tail.contains("self-reported"));
    assert!(tail.contains("No authenticity"));
    assert!(tail.contains("Absence is not proof"));
    assert!(md.contains("Runtime policy: none."));
    assert!(md.contains(
        "| B-2 | AGENT.HUMAN_APPROVAL.INTENT_BINDING | - | NOT_APPLICABLE | no_runtime_policy |"
    ));
    // With a policy and complete traces, an unexercised rule is NOT_TESTED.
    let md = render(&[good_trace("1")], true);
    assert!(md.contains(
        "| B-2 | AGENT.HUMAN_APPROVAL.INTENT_BINDING | - | NOT_TESTED | not_exercised |"
    ));
    assert!(md.contains("Every trace is structurally complete."));
}

#[test]
fn the_summary_does_not_depend_on_file_order() {
    assert_eq!(
        render(&[good_trace("1"), failing("2"), orphaned("3")], true),
        render(&[orphaned("3"), failing("2"), good_trace("1")], true)
    );
}

#[test]
fn a_span_bound_stop_is_stated() {
    let inputs = vec![input(&good_trace("1"))];
    let run = analyze(
        &inputs,
        None,
        &mapping(),
        Bounds { max_spans: 2 },
        Mode::Replay,
    )
    .unwrap();
    let md = summary(&run);
    assert!(md.contains("Span bound: 2 (**reached: max_spans**"));
    assert!(md.contains("span_bound"));
}
