//! Aggregation, the result document and its schema (task-017).
mod support;

use dare_runtime_telemetry::{
    complete::Gap,
    evaluate::Rule,
    limits::Bounds,
    result::{analyze, CoverageState, Mode, RuntimeTelemetryResult, RESULT_SCHEMA_JSON},
    schema::conforms,
    Refusal, TelemetryError,
};
use dare_security_evidence::Verdict;
use support::*;

fn run(files: &[Vec<Sp>], with_policy: bool) -> RuntimeTelemetryResult {
    let inputs: Vec<_> = files.iter().map(|f| input(f)).collect();
    let p = policy();
    analyze(
        &inputs,
        with_policy.then_some(&p),
        &mapping(),
        Bounds::default(),
        Mode::Replay,
    )
    .unwrap()
    .result
}

fn property(
    r: &RuntimeTelemetryResult,
    rule: Rule,
) -> &dare_runtime_telemetry::result::PropertyResult {
    r.properties.iter().find(|p| p.rule == rule).unwrap()
}

fn schema_ok(r: &RuntimeTelemetryResult) {
    let value = serde_json::to_value(r).unwrap();
    assert!(conforms(RESULT_SCHEMA_JSON, &value).unwrap(), "{value:#}");
}

#[test]
fn a_conformant_run_passes_and_validates() {
    let r = run(&[good_trace("1")], true);
    schema_ok(&r);
    assert_eq!(r.verdict, Verdict::Pass, "{:#?}", r.properties);
    assert_eq!(
        property(&r, Rule::ToolAuthorization).verdict,
        Some(Verdict::Pass)
    );
    assert_eq!(property(&r, Rule::Egress).verdict, Some(Verdict::Pass));
    // No destructive call, no retrieval: those rules were not exercised.
    let approval = property(&r, Rule::Approval);
    assert_eq!(
        (approval.verdict, approval.coverage),
        (None, CoverageState::NotTested)
    );
    assert_eq!(r.traces.count, 1);
    assert_eq!(r.inputs.policy_id.as_deref(), Some("support-desk"));
}

#[test]
fn one_failing_trace_fails_the_property_among_passing_ones() {
    let mut bad = good_trace("2");
    bad[1] = Sp::tool("2", "b", "a", "delete_all")
        .s("user.id", "user-7")
        .at(20);
    let r = run(&[good_trace("1"), bad], true);
    schema_ok(&r);
    let b1 = property(&r, Rule::ToolAuthorization);
    assert_eq!(b1.verdict, Some(Verdict::Fail));
    assert_eq!((b1.traces.fail, b1.traces.pass), (1, 1));
    assert_eq!(r.verdict, Verdict::Fail);
}

#[test]
fn an_incomplete_trace_makes_passing_ones_inconclusive_never_pass() {
    let mut orphaned = good_trace("2");
    orphaned[1].parent = Some(sid("f"));
    let r = run(&[good_trace("1"), orphaned], true);
    assert_eq!(
        property(&r, Rule::ToolAuthorization).verdict,
        Some(Verdict::Inconclusive)
    );
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert_eq!(r.traces.incomplete.len(), 1);
    assert!(r.traces.incomplete[0].gaps.contains(&Gap::Orphan));
}

#[test]
fn without_a_policy_behaviour_is_not_applicable_and_telemetry_is_judged() {
    let r = run(&[good_trace("1")], false);
    schema_ok(&r);
    for rule in Rule::ALL {
        let p = property(&r, rule);
        if rule.needs_policy() {
            assert_eq!(
                (p.verdict, p.coverage, p.reason),
                (None, CoverageState::NotApplicable, "no_runtime_policy")
            );
        }
    }
    assert_eq!(
        property(&r, Rule::Confidentiality).verdict,
        Some(Verdict::Pass)
    );
    assert_eq!(
        property(&r, Rule::Completeness).verdict,
        Some(Verdict::Pass)
    );
    assert_eq!(r.verdict, Verdict::Pass);
    assert!(r.inputs.policy_digest.is_none());
}

#[test]
fn a_required_operation_seen_in_no_trace_leaves_completeness_undecided() {
    let r = run(
        &[vec![
            Sp::agent("1", "a", None, "assistant").s("user.id", "user-7")
        ]],
        true,
    );
    let t2 = property(&r, Rule::Completeness);
    assert_eq!(
        (t2.verdict, t2.reason),
        (Some(Verdict::Inconclusive), "required_operation_unobserved")
    );
    assert!(t2.gaps.contains(&Gap::NoObservation));
}

#[test]
fn a_span_bound_stop_makes_every_judged_property_inconclusive() {
    let inputs = vec![input(&good_trace("1"))];
    let p = policy();
    let r = analyze(
        &inputs,
        Some(&p),
        &mapping(),
        Bounds { max_spans: 2 },
        Mode::Replay,
    )
    .unwrap()
    .result;
    schema_ok(&r);
    assert_eq!(r.stop_reason, Some("max_spans"));
    assert_eq!(r.traces.spans, 2);
    for p in &r.properties {
        assert_ne!(p.verdict, Some(Verdict::Pass), "{:?}", p.rule);
    }
    assert_eq!(r.verdict, Verdict::Inconclusive);
}

#[test]
fn an_empty_export_judges_nothing_and_is_not_a_pass() {
    let r = run(&[vec![]], false);
    assert_eq!(
        (r.verdict, r.reason),
        (Verdict::Inconclusive, "nothing_judged")
    );
    // With a policy requiring tool calls, the unseen operation is undecided.
    let r = run(&[vec![]], true);
    assert_eq!(
        property(&r, Rule::Completeness).reason,
        "required_operation_unobserved"
    );
    assert_eq!(r.verdict, Verdict::Inconclusive);
}

#[test]
fn a_file_outside_the_trace_schema_is_refused_by_position() {
    let mut bad = input(&good_trace("1"));
    bad.value["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"] =
        serde_json::json!("SPAN_KIND_CLIENT");
    let result = analyze(
        &[input(&good_trace("2")), bad],
        None,
        &mapping(),
        Bounds::default(),
        Mode::Replay,
    );
    match result {
        Err(TelemetryError::Refused(Refusal::InvalidTrace { input, reason })) => {
            assert_eq!(input, dare_runtime_telemetry::Input::Trace(1));
            assert_eq!(reason, "schema");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        analyze(&[], None, &mapping(), Bounds::default(), Mode::Replay),
        Err(TelemetryError::Refused(Refusal::NoTraceFiles))
    ));
}

#[test]
fn every_verdict_combination_aggregates_in_order() {
    // FAIL > INCONCLUSIVE > PASS > not exercised, across traces.
    let fail = {
        let mut t = good_trace("3");
        t[1] = Sp::tool("3", "b", "a", "nope")
            .s("user.id", "user-7")
            .at(20);
        t
    };
    let inconclusive = {
        let mut t = good_trace("4");
        t[1].parent = Some(sid("f"));
        t
    };
    let unexercised = vec![Sp::agent("5", "a", None, "assistant").s("user.id", "user-7")];
    for (files, want) in [
        (
            vec![good_trace("1"), fail.clone(), inconclusive.clone()],
            Some(Verdict::Fail),
        ),
        (
            vec![good_trace("1"), inconclusive.clone()],
            Some(Verdict::Inconclusive),
        ),
        (
            vec![good_trace("1"), unexercised.clone()],
            Some(Verdict::Pass),
        ),
        (vec![unexercised], None),
    ] {
        let r = run(&files, true);
        assert_eq!(property(&r, Rule::ToolAuthorization).verdict, want);
    }
}
