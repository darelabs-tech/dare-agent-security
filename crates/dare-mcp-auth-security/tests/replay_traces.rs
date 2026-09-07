//! Replay traces, and what a trace is never allowed to do.
//!
//! A trace is evidence of what happened. It is not the authority that says what
//! was approved — and the difference is not academic, because Cycle 017 shipped
//! a replay path that matched on `scenario_id` alone. Under that rule a trace
//! could restate a request with wider semantics, keep the same id, and have the
//! widened version judged as though it had been approved.
//!
//! So these tests check two things: that a bound trace replays and produces the
//! same verdict the staged run produces, and that an unbound one is refused
//! before any evaluator sees it.

use std::path::PathBuf;

use dare_mcp_auth_security::model::McpAuthScenario;
use dare_mcp_auth_security::replay::{load_trace, ReplayAdapter};
use dare_mcp_auth_security::result::run_scenario;
use dare_mcp_auth_security::schema::validate_scenario_document;
use dare_mcp_auth_security::simulated::SimulatedAdapter;
use dare_mcp_auth_security::trials::TrialPlan;
use dare_mcp_auth_security::Verdict;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn scenario(lab: &str) -> McpAuthScenario {
    let bytes = std::fs::read(fixtures().join("scenarios").join(format!("{lab}.json")))
        .expect("fixture readable");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    validate_scenario_document(&value).expect("admissible");
    let scenario: McpAuthScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
}

fn trace_path(name: &str) -> PathBuf {
    fixtures().join("traces").join(format!("{name}.json"))
}

/// Each bound trace and the lab it was recorded against.
const BOUND: [(&str, &str); 4] = [
    ("trace-lab-001", "mcp-auth-lab-001"),
    ("trace-lab-011", "mcp-auth-lab-011"),
    ("trace-lab-016", "mcp-auth-lab-016"),
    ("trace-lab-026", "mcp-auth-lab-026"),
];

#[test]
fn every_bound_trace_loads_and_declares_itself_replayable_and_synthetic() {
    for (name, _) in BOUND {
        let trace = load_trace(&trace_path(name)).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(trace.synthetic, "{name} does not declare itself synthetic");
        assert!(!trace.trials.is_empty());
    }
}

#[test]
fn a_bound_trace_replays_to_the_same_verdict_the_staged_run_reaches() {
    // Replay and simulation are different sources for the same observations. If
    // they disagreed, one of them would be manufacturing something.
    for (name, lab) in BOUND {
        let scenario = scenario(lab);
        let adapter = ReplayAdapter::from_path(&trace_path(name)).expect("trace loads");
        adapter
            .trace()
            .assert_matches(&scenario)
            .unwrap_or_else(|err| panic!("{name} is not bound to {lab}: {err}"));

        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let replayed = run_scenario(&scenario, None, &adapter, plan).expect("replays");

        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let staged = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("stages");

        assert_eq!(
            replayed.verdict, staged.verdict,
            "{name} replays to a different verdict than the staged run"
        );
        assert_eq!(replayed.verdict, Verdict::Pass);
        assert_eq!(replayed.mode.as_str(), "REPLAY");
        assert!(replayed.synthetic);
    }
}

#[test]
fn a_trace_that_widens_the_operation_is_refused_under_the_same_scenario_id() {
    // The Cycle 017 defect, reproduced deliberately. The trace keeps the
    // approved scenario id and restates the request with a wider operation. A
    // path that matched on id alone would evaluate the widened version as
    // though it had been approved.
    let scenario = scenario("mcp-auth-lab-001");
    let trace = load_trace(&trace_path("trace-unbound-operation")).expect("loads");
    assert_eq!(
        trace.scenario_id, scenario.id,
        "the fixture must keep the approved id, or it would prove nothing"
    );

    let err = trace
        .assert_matches(&scenario)
        .expect_err("a widened operation must be refused");
    let message = err.to_string();
    assert!(
        message.contains("operation") || message.contains("request"),
        "the refusal does not say what disagreed: {message}"
    );
}

#[test]
fn a_trace_recorded_against_another_scenario_is_refused() {
    let scenario = scenario("mcp-auth-lab-001");
    let trace = load_trace(&trace_path("trace-foreign-scenario")).expect("loads");
    assert!(trace.assert_matches(&scenario).is_err());
}

#[test]
fn a_refused_trace_never_reaches_an_evaluator() {
    // The refusal has to happen before observation, not after. A trace rejected
    // only at verdict time would already have been read.
    let scenario = scenario("mcp-auth-lab-001");
    let adapter = ReplayAdapter::from_path(&trace_path("trace-unbound-operation")).expect("loads");
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");

    // `run_scenario` re-checks the binding itself, so even a caller that forgot
    // `assert_matches` cannot get a verdict out of an unbound trace.
    let outcome = run_scenario(&scenario, None, &adapter, plan);
    assert!(
        outcome.is_err(),
        "an unbound trace produced a result instead of a refusal"
    );
}

#[test]
fn no_refusal_about_a_trace_echoes_the_trace_content() {
    let scenario = scenario("mcp-auth-lab-001");
    for name in ["trace-unbound-operation", "trace-foreign-scenario"] {
        let trace = load_trace(&trace_path(name)).expect("loads");
        let Err(err) = trace.assert_matches(&scenario) else {
            panic!("{name} was admitted");
        };
        let message = err.to_string();
        for marker in ["eyJhbGci", "sk-live-", "DARE-SYNTHETIC-CANARY-", "://"] {
            assert!(
                !message.contains(marker),
                "the refusal for {name} echoed `{marker}`"
            );
        }
    }
}

#[test]
fn a_trace_carries_no_verdict_expectation_or_invariant_field() {
    // A trace that declared its own outcome would let observed evidence decide
    // the judgement, which is the one thing it must never do. The schema closes
    // the object, so this is checked as text against the committed files.
    for entry in std::fs::read_dir(fixtures().join("traces")).expect("traces directory") {
        let path = entry.expect("entry").path();
        let raw = std::fs::read_to_string(&path).expect("readable");
        for banned in [
            "verdict",
            "expected",
            "expectation",
            "invariant",
            "violation",
            "pass",
            "fail",
        ] {
            assert!(
                !raw.to_ascii_lowercase().contains(banned),
                "{} carries a `{banned}` field",
                path.display()
            );
        }
    }
}
