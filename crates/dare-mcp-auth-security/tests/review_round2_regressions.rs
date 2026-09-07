//! Security review round 2 regressions.
//!
//! These tests close the three residual gaps found after the first post-merge
//! hotfix: a run selecting one invariant could hide another concrete failure,
//! an advertised-but-unselected sibling issuer could mint the token, and the
//! request budget was charged after normalization rather than at admission.

use std::path::PathBuf;

use serde_json::{json, Value};

use dare_mcp_auth_security::harness::{
    normalize_checked, HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest,
};
use dare_mcp_auth_security::invariant::evaluate;
use dare_mcp_auth_security::model::{McpAuthInvariantType, McpAuthScenario};
use dare_mcp_auth_security::observation::McpAuthObservation;
use dare_mcp_auth_security::result::{run_scenario, McpAuthSecurityResult};
use dare_mcp_auth_security::schema::validate_scenario_document;
use dare_mcp_auth_security::simulated::SimulatedAdapter;
use dare_mcp_auth_security::trials::TrialPlan;
use dare_mcp_auth_security::{Result, Verdict};

fn load_value(lab: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
        .join(format!("{lab}.json"));
    let bytes = std::fs::read(&path).expect("fixture readable");
    serde_json::from_slice(&bytes).expect("valid JSON")
}

fn decode(value: Value) -> McpAuthScenario {
    validate_scenario_document(&value).expect("admissible");
    let scenario: McpAuthScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
}

fn load(lab: &str) -> McpAuthScenario {
    decode(load_value(lab))
}

fn events(scenario: &McpAuthScenario) -> Vec<McpAuthObservation> {
    let raw = SimulatedAdapter::new()
        .observe(&TrialRequest {
            trial_index: 0,
            scenario,
        })
        .expect("stages");
    normalize_checked(&raw, scenario).expect("normalizes")
}

fn run(scenario: &McpAuthScenario) -> McpAuthSecurityResult {
    let plan = TrialPlan::from_scenario(scenario).expect("plan");
    run_scenario(scenario, None, &SimulatedAdapter::new(), plan).expect("runs")
}

#[test]
fn r2_a_secondary_invariant_failure_cannot_hide_behind_a_passing_primary() {
    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::TokenResourceAudienceBoundaryPreserved;
    scenario.property = scenario.invariant.type_.property();
    scenario.class = scenario.invariant.type_.surface();
    scenario.tokens.presented.as_mut().expect("token").issuer =
        dare_mcp_auth_security::protocol::SyntheticUri::new("as-attacker")
            .expect("synthetic identifier");

    let primary = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));
    assert_eq!(
        primary.verdict,
        Verdict::Pass,
        "the fixture no longer demonstrates a primary PASS with a secondary failure"
    );

    let result = run(&scenario);
    assert_eq!(
        result.verdict,
        Verdict::Fail,
        "the run hid a concrete issuer violation because audience was primary"
    );
    assert!(result.violations().iter().any(|violation| {
        violation.invariant == McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved
    }));
}

#[test]
fn r2_an_advertised_but_unselected_sibling_issuer_does_not_bind_the_token() {
    let mut value = load_value("mcp-auth-lab-007");

    value["protected_resource"]["metadata"]["authorization_servers"]
        .as_array_mut()
        .expect("advertised servers")
        .push(json!("as-secondary"));

    let mut sibling = value["protected_resource"]["authorization_servers"][0].clone();
    sibling["issuer"] = json!("as-secondary");
    sibling["authorization_endpoint"] = json!("as-secondary.authorize");
    sibling["token_endpoint"] = json!("as-secondary.token");
    value["protected_resource"]["authorization_servers"]
        .as_array_mut()
        .expect("server metadata")
        .push(sibling);

    value["tokens"]["presented"]["issuer"] = json!("as-secondary");
    let scenario = decode(value);

    let outcome = evaluate(
        McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved,
        &scenario,
        &events(&scenario),
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "a sibling issuer was accepted merely because the resource advertised it"
    );
    assert!(outcome.violations.iter().any(|violation| {
        violation.subject.as_deref() == Some("as-secondary")
            && violation.reason.contains("as-primary")
    }));
}

struct OverproducingAdapter;

impl HarnessAdapter for OverproducingAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Simulated
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        let mut observed_requests = request.scenario.requests.clone();
        let mut over_budget = observed_requests[0].clone();
        over_budget.request_id = "req-over-budget".to_owned();
        observed_requests.push(over_budget);
        Ok(RawTrialOutput {
            observed_requests,
            harness_error: None,
        })
    }
}

#[test]
fn r2_request_budget_is_an_admission_boundary_before_normalization() {
    let mut scenario = load("mcp-auth-lab-001");
    scenario.safety.max_requests_per_trial = Some(1);
    scenario.trials.count = 1;
    scenario.trials.stop_on_first_fail = false;

    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    let result = run_scenario(&scenario, None, &OverproducingAdapter, plan).expect("runs");

    assert!(
        result.budget.exhausted,
        "the fixture must exhaust the request budget"
    );
    assert_eq!(result.budget.requests_observed, 1);
    assert_eq!(result.trials.len(), 1);
    assert_eq!(result.trials[0].requests, 1);
    assert_ne!(
        result.verdict,
        Verdict::Pass,
        "a request-truncated trial cannot report PASS"
    );

    for event in &result.trials[0].events {
        let request_id = match event {
            McpAuthObservation::ProtocolContext { request_id, .. }
            | McpAuthObservation::HeaderContext { request_id, .. }
            | McpAuthObservation::OperationContext { request_id, .. } => Some(request_id.as_str()),
            _ => None,
        };
        assert_ne!(
            request_id,
            Some("req-over-budget"),
            "a request rejected by the budget still produced retained evidence"
        );
    }
}
