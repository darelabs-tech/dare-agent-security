//! Post-merge security review: one regression per false PASS that was found.
//!
//! Cycle 018 merged with 2799 tests green. Green was not the same as correct:
//! the suite asserted the behaviour the engine had, and in eleven places that
//! behaviour let an authentication or authorization control report PASS when it
//! should not have.
//!
//! Every test here is written against the *vulnerable* behaviour, not the fixed
//! one. Each would have failed before its fix, and the comment on each says
//! which false PASS it closes — so a later change that reintroduces the gap
//! fails a test that explains itself rather than one that merely goes red.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::json;

use dare_mcp_auth_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_mcp_auth_security::invariant::evaluate;
use dare_mcp_auth_security::model::{McpAuthInvariantType, McpAuthScenario};
use dare_mcp_auth_security::observation::McpAuthObservation;
use dare_mcp_auth_security::result::{run_scenario, McpAuthSecurityResult};
use dare_mcp_auth_security::schema::validate_scenario_document;
use dare_mcp_auth_security::simulated::SimulatedAdapter;
use dare_mcp_auth_security::source::{TokenValidityState, TrustClass};
use dare_mcp_auth_security::trials::TrialPlan;
use dare_mcp_auth_security::Verdict;

fn load(lab: &str) -> McpAuthScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
        .join(format!("{lab}.json"));
    let bytes = std::fs::read(&path).expect("fixture readable");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    validate_scenario_document(&value).expect("admissible");
    let scenario: McpAuthScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
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

/// Evaluate the invariant a scenario names, over its own staged observations.
fn verdict(scenario: &McpAuthScenario) -> Verdict {
    evaluate(scenario.invariant.type_, scenario, &events(scenario)).verdict
}

// ---------------------------------------------------------------- F01 -------

#[test]
fn f01_a_case_changed_mcp_name_does_not_escape_the_binding() {
    // The false PASS: `normalize_routing_value` lowercased both sides, so a
    // gateway routing on `Mcp-Name: DeleteInvoice` while the body executed
    // `deleteinvoice` compared equal and the name-binding invariant returned
    // PASS. A tool registry is keyed by the literal string it published; those
    // are two different keys, or one key and one miss.
    let mut scenario = load("mcp-auth-lab-001");
    scenario.invariant.type_ = McpAuthInvariantType::McpNameHeaderBodyBindingPreserved;
    scenario.requests[0].headers.name = Some("DeleteInvoice".to_owned());
    scenario.requests[0].operation.name = Some("deleteinvoice".to_owned());

    assert_eq!(
        verdict(&scenario),
        Verdict::Fail,
        "a case-changed routed name was treated as the same operation"
    );
}

#[test]
fn f01_a_case_changed_method_does_not_escape_the_binding_either() {
    let mut scenario = load("mcp-auth-lab-001");
    scenario.requests[0].headers.method = Some("Tools/Call".to_owned());
    scenario.requests[0].operation.method = "tools/call".to_owned();
    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f01_the_compliant_control_still_passes() {
    // Tightening a comparison is only correct if it does not turn every
    // well-formed request into a finding.
    assert_eq!(verdict(&load("mcp-auth-lab-001")), Verdict::Pass);
}

// ---------------------------------------------------------------- F02 -------

/// A final-operation scenario whose permit and execution start identical.
fn permit_scenario() -> McpAuthScenario {
    let mut scenario = load("mcp-auth-lab-031");
    let final_op = &mut scenario.final_operation;
    final_op.authorized_arguments = Some(json!({ "amount": 100, "to": "acct-1" }));
    final_op.performed_arguments = Some(json!({ "amount": 100, "to": "acct-1" }));
    final_op.authorized_principal = Some("user-A".to_owned());
    final_op.performed_principal = Some("user-A".to_owned());
    final_op.authorized_tenant = Some("tenant-A".to_owned());
    final_op.performed_tenant = Some("tenant-A".to_owned());
    final_op.authorized_scopes = vec!["payments.send".to_owned()];
    final_op.performed_scopes = vec!["payments.send".to_owned()];
    scenario
}

#[test]
fn f02_an_unmutated_permit_still_passes() {
    assert_eq!(verdict(&permit_scenario()), Verdict::Pass);
}

#[test]
fn f02_an_argument_mutation_after_the_permit_fails() {
    // The false PASS: the binding compared method, name and resource only, so
    // a permit for `payments.send(amount=100)` covered
    // `payments.send(amount=10000)` — same method, same name, same resource,
    // nothing to report.
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_arguments = Some(json!({ "amount": 10000, "to": "acct-1" }));

    assert_eq!(
        verdict(&scenario),
        Verdict::Fail,
        "a permit for 100 was treated as covering 10000"
    );

    let result = run(&scenario);
    assert!(result
        .violations()
        .iter()
        .any(|violation| violation.reason.contains("arguments")));
}

#[test]
fn f02_a_principal_mutation_after_the_permit_fails() {
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_principal = Some("user-B".to_owned());
    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f02_a_tenant_mutation_after_the_permit_fails() {
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_tenant = Some("tenant-B".to_owned());
    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f02_a_scope_mutation_after_the_permit_fails() {
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_scopes =
        vec!["payments.send".to_owned(), "payments.admin".to_owned()];
    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f02_a_mutation_that_was_reevaluated_is_not_a_stale_permit() {
    // The other half. An engine that reported every mutation would fail correct
    // behaviour, and an operator would learn to ignore the finding.
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_arguments = Some(json!({ "amount": 10000 }));
    scenario.final_operation.reevaluated_after_change = true;
    assert_eq!(verdict(&scenario), Verdict::Pass);
}

#[test]
fn f02_a_mutation_that_was_refused_is_not_a_stale_permit_either() {
    let mut scenario = permit_scenario();
    scenario.final_operation.performed_principal = Some("user-B".to_owned());
    scenario.final_operation.refused_after_change = true;
    assert_eq!(verdict(&scenario), Verdict::Pass);
}

#[test]
fn f02_the_decision_is_taken_by_cycle_003() {
    // The composition claim, checked rather than asserted in prose: the
    // engine's answer must equal Cycle 003's answer over the same projection.
    use dare_mcp_auth_security::compat::binding_preserved;

    let clean = permit_scenario();
    assert_eq!(
        binding_preserved(&clean.final_operation).expect("binds"),
        Some(true)
    );

    let mut mutated = permit_scenario();
    mutated.final_operation.performed_arguments = Some(json!({ "amount": 10000 }));
    assert_eq!(
        binding_preserved(&mutated.final_operation).expect("binds"),
        Some(false)
    );
}

// ---------------------------------------------------------------- F03 -------

fn token_scenario(validity: TokenValidityState, accepted: bool) -> McpAuthScenario {
    let mut scenario = load("mcp-auth-lab-013");
    let token = scenario.tokens.presented.as_mut().expect("a token");
    token.validity = validity;
    scenario.tokens.accepted_by_resource = accepted;
    scenario
}

#[test]
fn f03_an_expired_token_that_was_accepted_fails() {
    // The false PASS: `has_validity_evidence()` counted EXPIRED as evidence,
    // and the evaluator only asked whether evidence existed. A token past its
    // window that the resource accepted anyway reported PASS.
    assert_eq!(
        verdict(&token_scenario(TokenValidityState::Expired, true)),
        Verdict::Fail,
        "an expired token the resource accepted was treated as acceptable"
    );
}

#[test]
fn f03_a_rejected_token_that_was_accepted_fails() {
    // The starkest case: the deployment's own verifier said no, and the
    // resource accepted it regardless.
    assert_eq!(
        verdict(&token_scenario(TokenValidityState::Rejected, true)),
        Verdict::Fail,
        "a token the deployment itself rejected was treated as acceptable"
    );
}

#[test]
fn f03_an_unknown_token_that_was_accepted_fails() {
    assert_eq!(
        verdict(&token_scenario(TokenValidityState::Unknown, true)),
        Verdict::Fail
    );
}

#[test]
fn f03_unknown_validity_never_reaches_pass_even_when_nothing_was_accepted() {
    // The coverage half. Observing TOKEN_CLAIMS_CONTEXT proves the projection
    // that *would* carry a verification result exists — not that anyone
    // verified anything. Before the fix this satisfied the contract outright,
    // so a run reported "validity evidence is present" about a token nobody had
    // checked.
    let outcome = evaluate(
        McpAuthInvariantType::TokenValidityEvidencePresent,
        &token_scenario(TokenValidityState::Unknown, false),
        &events(&token_scenario(TokenValidityState::Unknown, false)),
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Inconclusive,
        "an unverified token satisfied the validity contract: {}",
        outcome.reason
    );
    assert!(!outcome.coverage_satisfied);
}

#[test]
fn f03_refusing_a_bad_token_is_the_control_working() {
    // A rejected token the deployment also rejected is correct behaviour and
    // must not be a finding — otherwise the only way to pass is to have no bad
    // tokens, which is not something a validator can observe.
    for validity in [TokenValidityState::Rejected, TokenValidityState::Expired] {
        let scenario = token_scenario(validity, false);
        assert_ne!(
            verdict(&scenario),
            Verdict::Fail,
            "{validity:?} that was correctly refused was reported as a violation"
        );
    }
}

#[test]
fn f03_a_verified_and_accepted_token_still_passes() {
    assert_eq!(
        verdict(&token_scenario(TokenValidityState::Verified, true)),
        Verdict::Pass
    );
}

// ---------------------------------------------------------------- F04 -------

#[test]
fn f04_a_token_from_an_unadvertised_issuer_fails_despite_a_correct_audience() {
    // The false PASS: the audience check asked whether the token names this
    // resource. It does — the attacker's authorization server minted it for
    // exactly this resource. Nothing asked whether that server was ever allowed
    // to issue for it.
    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved;
    let token = scenario.tokens.presented.as_mut().expect("a token");
    token.issuer = dare_mcp_auth_security::protocol::SyntheticUri::new("as-attacker")
        .expect("synthetic identifier");
    token.validity = TokenValidityState::Verified;
    scenario.tokens.accepted_by_resource = true;

    let outcome = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "a token minted by an unadvertised issuer was accepted on a correct audience"
    );
    assert!(
        outcome
            .violations
            .iter()
            .any(|violation| violation.subject.as_deref() == Some("as-attacker")),
        "the finding does not name the issuer"
    );
}

#[test]
fn f04_a_token_from_the_selected_issuer_still_passes() {
    // Independence: issuer, validity and audience stay three questions. A token
    // from the right issuer must not fail because of this check.
    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved;
    let token = scenario.tokens.presented.as_mut().expect("a token");
    token.validity = TokenValidityState::Verified;
    assert_eq!(verdict(&scenario), Verdict::Pass);
}

#[test]
fn f04_the_issuer_finding_is_independent_of_the_audience_finding() {
    // A wrong issuer and a wrong audience are two findings, not one boolean.
    let mut scenario = load("mcp-auth-lab-007");
    let token = scenario.tokens.presented.as_mut().expect("a token");
    token.issuer = dare_mcp_auth_security::protocol::SyntheticUri::new("as-attacker")
        .expect("synthetic identifier");

    let issuer = evaluate(
        McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved,
        &scenario,
        &events(&scenario),
    );
    let audience = evaluate(
        McpAuthInvariantType::TokenResourceAudienceBoundaryPreserved,
        &scenario,
        &events(&scenario),
    );

    assert_eq!(issuer.verdict, Verdict::Fail);
    assert_ne!(
        audience.verdict,
        Verdict::Fail,
        "a wrong issuer was reported as an audience violation too"
    );
}

// ---------------------------------------------------------------- F05 -------

#[test]
fn f05_self_reported_resource_metadata_cannot_fabricate_an_authorization_server() {
    // The false PASS: every identifier agreed. The metadata says it is about
    // `mcp-invoices`, it advertises `as-attacker`, `as-attacker`'s own metadata
    // says its issuer is `as-attacker`, and the client selected `as-attacker`.
    // Checking ids alone finds a perfectly consistent document — written by
    // whoever wanted the selection.
    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::ProtectedResourceMetadataBoundToResource;
    scenario
        .protected_resource
        .metadata
        .as_mut()
        .expect("metadata")
        .trust = TrustClass::SelfReported;

    let outcome = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "a self-reported metadata document established which servers may issue: {}",
        outcome.reason
    );
}

#[test]
fn f05_self_reported_authorization_server_metadata_cannot_establish_itself() {
    // The same shape as `clientInfo` naming a principal: a server's own
    // description of itself is not what makes it authoritative.
    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved;
    scenario.protected_resource.authorization_servers[0].trust = TrustClass::SelfReported;

    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f05_declared_metadata_is_not_silently_promoted_to_authenticated() {
    // DECLARED is not AUTHENTICATED. The project's contract has exactly one
    // class that may establish identity, and an engine that treated "configured
    // somewhere" as "proven" would be inventing a fourth.
    assert!(!TrustClass::Declared.may_establish_identity());
    assert!(!TrustClass::SelfReported.may_establish_identity());
    assert!(TrustClass::Authenticated.may_establish_identity());

    let mut scenario = load("mcp-auth-lab-007");
    scenario.invariant.type_ = McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved;
    scenario.protected_resource.authorization_servers[0].trust = TrustClass::Declared;
    assert_eq!(verdict(&scenario), Verdict::Fail);
}

#[test]
fn f05_authenticated_metadata_still_passes() {
    // The benign control for both halves above.
    let scenario = load("mcp-auth-lab-007");
    assert_eq!(
        scenario
            .protected_resource
            .metadata
            .as_ref()
            .expect("metadata")
            .trust,
        TrustClass::Authenticated
    );
    assert_eq!(verdict(&scenario), Verdict::Pass);
}

// ------------------------------------------------------------ F06 and F07 ---

#[test]
fn f06_the_self_report_finding_names_its_own_invariant_and_property() {
    // The false taxonomy: promoting `clientInfo` to a principal was filed under
    // INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY, an invariant about
    // forwarding a caller's credential to an upstream service. Different
    // problem, different fix, wrong place to send an operator.
    let result = run(&load("mcp-auth-lab-030"));
    assert_eq!(result.verdict, Verdict::Fail);

    let violation = result
        .violations()
        .into_iter()
        .find(|violation| violation.reason.contains("self-reported"))
        .expect("the promotion is reported");

    assert_eq!(
        violation.invariant,
        McpAuthInvariantType::SelfReportedMetadataNotAuthority
    );
    assert_eq!(
        result.property_id.as_str(),
        "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY"
    );
    assert_ne!(
        violation.invariant,
        McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority
    );
}

#[test]
fn f07_the_self_report_finding_carries_deciding_evidence_that_was_retained() {
    // The false claim: this violation shipped with an empty
    // `deciding_event_digests`, in a crate whose own contract says a finding
    // without deciding evidence is an assertion rather than a finding.
    let result = run(&load("mcp-auth-lab-030"));
    let violation = result
        .violations()
        .into_iter()
        .find(|violation| violation.reason.contains("self-reported"))
        .expect("the promotion is reported");

    assert!(
        !violation.deciding_event_digests.is_empty(),
        "the self-report finding names no deciding evidence"
    );

    // And the digest must name an event the artifact actually kept, or it
    // points at nothing an operator can open.
    let retained: BTreeSet<&String> = result
        .trials
        .iter()
        .flat_map(|trial| trial.event_digests.iter())
        .collect();
    for digest in &violation.deciding_event_digests {
        assert!(
            retained.contains(digest),
            "a deciding digest names an event the run did not retain"
        );
    }
}

#[test]
fn f06_the_boundary_is_still_checked_when_a_scenario_selects_another_invariant() {
    // The unconditional half, preserved. A deployment that derived its
    // principal from `clientInfo` is broken whatever else the run examined.
    let mut scenario = load("mcp-auth-lab-001");
    assert_eq!(
        scenario.invariant.type_,
        McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved
    );
    scenario
        .identity_metadata
        .principal_derived_from_self_report = true;

    let result = run(&scenario);
    assert_eq!(result.verdict, Verdict::Fail);
    assert!(result
        .violations()
        .iter()
        .any(|violation| violation.invariant
            == McpAuthInvariantType::SelfReportedMetadataNotAuthority));
}

#[test]
fn f06_a_target_with_no_self_description_is_not_judged_on_it() {
    let mut scenario = load("mcp-auth-lab-001");
    scenario.identity_metadata.client_info = None;
    scenario.identity_metadata.server_info = None;
    assert_eq!(run(&scenario).verdict, Verdict::Pass);
}

// ---------------------------------------------------------------- F08 -------

/// A scenario large enough to exhaust the run-wide output budget.
///
/// Eight requests per trial across ten trials is roughly 66 KB of observations
/// against a 64 KB ceiling, so the final trial is the one that cannot be kept.
fn oversized_scenario() -> McpAuthScenario {
    let mut scenario = load("mcp-auth-lab-001");
    let base = scenario.requests[0].clone();
    for index in 2..=8 {
        let mut request = base.clone();
        request.request_id = format!("req-{index}");
        scenario.requests.push(request);
    }
    scenario.trials.count = 10;
    scenario.trials.stop_on_first_fail = false;
    scenario
}

#[test]
fn f08_accounted_bytes_are_the_bytes_actually_persisted() {
    // The false accounting: the ledger stopped counting at the ceiling while
    // the trial record kept the whole observation set, so `retained_bytes`
    // described a smaller artifact than the one written.
    let result = run(&oversized_scenario());

    for trial in &result.trials {
        let persisted: usize = trial
            .events
            .iter()
            .map(|event| event.retained_bytes())
            .sum();
        assert_eq!(
            trial.retained_bytes, persisted,
            "trial {} accounted {} bytes and persisted {}",
            trial.index, trial.retained_bytes, persisted
        );
    }
}

#[test]
fn f08_persisted_bytes_stay_inside_both_hard_bounds() {
    let result = run(&oversized_scenario());

    let mut total = 0usize;
    for trial in &result.trials {
        let persisted: usize = trial
            .events
            .iter()
            .map(|event| event.retained_bytes())
            .sum();
        assert!(
            persisted <= dare_mcp_auth_security::limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            "trial {} persisted {persisted} bytes",
            trial.index
        );
        total += persisted;
    }
    assert!(
        total <= dare_mcp_auth_security::limits::MAX_TOTAL_OUTPUT_BYTES,
        "the run persisted {total} bytes"
    );
}

#[test]
fn f08_a_budget_that_stopped_the_evidence_never_yields_pass() {
    // "We saw no violation" and "we stopped looking" are different statements.
    // A trial whose observations could not be kept has not established the
    // first one.
    let result = run(&oversized_scenario());
    assert!(
        result.budget.exhausted,
        "the fixture no longer exhausts the budget; the test would prove nothing"
    );
    assert_ne!(
        result.verdict,
        Verdict::Pass,
        "a run that ran out of budget mid-evidence still reported PASS"
    );
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn f08_a_run_inside_the_budget_is_unaffected() {
    let result = run(&load("mcp-auth-lab-001"));
    assert!(!result.budget.exhausted);
    assert_eq!(result.verdict, Verdict::Pass);
    for trial in &result.trials {
        let persisted: usize = trial
            .events
            .iter()
            .map(|event| event.retained_bytes())
            .sum();
        assert_eq!(trial.retained_bytes, persisted);
    }
}

// ---------------------------------------------------------------- F09 -------

#[test]
fn f09_a_trial_override_cannot_widen_what_the_scenario_approved() {
    // The false authority: `--trials 10` against a scenario approving 3 ran ten
    // times. Every one of those is under HARD_MAX_TRIALS, and none was
    // approved by the scenario.
    let scenario = load("mcp-auth-lab-001");
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    assert_eq!(plan.trials, 3);

    for requested in [4, 5, 10] {
        assert!(
            plan.clone().with_trial_override(Some(requested)).is_err(),
            "--trials {requested} widened a plan approved for 3"
        );
    }
}

#[test]
fn f09_a_trial_override_may_still_narrow() {
    let scenario = load("mcp-auth-lab-001");
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    for requested in [1, 2, 3] {
        assert_eq!(
            plan.clone()
                .with_trial_override(Some(requested))
                .expect("narrowing is allowed")
                .trials,
            requested
        );
    }
}

// ------------------------------------------------------------- hygiene ------

#[test]
fn every_new_finding_still_names_the_evidence_that_decided_it() {
    // Swept across every regression above that produces a FAIL, so a new
    // evaluator cannot quietly reintroduce an evidence-free finding.
    let mut scenarios: Vec<McpAuthScenario> = Vec::new();

    let mut case = permit_scenario();
    case.final_operation.performed_arguments = Some(json!({ "amount": 10000 }));
    scenarios.push(case);

    scenarios.push(token_scenario(TokenValidityState::Rejected, true));
    scenarios.push(token_scenario(TokenValidityState::Expired, true));
    scenarios.push(load("mcp-auth-lab-030"));

    let mut case = load("mcp-auth-lab-001");
    case.invariant.type_ = McpAuthInvariantType::McpNameHeaderBodyBindingPreserved;
    case.requests[0].headers.name = Some("DeleteInvoice".to_owned());
    case.requests[0].operation.name = Some("deleteinvoice".to_owned());
    scenarios.push(case);

    for scenario in scenarios {
        let result = run(&scenario);
        assert_eq!(result.verdict, Verdict::Fail, "{}", scenario.id);
        for violation in result.violations() {
            assert!(
                !violation.deciding_event_digests.is_empty(),
                "{} produced a finding with no deciding evidence: {}",
                scenario.id,
                violation.reason
            );
        }
    }
}

#[test]
fn no_new_finding_echoes_a_credential_or_a_reachable_target() {
    // The corrected evaluators produce new prose. It is held to the same rule
    // as the rest: a report of a breach must not reproduce what breached.
    let mut cases: Vec<McpAuthScenario> = vec![load("mcp-auth-lab-030")];

    let mut token = token_scenario(TokenValidityState::Rejected, true);
    token.tokens.presented.as_mut().expect("token").token_id = "tok-rejected".to_owned();
    cases.push(token);

    let mut metadata = load("mcp-auth-lab-007");
    metadata.protected_resource.authorization_servers[0].trust = TrustClass::SelfReported;
    metadata.invariant.type_ = McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved;
    cases.push(metadata);

    for scenario in cases {
        let rendered = serde_json::to_string(&run(&scenario)).expect("serializes");
        for marker in [
            "DARE-SYNTHETIC-CANARY-",
            "sk-live-",
            "-----BEGIN",
            "eyJhbGci",
            "Bearer ey",
        ] {
            assert!(
                !rendered.contains(marker),
                "{} leaked {marker}",
                scenario.id
            );
        }
        for (offset, _) in rendered.match_indices("://") {
            let from = rendered[..offset].rfind('"').map_or(0, |at| at + 1);
            assert!(
                rendered[from..].starts_with("https://darelabs.tech/schemas/"),
                "{} retained a reachable target",
                scenario.id
            );
        }
    }
}
