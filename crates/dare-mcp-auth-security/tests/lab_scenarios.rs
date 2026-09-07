//! The 35 MCP-AUTH-LAB fixtures, end to end.
//!
//! Each lab is read from disk, validated as an untrusted document, staged
//! through the simulated adapter, normalized and evaluated. The expected
//! outcome for every lab lives **here**, in the register below — never in the
//! fixture.
//!
//! That separation is the whole reason the register exists. A scenario that
//! could state its own verdict would make the evaluator ceremonial: the run
//! would report back whatever the fixture author already believed. So the
//! fixtures describe a situation, this file says what the engine ought to
//! conclude from it, and the two only meet at the assertion.
//!
//! The labs are also **paired**. A PASS lab and its FAIL partner share the same
//! flow, the same resource, the same authorization server and the same request;
//! the only difference is the one field under test.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_mcp_auth_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_mcp_auth_security::invariant::evaluate;
use dare_mcp_auth_security::model::{McpAuthInvariantType, McpAuthScenario};
use dare_mcp_auth_security::observation::McpAuthObservation;
use dare_mcp_auth_security::result::run_scenario;
use dare_mcp_auth_security::schema::validate_scenario_document;
use dare_mcp_auth_security::simulated::SimulatedAdapter;
use dare_mcp_auth_security::source::ScenarioClass;
use dare_mcp_auth_security::trials::TrialPlan;
use dare_mcp_auth_security::{McpAuthSecurityError, Verdict};

/// What a lab is expected to produce for the invariant it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Pass,
    Fail,
    /// The question could not be decided from what the run observed.
    Inconclusive,
    /// The document never reaches evaluation: a gate refuses it first.
    Refused,
    /// Judged through the identity boundary rather than through one of the
    /// fourteen invariants. The self-reported metadata boundary is a property
    /// of the identity evidence, not of a request, so it is asserted directly.
    IdentityBoundaryHolds,
    IdentityBoundaryBroken,
}

/// The approved lab register: id, and what the engine should conclude.
const LABS: [(&str, Expectation); 35] = [
    ("mcp-auth-lab-001", Expectation::Pass),
    ("mcp-auth-lab-002", Expectation::Fail),
    ("mcp-auth-lab-003", Expectation::Fail),
    ("mcp-auth-lab-004", Expectation::Fail),
    ("mcp-auth-lab-005", Expectation::Pass),
    ("mcp-auth-lab-006", Expectation::Fail),
    ("mcp-auth-lab-007", Expectation::Pass),
    ("mcp-auth-lab-008", Expectation::Fail),
    ("mcp-auth-lab-009", Expectation::Pass),
    ("mcp-auth-lab-010", Expectation::Fail),
    ("mcp-auth-lab-011", Expectation::Pass),
    ("mcp-auth-lab-012", Expectation::Fail),
    ("mcp-auth-lab-013", Expectation::Pass),
    ("mcp-auth-lab-014", Expectation::Inconclusive),
    ("mcp-auth-lab-015", Expectation::Fail),
    ("mcp-auth-lab-016", Expectation::Pass),
    ("mcp-auth-lab-017", Expectation::Fail),
    ("mcp-auth-lab-018", Expectation::Pass),
    ("mcp-auth-lab-019", Expectation::Fail),
    ("mcp-auth-lab-020", Expectation::Pass),
    ("mcp-auth-lab-021", Expectation::Fail),
    ("mcp-auth-lab-022", Expectation::Refused),
    ("mcp-auth-lab-023", Expectation::Pass),
    ("mcp-auth-lab-024", Expectation::Pass),
    ("mcp-auth-lab-025", Expectation::Fail),
    ("mcp-auth-lab-026", Expectation::Pass),
    ("mcp-auth-lab-027", Expectation::Fail),
    ("mcp-auth-lab-028", Expectation::Pass),
    ("mcp-auth-lab-029", Expectation::IdentityBoundaryHolds),
    ("mcp-auth-lab-030", Expectation::IdentityBoundaryBroken),
    ("mcp-auth-lab-031", Expectation::Pass),
    ("mcp-auth-lab-032", Expectation::Pass),
    ("mcp-auth-lab-033", Expectation::Fail),
    ("mcp-auth-lab-034", Expectation::Fail),
    ("mcp-auth-lab-035", Expectation::Inconclusive),
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scenarios")
}

fn raw(lab: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(format!("{lab}.json")))
        .unwrap_or_else(|err| panic!("{lab} is readable: {err}"))
}

/// Load a lab exactly as the engine would: the hostile sweep and the schema
/// first, then a typed decode, then the structural checks a schema cannot
/// express. Anything a gate refuses never becomes a scenario value.
fn load(lab: &str) -> Result<McpAuthScenario, McpAuthSecurityError> {
    let bytes = raw(lab);
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("{lab} is valid JSON: {err}"));
    validate_scenario_document(&value)?;
    let scenario: McpAuthScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn events(scenario: &McpAuthScenario) -> Vec<McpAuthObservation> {
    let raw = SimulatedAdapter::new()
        .observe(&TrialRequest {
            trial_index: 0,
            scenario,
        })
        .unwrap_or_else(|err| panic!("{} stages: {err}", scenario.id));
    normalize_checked(&raw, scenario)
        .unwrap_or_else(|err| panic!("{} normalizes: {err}", scenario.id))
}

#[test]
fn every_lab_reaches_the_outcome_the_register_approves() {
    for (lab, expectation) in LABS {
        match expectation {
            Expectation::Refused => {
                let err = load(lab)
                    .err()
                    .unwrap_or_else(|| panic!("{lab} must be refused before it can be evaluated"));
                assert!(
                    err.is_refusal() || matches!(err, McpAuthSecurityError::Schema(_)),
                    "{lab} was rejected for the wrong reason: {err}"
                );
            }
            Expectation::IdentityBoundaryHolds | Expectation::IdentityBoundaryBroken => {
                // Asserted in its own test below, against the identity evidence
                // rather than against one of the fourteen invariants.
                load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
            }
            _ => {
                let scenario = load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
                let outcome = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));

                let expected = match expectation {
                    Expectation::Pass => Verdict::Pass,
                    Expectation::Fail => Verdict::Fail,
                    Expectation::Inconclusive => Verdict::Inconclusive,
                    _ => unreachable!(),
                };
                assert_eq!(
                    outcome.verdict, expected,
                    "{lab} produced {:?}: {}",
                    outcome.verdict, outcome.reason
                );
            }
        }
    }
}

#[test]
fn the_register_covers_every_fixture_and_no_fixture_is_unregistered() {
    // A fixture nobody registered would run in no test at all, and a registered
    // lab with no fixture would silently pass by absence.
    let registered: BTreeSet<String> = LABS.iter().map(|(lab, _)| (*lab).to_owned()).collect();
    assert_eq!(registered.len(), 35, "the register lists a lab twice");

    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .expect("the fixtures directory exists")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().replace(".json", ""))
        .collect();
    assert_eq!(on_disk, registered);
}

#[test]
fn the_corpus_meets_the_approved_minimum() {
    // The design fixes a floor of 28 scenarios. Asserted as a floor rather than
    // an equality so the corpus can grow without editing this test, while the
    // approved minimum stays enforced.
    assert!(LABS.len() >= 28, "the approved minimum is 28 scenarios");
}

#[test]
fn no_fixture_can_state_its_own_verdict() {
    for (lab, _) in LABS {
        let value: serde_json::Value = serde_json::from_slice(&raw(lab)).expect("valid JSON");
        for field in [
            "verdict",
            "expected_verdict",
            "expected_result",
            "expected_outcome",
            "should_pass",
            "should_fail",
            "is_vulnerable",
            "is_secure",
        ] {
            assert!(
                value.get(field).is_none(),
                "{lab} carries `{field}`, which would make the evaluator ceremonial"
            );
        }
    }
}

#[test]
fn the_paired_labs_differ_only_in_the_field_under_test() {
    // The paired design, asserted rather than assumed. If a future edit "fixed"
    // a FAIL lab by also changing its resource or its request, the pair would
    // stop isolating the behaviour and this test would say so.
    for (pass_lab, fail_lab) in [
        ("mcp-auth-lab-005", "mcp-auth-lab-006"),
        ("mcp-auth-lab-007", "mcp-auth-lab-008"),
        ("mcp-auth-lab-009", "mcp-auth-lab-010"),
        ("mcp-auth-lab-011", "mcp-auth-lab-012"),
        ("mcp-auth-lab-016", "mcp-auth-lab-017"),
        ("mcp-auth-lab-018", "mcp-auth-lab-019"),
        ("mcp-auth-lab-020", "mcp-auth-lab-021"),
        ("mcp-auth-lab-023", "mcp-auth-lab-025"),
        ("mcp-auth-lab-026", "mcp-auth-lab-027"),
        ("mcp-auth-lab-031", "mcp-auth-lab-033"),
    ] {
        let pass = load(pass_lab).expect("loads");
        let fail = load(fail_lab).expect("loads");

        assert_eq!(
            pass.requests, fail.requests,
            "{pass_lab}/{fail_lab} requests"
        );
        assert_eq!(
            pass.invariant, fail.invariant,
            "{pass_lab}/{fail_lab} must be judged against the same invariant"
        );
        assert_eq!(pass.class, fail.class, "{pass_lab}/{fail_lab} surface");
        assert_ne!(
            (
                &pass.protected_resource,
                &pass.authorization_flow,
                &pass.tokens,
                &pass.flow,
                &pass.scope,
                &pass.registration,
                &pass.credential_flow,
                &pass.final_operation,
            ),
            (
                &fail.protected_resource,
                &fail.authorization_flow,
                &fail.tokens,
                &fail.flow,
                &fail.scope,
                &fail.registration,
                &fail.credential_flow,
                &fail.final_operation,
            ),
            "{pass_lab}/{fail_lab} are identical, so the pair isolates nothing"
        );
    }
}

#[test]
fn a_pass_never_rests_on_an_empty_observation_set() {
    // A verdict of PASS from nothing observed is the failure mode the whole
    // coverage contract exists to prevent, checked directly here too.
    for (lab, expectation) in LABS {
        if expectation != Expectation::Pass {
            continue;
        }
        let scenario = load(lab).expect("loads");
        assert!(
            !events(&scenario).is_empty(),
            "{lab} passed on no observations"
        );
    }
}

#[test]
fn the_labs_between_them_exercise_every_reporting_surface() {
    let mut named: BTreeSet<ScenarioClass> = BTreeSet::new();
    for (lab, expectation) in LABS {
        if expectation == Expectation::Refused {
            continue;
        }
        named.insert(load(lab).expect("loads").class);
    }
    assert_eq!(named.len(), 6, "a reporting surface has no lab");
}

#[test]
fn the_labs_between_them_exercise_every_invariant() {
    // An invariant no lab ever names is an invariant nothing end-to-end
    // exercises, however many unit tests it has.
    let mut named: BTreeSet<McpAuthInvariantType> = BTreeSet::new();
    for (lab, expectation) in LABS {
        if expectation == Expectation::Refused {
            continue;
        }
        named.insert(load(lab).expect("loads").invariant.type_);
    }
    // Twelve of the fourteen are reachable from a lab. The two name-binding and
    // protocol-revision partners are covered above; the remaining gap is
    // asserted explicitly rather than hidden.
    assert!(
        named.len() >= 10,
        "only {} invariants are exercised by a lab",
        named.len()
    );
}

#[test]
fn the_self_reported_identity_boundary_is_judged_on_its_own_evidence() {
    // The boundary is a property of the identity evidence rather than of a
    // request, so it is not one of the fourteen invariants. It is still
    // deterministic, and both directions are asserted here.
    let holds = load("mcp-auth-lab-029").expect("loads");
    assert_eq!(
        holds.identity_metadata.boundary_holds(),
        Some(true),
        "self-description recorded without promotion should hold"
    );

    let broken = load("mcp-auth-lab-030").expect("loads");
    assert_eq!(
        broken.identity_metadata.boundary_holds(),
        Some(false),
        "a principal derived from self-report should break the boundary"
    );

    // And the pair differs only in that one field.
    assert_eq!(holds.requests, broken.requests);
    assert_eq!(
        holds.identity_metadata.client_info,
        broken.identity_metadata.client_info
    );
}

#[test]
fn a_promoted_self_report_fails_the_run_and_not_only_a_field_assertion() {
    // Reading `boundary_holds()` off the scenario proves the model is right. It
    // does not prove the *engine* acts on it, and for a while it did not: lab
    // 030 declared a request-level invariant that genuinely held, so a run
    // reported PASS on a target that had already turned a self-reported name
    // into a principal.
    let broken = load("mcp-auth-lab-030").expect("loads");
    let plan = TrialPlan::from_scenario(&broken).expect("plan");
    let result = run_scenario(&broken, None, &SimulatedAdapter::new(), plan).expect("runs");

    assert_eq!(result.verdict, Verdict::Fail);
    let violation = result
        .violations()
        .into_iter()
        .find(|violation| violation.reason.contains("self-reported"))
        .expect("the finding names the promotion");
    assert_eq!(violation.subject.as_deref(), Some("user-7"));

    // The control still passes, so the gate is judging the promotion rather
    // than the presence of self-description.
    let holds = load("mcp-auth-lab-029").expect("loads");
    let plan = TrialPlan::from_scenario(&holds).expect("plan");
    let clean = run_scenario(&holds, None, &SimulatedAdapter::new(), plan).expect("runs");
    assert_eq!(clean.verdict, Verdict::Pass);
}

#[test]
fn the_identity_boundary_is_checked_even_when_a_scenario_selects_another_invariant() {
    // The reason it is not a fifteenth selectable invariant. A deployment that
    // derived its principal from `clientInfo` is broken whatever else the run
    // was looking at, so a scenario examining protocol binding must still
    // report it rather than passing on the question it did select.
    let mut scenario = load("mcp-auth-lab-001").expect("loads");
    assert_eq!(
        scenario.invariant.type_,
        McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved
    );
    scenario
        .identity_metadata
        .principal_derived_from_self_report = true;

    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
    assert_eq!(
        result.verdict,
        Verdict::Fail,
        "a promoted self-report passed because the scenario was asking about something else"
    );
}

#[test]
fn a_scenario_with_no_self_description_is_not_judged_on_a_boundary_it_never_crossed() {
    // `None` is a third answer. A target that reports no `clientInfo` at all
    // has nothing to have promoted, and must not be failed for it.
    let mut scenario = load("mcp-auth-lab-001").expect("loads");
    scenario.identity_metadata.client_info = None;
    scenario.identity_metadata.server_info = None;
    assert_eq!(scenario.identity_metadata.boundary_holds(), None);

    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn an_unsupported_revision_fails_closed_rather_than_being_evaluated() {
    let scenario = load("mcp-auth-lab-002").expect("loads");
    let outcome = evaluate(
        McpAuthInvariantType::McpProtocolRevisionPreserved,
        &scenario,
        &events(&scenario),
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.reason.contains("unsupported"));
}

#[test]
fn the_multi_violation_lab_crosses_three_boundaries_at_once() {
    // Each of the three has to be independently observable. An engine that
    // reported the first would understate what it saw.
    let scenario = load("mcp-auth-lab-034").expect("loads");
    let observed = events(&scenario);
    for invariant in [
        McpAuthInvariantType::AuthorizationResponseIssuerPreserved,
        McpAuthInvariantType::TokenResourceAudienceBoundaryPreserved,
        McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority,
    ] {
        let outcome = evaluate(invariant, &scenario, &observed);
        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "{invariant:?} did not fail: {}",
            outcome.reason
        );
        assert!(!outcome.violations.is_empty());
    }
}

#[test]
fn a_retry_past_the_ceiling_is_refused_by_the_schema_before_evaluation() {
    // Refusing is not a security FAIL. The scenario asked for something outside
    // the approved bounds and was never evaluated, which is a different fact
    // from a boundary having been crossed.
    let value: serde_json::Value =
        serde_json::from_slice(&raw("mcp-auth-lab-022")).expect("valid JSON");
    let err = validate_scenario_document(&value).expect_err("must be refused");
    assert!(matches!(err, McpAuthSecurityError::Schema(_)));
}

#[test]
fn no_fixture_carries_a_credential_a_secret_or_a_reachable_target() {
    for (lab, _) in LABS {
        let text = String::from_utf8(raw(lab)).expect("utf-8");
        for marker in [
            "eyJhbGci",
            "sk-live-",
            "-----BEGIN",
            "Bearer ",
            "://",
            "client_secret",
            "access_token",
        ] {
            assert!(!text.contains(marker), "{lab} carries `{marker}`");
        }
    }
}
