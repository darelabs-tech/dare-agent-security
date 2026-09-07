//! Independent multi-violation capture, and redaction before persistence.
//!
//! **All of them, not the first.** One authorization flow can mix up the
//! issuer, present a token minted for another resource and forward the inbound
//! credential upstream, all at once. An engine that stops at the first finding
//! reports a smaller problem than the one it saw: the operator fixes the
//! issuer, re-runs, and learns about the audience — then fixes that and learns
//! about the credential. Each round trip looks like progress and none of them
//! was the whole picture.
//!
//! **Redaction happens before anything is kept.** Evidence text, refusal
//! messages, observation records and the result artifact are all persistence
//! surfaces. A canary or a credential that reaches one of them has left the
//! process, and masking it afterwards is too late.

use std::path::PathBuf;

use dare_mcp_auth_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_mcp_auth_security::invariant::evaluate;
use dare_mcp_auth_security::model::{McpAuthInvariantType, McpAuthScenario};
use dare_mcp_auth_security::observation::{
    mask_sensitive, EvidenceText, McpAuthObservation, REDACTION_MARKER,
};
use dare_mcp_auth_security::schema::validate_scenario_document;
use dare_mcp_auth_security::simulated::SimulatedAdapter;
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

/// The three invariants lab 034 breaches at once.
const SIMULTANEOUS: [McpAuthInvariantType; 3] = [
    McpAuthInvariantType::AuthorizationResponseIssuerPreserved,
    McpAuthInvariantType::TokenResourceAudienceBoundaryPreserved,
    McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority,
];

#[test]
fn three_simultaneous_violations_are_all_reported_from_one_trial() {
    let scenario = load("mcp-auth-lab-034");
    let observed = events(&scenario);

    for invariant in SIMULTANEOUS {
        let outcome = evaluate(invariant, &scenario, &observed);
        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "{invariant:?} did not fail: {}",
            outcome.reason
        );
        assert!(
            !outcome.violations.is_empty(),
            "{invariant:?} failed with no recorded violation, so nothing says why"
        );
        assert!(
            outcome
                .violations
                .iter()
                .all(|violation| violation.invariant == invariant),
            "{invariant:?} recorded a violation belonging to another invariant"
        );
    }
}

#[test]
fn evaluating_one_invariant_never_consumes_or_hides_another() {
    // Order independence. If evaluating the issuer invariant first changed what
    // the credential invariant could see, "first violation wins" would be back
    // in a subtler form.
    let scenario = load("mcp-auth-lab-034");
    let observed = events(&scenario);

    let forward: Vec<Verdict> = SIMULTANEOUS
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();

    let mut reversed = SIMULTANEOUS;
    reversed.reverse();
    let mut backward: Vec<Verdict> = reversed
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();
    backward.reverse();

    assert_eq!(forward, backward);
    assert!(forward.iter().all(|verdict| *verdict == Verdict::Fail));
}

#[test]
fn every_violation_names_the_evidence_that_decided_it() {
    // A finding with no deciding evidence is an assertion, not a finding. An
    // operator has to be able to go from the verdict back to the observation.
    let scenario = load("mcp-auth-lab-034");
    let observed = events(&scenario);

    for invariant in SIMULTANEOUS {
        for violation in evaluate(invariant, &scenario, &observed).violations {
            assert!(
                !violation.deciding_event_digests.is_empty(),
                "{invariant:?} recorded a violation with no deciding evidence"
            );
            assert!(
                !violation.reason.trim().is_empty(),
                "{invariant:?} recorded a violation with no reason"
            );
        }
    }
}

#[test]
fn an_invariant_the_flow_did_not_breach_stays_independently_judged() {
    // The mirror of the test above. Lab 034 breaches three boundaries; the PKCE
    // binding is untouched and has to say so on its own. If failures propagated
    // between evaluators, every report on a bad run would overstate itself.
    let scenario = load("mcp-auth-lab-034");
    let observed = events(&scenario);
    let untouched = evaluate(
        McpAuthInvariantType::PkceBindingPreserved,
        &scenario,
        &observed,
    );
    assert_eq!(
        untouched.verdict,
        Verdict::Pass,
        "an invariant nothing breached did not hold on its own: {}",
        untouched.reason
    );
    assert!(untouched.violations.is_empty());
}

#[test]
fn a_violation_carries_the_subject_it_is_about() {
    // "An issuer was wrong" is not actionable. The finding names which one.
    let scenario = load("mcp-auth-lab-010");
    let observed = events(&scenario);
    let outcome = evaluate(
        McpAuthInvariantType::AuthorizationResponseIssuerPreserved,
        &scenario,
        &observed,
    );
    let violation = &outcome.violations[0];
    assert_eq!(violation.subject.as_deref(), Some("as-attacker"));
    assert!(violation.request_id.is_some());
}

#[test]
fn stopping_on_first_fail_never_discards_the_evidence_that_caused_it() {
    // The stop is a decision about *later* trials. The failing trial's record
    // has to be complete, or the run would report that something failed while
    // discarding why.
    let scenario = load("mcp-auth-lab-034");
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    assert!(plan.stop_on_first_fail);

    let result = dare_mcp_auth_security::result::run_scenario(
        &scenario,
        None,
        &SimulatedAdapter::new(),
        plan,
    )
    .expect("runs");

    assert_eq!(result.verdict, Verdict::Fail);
    assert_eq!(result.trials_executed, 1);
    assert_eq!(result.stop_reason.as_str(), "FIRST_FAIL");
    assert!(!result.trials[0].violations.is_empty());
    assert!(!result.trials[0].event_digests.is_empty());
    assert!(!result.trials[0].events.is_empty());
}

#[test]
fn no_retained_text_from_any_lab_carries_a_canary_or_a_credential() {
    // Everything a run would keep: violation reasons, details, the outcome
    // reason and the observation records themselves.
    for index in 1..=35 {
        if index == 22 {
            continue; // refused before evaluation; covered by the hostile suite
        }
        let lab = format!("mcp-auth-lab-{index:03}");
        let scenario = load(&lab);
        let observed = events(&scenario);

        let mut retained = Vec::new();
        for invariant in McpAuthInvariantType::all() {
            let outcome = evaluate(invariant, &scenario, &observed);
            retained.push(outcome.reason.clone());
            for violation in outcome.violations {
                retained.push(violation.reason);
                if let Some(detail) = violation.detail {
                    retained.push(detail);
                }
                if let Some(subject) = violation.subject {
                    retained.push(subject);
                }
            }
        }
        retained.push(serde_json::to_string(&observed).expect("serializes"));

        for text in retained {
            for canary in &scenario.objective.protected_canaries {
                assert!(
                    !text.contains(canary.as_str()),
                    "{lab} retained a protected canary"
                );
            }
            for marker in ["sk-live-", "-----BEGIN", "Bearer ey", "eyJhbGci"] {
                assert!(!text.contains(marker), "{lab} retained `{marker}`");
            }
        }
    }
}

#[test]
fn no_retained_observation_names_a_reachable_target() {
    // The offline boundary, checked against everything a run keeps. A schema
    // `$id` names a contract and is never resolved; anything else with a scheme
    // would be something a reader's tooling could follow.
    for index in 1..=35 {
        if index == 22 {
            continue;
        }
        let lab = format!("mcp-auth-lab-{index:03}");
        let serialized = serde_json::to_string(&events(&load(&lab))).expect("serializes");
        for (offset, _) in serialized.match_indices("://") {
            let from = serialized[..offset].rfind('"').map_or(0, |at| at + 1);
            assert!(
                serialized[from..].starts_with("https://darelabs.tech/schemas/"),
                "{lab} retained a reachable target"
            );
        }
    }
}

#[test]
fn masking_replaces_the_value_and_keeps_the_sentence_readable() {
    // A mask that erased the whole line would make evidence useless; one that
    // kept the value would make it dangerous.
    let masked = mask_sensitive("the request carried Authorization: Bearer abcdefghijklmnopqrst");
    assert!(masked.contains(REDACTION_MARKER));
    assert!(!masked.contains("abcdefghijklmnopqrst"));
    assert!(masked.contains("the request carried"));
}

#[test]
fn evidence_text_is_masked_at_construction_rather_than_on_the_way_out() {
    // The distinction that matters: if masking happened at render time, the
    // unmasked value would already be sitting in memory, in a serialized
    // record, and in whatever else read the struct first.
    let evidence =
        EvidenceText::from_raw("the upstream call carried sk-live-000000000000000000000000");
    assert!(!evidence.text.contains("sk-live-"));
    assert!(evidence.text.contains(REDACTION_MARKER));
    assert!(evidence.redacted);
    assert!(evidence.is_secret_safe());

    let serialized = serde_json::to_string(&evidence).expect("serializes");
    assert!(!serialized.contains("sk-live-"));
}

#[test]
fn the_result_artifact_of_a_failing_run_is_still_secret_safe() {
    // The report of a breach is the place most likely to quote what breached.
    let scenario = load("mcp-auth-lab-034");
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    let result = dare_mcp_auth_security::result::run_scenario(
        &scenario,
        None,
        &SimulatedAdapter::new(),
        plan,
    )
    .expect("runs");

    let rendered = serde_json::to_string(&result).expect("serializes");
    for marker in [
        "DARE-SYNTHETIC-CANARY-",
        "sk-live-",
        "-----BEGIN",
        "Bearer ey",
        "eyJhbGci",
    ] {
        assert!(!rendered.contains(marker), "the artifact carried {marker}");
    }
    assert_eq!(result.redaction_state, "REDACTED");
}
