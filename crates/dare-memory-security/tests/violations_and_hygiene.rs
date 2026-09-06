//! Independent multi-violation capture and redaction before persistence.
//!
//! Two properties that are easy to lose and hard to notice losing.
//!
//! **All of them, not the first.** When one trial breaks three boundaries, an
//! engine that stops at the first finding reports a smaller problem than the
//! one it saw. The operator fixes the trust promotion, re-runs, and learns
//! about the tenant crossing — then fixes that and learns about the
//! substitution. Each round trip looks like progress and none of them was the
//! whole picture. So every independently observed violation is retained, and
//! this suite proves the three fail together on the same events.
//!
//! **Redaction happens before anything is kept.** Evidence text, refusal
//! messages and observation records are all persistence surfaces. A canary or a
//! credential that reaches one of them has left the process, and masking it
//! afterwards is too late.

use std::path::PathBuf;

use dare_memory_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_memory_security::invariant::evaluate;
use dare_memory_security::model::{MemoryInvariantType, MemorySecurityScenario};
use dare_memory_security::observation::{
    mask_sensitive, EvidenceText, MemoryObservationEvent, REDACTION_MARKER,
};
use dare_memory_security::schema::validate_scenario_document;
use dare_memory_security::simulated::SimulatedAdapter;
use dare_memory_security::Verdict;

fn load(lab: &str) -> MemorySecurityScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
        .join(format!("{lab}.json"));
    let bytes = std::fs::read(&path).expect("fixture readable");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    validate_scenario_document(&value).expect("admissible");
    let scenario: MemorySecurityScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
}

fn events(scenario: &MemorySecurityScenario) -> Vec<MemoryObservationEvent> {
    let raw = SimulatedAdapter::new()
        .observe(&TrialRequest {
            trial_index: 0,
            scenario,
        })
        .expect("stages");
    normalize_checked(&raw, scenario).expect("normalizes")
}

/// The three invariants MEMORY-LAB-022 breaks at once.
const SIMULTANEOUS: [MemoryInvariantType; 3] = [
    MemoryInvariantType::UntrustedMemoryNotPromotedToAuthority,
    MemoryInvariantType::MemoryTenantBoundaryPreserved,
    MemoryInvariantType::MemoryIntegrityDigestPreserved,
];

#[test]
fn three_simultaneous_violations_are_all_reported_from_one_trial() {
    let scenario = load("memory-lab-022");
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
    // Order independence. If evaluating the trust invariant first changed what
    // the tenant invariant could see, "first violation wins" would be back in
    // a subtler form.
    let scenario = load("memory-lab-022");
    let observed = events(&scenario);

    let forward: Vec<Verdict> = SIMULTANEOUS
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();

    let mut reversed_order = SIMULTANEOUS;
    reversed_order.reverse();
    let mut backward: Vec<Verdict> = reversed_order
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();
    backward.reverse();

    assert_eq!(forward, backward);
    assert!(forward.iter().all(|verdict| *verdict == Verdict::Fail));
}

#[test]
fn every_violation_names_the_events_that_decided_it() {
    // A finding with no deciding event is an assertion, not evidence. An
    // operator has to be able to go from the verdict back to the observation.
    let scenario = load("memory-lab-022");
    let observed = events(&scenario);

    for invariant in SIMULTANEOUS {
        for violation in evaluate(invariant, &scenario, &observed).violations {
            assert!(
                !violation.deciding_event_digests.is_empty(),
                "{invariant:?} recorded a violation with no deciding event"
            );
            assert!(
                !violation.reason.trim().is_empty(),
                "{invariant:?} recorded a violation with no reason"
            );
        }
    }
}

#[test]
fn a_failing_run_of_one_invariant_leaves_the_others_independently_judged() {
    // The lifecycle invariant is not broken by lab 022, and must not be
    // dragged down by the three that are. Bundling unrelated invariants into
    // one verdict would overstate the finding.
    let scenario = load("memory-lab-022");
    let observed = events(&scenario);

    let unrelated = evaluate(
        MemoryInvariantType::ExpiredOrRevokedMemoryNotUsed,
        &scenario,
        &observed,
    );
    assert_ne!(
        unrelated.verdict,
        Verdict::Fail,
        "an unrelated invariant was failed by another invariant's violations: {}",
        unrelated.reason
    );
}

#[test]
fn no_retained_text_from_any_lab_carries_a_canary_or_a_credential() {
    // Everything a run would keep: violation reasons, details and the outcome
    // reason itself. None of it may carry protected material.
    for index in 1..=22 {
        let lab = format!("memory-lab-{index:03}");
        let scenario = load(&lab);
        let observed = events(&scenario);

        let mut retained = Vec::new();
        for invariant in MemoryInvariantType::all() {
            let outcome = evaluate(invariant, &scenario, &observed);
            retained.push(outcome.reason.clone());
            for violation in outcome.violations {
                retained.push(violation.reason);
                if let Some(detail) = violation.detail {
                    retained.push(detail);
                }
            }
        }
        // The observation records are retained too.
        retained.push(serde_json::to_string(&observed).expect("serializes"));

        for text in retained {
            for canary in &scenario.objective.protected_canaries {
                assert!(
                    !text.contains(canary.as_str()),
                    "{lab} retained a protected canary in `{text}`"
                );
            }
            for marker in ["sk-live-", "-----BEGIN", "Bearer ey"] {
                assert!(!text.contains(marker), "{lab} retained `{marker}`");
            }
        }
    }
}

#[test]
fn masking_replaces_the_value_and_keeps_the_sentence_readable() {
    // A mask that erased the whole line would make evidence useless; one that
    // kept the value would make it dangerous.
    let masked = mask_sensitive("the write carried Authorization: Bearer abcdefghijklmnopqrst");
    assert!(masked.contains(REDACTION_MARKER));
    assert!(!masked.contains("abcdefghijklmnopqrst"));
    assert!(masked.contains("the write carried"));
}

#[test]
fn evidence_text_is_masked_at_construction_rather_than_on_the_way_out() {
    // The distinction that matters: if masking happened at render time, the
    // unmasked value would already be sitting in memory, in a serialized
    // record, and in whatever else read the struct first.
    let evidence =
        EvidenceText::from_raw("recalled sk-live-000000000000000000000000 into the summary");
    assert!(!evidence.text.contains("sk-live-"));
    assert!(evidence.text.contains(REDACTION_MARKER));
    assert!(evidence.redacted);
    assert!(evidence.is_secret_safe());

    let serialized = serde_json::to_string(&evidence).expect("serializes");
    assert!(!serialized.contains("sk-live-"));
}
