//! The 24 MEMORY-LAB fixtures, end to end.
//!
//! Each lab is read from disk, validated as an untrusted document, staged
//! through the simulated adapter, normalized and evaluated. The expected
//! outcome for every lab lives **here**, in the test — never in the fixture.
//!
//! That separation is the whole reason the register below exists. A scenario
//! that could state its own verdict would make the evaluator ceremonial: the
//! run would report back whatever the fixture author already believed. So the
//! fixtures describe a situation and a reference agent's behavior, this file
//! says what the engine ought to conclude from that, and the two only meet at
//! the assertion.
//!
//! The labs are also **paired**. A PASS lab and its FAIL partner share the same
//! store, the same principals, the same policy and the same recall; the only
//! difference is what the reference agent did. If they differed in ten ways, a
//! verdict difference would prove nothing about which way mattered.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_memory_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_memory_security::invariant::evaluate;
use dare_memory_security::model::{MemoryInvariantType, MemorySecurityScenario};
use dare_memory_security::observation::MemoryObservationEvent;
use dare_memory_security::schema::validate_scenario_document;
use dare_memory_security::simulated::SimulatedAdapter;
use dare_memory_security::{MemorySecurityError, Verdict};

/// What a lab is expected to produce for the invariant it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Pass,
    Fail,
    /// The question could not be decided from what the run observed.
    Inconclusive,
    /// The document never reaches evaluation: a gate refuses it first.
    Refused,
}

/// The approved lab register: id, and what the engine should conclude.
const LABS: [(&str, Expectation); 24] = [
    ("memory-lab-001", Expectation::Pass),
    ("memory-lab-002", Expectation::Fail),
    ("memory-lab-003", Expectation::Pass),
    ("memory-lab-004", Expectation::Fail),
    ("memory-lab-005", Expectation::Pass),
    ("memory-lab-006", Expectation::Fail),
    ("memory-lab-007", Expectation::Pass),
    ("memory-lab-008", Expectation::Fail),
    ("memory-lab-009", Expectation::Pass),
    ("memory-lab-010", Expectation::Fail),
    ("memory-lab-011", Expectation::Pass),
    ("memory-lab-012", Expectation::Fail),
    ("memory-lab-013", Expectation::Pass),
    ("memory-lab-014", Expectation::Fail),
    ("memory-lab-015", Expectation::Fail),
    ("memory-lab-016", Expectation::Pass),
    ("memory-lab-017", Expectation::Fail),
    ("memory-lab-018", Expectation::Fail),
    ("memory-lab-019", Expectation::Fail),
    ("memory-lab-020", Expectation::Fail),
    ("memory-lab-021", Expectation::Inconclusive),
    ("memory-lab-022", Expectation::Fail),
    ("memory-lab-023", Expectation::Refused),
    ("memory-lab-024", Expectation::Refused),
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
fn load(lab: &str) -> Result<MemorySecurityScenario, MemorySecurityError> {
    let bytes = raw(lab);
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("{lab} is valid JSON: {err}"));
    validate_scenario_document(&value)?;
    let scenario: MemorySecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn events(scenario: &MemorySecurityScenario) -> Vec<MemoryObservationEvent> {
    let adapter = SimulatedAdapter::new();
    let raw = adapter
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
                    err.is_refusal() || matches!(err, MemorySecurityError::Schema(_)),
                    "{lab} was rejected for the wrong reason: {err}"
                );
            }
            _ => {
                let scenario = load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
                let outcome = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));

                let expected = match expectation {
                    Expectation::Pass => Verdict::Pass,
                    Expectation::Fail => Verdict::Fail,
                    Expectation::Inconclusive => Verdict::Inconclusive,
                    Expectation::Refused => unreachable!(),
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
fn the_register_covers_twenty_four_distinct_labs() {
    let ids: BTreeSet<&str> = LABS.iter().map(|(lab, _)| *lab).collect();
    assert_eq!(ids.len(), 24, "the register lists a lab twice");

    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .expect("the fixtures directory exists")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().replace(".json", ""))
        .collect();
    let registered: BTreeSet<String> = ids.iter().map(|lab| (*lab).to_owned()).collect();

    // A fixture nobody registered would run in no test at all, and a
    // registered lab with no fixture would silently pass by absence.
    assert_eq!(on_disk, registered);
}

#[test]
fn no_fixture_can_state_its_own_verdict() {
    for (lab, _) in LABS {
        let text = String::from_utf8(raw(lab)).expect("fixtures are UTF-8");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

        // Lab 24 exists precisely to smuggle one, and is refused for it.
        if lab == "memory-lab-024" {
            assert!(value.get("expected_verdict").is_some());
            continue;
        }

        for field in [
            "verdict",
            "expected_verdict",
            "expected_result",
            "expected_outcome",
            "should_pass",
            "should_fail",
        ] {
            assert!(
                value.get(field).is_none(),
                "{lab} carries `{field}`, which would make the evaluator ceremonial"
            );
        }
    }
}

#[test]
fn the_pass_labs_and_their_fail_partners_differ_only_in_reference_behavior() {
    // The paired design, asserted rather than assumed. If a future edit
    // "fixed" a FAIL lab by also changing its store or policy, the pair would
    // stop isolating the behavior and this test would say so.
    for (pass_lab, fail_lab) in [
        ("memory-lab-001", "memory-lab-002"),
        ("memory-lab-003", "memory-lab-004"),
        ("memory-lab-005", "memory-lab-006"),
        ("memory-lab-007", "memory-lab-008"),
        ("memory-lab-009", "memory-lab-010"),
        ("memory-lab-011", "memory-lab-012"),
        ("memory-lab-013", "memory-lab-014"),
        ("memory-lab-016", "memory-lab-017"),
    ] {
        let pass = load(pass_lab).expect("loads");
        let fail = load(fail_lab).expect("loads");

        assert_eq!(pass.store, fail.store, "{pass_lab}/{fail_lab} store");
        assert_eq!(pass.context, fail.context, "{pass_lab}/{fail_lab} context");
        assert_eq!(pass.policy, fail.policy, "{pass_lab}/{fail_lab} policy");
        assert_eq!(pass.recall, fail.recall, "{pass_lab}/{fail_lab} recall");
        assert_eq!(
            pass.decision, fail.decision,
            "{pass_lab}/{fail_lab} decision"
        );
        assert_eq!(
            pass.evaluation_time, fail.evaluation_time,
            "{pass_lab}/{fail_lab} evaluation time"
        );
        assert_eq!(
            pass.invariant, fail.invariant,
            "{pass_lab}/{fail_lab} must be judged against the same invariant"
        );
        assert_ne!(
            pass.lab.as_ref().map(|lab| lab.reference_behavior),
            fail.lab.as_ref().map(|lab| lab.reference_behavior),
            "{pass_lab}/{fail_lab} stage the same behavior"
        );
    }
}

#[test]
fn a_pass_never_rests_on_an_empty_observation_set() {
    // Every PASS lab must have produced observations. A verdict of PASS from
    // nothing observed is the failure mode the whole coverage contract exists
    // to prevent, so it is checked directly here too.
    for (lab, expectation) in LABS {
        if expectation != Expectation::Pass {
            continue;
        }
        let scenario = load(lab).expect("loads");
        let observed = events(&scenario);
        assert!(!observed.is_empty(), "{lab} passed on no observations");
    }
}

#[test]
fn the_labs_between_them_exercise_every_invariant_surface() {
    let mut named: BTreeSet<MemoryInvariantType> = BTreeSet::new();
    for (lab, expectation) in LABS {
        if expectation == Expectation::Refused {
            continue;
        }
        named.insert(load(lab).expect("loads").invariant.type_);
    }

    // Not every invariant needs a lab — some are exercised by the corpus and
    // the unit suite — but the surfaces must all be represented, or a whole
    // family of poisoning would go untested while the report looked complete.
    let surfaces: BTreeSet<&str> = named
        .iter()
        .map(|invariant| invariant.surface().as_str())
        .collect();
    assert_eq!(surfaces.len(), 5, "a memory-security surface has no lab");
}

#[test]
fn the_over_bound_lab_is_refused_by_two_independent_gates() {
    // The schema refuses it, and so does the typed store check. Either gate
    // alone would be a single point of failure for a bound the engine promises
    // never to exceed.
    let bytes = raw("memory-lab-023");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(
        validate_scenario_document(&value).is_err(),
        "the schema admitted an over-bound store"
    );

    let scenario: MemorySecurityScenario =
        serde_json::from_value(value).expect("the typed shape still decodes");
    let err = scenario
        .validate()
        .expect_err("the structural check must refuse it too");
    assert!(err.is_refusal() || matches!(err, MemorySecurityError::BudgetExhausted(_)));
}

#[test]
fn the_smuggling_lab_is_refused_before_anything_is_read_as_a_scenario() {
    let bytes = raw("memory-lab-024");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let err = validate_scenario_document(&value).expect_err("must be refused");

    // The refusal must not echo the smuggled material back into a message.
    let message = err.to_string();
    assert!(!message.contains("sk-live-"), "the refusal echoed a secret");
    assert!(
        !message.contains("example.invalid"),
        "the refusal echoed a remote target"
    );
}
