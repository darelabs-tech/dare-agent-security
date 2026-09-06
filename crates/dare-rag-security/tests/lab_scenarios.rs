//! The 24 RAG-LAB fixtures, end to end.
//!
//! Each lab is read from disk, validated as an untrusted document, staged
//! through the simulated adapter, normalized and evaluated. The expected
//! outcome for every lab lives **here**, in the register below — never in the
//! fixture.
//!
//! That separation is the whole reason the register exists. A scenario that
//! could state its own verdict would make the evaluator ceremonial: the run
//! would report back whatever the fixture author already believed. So the
//! fixtures describe a situation and a reference retriever's behaviour, this
//! file says what the engine ought to conclude from that, and the two only meet
//! at the assertion.
//!
//! The labs are also **paired**. A PASS lab and its FAIL partner share the same
//! corpus, the same principals, the same policy and the same query; the only
//! difference is what the retriever did. If they differed in ten ways, a
//! verdict difference would prove nothing about which way mattered.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_rag_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_rag_security::invariant::evaluate;
use dare_rag_security::model::{RagInvariantType, RagSecurityScenario};
use dare_rag_security::observation::RagObservationEvent;
use dare_rag_security::schema::validate_scenario_document;
use dare_rag_security::simulated::SimulatedAdapter;
use dare_rag_security::{RagSecurityError, Verdict};

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
    ("rag-lab-001", Expectation::Pass),
    ("rag-lab-002", Expectation::Fail),
    ("rag-lab-003", Expectation::Pass),
    ("rag-lab-004", Expectation::Fail),
    ("rag-lab-005", Expectation::Pass),
    ("rag-lab-006", Expectation::Fail),
    ("rag-lab-007", Expectation::Pass),
    ("rag-lab-008", Expectation::Fail),
    ("rag-lab-009", Expectation::Pass),
    ("rag-lab-010", Expectation::Fail),
    ("rag-lab-011", Expectation::Pass),
    ("rag-lab-012", Expectation::Fail),
    ("rag-lab-013", Expectation::Pass),
    ("rag-lab-014", Expectation::Fail),
    ("rag-lab-015", Expectation::Pass),
    ("rag-lab-016", Expectation::Fail),
    ("rag-lab-017", Expectation::Pass),
    ("rag-lab-018", Expectation::Fail),
    ("rag-lab-019", Expectation::Pass),
    ("rag-lab-020", Expectation::Fail),
    ("rag-lab-021", Expectation::Inconclusive),
    ("rag-lab-022", Expectation::Fail),
    ("rag-lab-023", Expectation::Refused),
    ("rag-lab-024", Expectation::Refused),
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
fn load(lab: &str) -> Result<RagSecurityScenario, RagSecurityError> {
    let bytes = raw(lab);
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("{lab} is valid JSON: {err}"));
    validate_scenario_document(&value)?;
    let scenario: RagSecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn events(scenario: &RagSecurityScenario) -> Vec<RagObservationEvent> {
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
                    err.is_refusal() || matches!(err, RagSecurityError::Schema(_)),
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
        let value: serde_json::Value = serde_json::from_slice(&raw(lab)).expect("valid JSON");

        // Lab 24 exists precisely to smuggle one, and is refused for it.
        if lab == "rag-lab-024" {
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
            "is_leaked",
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
    // "fixed" a FAIL lab by also changing its corpus or policy, the pair would
    // stop isolating the behaviour and this test would say so.
    for (pass_lab, fail_lab) in [
        ("rag-lab-001", "rag-lab-002"),
        ("rag-lab-003", "rag-lab-004"),
        ("rag-lab-005", "rag-lab-006"),
        ("rag-lab-007", "rag-lab-008"),
        ("rag-lab-009", "rag-lab-010"),
        ("rag-lab-011", "rag-lab-012"),
        ("rag-lab-013", "rag-lab-014"),
        ("rag-lab-015", "rag-lab-016"),
        ("rag-lab-017", "rag-lab-018"),
        ("rag-lab-019", "rag-lab-020"),
    ] {
        let pass = load(pass_lab).expect("loads");
        let fail = load(fail_lab).expect("loads");

        assert_eq!(pass.store, fail.store, "{pass_lab}/{fail_lab} corpus");
        assert_eq!(pass.context, fail.context, "{pass_lab}/{fail_lab} context");
        assert_eq!(pass.policy, fail.policy, "{pass_lab}/{fail_lab} policy");
        assert_eq!(pass.queries, fail.queries, "{pass_lab}/{fail_lab} queries");
        assert_eq!(
            pass.candidate_sets, fail.candidate_sets,
            "{pass_lab}/{fail_lab} candidates"
        );
        assert_eq!(
            pass.invariant, fail.invariant,
            "{pass_lab}/{fail_lab} must be judged against the same invariant"
        );
        assert_ne!(
            pass.lab.as_ref().map(|lab| lab.reference_behavior),
            fail.lab.as_ref().map(|lab| lab.reference_behavior),
            "{pass_lab}/{fail_lab} stage the same behaviour"
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
        assert!(
            !events(&scenario).is_empty(),
            "{lab} passed on no observations"
        );
    }
}

#[test]
fn the_labs_between_them_exercise_every_reporting_surface() {
    let mut named: BTreeSet<RagInvariantType> = BTreeSet::new();
    for (lab, expectation) in LABS {
        if expectation == Expectation::Refused {
            continue;
        }
        named.insert(load(lab).expect("loads").invariant.type_);
    }

    // Not every invariant needs a lab — some are exercised by the corpus and
    // the unit suite — but the surfaces must all be represented, or a whole
    // family of retrieval failure would go untested while the report looked
    // complete.
    let surfaces: BTreeSet<&str> = named
        .iter()
        .map(|invariant| invariant.surface().as_str())
        .collect();
    assert_eq!(surfaces.len(), 6, "a retrieval surface has no lab");
}

#[test]
fn a_high_score_never_rescues_a_boundary_crossing() {
    // The cycle's thesis, at the level of a whole lab. Lab 016 stages the
    // protected document at the top of the ranking; it still fails.
    let scenario = load("rag-lab-016").expect("loads");
    let outcome = evaluate(scenario.invariant.type_, &scenario, &events(&scenario));
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.reason.contains("protected"));
    assert!(!outcome.reason.contains("score"));
}

#[test]
fn the_over_bound_lab_is_refused_by_two_independent_gates() {
    // The schema refuses it, and so does the typed corpus check. Either gate
    // alone would be a single point of failure for a bound the engine promises
    // never to exceed.
    let value: serde_json::Value = serde_json::from_slice(&raw("rag-lab-023")).expect("valid JSON");
    assert!(
        validate_scenario_document(&value).is_err(),
        "the schema admitted an over-bound corpus"
    );

    let scenario: RagSecurityScenario =
        serde_json::from_value(value).expect("the typed shape still decodes");
    let err = scenario
        .validate()
        .expect_err("the structural check must refuse it too");
    assert!(err.is_refusal() || matches!(err, RagSecurityError::BudgetExhausted(_)));
}

#[test]
fn the_smuggling_lab_is_refused_before_anything_is_read_as_a_scenario() {
    let value: serde_json::Value = serde_json::from_slice(&raw("rag-lab-024")).expect("valid JSON");
    let err = validate_scenario_document(&value).expect_err("must be refused");

    // The refusal must not echo the smuggled material back into a message.
    let message = err.to_string();
    assert!(!message.contains("sk-live-"), "the refusal echoed a secret");
    assert!(
        !message.contains("example.invalid"),
        "the refusal echoed a remote target"
    );
}
