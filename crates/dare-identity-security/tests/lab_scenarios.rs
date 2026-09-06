//! The 24 IDENTITY-LAB fixtures, end to end.
//!
//! Each lab is loaded from disk, validated, staged through the simulated
//! adapter, normalized and evaluated. The expected outcome for each lab lives
//! **here**, in the test — never in the fixture. A fixture that could state its
//! own verdict would make the evaluator ceremonial, so the two are kept apart
//! and this file is the only place the two meet.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_identity_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_identity_security::invariant::evaluate;
use dare_identity_security::model::{IdentityInvariantType, IdentitySecurityScenario};
use dare_identity_security::observation::IdentityObservationEvent;
use dare_identity_security::schema::validate_scenario_document;
use dare_identity_security::simulated::SimulatedAdapter;
use dare_identity_security::{IdentitySecurityError, Verdict};

/// What the lab is expected to produce for its own declared invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Pass,
    Fail,
    Inconclusive,
    /// The document is admitted by the schema and refused by the engine.
    Refused,
}

/// The approved lab register: id, what it exercises, and what it should yield.
const LABS: [(&str, Expectation); 24] = [
    ("identity-lab-001", Expectation::Pass),
    ("identity-lab-002", Expectation::Fail),
    ("identity-lab-003", Expectation::Pass),
    ("identity-lab-004", Expectation::Fail),
    ("identity-lab-005", Expectation::Pass),
    ("identity-lab-006", Expectation::Fail),
    ("identity-lab-007", Expectation::Pass),
    ("identity-lab-008", Expectation::Fail),
    ("identity-lab-009", Expectation::Pass),
    ("identity-lab-010", Expectation::Fail),
    ("identity-lab-011", Expectation::Pass),
    ("identity-lab-012", Expectation::Fail),
    ("identity-lab-013", Expectation::Fail),
    ("identity-lab-014", Expectation::Fail),
    ("identity-lab-015", Expectation::Fail),
    ("identity-lab-016", Expectation::Inconclusive),
    ("identity-lab-017", Expectation::Fail),
    ("identity-lab-018", Expectation::Refused),
    ("identity-lab-019", Expectation::Pass),
    ("identity-lab-020", Expectation::Fail),
    ("identity-lab-021", Expectation::Refused),
    ("identity-lab-022", Expectation::Fail),
    ("identity-lab-023", Expectation::Pass),
    ("identity-lab-024", Expectation::Refused),
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scenarios")
}

fn raw(lab: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(format!("{lab}.json")))
        .unwrap_or_else(|err| panic!("{lab} is readable: {err}"))
}

/// Load a lab the way the engine would: schema, then typed decode, then the
/// structural checks the schema cannot express.
fn load(lab: &str) -> Result<IdentitySecurityScenario, IdentitySecurityError> {
    let bytes = raw(lab);
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("{lab} is valid JSON: {err}"));
    validate_scenario_document(&value)?;
    let scenario: IdentitySecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn events(scenario: &IdentitySecurityScenario) -> Vec<IdentityObservationEvent> {
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
fn all_twenty_four_labs_are_present_and_uniquely_named() {
    let ids: BTreeSet<&str> = LABS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids.len(), 24);
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures directory exists")
        .map(|entry| {
            entry
                .expect("readable entry")
                .path()
                .file_stem()
                .expect("named file")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let expected: BTreeSet<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    assert_eq!(on_disk, expected);
}

#[test]
fn every_lab_produces_its_expected_outcome() {
    for (lab, expectation) in LABS {
        match expectation {
            Expectation::Refused => {
                let err = load(lab)
                    .err()
                    .unwrap_or_else(|| panic!("{lab} must be refused, but it loaded successfully"));
                // A refusal is a refusal — never a security verdict about the
                // scenario the engine declined to run.
                assert!(
                    err.is_refusal()
                        || matches!(
                            err,
                            IdentitySecurityError::Schema(_) | IdentitySecurityError::Invalid(_)
                        ),
                    "{lab}: {err}"
                );
            }
            _ => {
                let scenario = load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
                let observed = events(&scenario);
                let outcome = evaluate(scenario.invariant.type_, &scenario, &observed);
                let expected = match expectation {
                    Expectation::Pass => Verdict::Pass,
                    Expectation::Fail => Verdict::Fail,
                    Expectation::Inconclusive => Verdict::Inconclusive,
                    Expectation::Refused => unreachable!(),
                };
                assert_eq!(
                    outcome.verdict,
                    expected,
                    "{lab} ({}): {}",
                    scenario.invariant.type_.as_str(),
                    outcome.reason
                );
            }
        }
    }
}

#[test]
fn a_passing_lab_passes_on_evidence_and_not_on_silence() {
    // The distinction the whole cycle rests on: absence of evidence is not
    // evidence of absence. A PASS must have satisfied its coverage contract.
    for (lab, expectation) in LABS {
        if expectation != Expectation::Pass {
            continue;
        }
        let scenario = load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
        let observed = events(&scenario);
        let outcome = evaluate(scenario.invariant.type_, &scenario, &observed);
        assert!(outcome.coverage_satisfied, "{lab} passed without coverage");
        assert!(!observed.is_empty(), "{lab} passed on an empty observation");
    }
}

#[test]
fn a_failing_lab_names_the_violations_it_observed() {
    for (lab, expectation) in LABS {
        if expectation != Expectation::Fail {
            continue;
        }
        let scenario = load(lab).unwrap_or_else(|err| panic!("{lab} loads: {err}"));
        let observed = events(&scenario);
        let outcome = evaluate(scenario.invariant.type_, &scenario, &observed);
        assert!(
            !outcome.violations.is_empty(),
            "{lab} failed without detail"
        );
        for violation in &outcome.violations {
            assert_eq!(violation.invariant, scenario.invariant.type_, "{lab}");
            assert!(!violation.reason.is_empty(), "{lab}");
        }
    }
}

#[test]
fn lab_020_reports_three_independent_violations_rather_than_the_first() {
    // Both principal roles substituted, the tenant crossed and authority
    // expanded through a credential are all true in the same trial. One
    // classification must not mask another.
    let scenario = load("identity-lab-020").expect("loads");
    let observed = events(&scenario);

    let failing: Vec<&'static str> = IdentityInvariantType::all()
        .into_iter()
        .filter(|invariant| evaluate(*invariant, &scenario, &observed).verdict == Verdict::Fail)
        .map(IdentityInvariantType::as_str)
        .collect();

    for expected in [
        "INITIATING_PRINCIPAL_PRESERVED",
        "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER",
        "TENANT_BOUNDARY_PRESERVED",
        "CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY",
    ] {
        assert!(
            failing.contains(&expected),
            "{expected} missing from {failing:?}"
        );
    }
}

#[test]
fn lab_015_reaches_fail_without_dispatching_anything() {
    let scenario = load("identity-lab-015").expect("loads");
    let observed = events(&scenario);
    let outcome = evaluate(IdentityInvariantType::DenyNotBypassed, &scenario, &observed);
    assert_eq!(outcome.verdict, Verdict::Fail);

    let mut saw_operation = false;
    for event in &observed {
        if let IdentityObservationEvent::FinalOperation(op)
        | IdentityObservationEvent::OperationRequest(op) = event
        {
            saw_operation = true;
            assert!(
                !op.dispatched,
                "a denied operation must never be dispatched"
            );
        }
    }
    assert!(
        saw_operation,
        "the denied request must be observed to be reported"
    );
}

#[test]
fn the_labs_cover_every_invariant_in_both_directions() {
    // A corpus that only ever fails proves nothing about false positives, and
    // one that only ever passes proves nothing about detection.
    let mut passing = BTreeSet::new();
    let mut failing = BTreeSet::new();

    for (lab, _) in LABS {
        let Ok(scenario) = load(lab) else { continue };
        let observed = events(&scenario);
        for invariant in IdentityInvariantType::all() {
            match evaluate(invariant, &scenario, &observed).verdict {
                Verdict::Pass => {
                    passing.insert(invariant.as_str());
                }
                Verdict::Fail => {
                    failing.insert(invariant.as_str());
                }
                _ => {}
            }
        }
    }

    for invariant in IdentityInvariantType::all() {
        assert!(
            passing.contains(invariant.as_str()),
            "{} never passes anywhere in the labs",
            invariant.as_str()
        );
        assert!(
            failing.contains(invariant.as_str()),
            "{} never fails anywhere in the labs",
            invariant.as_str()
        );
    }
}

#[test]
fn no_lab_fixture_declares_an_expected_outcome() {
    // The register above is the only place an expectation is written down.
    for (lab, _) in LABS {
        let text = String::from_utf8(raw(lab)).expect("utf-8");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert!(value.get("expected_verdict").is_none(), "{lab}");
        assert!(value.get("verdict").is_none(), "{lab}");
        assert!(
            value
                .get("invariant")
                .and_then(|invariant| invariant.get("expected"))
                .is_none(),
            "{lab}"
        );
        for banned in ["\"PASS\"", "\"FAIL\"", "\"INCONCLUSIVE\""] {
            assert!(!text.contains(banned), "{lab} mentions {banned}");
        }
    }
}

#[test]
fn no_lab_fixture_carries_credential_material_or_a_remote_target() {
    for (lab, _) in LABS {
        let text = String::from_utf8(raw(lab)).expect("utf-8").to_lowercase();
        for marker in [
            "sk-live-",
            "-----begin",
            "ghp_",
            "xoxb-",
            "eyjhbgci",
            "https://",
            "http://",
        ] {
            assert!(!text.contains(marker), "{lab} contains `{marker}`");
        }
    }
}
