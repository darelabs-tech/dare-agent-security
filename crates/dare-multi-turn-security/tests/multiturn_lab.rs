//! The MULTITURN-LAB harness contract.
//!
//! Expectations live here, one per class, never in the fixtures:
//!
//! - ATTACK  → FAIL, and the entry's own invariant is among the failures;
//! - CONTROL → PASS;
//! - GAP     → INCONCLUSIVE;
//! - FAULT   → ERROR;
//! - REFUSAL → refused before any turn runs.
//!
//! Every entry runs in every mode it is staged for. Agent-driven entries are
//! also recorded and replayed: the replayed verdict must equal the simulated
//! one, which proves REPLAY evaluates what was recorded and nothing else.

use std::collections::BTreeSet;

use dare_multi_turn_security::budget::OutputLedger;
use dare_multi_turn_security::corpus::{
    adapter_for, entry_by_id, graph_set, ids, LabClass, LabEntry, RecordingAdapter, Source, CORPUS,
};
use dare_multi_turn_security::model::HarnessMode;
use dare_multi_turn_security::replay::ReplayAdapter;
use dare_multi_turn_security::result::{run_scenario, MultiTurnResult};
use dare_security_evidence::Verdict;

const AT: &str = "2026-09-27T00:00:00Z";

fn run(
    entry: &LabEntry,
    mode: HarnessMode,
) -> Result<MultiTurnResult, dare_multi_turn_security::error::MultiTurnError> {
    let case = entry.case();
    let graphs = graph_set(&case)?;
    let mut adapter = adapter_for(&case, mode)?;
    let mut ledger = OutputLedger::new(case.scenario.effective_bounds()?);
    run_scenario(&case.scenario, &graphs, adapter.as_mut(), &mut ledger, AT).map(|(r, _)| r)
}

fn assert_contract(entry: &LabEntry, mode: HarnessMode) {
    let outcome = run(entry, mode);
    let label = format!("{} [{}] in {mode:?}", entry.id, entry.class.as_str());
    match entry.class {
        LabClass::Refusal => {
            let error = outcome.expect_err(&format!("{label}: must be refused"));
            assert!(error.is_refusal(), "{label}: {error} is not a refusal");
        }
        class => {
            let result = outcome.unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
            let expected = match class {
                LabClass::Attack => Verdict::Fail,
                LabClass::Control => Verdict::Pass,
                LabClass::Gap => Verdict::Inconclusive,
                LabClass::Fault => Verdict::Error,
                LabClass::Refusal => unreachable!(),
            };
            assert_eq!(
                result.verdict, expected,
                "{label}: {}",
                result.bounded_claim
            );
            if class == LabClass::Attack {
                let own = result
                    .invariants
                    .iter()
                    .find(|o| o.invariant == entry.invariant)
                    .expect("own invariant");
                assert_eq!(
                    own.verdict,
                    Verdict::Fail,
                    "{label}: its own invariant must be the one that fails"
                );
                assert!(
                    !own.deciding_turns.is_empty(),
                    "{label}: a FAIL carries its deciding turns"
                );
            }
        }
    }
}

#[test]
fn the_corpus_has_at_least_forty_entries_with_unique_ids() {
    assert!(CORPUS.len() >= 40, "{}", CORPUS.len());
    let unique: BTreeSet<&str> = ids().into_iter().collect();
    assert_eq!(unique.len(), CORPUS.len());
    for (i, entry) in CORPUS.iter().enumerate() {
        assert_eq!(entry.id, format!("multiturn-lab-{:03}", i + 1));
        assert!(entry_by_id(entry.id).is_some());
    }
}

#[test]
fn every_attack_theme_has_a_control() {
    let themes_with = |class: LabClass| -> BTreeSet<&str> {
        CORPUS
            .iter()
            .filter(|e| e.class == class)
            .map(|e| e.theme)
            .collect()
    };
    let attacks = themes_with(LabClass::Attack);
    let controls = themes_with(LabClass::Control);
    assert!(
        attacks.is_subset(&controls),
        "attack themes without a control: {:?}",
        attacks.difference(&controls).collect::<Vec<_>>()
    );
    for class in [
        LabClass::Attack,
        LabClass::Control,
        LabClass::Gap,
        LabClass::Fault,
        LabClass::Refusal,
    ] {
        assert!(
            CORPUS.iter().any(|e| e.class == class),
            "no {} entry",
            class.as_str()
        );
    }
}

#[test]
fn every_invariant_has_an_attack_and_a_control() {
    use dare_multi_turn_security::model::MultiTurnInvariant;
    for invariant in MultiTurnInvariant::ALL {
        for class in [LabClass::Attack, LabClass::Control] {
            assert!(
                CORPUS
                    .iter()
                    .any(|e| e.invariant == invariant && e.class == class),
                "{} has no {}",
                invariant.as_str(),
                class.as_str()
            );
        }
    }
}

#[test]
fn every_entry_meets_its_class_contract_in_every_staged_mode() {
    for entry in &CORPUS {
        for mode in entry.modes() {
            assert_contract(entry, mode);
        }
    }
}

#[test]
fn recorded_simulated_runs_replay_to_the_same_verdict() {
    for entry in CORPUS.iter().filter(|e| e.class != LabClass::Refusal) {
        let case = entry.case();
        let Source::Agent(_) = case.source else {
            continue;
        };
        let graphs = graph_set(&case).expect("graphs");
        let mut inner = adapter_for(&case, HarnessMode::Simulated).expect("adapter");
        let mut recorder = RecordingAdapter::new(inner.as_mut());
        let mut ledger = OutputLedger::new(case.scenario.effective_bounds().expect("bounds"));
        let (simulated, _) = run_scenario(&case.scenario, &graphs, &mut recorder, &mut ledger, AT)
            .expect("simulated run");
        let transcript = recorder.transcript(&case.scenario);

        let mut replay = ReplayAdapter::new(transcript, &case.scenario).expect("binds");
        let mut ledger = OutputLedger::new(case.scenario.effective_bounds().expect("bounds"));
        let (replayed, _) = run_scenario(&case.scenario, &graphs, &mut replay, &mut ledger, AT)
            .expect("replay run");
        assert_eq!(replayed.verdict, simulated.verdict, "{}", entry.id);
        assert_eq!(
            replayed.conversations, simulated.conversations,
            "{}: same path, same chain",
            entry.id
        );
        assert!(!replayed.synthetic && simulated.synthetic);
    }
}

#[test]
fn no_fixture_states_its_own_outcome() {
    for entry in &CORPUS {
        let case = entry.case();
        let json = serde_json::to_string(&case.scenario)
            .expect("json")
            .to_ascii_lowercase()
            + &serde_json::to_string(&case.graphs)
                .expect("json")
                .to_ascii_lowercase();
        for word in [
            "expected",
            "verdict",
            "should_fail",
            "should_pass",
            "is_vulnerable",
        ] {
            assert!(
                !json.contains(word),
                "{}: fixture mentions `{word}`",
                entry.id
            );
        }
    }
}

#[test]
fn no_pass_is_ever_produced_for_a_gap_or_fault_in_any_mode() {
    for entry in CORPUS
        .iter()
        .filter(|e| matches!(e.class, LabClass::Gap | LabClass::Fault))
    {
        for mode in entry.modes() {
            let result = run(entry, mode).expect("runs");
            assert_ne!(result.verdict, Verdict::Pass, "{} in {mode:?}", entry.id);
        }
    }
}
