//! Determinism: identical inputs give byte-identical artifacts.
//!
//! Every corpus entry, in every mode it is staged for, is run ten times and
//! every artifact is compared byte for byte. `generated_at` is supplied by the
//! caller and held fixed; nothing else in an artifact may depend on the clock,
//! a random source or hash-map iteration order.

use dare_multi_turn_security::budget::OutputLedger;
use dare_multi_turn_security::corpus::{adapter_for, graph_set, LabClass, CORPUS};
use dare_multi_turn_security::result::{render_artifacts, run_scenario, Artifact};

const RUNS: usize = 10;

fn artifacts(
    entry: &dare_multi_turn_security::corpus::LabEntry,
    mode: dare_multi_turn_security::model::HarnessMode,
) -> Vec<Artifact> {
    let case = entry.case();
    let graphs = graph_set(&case).expect("graphs");
    let mut adapter = adapter_for(&case, mode).expect("adapter");
    let mut ledger = OutputLedger::new(case.scenario.effective_bounds().expect("bounds"));
    let (result, run) = run_scenario(
        &case.scenario,
        &graphs,
        adapter.as_mut(),
        &mut ledger,
        "2026-09-27T00:00:00Z",
    )
    .expect("runs");
    // The evidence-budget GAP entries exhaust the byte budget by design, so
    // their artifacts are rendered under an unbounded ledger for comparison.
    let mut render_ledger = OutputLedger::new(Default::default());
    render_artifacts(&result, &run, Vec::new(), &mut render_ledger).expect("renders")
}

#[test]
fn every_entry_produces_byte_identical_artifacts_across_ten_runs() {
    let mut compared = 0;
    for entry in CORPUS.iter().filter(|e| e.class != LabClass::Refusal) {
        for mode in entry.modes() {
            let first = artifacts(entry, mode);
            for _ in 1..RUNS {
                let again = artifacts(entry, mode);
                assert_eq!(again.len(), first.len());
                for (a, b) in first.iter().zip(&again) {
                    assert_eq!(a.name, b.name);
                    assert!(
                        a.bytes == b.bytes,
                        "{} {mode:?}: {} differs between runs",
                        entry.id,
                        a.name
                    );
                }
            }
            compared += 1;
        }
    }
    assert!(compared >= 40, "only {compared} entry/mode pairs compared");
}

#[test]
fn refusals_are_deterministic_too() {
    for entry in CORPUS.iter().filter(|e| e.class == LabClass::Refusal) {
        let messages: Vec<String> = (0..RUNS)
            .map(|_| {
                let case = entry.case();
                let outcome = graph_set(&case).and_then(|graphs| {
                    let mut adapter = adapter_for(&case, entry.modes()[0])?;
                    let mut ledger = OutputLedger::new(case.scenario.effective_bounds()?);
                    run_scenario(&case.scenario, &graphs, adapter.as_mut(), &mut ledger, "t")
                        .map(|_| ())
                });
                outcome.expect_err("refused").to_string()
            })
            .collect();
        assert!(messages.windows(2).all(|w| w[0] == w[1]), "{}", entry.id);
    }
}
