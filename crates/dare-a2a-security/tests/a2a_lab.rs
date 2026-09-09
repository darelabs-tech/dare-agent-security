//! The A2A-LAB harness contract.
//!
//! The corpus entries in `corpus.rs` describe vectors. This file holds every
//! expectation about what the engine must conclude for them, and it holds all
//! of it — no entry carries an `expected_verdict`, and none can.
//!
//! Keeping the expectation here is what makes a paired corpus worth running. If
//! a fixture declared its own outcome, each pair would test whether the fixture
//! author and the evaluator agreed on a label rather than whether the evaluator
//! can see a substitution.
//!
//! The four contracts, one per class:
//!
//! * **ATTACK** — the invariant the entry was built for reports a concrete
//!   failure, with at least one violation carrying deciding evidence.
//! * **CONTROL** — that invariant reports no failure. An engine that failed
//!   everything would score perfectly against attacks alone and be worse than
//!   useless, because an operator would learn to ignore it.
//! * **GAP** — that invariant never reaches an applicable PASS. Missing
//!   evidence is a gap, and a gap silently read as success is the failure mode
//!   this cycle exists to prevent.
//! * **REFUSAL** — the bundle is refused during admission, before any
//!   invariant is evaluated at all.

use std::collections::{BTreeMap, BTreeSet};

use dare_a2a_security::budget::AdmissionLedger;
use dare_a2a_security::corpus::{corpus, scenario_for, A2aLabClass, A2aLabEntry, CorpusAdapter};
use dare_a2a_security::harness::A2aAdapter;
use dare_a2a_security::invariant::{aggregate, evaluate_all, A2aInvariantOutcome};
use dare_a2a_security::model::A2aInvariant;
use dare_a2a_security::observation::project;
use dare_a2a_security::source::{A2aMode, ScenarioClass};
use dare_security_evidence::Verdict;

/// Run one entry all the way to its outcomes.
fn outcomes_for(entry: &A2aLabEntry) -> Vec<A2aInvariantOutcome> {
    let mut ledger = AdmissionLedger::new();
    let evidence = (entry.build)(&mut ledger)
        .unwrap_or_else(|error| panic!("{} did not stage: {error}", entry.id));
    evaluate_all(&project(&evidence))
}

fn outcome_for(outcomes: &[A2aInvariantOutcome], invariant: A2aInvariant) -> &A2aInvariantOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.invariant == invariant)
        .expect("every invariant is evaluated on every run")
}

#[test]
fn the_corpus_meets_the_approved_minimum_and_names_every_entry_once() {
    let entries = corpus();
    assert!(
        entries.len() >= 44,
        "the approved minimum is 44 scenarios; the corpus holds {}",
        entries.len()
    );

    let ids: BTreeSet<&str> = entries.iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids.len(),
        entries.len(),
        "two entries share an id, so one of them can never be selected"
    );
}

#[test]
fn every_surface_and_every_invariant_has_at_least_one_entry() {
    // A corpus that skipped a surface would let that surface's evaluator ship
    // untested while the totals still looked complete.
    let entries = corpus();

    let dimensions: BTreeSet<&str> = entries
        .iter()
        .map(|entry| entry.dimension.as_str())
        .collect();
    for class in ScenarioClass::all() {
        assert!(
            dimensions.contains(class.as_str()),
            "no corpus entry exercises {}",
            class.as_str()
        );
    }

    let invariants: BTreeSet<&str> = entries
        .iter()
        .map(|entry| entry.invariant.as_str())
        .collect();
    for invariant in A2aInvariant::all() {
        assert!(
            invariants.contains(invariant.as_str()),
            "no corpus entry is built for {} ({})",
            invariant.design_id(),
            invariant.as_str()
        );
    }
}

#[test]
fn every_class_is_represented_and_attacks_are_not_the_whole_corpus() {
    let entries = corpus();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &entries {
        *counts.entry(entry.class.as_str()).or_default() += 1;
    }

    for class in ["CONTROL", "ATTACK", "REFUSAL", "GAP"] {
        assert!(
            counts.get(class).copied().unwrap_or(0) > 0,
            "no {class} entries"
        );
    }

    // A corpus of attacks alone cannot tell a working engine from one that
    // reports everything. The non-attack entries are what makes a clean run
    // mean something, so they are held above a floor rather than left to
    // erode entry by entry.
    let attacks = counts["ATTACK"];
    let others = entries.len() - attacks;
    assert!(
        others * 2 >= attacks,
        "{others} non-attack entries against {attacks} attacks: too few to catch an \
         over-reporting engine"
    );
}

#[test]
fn no_corpus_entry_can_state_its_own_outcome() {
    // Asserted against the rendered scenario, which is what a fixture written
    // to disk would carry. A verdict-shaped field here would move the decision
    // from the evaluator to the fixture author.
    for entry in corpus() {
        let scenario = scenario_for(&entry);
        let rendered = serde_json::to_string(&scenario)
            .expect("serializes")
            .to_lowercase();
        for absent in [
            "expected_verdict",
            "expected_findings",
            "expected_outcome",
            "\"verdict\"",
            "should_fail",
            "should_pass",
            "is_secure",
            "evaluator_override",
        ] {
            assert!(
                !rendered.contains(absent),
                "{} carries `{absent}`",
                entry.id
            );
        }
    }
}

#[test]
fn every_attack_is_seen_by_the_invariant_it_was_built_for() {
    for entry in corpus() {
        if entry.class != A2aLabClass::Attack {
            continue;
        }
        let outcomes = outcomes_for(&entry);
        let outcome = outcome_for(&outcomes, entry.invariant);

        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "{} ({}) reported {} for {}: {}",
            entry.id,
            entry.description,
            outcome.verdict.as_str(),
            entry.invariant.design_id(),
            outcome.reason
        );
        assert!(
            outcome.applicable,
            "{} failed an invariant it also calls inapplicable",
            entry.id
        );
        assert!(
            !outcome.violations.is_empty(),
            "{} failed with no violation to show an operator",
            entry.id
        );
        for violation in &outcome.violations {
            assert!(
                !violation.deciding_observation_digests.is_empty(),
                "{}: a finding with no deciding evidence is an assertion, not a finding",
                entry.id
            );
        }
        assert_eq!(aggregate(&outcomes), Verdict::Fail, "{}", entry.id);
    }
}

#[test]
fn no_control_is_reported_by_the_invariant_it_exercises() {
    for entry in corpus() {
        if entry.class != A2aLabClass::Control {
            continue;
        }
        let outcomes = outcomes_for(&entry);
        let outcome = outcome_for(&outcomes, entry.invariant);
        assert_ne!(
            outcome.verdict,
            Verdict::Fail,
            "{} ({}) is legitimate activity and {} reported it: {}",
            entry.id,
            entry.description,
            entry.invariant.design_id(),
            outcome.reason
        );
    }
}

#[test]
fn no_gap_is_reported_as_an_applicable_pass() {
    // The rule the whole cycle turns on. INDETERMINATE and UNRECORDED evidence
    // can never become a PASS, because an operator reading PASS would believe
    // something was checked that nobody checked.
    for entry in corpus() {
        if entry.class != A2aLabClass::Gap {
            continue;
        }
        let outcomes = outcomes_for(&entry);
        let outcome = outcome_for(&outcomes, entry.invariant);
        assert!(
            !(outcome.applicable && outcome.verdict == Verdict::Pass),
            "{} ({}) has no evidence to decide {} on, and the run called it PASS: {}",
            entry.id,
            entry.description,
            entry.invariant.design_id(),
            outcome.reason
        );
        assert_ne!(
            aggregate(&outcomes),
            Verdict::Pass,
            "{} aggregated a missing-evidence run to PASS",
            entry.id
        );
    }
}

#[test]
fn every_refusal_is_refused_before_any_invariant_is_evaluated() {
    for entry in corpus() {
        if entry.class != A2aLabClass::Refusal {
            continue;
        }
        let mut ledger = AdmissionLedger::new();
        let outcome = (entry.build)(&mut ledger);
        let error = outcome.err().unwrap_or_else(|| {
            panic!(
                "{} ({}) was admitted; hostile input accepted at the door is hostile input the \
                 evaluator now has to be right about",
                entry.id, entry.description
            )
        });
        // The refusal must name something. A bare error tells an operator that
        // a run stopped, not what to fix.
        assert!(
            error.to_string().len() > 20,
            "{} was refused without saying why: {error}",
            entry.id
        );
    }
}

#[test]
fn a_multi_violation_exchange_reports_every_boundary_it_crossed() {
    // Reporting only the first crossing understates what was observed, and an
    // operator who fixes it believes the exchange is now clean.
    let entries = corpus();
    let entry = entries
        .iter()
        .find(|entry| entry.id == "A2A-LAB-050")
        .expect("the multi-violation entry");
    let outcomes = outcomes_for(entry);

    let failed: BTreeSet<&str> = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .map(|outcome| outcome.invariant.design_id())
        .collect();
    assert!(
        failed.len() >= 3,
        "three boundaries were crossed and only {failed:?} were reported"
    );
}

#[test]
fn the_corpus_adapter_refuses_a_scenario_it_has_no_entry_for() {
    // Silently staging nothing would produce a clean run for a vector nobody
    // exercised — the most expensive way for this engine to be wrong.
    let entries = corpus();
    let mut scenario = scenario_for(&entries[0]);
    scenario.scenario_id = "A2A-LAB-999".to_owned();

    let mut ledger = AdmissionLedger::new();
    let error = CorpusAdapter
        .collect(&scenario, &mut ledger)
        .expect_err("a scenario naming no entry must not run");
    assert!(error.to_string().contains("A2A-LAB-999"));
}

#[test]
fn the_corpus_adapter_stages_the_entry_a_scenario_names() {
    let entries = corpus();
    for entry in &entries {
        if entry.class == A2aLabClass::Refusal {
            continue;
        }
        let scenario = scenario_for(entry);
        assert_eq!(scenario.mode, A2aMode::Simulated);
        let mut ledger = AdmissionLedger::new();
        let through_adapter = CorpusAdapter
            .collect(&scenario, &mut ledger)
            .unwrap_or_else(|error| panic!("{} did not stage: {error}", entry.id));

        let mut direct_ledger = AdmissionLedger::new();
        let direct = (entry.build)(&mut direct_ledger).expect("stages");
        assert_eq!(through_adapter, direct, "{}", entry.id);
    }
}

#[test]
fn staging_an_entry_twice_produces_the_same_observations() {
    // A corpus that drifted between runs would make every regression argument
    // unfalsifiable.
    for entry in corpus() {
        if entry.class == A2aLabClass::Refusal {
            continue;
        }
        let mut first_ledger = AdmissionLedger::new();
        let first = (entry.build)(&mut first_ledger).expect("stages");
        let mut second_ledger = AdmissionLedger::new();
        let second = (entry.build)(&mut second_ledger).expect("stages");

        let first_digests: Vec<String> = project(&first)
            .observations
            .iter()
            .map(|observation| observation.digest().expect("digests"))
            .collect();
        let second_digests: Vec<String> = project(&second)
            .observations
            .iter()
            .map(|observation| observation.digest().expect("digests"))
            .collect();
        assert_eq!(first_digests, second_digests, "{}", entry.id);
    }
}

#[test]
fn the_engine_never_reports_a_verdict_about_a_peer_it_did_not_observe() {
    // The claim boundary, asserted mechanically: every violation names a peer
    // or a message that appears in the evidence, so no report can be read as a
    // statement about a remote agent nobody looked at.
    for entry in corpus() {
        if entry.class == A2aLabClass::Refusal {
            continue;
        }
        let mut ledger = AdmissionLedger::new();
        let evidence = (entry.build)(&mut ledger).expect("stages");
        let known_peers: BTreeSet<&str> = evidence
            .peers
            .peers
            .iter()
            .map(|peer| peer.peer_id.as_str())
            .collect();
        let known_messages: BTreeSet<&str> = evidence
            .exchanges
            .exchanges
            .iter()
            .map(|exchange| exchange.message_id.as_str())
            .collect();

        for outcome in evaluate_all(&project(&evidence)) {
            for violation in &outcome.violations {
                if let Some(peer_id) = &violation.peer_id {
                    assert!(
                        known_peers.contains(peer_id.as_str()),
                        "{} reported about peer `{peer_id}`, which the evidence does not describe",
                        entry.id
                    );
                }
                if let Some(message_id) = &violation.message_id {
                    assert!(
                        known_messages.contains(message_id.as_str()),
                        "{} reported about message `{message_id}`, which was never observed",
                        entry.id
                    );
                }
            }
        }
    }
}
