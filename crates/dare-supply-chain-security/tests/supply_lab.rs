//! The SUPPLY-LAB harness contract.
//!
//! The corpus records what each entry *is*; this file records what the engine
//! must do about each class. Keeping the two apart is the whole discipline: a
//! fixture that carried its own expected verdict would be testing whether the
//! author and the engine agreed about a label rather than whether the engine
//! can see a substitution.
//!
//! Four contracts, one per class:
//!
//! - **ATTACK** — the declared invariant must report `FAIL`, and the finding
//!   must cite deciding evidence.
//! - **CONTROL** — nothing may `FAIL`, and the declared invariant must reach
//!   `PASS`. An engine that reported everything would score perfectly against
//!   attacks alone.
//! - **REFUSAL** — the bundle must be refused before evaluation, and the
//!   refusal must not echo what it refused.
//! - **GAP** — the declared invariant must be `INCONCLUSIVE`. Never `PASS`, and
//!   never `FAIL` either: thin evidence is not a finding.

use std::collections::BTreeSet;

use dare_security_evidence::Verdict;
use dare_supply_chain_security::budget::AdmissionLedger;
use dare_supply_chain_security::canonical::digest;
use dare_supply_chain_security::corpus::{corpus, SupplyLabClass, SupplyLabEntry};
use dare_supply_chain_security::invariant::{collect_observed_violations, evaluate};
use dare_supply_chain_security::model::SupplyChainInvariant;
use dare_supply_chain_security::observation::project;
use dare_supply_chain_security::source::ScenarioClass;

fn built(entry: &SupplyLabEntry) -> dare_supply_chain_security::normalize::SupplyChainEvidence {
    let mut ledger = AdmissionLedger::new();
    (entry.build)(&mut ledger)
        .unwrap_or_else(|error| panic!("{} could not be staged: {error}", entry.id))
}

#[test]
fn the_corpus_meets_the_minimum_and_the_recommended_size() {
    let corpus = corpus();
    assert!(
        corpus.len() >= 36,
        "the corpus has {} entries and the minimum is 36",
        corpus.len()
    );
    assert_eq!(corpus.len(), 40, "the recommended size is 40");
}

#[test]
fn every_entry_is_uniquely_identified_and_explained() {
    // A fixture nobody can explain is a fixture nobody can review, and a corpus
    // of them proves only that the engine agrees with itself.
    let corpus = corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|entry| entry.id).collect();
    assert_eq!(ids.len(), corpus.len(), "two entries share an id");
    for entry in &corpus {
        assert!(
            !entry.description.trim().is_empty(),
            "{} explains nothing",
            entry.id
        );
        assert!(
            entry.id.starts_with("SUPPLY-LAB-"),
            "{} is misnamed",
            entry.id
        );
    }
}

#[test]
fn the_corpus_covers_every_dimension_in_both_directions() {
    // AC-67. A dimension with only attacks lets an over-strict engine look
    // perfect on it; one with only controls proves nothing was ever detected.
    let corpus = corpus();
    for dimension in ScenarioClass::all() {
        let entries: Vec<&SupplyLabEntry> = corpus
            .iter()
            .filter(|entry| entry.dimension == dimension)
            .collect();
        assert!(
            !entries.is_empty(),
            "{} has no corpus entry",
            dimension.as_str()
        );
    }

    for dimension in [
        ScenarioClass::ComponentIdentity,
        ScenarioClass::ArtifactIntegrity,
        ScenarioClass::SourceTrust,
        ScenarioClass::ProvenanceBinding,
        ScenarioClass::AttestationBinding,
        ScenarioClass::DependencyIntegrity,
        ScenarioClass::CapabilityDrift,
        ScenarioClass::ModelLineage,
        ScenarioClass::DatasetProvenance,
    ] {
        let classes: BTreeSet<&str> = corpus
            .iter()
            .filter(|entry| entry.dimension == dimension)
            .map(|entry| entry.class.as_str())
            .collect();
        assert!(
            classes.contains("ATTACK"),
            "{} has no attack",
            dimension.as_str()
        );
        assert!(
            classes.contains("CONTROL") || classes.contains("GAP"),
            "{} has no legitimate counterpart",
            dimension.as_str()
        );
    }
}

#[test]
fn a_meaningful_share_of_the_corpus_is_legitimate_activity() {
    // An engine that reported FAIL for everything would score 100% against a
    // corpus of attacks, and be worse than useless.
    let corpus = corpus();
    let legitimate = corpus
        .iter()
        .filter(|entry| matches!(entry.class, SupplyLabClass::Control | SupplyLabClass::Gap))
        .count();
    assert!(
        legitimate * 100 / corpus.len() >= 35,
        "only {legitimate} of {} entries are controls or gaps",
        corpus.len()
    );
}

#[test]
fn every_attack_is_seen_by_the_invariant_it_names() {
    for entry in corpus()
        .iter()
        .filter(|entry| entry.class == SupplyLabClass::Attack)
    {
        let observations = project(&built(entry));
        let outcome = evaluate(entry.invariant, &observations);
        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "{} ({}) was not seen by {}: {}",
            entry.id,
            entry.description,
            entry.invariant.as_str(),
            outcome.reason
        );
        for violation in &outcome.violations {
            assert!(
                !violation.deciding_observation_digests.is_empty(),
                "{} produced a finding with no deciding evidence",
                entry.id
            );
        }
    }
}

#[test]
fn no_control_is_reported_and_the_named_invariant_passes() {
    for entry in corpus()
        .iter()
        .filter(|entry| entry.class == SupplyLabClass::Control)
    {
        let observations = project(&built(entry));
        let violations = collect_observed_violations(&observations);
        assert!(
            violations.is_empty(),
            "{} ({}) was reported: {violations:#?}",
            entry.id,
            entry.description
        );

        let outcome = evaluate(entry.invariant, &observations);
        assert_eq!(
            outcome.verdict,
            Verdict::Pass,
            "{} could not decide {}: {}",
            entry.id,
            entry.invariant.as_str(),
            outcome.reason
        );
    }
}

#[test]
fn every_refusal_is_refused_before_anything_is_evaluated() {
    for entry in corpus()
        .iter()
        .filter(|entry| entry.class == SupplyLabClass::Refusal)
    {
        let mut ledger = AdmissionLedger::new();
        let error = (entry.build)(&mut ledger)
            .err()
            .unwrap_or_else(|| panic!("{} ({}) was admitted", entry.id, entry.description));

        let message = error.to_string();
        // A refusal that quoted the offending value would store the thing it
        // declined to store.
        for smuggled in ["not-a-real-key", "abc123"] {
            assert!(
                !message.contains(smuggled),
                "{} echoed what it refused: {message}",
                entry.id
            );
        }
    }
}

#[test]
fn every_gap_is_undecidable_rather_than_passing_or_failing() {
    for entry in corpus()
        .iter()
        .filter(|entry| entry.class == SupplyLabClass::Gap)
    {
        let outcome = evaluate(entry.invariant, &project(&built(entry)));
        assert_eq!(
            outcome.verdict,
            Verdict::Inconclusive,
            "{} ({}) reported {:?} where the evidence was too thin to decide: {}",
            entry.id,
            entry.description,
            outcome.verdict,
            outcome.reason
        );
        assert!(!outcome.coverage_satisfied);
    }
}

#[test]
fn the_multi_violation_entry_retains_every_independent_finding() {
    // AC-68. One bundle crossing three boundaries must report three, or a run
    // understates what it saw and an operator fixes one of them.
    let corpus = corpus();
    let entry = corpus
        .iter()
        .find(|entry| entry.id == "SUPPLY-LAB-036")
        .expect("the multi-violation entry");

    let invariants: BTreeSet<&str> = collect_observed_violations(&project(&built(entry)))
        .iter()
        .map(|violation| violation.invariant.as_str())
        .collect();
    assert!(
        invariants.len() >= 3,
        "only {invariants:?} were retained from a bundle crossing three boundaries"
    );
    assert!(invariants.contains("ARTIFACT_DIGEST_BOUND_TO_COMPONENT"));
    assert!(invariants.contains("COMPONENT_SOURCE_TRUST_PRESERVED"));
    assert!(invariants.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
}

#[test]
fn cyclonedx_and_spdx_halves_describe_the_same_system() {
    // AC-26. The comparison is semantic: the two bundles come from different
    // parsers and different documents, and must still resolve to one system.
    let mut ledger = AdmissionLedger::new();
    let cyclonedx = dare_supply_chain_security::corpus::cyclonedx_equivalence_half(&mut ledger)
        .expect("imports");

    let corpus = corpus();
    let spdx_entry = corpus
        .iter()
        .find(|entry| entry.id == "SUPPLY-LAB-032")
        .expect("the SPDX half");
    let spdx = built(spdx_entry);

    assert_ne!(
        cyclonedx.documents[0].format, spdx.documents[0].format,
        "the equivalence pair compared one bundle with itself"
    );
    assert!(
        cyclonedx.describes_same_system_as(&spdx),
        "the two formats normalized to different systems:\n{:#?}\n{:#?}",
        cyclonedx.semantic_keys(),
        spdx.semantic_keys()
    );
}

#[test]
fn staging_is_deterministic_for_every_entry() {
    // A corpus that staged differently between runs would produce reports that
    // differ from themselves, and no regression could be trusted.
    for entry in corpus() {
        let mut first = AdmissionLedger::new();
        let mut second = AdmissionLedger::new();
        match ((entry.build)(&mut first), (entry.build)(&mut second)) {
            (Ok(left), Ok(right)) => assert_eq!(
                digest(&left).expect("digests"),
                digest(&right).expect("digests"),
                "{} staged two different bundles",
                entry.id
            ),
            (Err(_), Err(_)) => {}
            _ => panic!("{} staged inconsistently between two runs", entry.id),
        }
    }
}

#[test]
fn no_entry_declares_an_outcome_anywhere_in_its_evidence() {
    // The corpus authority boundary, checked over what actually reaches the
    // evaluator rather than over the type that carries it.
    for entry in corpus() {
        let mut ledger = AdmissionLedger::new();
        let Ok(evidence) = (entry.build)(&mut ledger) else {
            continue;
        };
        let rendered = serde_json::to_string(&evidence)
            .expect("serializes")
            .to_lowercase();
        for absent in [
            "expected_verdict",
            "expected_findings",
            "is_secure",
            "should_fail",
        ] {
            assert!(
                !rendered.contains(absent),
                "{} carries `{absent}` into the evaluator",
                entry.id
            );
        }
    }
}

#[test]
fn the_dangling_edge_entry_is_refused_and_not_silently_dropped() {
    // A dropped edge is a dependency that stops being checked, which looks
    // exactly like a dependency that was never there.
    let corpus = corpus();
    let entry = corpus
        .iter()
        .find(|entry| entry.id == "SUPPLY-LAB-019")
        .expect("the dangling-edge entry");
    let mut ledger = AdmissionLedger::new();
    let error = (entry.build)(&mut ledger).expect_err("a dangling edge was admitted");
    let message = error.to_string();
    assert!(
        message.contains("target component that is not in the graph"),
        "the refusal did not say which end of the edge was missing: {message}"
    );
}

#[test]
fn every_invariant_is_exercised_by_at_least_one_entry() {
    // An invariant with no fixture behind it is an untested claim in the
    // report, and it would look exactly like a covered one.
    let corpus = corpus();
    let named: BTreeSet<&str> = corpus
        .iter()
        .map(|entry| entry.invariant.as_str())
        .collect();

    let mut observed: BTreeSet<&str> = named.clone();
    for entry in &corpus {
        let mut ledger = AdmissionLedger::new();
        let Ok(evidence) = (entry.build)(&mut ledger) else {
            continue;
        };
        for violation in collect_observed_violations(&project(&evidence)) {
            observed.insert(violation.invariant.as_str());
        }
    }

    for invariant in SupplyChainInvariant::all() {
        assert!(
            observed.contains(invariant.as_str()),
            "{} has no corpus entry behind it",
            invariant.as_str()
        );
    }
}
