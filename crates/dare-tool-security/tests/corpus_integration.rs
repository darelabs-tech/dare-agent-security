//! Cycle 014 corpus integration tests.
//!
//! These run the corpus that ships with the workspace end to end: load and
//! validate it, stage each vector through the offline simulator, and evaluate
//! the result deterministically. Nothing here invokes a tool, contacts a
//! server, touches the network or changes any state.

use std::collections::BTreeSet;

use dare_tool_security::canonical::bind;
use dare_tool_security::corpus::builtin_corpus;
use dare_tool_security::harness::{normalize_checked, ToolHarnessAdapter, ToolTrialRequest};
use dare_tool_security::invariant::evaluate;
use dare_tool_security::model::{ReferenceBehavior, ToolCorpusEntry, ToolSecurityScenario};
use dare_tool_security::observation::ToolObservationEvent;
use dare_tool_security::simulated::ToolSimulatedAdapter;
use dare_tool_security::source::CorpusClass;
use dare_tool_security::Verdict;

fn scenario() -> ToolSecurityScenario {
    let raw = include_str!("fixtures/scenario.json");
    let value: serde_json::Value = serde_json::from_str(raw).expect("scenario fixture parses");
    dare_tool_security::schema::validate_scenario_document(&value).expect("scenario validates");
    serde_json::from_value(value).expect("scenario decodes")
}

/// Run one corpus entry through the whole offline pipeline.
fn verdict_for(entry: &ToolCorpusEntry) -> (Verdict, Vec<ToolObservationEvent>) {
    let scenario = scenario();
    let binding = bind(&scenario).expect("scenario binds");
    let raw = ToolSimulatedAdapter::from_entry(entry)
        .observe(&ToolTrialRequest {
            trial_index: 0,
            scenario: &scenario,
            binding: &binding,
            entry: Some(entry),
        })
        .expect("simulation observes");
    let events = normalize_checked(&raw, &binding).expect("observations normalize");
    let outcome = evaluate(
        entry.expected_invariant,
        &scenario.objective,
        &scenario.policy,
        &events,
    );
    (outcome.verdict, events)
}

#[test]
fn the_shipped_corpus_loads_and_validates() {
    let corpus = builtin_corpus().expect("corpus loads");
    assert_eq!(corpus.corpus_id, "tool-security-v1");
    assert_eq!(corpus.version, "1.0.0");
    assert!(
        corpus.entries.len() >= 20,
        "Cycle 014 requires at least 20 fixtures, found {}",
        corpus.entries.len()
    );
}

#[test]
fn every_registry_digest_is_pinned_and_matches_its_file() {
    // load_corpus verifies a pinned digest when one is present; this asserts
    // every entry actually pins one, so a swapped fixture cannot pass silently.
    let raw =
        std::fs::read(dare_tool_security::corpus::builtin_corpus_root().join("registry.json"))
            .expect("registry readable");
    let registry: serde_json::Value = serde_json::from_slice(&raw).expect("registry parses");
    let entries = registry["entries"].as_array().expect("entries array");
    assert!(!entries.is_empty());
    for entry in entries {
        let digest = entry["digest"].as_str().unwrap_or_default();
        assert!(
            digest.starts_with("sha256:") && digest.len() == 71,
            "{} must pin a sha256 digest",
            entry["id"]
        );
    }
    // And the loader accepted them, which is the actual verification.
    builtin_corpus().expect("pinned digests verify");
}

#[test]
fn poisoning_and_misuse_are_both_represented_and_stay_separate() {
    let corpus = builtin_corpus().expect("corpus loads");
    let poisoning = corpus.by_class(CorpusClass::PoisoningAttack);
    let misuse = corpus.by_class(CorpusClass::MisuseAttack);
    let benign = corpus.by_class(CorpusClass::BenignControl);

    assert!(poisoning.len() >= 6, "TOOL-LAB-001..006 poisoning coverage");
    assert!(misuse.len() >= 8, "TOOL-LAB-007..014 misuse coverage");
    assert!(benign.len() >= 6, "paired benign controls");

    // The two dimensions are disjoint by construction, not by convention.
    let poisoning_families: BTreeSet<&str> = poisoning
        .iter()
        .map(|entry| entry.family.as_str())
        .collect();
    let misuse_families: BTreeSet<&str> =
        misuse.iter().map(|entry| entry.family.as_str()).collect();
    assert!(poisoning_families.is_disjoint(&misuse_families));
}

#[test]
fn every_poisoning_and_misuse_family_has_a_vector() {
    use dare_tool_security::source::{MisuseFamily, PoisoningFamily};
    let corpus = builtin_corpus().expect("corpus loads");
    let families: BTreeSet<&str> = corpus
        .entries
        .iter()
        .map(|entry| entry.family.as_str())
        .collect();

    for family in PoisoningFamily::all() {
        assert!(
            families.contains(family.as_str()),
            "poisoning family {} has no vector",
            family.as_str()
        );
    }
    for family in MisuseFamily::all() {
        assert!(
            families.contains(family.as_str()),
            "misuse family {} has no vector",
            family.as_str()
        );
    }
}

#[test]
fn every_attack_vector_fails_the_invariant_it_targets() {
    let corpus = builtin_corpus().expect("corpus loads");
    for entry in &corpus.entries {
        if entry.class == CorpusClass::BenignControl {
            continue;
        }
        // A vector that stages nothing decidable is the exception, and it is
        // the point: it must read INCONCLUSIVE, never PASS.
        let expected = if entry.reference_behavior == ReferenceBehavior::NoRelevantObservation {
            Verdict::Inconclusive
        } else {
            Verdict::Fail
        };
        let (verdict, _) = verdict_for(entry);
        assert_eq!(
            verdict,
            expected,
            "{} ({}) should be {expected:?} for {}",
            entry.id,
            entry.reference_behavior.as_str(),
            entry.expected_invariant.as_str()
        );
    }
}

#[test]
fn every_benign_control_passes_without_a_false_violation() {
    let corpus = builtin_corpus().expect("corpus loads");
    let benign = corpus.by_class(CorpusClass::BenignControl);
    assert!(!benign.is_empty());
    for entry in benign {
        let (verdict, _) = verdict_for(entry);
        assert_eq!(
            verdict,
            Verdict::Pass,
            "{} must not produce a false violation",
            entry.id
        );
    }
}

#[test]
fn benign_security_prose_alone_cannot_cause_a_failure() {
    // The false-positive regression that matters most: a tool whose description
    // and output legitimately discuss deleting, payments and approvals. Reading
    // those words is not a violation; only behavior is.
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = corpus
        .require("benign-security-prose")
        .expect("control present");
    let payload = entry.payload.as_ref().expect("carries prose");
    for word in ["payment", "deleted", "sending", "reversed"] {
        assert!(
            payload.content.to_ascii_lowercase().contains(word),
            "the control must actually contain `{word}`"
        );
    }

    let scenario = scenario();
    let binding = bind(&scenario).expect("binds");
    let raw = ToolSimulatedAdapter::from_entry(entry)
        .observe(&ToolTrialRequest {
            trial_index: 0,
            scenario: &scenario,
            binding: &binding,
            entry: Some(entry),
        })
        .expect("observes");
    let events = normalize_checked(&raw, &binding).expect("normalizes");

    // Not just its own invariant — no invariant may fail on this prose.
    for invariant in dare_tool_security::invariant::supported_invariants() {
        let outcome = evaluate(invariant, &scenario.objective, &scenario.policy, &events);
        assert_ne!(
            outcome.verdict,
            Verdict::Fail,
            "{} must not fail on benign security prose",
            invariant.as_str()
        );
    }
}

#[test]
fn a_synthetic_canary_reaches_evidence_masked() {
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = corpus
        .require("benign-redaction-hygiene")
        .expect("control present");
    let (verdict, events) = verdict_for(entry);
    assert_eq!(verdict, Verdict::Pass);

    let output = events
        .iter()
        .find_map(|event| match event {
            ToolObservationEvent::ToolOutputObserved(output) => Some(output),
            _ => None,
        })
        .expect("output observed");

    assert!(output.content.redacted, "the canary must be masked");
    assert!(!output.content.text.contains("DARE-SYNTHETIC-CANARY-TOOL01"));
    assert!(output.content.text.contains("[REDACTED]"));
    // Correlation without disclosure: the digest is over the original bytes.
    assert!(output.content.digest.starts_with("sha256:"));
    assert!(output.content.original_bytes > output.content.text.len());
}

#[test]
fn independent_violations_are_all_recorded() {
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = corpus
        .require("misuse-multiple-independent")
        .expect("vector present");
    let (_, events) = verdict_for(entry);
    let scenario = scenario();

    let failing: Vec<_> = dare_tool_security::invariant::supported_invariants()
        .into_iter()
        .filter(|invariant| {
            evaluate(*invariant, &scenario.objective, &scenario.policy, &events).verdict
                == Verdict::Fail
        })
        .collect();
    assert!(
        failing.len() >= 3,
        "one classification must never mask another; got {failing:?}"
    );
}

#[test]
fn a_risky_vector_stays_inert() {
    // The delete vector produces a deterministic FAIL from an observation. The
    // request is recorded; it is never dispatched, and nothing is deleted.
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = corpus
        .require("misuse-dangerous-argument")
        .expect("vector present");
    let (verdict, events) = verdict_for(entry);
    assert_eq!(verdict, Verdict::Fail);

    let requests: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ToolObservationEvent::ToolRequested(request) => Some(request),
            _ => None,
        })
        .collect();
    assert!(!requests.is_empty());
    for request in requests {
        assert!(!request.dispatched, "no request is ever dispatched");
    }
}

#[test]
fn no_corpus_entry_carries_an_expected_verdict() {
    // A fixture must never be able to tell the engine the answer.
    let root = dare_tool_security::corpus::builtin_corpus_root();
    for path in std::fs::read_dir(&root).expect("corpus root") {
        let path = path.expect("entry").path();
        // The adversarial fixtures are hostile by design and live outside the
        // registry; hostile_fixtures.rs proves each of them fails closed.
        if !path.is_dir() || path.ends_with("adversarial-parser-fixtures") {
            continue;
        }
        for file in std::fs::read_dir(&path).expect("corpus directory") {
            let file = file.expect("file").path();
            let raw = std::fs::read_to_string(&file).expect("readable");
            let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
            dare_tool_security::schema::assert_no_hostile_fields(&value, "corpus entry")
                .unwrap_or_else(|err| panic!("{}: {err}", file.display()));
        }
    }
}

#[test]
fn corpus_results_are_reproducible() {
    let corpus = builtin_corpus().expect("corpus loads");
    for entry in &corpus.entries {
        let (first, first_events) = verdict_for(entry);
        let (second, second_events) = verdict_for(entry);
        assert_eq!(first, second, "{} must be reproducible", entry.id);
        assert_eq!(first_events, second_events);
    }
}
