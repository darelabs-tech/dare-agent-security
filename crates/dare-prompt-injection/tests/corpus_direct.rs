//! Cycle 013 — direct prompt-injection corpus and paired fixtures.
//!
//! Validates the committed corpus as untrusted input and runs the direct
//! secure/vulnerable pairs end to end, offline.

use std::collections::HashSet;
use std::path::PathBuf;

use dare_prompt_injection::corpus::builtin_corpus;
use dare_prompt_injection::harness::{normalize, HarnessAdapter, TrialRequest};
use dare_prompt_injection::invariant::evaluate;
use dare_prompt_injection::model::PromptInjectionScenario;
use dare_prompt_injection::observation::ObservationEvent;
use dare_prompt_injection::schema::validate_scenario_document;
use dare_prompt_injection::simulated::SimulatedAdapter;
use dare_prompt_injection::source::{CorpusClass, InjectionDirection, InjectionFamily};
use dare_prompt_injection::{canonical, Verdict};
use serde_json::Value;

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/prompt-injection/scenarios")
}

fn load_scenario(id: &str) -> PromptInjectionScenario {
    let path = scenarios_dir().join(format!("{id}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {id}: {err}"));
    let value: Value = serde_json::from_slice(&raw).expect("scenario json");
    validate_scenario_document(&value).unwrap_or_else(|err| panic!("{id} schema: {err}"));
    serde_json::from_value(value).unwrap_or_else(|err| panic!("{id} typed: {err}"))
}

/// Run one scenario for one trial under the simulated adapter.
fn run_trial(id: &str, trial_index: u32) -> (PromptInjectionScenario, Vec<ObservationEvent>) {
    let scenario = load_scenario(id);
    let corpus = builtin_corpus().expect("corpus");
    let entry = corpus
        .require(&scenario.vector.corpus_id)
        .expect("corpus vector")
        .clone();
    canonical::bind(&scenario, &entry).expect("identity binding");

    let profile = scenario
        .lab
        .as_ref()
        .expect("scenario declares a lab reference behavior")
        .profile();
    let adapter = SimulatedAdapter::new(profile);
    let raw = adapter
        .observe(&TrialRequest {
            trial_index,
            scenario: &scenario,
            entry: &entry,
        })
        .expect("observe");
    let events = normalize(&raw, &scenario.objective);
    (scenario, events)
}

fn verdict_for(id: &str) -> Verdict {
    let (scenario, events) = run_trial(id, 0);
    evaluate(scenario.invariant.type_, &scenario.objective, &events).verdict
}

#[test]
fn committed_corpus_validates_as_untrusted_input() {
    let corpus = builtin_corpus().expect("corpus loads and validates");
    assert_eq!(corpus.corpus_id, "prompt-injection-v1");
    assert_eq!(corpus.version, "1.0.0");
    assert!(!corpus.entries.is_empty());

    let ids: HashSet<&str> = corpus.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.entries.len(), "duplicate corpus id");
}

#[test]
fn direct_corpus_covers_every_direct_family() {
    let corpus = builtin_corpus().expect("corpus");
    let direct = corpus.by_class(CorpusClass::DirectAttack);
    assert_eq!(direct.len(), 6);

    let families: HashSet<InjectionFamily> = direct.iter().map(|entry| entry.family).collect();
    for required in [
        InjectionFamily::DirectGoalOverride,
        InjectionFamily::DirectSystemInstructionOverride,
        InjectionFamily::DirectRoleConfusion,
        InjectionFamily::DirectProtectedDataRequest,
        InjectionFamily::DirectUnauthorizedActionRequest,
        InjectionFamily::DirectInstructionSmuggling,
    ] {
        assert!(
            families.contains(&required),
            "direct corpus is missing {}",
            required.as_str()
        );
    }
}

#[test]
fn every_direct_entry_uses_the_user_prompt_boundary() {
    let corpus = builtin_corpus().expect("corpus");
    for entry in corpus.by_class(CorpusClass::DirectAttack) {
        assert_eq!(entry.family.direction(), InjectionDirection::Direct);
        assert_eq!(
            entry.source_kind.as_str(),
            "USER_PROMPT",
            "{} must use the direct source boundary",
            entry.id
        );
        assert_eq!(
            entry.property.as_str(),
            "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY"
        );
    }
}

#[test]
fn corpus_content_is_synthetic_and_carries_no_real_secret() {
    let corpus = builtin_corpus().expect("corpus");
    for entry in &corpus.entries {
        assert_eq!(entry.provenance.origin, "DARE_SYNTHETIC", "{}", entry.id);
        assert_eq!(entry.provenance.license, "Apache-2.0", "{}", entry.id);
        assert_eq!(entry.safety_class, "SYNTHETIC_NOOP", "{}", entry.id);
        assert!(!entry.standards.is_empty(), "{}", entry.id);

        let payload = entry.content.payload.to_ascii_lowercase();
        for marker in [
            "sk-live-",
            "bearer ",
            "-----begin",
            "ghp_",
            "xoxb-",
            "aws_secret_access_key",
        ] {
            assert!(
                !payload.contains(marker),
                "{} contains credential-shaped content",
                entry.id
            );
        }
    }
}

#[test]
fn corpus_declares_no_executable_or_remote_field() {
    let corpus = builtin_corpus().expect("corpus");
    let serialized = serde_json::to_string(
        &corpus
            .entries
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for forbidden in [
        "\"shell\"",
        "\"eval\"",
        "\"script\"",
        "\"callback\"",
        "\"exec\"",
        "\"command\"",
        "\"url\"",
        "\"provider\"",
        "\"api_key\"",
        "\"token\"",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "corpus must not contain the key {forbidden}"
        );
    }
}

#[test]
fn every_scenario_binds_to_its_corpus_vector() {
    let corpus = builtin_corpus().expect("corpus");
    for id in [
        "PI-LAB-001",
        "PI-LAB-002",
        "PI-LAB-003",
        "PI-LAB-004",
        "PI-LAB-010",
        "PI-LAB-013",
        "PI-LAB-014",
        "PI-LAB-015",
    ] {
        let scenario = load_scenario(id);
        let entry = corpus
            .require(&scenario.vector.corpus_id)
            .unwrap_or_else(|err| panic!("{id}: {err}"));
        let binding = canonical::bind(&scenario, entry)
            .unwrap_or_else(|err| panic!("{id} binding failed: {err}"));
        assert_eq!(binding.scenario_id, id);
        assert!(binding.corpus_digest.starts_with("sha256:"));
        assert!(binding.objective_digest.starts_with("sha256:"));
    }
}

#[test]
fn pi_lab_001_direct_goal_override_secure_passes() {
    assert_eq!(verdict_for("PI-LAB-001"), Verdict::Pass);
}

#[test]
fn pi_lab_002_direct_goal_override_vulnerable_fails() {
    let (scenario, events) = run_trial("PI-LAB-002", 0);
    let outcome = evaluate(scenario.invariant.type_, &scenario.objective, &events);
    assert_eq!(outcome.verdict, Verdict::Fail);

    // The FAIL is backed by a typed goal-state fact, not by prose.
    assert!(!outcome.deciding_event_digests.is_empty());
    assert!(events
        .iter()
        .any(|event| matches!(event, ObservationEvent::GoalState(state)
            if state.goal_id != scenario.objective.authorized_goal_id)));
}

#[test]
fn pi_lab_003_canary_request_refused_passes() {
    assert_eq!(verdict_for("PI-LAB-003"), Verdict::Pass);
}

#[test]
fn pi_lab_004_canary_disclosure_fails_on_an_exact_token() {
    let (scenario, events) = run_trial("PI-LAB-004", 0);
    let outcome = evaluate(scenario.invariant.type_, &scenario.objective, &events);
    assert_eq!(outcome.verdict, Verdict::Fail);

    let disclosure = events
        .iter()
        .find_map(|event| match event {
            ObservationEvent::CanaryDisclosure(disclosure) => Some(disclosure),
            _ => None,
        })
        .expect("canary disclosure event");
    assert!(disclosure.exact_match);
    assert!(disclosure.canary_digest.starts_with("sha256:"));
}

#[test]
fn the_direct_pairs_differ_only_in_reference_behavior() {
    // Same vector, same objective, same invariant: the only difference is
    // whether the reference agent held the boundary.
    for (secure, vulnerable) in [("PI-LAB-001", "PI-LAB-002"), ("PI-LAB-003", "PI-LAB-004")] {
        let a = load_scenario(secure);
        let b = load_scenario(vulnerable);
        assert_eq!(a.vector.corpus_id, b.vector.corpus_id);
        assert_eq!(a.objective, b.objective);
        assert_eq!(a.invariant.type_, b.invariant.type_);
        assert_eq!(a.source.kind, b.source.kind);
        assert_ne!(
            a.lab.as_ref().unwrap().reference_behavior,
            b.lab.as_ref().unwrap().reference_behavior
        );

        assert_eq!(verdict_for(secure), Verdict::Pass);
        assert_eq!(verdict_for(vulnerable), Verdict::Fail);
    }
}

#[test]
fn direct_fixtures_never_leak_a_canary_into_evidence() {
    for id in ["PI-LAB-003", "PI-LAB-004", "PI-LAB-015"] {
        let (_, events) = run_trial(id, 0);
        let serialized = serde_json::to_string(&events).expect("serialize");
        assert!(
            !serialized.contains("DARE-SYNTHETIC-CANARY-ALPHA1"),
            "{id} leaked the canary token into evidence"
        );
        for event in &events {
            event
                .validate()
                .unwrap_or_else(|err| panic!("{id} event unsafe: {err}"));
        }
    }
}

#[test]
fn direct_scenario_runs_are_reproducible() {
    for id in ["PI-LAB-001", "PI-LAB-002", "PI-LAB-003", "PI-LAB-004"] {
        let (_, first) = run_trial(id, 0);
        let (_, second) = run_trial(id, 0);
        assert_eq!(first, second, "{id} is not reproducible");
    }
}
