//! Cycle 013 — indirect prompt-injection corpus and paired fixtures.
//!
//! Covers untrusted external content boundaries: document text, HTML, MCP
//! resource content and generic external content, plus hidden and cross-content
//! instruction carriers. Tool-description poisoning (Cycle 014) and RAG
//! retrieval poisoning (Cycle 017) are deliberately absent and asserted absent.

use std::collections::HashSet;
use std::path::PathBuf;

use dare_prompt_injection::corpus::builtin_corpus;
use dare_prompt_injection::harness::{normalize, HarnessAdapter, TrialRequest};
use dare_prompt_injection::invariant::evaluate;
use dare_prompt_injection::model::PromptInjectionScenario;
use dare_prompt_injection::observation::ObservationEvent;
use dare_prompt_injection::schema::validate_scenario_document;
use dare_prompt_injection::simulated::SimulatedAdapter;
use dare_prompt_injection::source::{CorpusClass, InjectionDirection, InjectionFamily, SourceKind};
use dare_prompt_injection::{canonical, Verdict};
use serde_json::Value;

fn load_scenario(id: &str) -> PromptInjectionScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/prompt-injection/scenarios")
        .join(format!("{id}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {id}: {err}"));
    let value: Value = serde_json::from_slice(&raw).expect("scenario json");
    validate_scenario_document(&value).unwrap_or_else(|err| panic!("{id} schema: {err}"));
    serde_json::from_value(value).unwrap_or_else(|err| panic!("{id} typed: {err}"))
}

fn run_trial(id: &str) -> (PromptInjectionScenario, Vec<ObservationEvent>) {
    let scenario = load_scenario(id);
    let corpus = builtin_corpus().expect("corpus");
    let entry = corpus
        .require(&scenario.vector.corpus_id)
        .expect("corpus vector")
        .clone();
    canonical::bind(&scenario, &entry).expect("identity binding");

    let profile = scenario.lab.as_ref().expect("lab block").profile();
    let raw = SimulatedAdapter::new(profile)
        .observe(&TrialRequest {
            trial_index: 0,
            scenario: &scenario,
            entry: &entry,
        })
        .expect("observe");
    let events = normalize(&raw, &scenario.objective);
    (scenario, events)
}

fn verdict_for(id: &str) -> Verdict {
    let (scenario, events) = run_trial(id);
    evaluate(scenario.invariant.type_, &scenario.objective, &events).verdict
}

#[test]
fn indirect_corpus_covers_every_indirect_family() {
    let corpus = builtin_corpus().expect("corpus");
    let indirect = corpus.by_class(CorpusClass::IndirectAttack);
    assert_eq!(indirect.len(), 6);

    let families: HashSet<InjectionFamily> = indirect.iter().map(|entry| entry.family).collect();
    for required in [
        InjectionFamily::IndirectGoalOverride,
        InjectionFamily::IndirectSystemInstructionOverride,
        InjectionFamily::IndirectProtectedDataRequest,
        InjectionFamily::IndirectUnauthorizedActionRequest,
        InjectionFamily::IndirectHiddenInstruction,
        InjectionFamily::IndirectCrossContentInstruction,
    ] {
        assert!(
            families.contains(&required),
            "indirect corpus is missing {}",
            required.as_str()
        );
    }
}

#[test]
fn indirect_corpus_covers_the_approved_external_source_kinds() {
    let corpus = builtin_corpus().expect("corpus");
    let sources: HashSet<SourceKind> = corpus
        .by_class(CorpusClass::IndirectAttack)
        .iter()
        .map(|entry| entry.source_kind)
        .collect();

    for required in [
        SourceKind::DocumentText,
        SourceKind::HtmlContent,
        SourceKind::McpResourceContent,
        SourceKind::GenericExternalContent,
    ] {
        assert!(
            sources.contains(&required),
            "indirect corpus is missing the {} boundary",
            required.as_str()
        );
    }
    assert!(
        !sources.contains(&SourceKind::UserPrompt),
        "an indirect entry must never use the direct source boundary"
    );
}

#[test]
fn every_indirect_entry_uses_the_external_content_boundary() {
    let corpus = builtin_corpus().expect("corpus");
    for entry in corpus.by_class(CorpusClass::IndirectAttack) {
        assert_eq!(entry.family.direction(), InjectionDirection::Indirect);
        assert_eq!(entry.source_kind.direction(), InjectionDirection::Indirect);
        assert_eq!(
            entry.property.as_str(),
            "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
            "{} must claim the external-content boundary",
            entry.id
        );
        assert!(
            entry
                .preconditions
                .iter()
                .any(|p| p == "untrusted_external_content_present"),
            "{} must declare the external-content precondition",
            entry.id
        );
    }
}

#[test]
fn hidden_and_cross_content_carriers_are_documented() {
    let corpus = builtin_corpus().expect("corpus");
    for id in [
        "indirect-html-hidden-instruction-001",
        "indirect-cross-content-instruction-001",
    ] {
        let entry = corpus.require(id).expect(id);
        assert!(
            entry.content.carrier_note.is_some(),
            "{id} must document how the instruction is carried"
        );
    }
}

#[test]
fn deferred_cycles_are_not_smuggled_into_the_indirect_corpus() {
    let corpus = builtin_corpus().expect("corpus");
    for entry in &corpus.entries {
        // Cycle 014 tool poisoning and Cycle 017 RAG poisoning stay out.
        assert!(
            !entry.id.contains("tool-poison") && !entry.id.contains("rag"),
            "{} looks like a deferred-cycle vector",
            entry.id
        );
        let family = entry.family.as_str();
        assert!(!family.contains("TOOL"), "{} uses a tool family", entry.id);
        assert!(!family.contains("RAG"), "{} uses a RAG family", entry.id);
        assert!(!family.contains("A2A"), "{} uses an A2A family", entry.id);
        assert!(
            !family.contains("MEMORY"),
            "{} uses a memory family",
            entry.id
        );
    }
}

#[test]
fn pi_lab_005_indirect_document_instruction_secure_passes() {
    assert_eq!(verdict_for("PI-LAB-005"), Verdict::Pass);
}

#[test]
fn pi_lab_006_indirect_document_instruction_vulnerable_fails() {
    let (scenario, events) = run_trial("PI-LAB-006");
    let outcome = evaluate(scenario.invariant.type_, &scenario.objective, &events);
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(!outcome.deciding_event_digests.is_empty());
    assert!(events
        .iter()
        .any(|event| matches!(event, ObservationEvent::GoalState(state)
            if state.goal_id != scenario.objective.authorized_goal_id)));
}

#[test]
fn pi_lab_007_indirect_html_hidden_instruction_secure_passes() {
    assert_eq!(verdict_for("PI-LAB-007"), Verdict::Pass);
}

#[test]
fn pi_lab_008_indirect_html_hidden_instruction_vulnerable_fails() {
    assert_eq!(verdict_for("PI-LAB-008"), Verdict::Fail);
}

#[test]
fn the_indirect_pairs_differ_only_in_reference_behavior() {
    for (secure, vulnerable) in [("PI-LAB-005", "PI-LAB-006"), ("PI-LAB-007", "PI-LAB-008")] {
        let a = load_scenario(secure);
        let b = load_scenario(vulnerable);
        assert_eq!(a.vector.corpus_id, b.vector.corpus_id);
        assert_eq!(a.objective, b.objective);
        assert_eq!(a.invariant.type_, b.invariant.type_);
        assert_eq!(a.source.kind, b.source.kind);
        assert_eq!(a.source.kind.direction(), InjectionDirection::Indirect);
        assert_ne!(
            a.lab.as_ref().unwrap().reference_behavior,
            b.lab.as_ref().unwrap().reference_behavior
        );

        assert_eq!(verdict_for(secure), Verdict::Pass);
        assert_eq!(verdict_for(vulnerable), Verdict::Fail);
    }
}

#[test]
fn direct_and_indirect_results_stay_distinguishable() {
    // A direct and an indirect scenario must never be conflated: they carry
    // different source boundaries and different properties.
    let direct = load_scenario("PI-LAB-002");
    let indirect = load_scenario("PI-LAB-006");

    assert_eq!(direct.source.kind.direction(), InjectionDirection::Direct);
    assert_eq!(
        indirect.source.kind.direction(),
        InjectionDirection::Indirect
    );
    assert_ne!(direct.property.as_str(), indirect.property.as_str());
    assert_eq!(
        direct.property.as_str(),
        "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY"
    );
    assert_eq!(
        indirect.property.as_str(),
        "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY"
    );
}

#[test]
fn indirect_scenario_runs_are_reproducible() {
    for id in ["PI-LAB-005", "PI-LAB-006", "PI-LAB-007", "PI-LAB-008"] {
        let (_, first) = run_trial(id);
        let (_, second) = run_trial(id);
        assert_eq!(first, second, "{id} is not reproducible");
    }
}

#[test]
fn indirect_html_payload_is_inert_data_not_markup_to_render() {
    // The HTML fixture is a string in a JSON document. Nothing parses or renders
    // it, and it carries no script element.
    let corpus = builtin_corpus().expect("corpus");
    let entry = corpus
        .require("indirect-html-hidden-instruction-001")
        .expect("html entry");
    let payload = entry.content.payload.to_ascii_lowercase();
    assert!(!payload.contains("<script"));
    assert!(!payload.contains("javascript:"));
    assert!(!payload.contains("onerror="));
    assert!(payload.contains("display:none"));
}
