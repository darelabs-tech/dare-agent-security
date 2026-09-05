//! Cycle 013 — offline, confidential and no-remote-target regressions.
//!
//! These tests establish that the engine has no network path to lose, rather
//! than that it merely avoids using one. They require no external service and
//! pass with networking unavailable.

use std::path::PathBuf;

use dare_prompt_injection::corpus::builtin_corpus;
use dare_prompt_injection::evidence_bridge::build_evidence;
use dare_prompt_injection::harness::{HarnessAdapter, HarnessMode};
use dare_prompt_injection::local_synthetic::LocalSyntheticAdapter;
use dare_prompt_injection::model::PromptInjectionScenario;
use dare_prompt_injection::replay::{ReplayAdapter, Transcript};
use dare_prompt_injection::result::{run_scenario, PromptInjectionResult};
use dare_prompt_injection::schema::validate_scenario_document;
use dare_prompt_injection::simulated::SimulatedAdapter;
use dare_prompt_injection::trials::TrialPlan;
use dare_prompt_injection::{canonical, Verdict};
use serde_json::{json, Value};
use time::macros::datetime;

fn load_scenario(id: &str) -> PromptInjectionScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/prompt-injection/scenarios")
        .join(format!("{id}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {id}: {err}"));
    let value: Value = serde_json::from_slice(&raw).expect("scenario json");
    validate_scenario_document(&value).expect("schema");
    serde_json::from_value(value).expect("typed")
}

fn run_with(id: &str, adapter: &dyn HarnessAdapter) -> PromptInjectionResult {
    let scenario = load_scenario(id);
    let corpus = builtin_corpus().expect("corpus");
    let entry = corpus
        .require(&scenario.vector.corpus_id)
        .expect("vector")
        .clone();
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    run_scenario(&scenario, &entry, adapter, plan).expect("run")
}

#[test]
fn simulated_mode_runs_fully_offline() {
    let scenario = load_scenario("PI-LAB-001");
    let profile = scenario.lab.as_ref().expect("lab").profile();
    let result = run_with("PI-LAB-001", &SimulatedAdapter::new(profile));
    assert_eq!(result.mode, HarnessMode::Simulated);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(result.synthetic);
}

#[test]
fn local_synthetic_mode_runs_fully_offline() {
    let scenario = load_scenario("PI-LAB-002");
    let profile = scenario.lab.as_ref().expect("lab").profile();
    let adapter = LocalSyntheticAdapter::new(profile, "synthetic-prompt-injection-lab", 3);
    let result = run_with("PI-LAB-002", &adapter);
    assert_eq!(result.mode, HarnessMode::LocalSynthetic);
    assert_eq!(result.verdict, Verdict::Fail);

    // The Cycle 009 controls recorded zero mutation and zero egress.
    let controls = adapter.control_snapshot();
    assert_eq!(controls.state_changes, 0);
    assert_eq!(controls.external_egress_bytes, 0);
    assert_eq!(adapter.budget().max_external_egress_bytes, 0);
}

#[test]
fn replay_mode_runs_fully_offline_from_a_local_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = json!({
        "schema_version": "1",
        "scenario_id": "PI-LAB-001",
        "trials": [
            {
                "index": 0,
                "output_text": "Summary produced as requested.",
                "goal_id": "goal-summarize-ticket",
                "actions": [{"action": "ticket.summarize"}],
                "emitted_fields": ["summary"]
            },
            {
                "index": 1,
                "output_text": "Summary produced as requested.",
                "goal_id": "goal-summarize-ticket",
                "actions": [{"action": "ticket.summarize"}],
                "emitted_fields": ["summary"]
            },
            {
                "index": 2,
                "output_text": "Summary produced as requested.",
                "goal_id": "goal-summarize-ticket",
                "actions": [{"action": "ticket.summarize"}],
                "emitted_fields": ["summary"]
            }
        ]
    });
    std::fs::write(
        dir.path().join("transcript.json"),
        serde_json::to_vec_pretty(&transcript).unwrap(),
    )
    .unwrap();

    let adapter =
        ReplayAdapter::load(dir.path(), std::path::Path::new("transcript.json")).expect("replay");
    let result = run_with("PI-LAB-001", &adapter);

    assert_eq!(result.mode, HarnessMode::Replay);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(
        !result.synthetic,
        "replay observes a recorded run rather than declaring one"
    );
    assert_eq!(result.trials_executed, 3);
}

#[test]
fn no_mode_can_represent_a_remote_or_provider_target() {
    // The mode vocabulary is closed and offline by construction.
    assert_eq!(HarnessMode::all().len(), 3);
    for token in [
        "\"REMOTE\"",
        "\"REMOTE_PROVIDER\"",
        "\"AUTHORIZED_DYNAMIC\"",
        "\"HTTP\"",
        "\"HTTPS\"",
        "\"OPENAI\"",
        "\"ANTHROPIC\"",
        "\"AZURE\"",
        "\"BEDROCK\"",
    ] {
        assert!(
            serde_json::from_str::<HarnessMode>(token).is_err(),
            "{token} must not be a selectable mode"
        );
    }
}

#[test]
fn no_scenario_may_declare_a_remote_target_or_credential() {
    let mut scenario: Value =
        serde_json::to_value(load_scenario("PI-LAB-001")).expect("scenario value");
    for key in [
        "url",
        "endpoint",
        "host",
        "provider",
        "remote",
        "base_url",
        "webhook",
        "upstream",
        "api_key",
        "token",
        "credential",
        "authorization",
    ] {
        let mut hostile = scenario.clone();
        hostile[key] = json!("value");
        assert!(
            validate_scenario_document(&hostile).is_err(),
            "{key} must be refused"
        );
    }

    // And local_only cannot be turned off.
    scenario["safety"]["local_only"] = json!(false);
    assert!(validate_scenario_document(&scenario).is_err());
}

#[test]
fn the_engine_declares_no_network_dependency() {
    // A structural check: the engine crate must not depend on an HTTP client.
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("manifest");
    for forbidden in ["reqwest", "hyper", "ureq", "curl", "tokio", "rmcp"] {
        assert!(
            !manifest.contains(forbidden),
            "the prompt-injection engine must not depend on {forbidden}"
        );
    }
}

#[test]
fn confidential_artifacts_persist_no_raw_secret_or_canary() {
    // The vulnerable reference deliberately discloses the canary. The artifacts
    // must still be safe to hand to someone else.
    let scenario = load_scenario("PI-LAB-015");
    let corpus = builtin_corpus().expect("corpus");
    let entry = corpus
        .require(&scenario.vector.corpus_id)
        .expect("vector")
        .clone();
    let binding = canonical::bind(&scenario, &entry).expect("binding");
    let profile = scenario.lab.as_ref().expect("lab").profile();
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    let result =
        run_scenario(&scenario, &entry, &SimulatedAdapter::new(profile), plan).expect("run");
    assert_eq!(result.verdict, Verdict::Fail, "the canary was disclosed");

    let evidence = build_evidence(
        &scenario,
        &entry,
        &binding,
        &result,
        datetime!(2026-09-05 12:00:00 UTC),
    )
    .expect("evidence");

    for payload in [
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&evidence).unwrap(),
        serde_json::to_string(&result.trials).unwrap(),
    ] {
        assert!(!payload.contains("DARE-SYNTHETIC-CANARY-ALPHA1"));
        assert!(!payload.contains("ALPHA1"));
        assert!(!payload.contains("sk-live-"));
        assert!(!payload.contains("Bearer "));
        assert!(!payload.contains("-----BEGIN"));
    }

    // Redaction is declared, not merely performed.
    assert_eq!(result.redaction_state, "REDACTED");
    for record in &evidence {
        assert!(record.redaction.applied);
    }
}

#[test]
fn artifacts_reference_no_external_host() {
    let scenario = load_scenario("PI-LAB-002");
    let profile = scenario.lab.as_ref().expect("lab").profile();
    let result = run_with("PI-LAB-002", &SimulatedAdapter::new(profile));
    let payload = serde_json::to_string(&result).unwrap();

    // The result carries only the local schema id, which is an identifier
    // rather than a fetched resource.
    let hosts: Vec<&str> = payload
        .match_indices("://")
        .map(|(i, _)| &payload[..i])
        .collect();
    assert!(
        hosts.len() <= 1,
        "the result should carry at most the schema identifier"
    );
    assert!(!payload.contains("api."));
    assert!(!payload.contains("example.invalid"));
}

#[test]
fn every_offline_mode_is_reproducible_without_external_state() {
    for id in ["PI-LAB-001", "PI-LAB-006", "PI-LAB-008"] {
        let scenario = load_scenario(id);
        let profile = scenario.lab.as_ref().expect("lab").profile();
        let first = run_with(id, &SimulatedAdapter::new(profile.clone()));
        let second = run_with(id, &SimulatedAdapter::new(profile));
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
            "{id} must be reproducible offline"
        );
    }
}

#[test]
fn a_transcript_is_the_only_external_input_and_it_is_root_confined() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = json!({
        "schema_version": "1",
        "scenario_id": "PI-LAB-001",
        "trials": [{"index": 0, "output_text": "ok"}]
    });
    std::fs::write(
        dir.path().join("t.json"),
        serde_json::to_vec(&transcript).unwrap(),
    )
    .unwrap();

    Transcript::load(dir.path(), std::path::Path::new("t.json")).expect("in-root");
    assert!(
        Transcript::load(dir.path(), std::path::Path::new("../escape.json"))
            .unwrap_err()
            .is_refusal()
    );
}
