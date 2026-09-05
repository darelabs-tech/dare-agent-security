//! Cycle 013 — validator threat model.
//!
//! Scenario, corpus, registry and transcript documents are untrusted third-party
//! input. Every case in the committed hostile fixture must be refused, and no
//! fixture may execute anything.

use std::path::{Path, PathBuf};

use dare_prompt_injection::canonical::assert_safe_identifier;
use dare_prompt_injection::corpus::{
    assert_root_confined, load_corpus, validate_corpus_entry, validate_corpus_registry,
};
use dare_prompt_injection::model::PromptInjectionScenario;
use dare_prompt_injection::replay::Transcript;
use dare_prompt_injection::schema::{enforce_document_size, validate_scenario_document};
use dare_prompt_injection::trials::TrialPlan;
use serde_json::Value;

fn hostile_cases() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/prompt-injection/v1/adversarial-parser-fixtures/hostile-cases.json");
    let raw = std::fs::read(&path).expect("hostile fixture");
    serde_json::from_slice(&raw).expect("hostile fixture json")
}

fn cases(group: &str) -> Vec<(String, String, Value)> {
    hostile_cases()[group]
        .as_array()
        .unwrap_or_else(|| panic!("group {group} missing"))
        .iter()
        .map(|case| {
            (
                case["name"].as_str().unwrap_or_default().to_owned(),
                case["reason"].as_str().unwrap_or_default().to_owned(),
                case["document"].clone(),
            )
        })
        .collect()
}

/// A scenario document is refused if the schema layer rejects it, or if the
/// typed layer rejects it, or if the trial planner refuses its bounds.
fn scenario_is_refused(document: &Value) -> bool {
    if validate_scenario_document(document).is_err() {
        return true;
    }
    let Ok(scenario) = serde_json::from_value::<PromptInjectionScenario>(document.clone()) else {
        return true;
    };
    TrialPlan::from_scenario(&scenario).is_err()
}

#[test]
fn the_hostile_fixture_is_present_and_declares_its_intent() {
    let fixture = hostile_cases();
    assert_eq!(fixture["schema_version"], "1");
    assert_eq!(fixture["provenance"]["origin"], "DARE_SYNTHETIC");
    assert!(fixture["note"]
        .as_str()
        .unwrap_or_default()
        .contains("MUST be refused"));

    assert!(!cases("scenario_cases").is_empty());
    assert!(!cases("corpus_entry_cases").is_empty());
    assert!(!cases("registry_cases").is_empty());
    assert!(!cases("transcript_cases").is_empty());
}

#[test]
fn every_hostile_scenario_case_is_refused() {
    let cases = cases("scenario_cases");
    assert_eq!(cases.len(), 15, "hostile scenario coverage shrank");
    for (name, reason, document) in cases {
        assert!(
            scenario_is_refused(&document),
            "hostile scenario `{name}` was accepted ({reason})"
        );
    }
}

#[test]
fn every_hostile_corpus_entry_case_is_refused() {
    for (name, reason, document) in cases("corpus_entry_cases") {
        assert!(
            validate_corpus_entry(&document).is_err(),
            "hostile corpus entry `{name}` was accepted ({reason})"
        );
    }
}

#[test]
fn every_hostile_registry_case_is_refused() {
    for (name, reason, document) in cases("registry_cases") {
        assert!(
            validate_corpus_registry(&document).is_err(),
            "hostile registry `{name}` was accepted ({reason})"
        );
    }
}

#[test]
fn every_hostile_transcript_case_is_refused() {
    for (name, reason, document) in cases("transcript_cases") {
        assert!(
            Transcript::parse(document).is_err(),
            "hostile transcript `{name}` was accepted ({reason})"
        );
    }
}

#[test]
fn executable_fields_are_refused_at_any_depth() {
    let base = hostile_cases()["scenario_cases"][0]["document"].clone();
    for key in [
        "shell",
        "sh",
        "bash",
        "cmd",
        "command",
        "exec",
        "execute",
        "eval",
        "script",
        "callback",
        "hook",
        "plugin",
        "run",
        "entrypoint",
    ] {
        let mut document = base.clone();
        document.as_object_mut().unwrap().remove("shell");
        document[key] = Value::String("payload".to_owned());
        assert!(
            validate_scenario_document(&document).is_err(),
            "executable field `{key}` must be refused"
        );

        // Nested inside the objective as well.
        let mut nested = base.clone();
        nested.as_object_mut().unwrap().remove("shell");
        nested["objective"][key] = Value::String("payload".to_owned());
        assert!(
            validate_scenario_document(&nested).is_err(),
            "nested executable field `{key}` must be refused"
        );
    }
}

#[test]
fn credential_and_remote_fields_are_refused() {
    let base = hostile_cases()["scenario_cases"][0]["document"].clone();
    for key in [
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "private_key",
        "url",
        "endpoint",
        "host",
        "provider",
        "remote",
        "base_url",
        "webhook",
        "upstream",
    ] {
        let mut document = base.clone();
        document.as_object_mut().unwrap().remove("shell");
        document[key] = Value::String("value".to_owned());
        assert!(
            validate_scenario_document(&document).is_err(),
            "field `{key}` must be refused"
        );
    }
}

#[test]
fn hostile_unicode_identifiers_are_refused() {
    for hostile in [
        "PI-LAB-001\u{200b}",
        "PI\u{200d}-LAB-001",
        "PI-LAB-\u{202e}100",
        "PI-LAB-001\u{feff}",
        "PI-LAB-001\u{00a0}",
        "\u{0420}I-LAB-001",
    ] {
        assert!(
            assert_safe_identifier(hostile, "scenario id").is_err(),
            "hostile identifier {hostile:?} must be refused"
        );
    }
}

#[test]
fn path_traversal_is_refused_everywhere_paths_are_accepted() {
    for path in [
        "..",
        "../secrets.json",
        "direct/../../escape.json",
        "/etc/passwd",
        "\\\\server\\share",
        "C:/windows/system32",
        "https://example.invalid/x.json",
        "direct\\windows.json",
    ] {
        assert!(
            assert_root_confined(path).is_err(),
            "path {path} must be refused"
        );
    }
}

#[test]
fn oversized_documents_are_refused_before_parsing() {
    let oversized = vec![b'x'; 65_537];
    for label in ["scenario", "corpus entry", "transcript"] {
        let err = enforce_document_size(&oversized, label).unwrap_err();
        assert!(err.is_refusal(), "{label} size guard must refuse");
    }
}

#[test]
fn a_corpus_whose_file_id_disagrees_with_the_registry_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("direct")).unwrap();

    // A valid entry, listed under a different id.
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/prompt-injection/v1/direct/direct-goal-override-001.json");
    let entry = std::fs::read(&source).expect("source entry");
    std::fs::write(root.join("direct/direct-goal-override-001.json"), &entry).unwrap();

    let registry = serde_json::json!({
        "schema_version": "1",
        "corpus_id": "prompt-injection-substituted",
        "version": "1.0.0",
        "entries": [{
            "id": "direct-role-confusion-001",
            "class": "DIRECT_ATTACK",
            "path": "direct/direct-goal-override-001.json"
        }]
    });
    std::fs::write(
        root.join("registry.json"),
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();

    let err = load_corpus(root).unwrap_err();
    assert!(
        err.is_refusal(),
        "id substitution must fail closed, got {err}"
    );
}

#[test]
fn a_corpus_with_a_mismatched_pinned_digest_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("direct")).unwrap();

    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/prompt-injection/v1/direct/direct-goal-override-001.json");
    std::fs::copy(&source, root.join("direct/direct-goal-override-001.json")).unwrap();

    let registry = serde_json::json!({
        "schema_version": "1",
        "corpus_id": "prompt-injection-pinned",
        "version": "1.0.0",
        "entries": [{
            "id": "direct-goal-override-001",
            "class": "DIRECT_ATTACK",
            "path": "direct/direct-goal-override-001.json",
            "digest": format!("sha256:{}", "0".repeat(64))
        }]
    });
    std::fs::write(
        root.join("registry.json"),
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();

    let err = load_corpus(root).unwrap_err();
    assert!(err.is_refusal(), "digest mismatch must fail closed");
}

#[test]
fn a_corpus_with_a_missing_file_is_refused_not_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let registry = serde_json::json!({
        "schema_version": "1",
        "corpus_id": "prompt-injection-missing",
        "version": "1.0.0",
        "entries": [{
            "id": "direct-goal-override-001",
            "class": "DIRECT_ATTACK",
            "path": "direct/direct-goal-override-001.json"
        }]
    });
    std::fs::write(
        root.join("registry.json"),
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();

    assert!(
        load_corpus(root).is_err(),
        "a missing vector must fail the load, never be skipped"
    );
}

#[test]
fn the_hostile_fixture_contains_no_executable_payload() {
    // The fixture describes hostile documents; it must not itself be able to run
    // anything. Every case is inert JSON data.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/prompt-injection/v1/adversarial-parser-fixtures/hostile-cases.json");
    assert!(Path::new(&path).is_file());
    let raw = std::fs::read_to_string(&path).expect("fixture");

    // It is parseable JSON and nothing more.
    let _: Value = serde_json::from_str(&raw).expect("inert json");
    assert!(!raw.contains("#!/"), "fixture must not carry a shebang");

    // The fixture is deliberately excluded from the loadable corpus registry.
    let corpus = dare_prompt_injection::corpus::builtin_corpus().expect("corpus");
    assert!(
        !corpus
            .entries
            .iter()
            .any(|entry| entry.id.starts_with("hostile")),
        "hostile fixtures must never be listed in the loadable registry"
    );
}

#[test]
fn the_committed_corpus_still_loads_after_all_of_this() {
    // The hostile directory sits beside the real corpus and does not break it.
    let corpus = dare_prompt_injection::corpus::builtin_corpus().expect("corpus loads");
    assert_eq!(corpus.entries.len(), 16);
}
