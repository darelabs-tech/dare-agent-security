//! Cycle 015 adversarial parser fixtures.
//!
//! Every document under `adversarial-parser-fixtures/` is invalid by design.
//! This suite routes each one to the validator that owns its document kind and
//! proves it is refused *before* anything is evaluated — nothing here loads a
//! corpus for use, stages a trial, or reaches a verdict.
//!
//! The manifest names the document kind rather than the expected error,
//! deliberately. A fixture must not be able to tell the engine what to
//! conclude, including about itself; the assertion is only that it fails
//! closed.

use std::path::PathBuf;

use dare_identity_security::corpus::{
    builtin_corpus_root, validate_corpus_entry, validate_corpus_registry,
};
use dare_identity_security::error::IdentitySecurityError;
use dare_identity_security::model::IdentitySecurityScenario;
use dare_identity_security::replay::parse_trace;
use dare_identity_security::schema::validate_scenario_document;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostileManifest {
    schema_version: String,
    #[allow(dead_code)]
    title: String,
    #[allow(dead_code)]
    note: String,
    cases: Vec<HostileCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostileCase {
    id: String,
    kind: String,
    path: String,
    reason: String,
}

fn fixtures_root() -> PathBuf {
    builtin_corpus_root().join("adversarial-parser-fixtures")
}

fn manifest() -> HostileManifest {
    let raw = std::fs::read(fixtures_root().join("manifest.json")).expect("manifest readable");
    serde_json::from_slice(&raw).expect("manifest decodes")
}

fn document(path: &str) -> Value {
    let file = fixtures_root().join(path);
    let raw = std::fs::read(&file).unwrap_or_else(|err| panic!("{}: {err}", file.display()));
    serde_json::from_slice(&raw).expect("hostile fixture is still valid JSON")
}

/// Route one hostile document to the validator that owns its kind.
///
/// A scenario is checked the way the engine loads one: schema, typed decode,
/// then the structural rules the schema cannot express. Something that survives
/// the schema still has to survive the model.
fn refusal_for(case: &HostileCase, value: &Value) -> Result<(), IdentitySecurityError> {
    match case.kind.as_str() {
        "CORPUS_ENTRY" => validate_corpus_entry(value),
        "CORPUS_REGISTRY" => validate_corpus_registry(value),
        "TRACE" => parse_trace(
            &serde_json::to_vec(value).expect("serializes"),
            "hostile trace",
        )
        .map(|_| ()),
        "SCENARIO" => {
            validate_scenario_document(value)?;
            let scenario: IdentitySecurityScenario = serde_json::from_value(value.clone())?;
            scenario.validate()
        }
        other => panic!("{}: unknown fixture kind `{other}`", case.id),
    }
}

#[test]
fn the_manifest_covers_every_shipped_fixture() {
    let manifest = manifest();
    assert_eq!(manifest.schema_version, "1");
    assert!(
        manifest.cases.len() >= 50,
        "the threat model needs broad coverage, found {}",
        manifest.cases.len()
    );

    let mut listed: Vec<&str> = manifest
        .cases
        .iter()
        .map(|case| case.path.as_str())
        .collect();
    listed.sort_unstable();

    let mut on_disk: Vec<String> = std::fs::read_dir(fixtures_root())
        .expect("fixtures directory")
        .filter_map(|entry| {
            let name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            (name != "manifest.json").then_some(name)
        })
        .collect();
    on_disk.sort();

    assert_eq!(
        listed,
        on_disk.iter().map(String::as_str).collect::<Vec<_>>(),
        "an unlisted fixture would go untested"
    );
}

#[test]
fn every_hostile_fixture_fails_closed() {
    for case in manifest().cases {
        let value = document(&case.path);
        let result = refusal_for(&case, &value);
        assert!(
            result.is_err(),
            "{} was accepted but must fail closed: {}",
            case.id,
            case.reason
        );
    }
}

#[test]
fn a_refusal_is_never_a_security_verdict() {
    // Refusing to run is not evidence that an authority boundary was crossed.
    // No refusal message may read as a verdict about the target.
    for case in manifest().cases {
        let value = document(&case.path);
        let Err(error) = refusal_for(&case, &value) else {
            continue;
        };
        let text = error.to_string();
        for banned in ["PASS", "FAIL", "INCONCLUSIVE", "Verdict"] {
            assert!(!text.contains(banned), "{}: `{text}`", case.id);
        }
    }
}

#[test]
fn a_refusal_never_echoes_credential_shaped_content() {
    // The engine must be able to say *that* it refused without repeating what
    // it refused. An error message is a persistence surface like any other.
    for case in manifest().cases {
        let value = document(&case.path);
        let Err(error) = refusal_for(&case, &value) else {
            continue;
        };
        let text = error.to_string().to_ascii_lowercase();
        for marker in [
            "sk-live-",
            "eyjhbgci",
            "-----begin",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                !text.contains(marker),
                "{} echoed `{marker}` in `{text}`",
                case.id
            );
        }
    }
}

#[test]
fn no_hostile_fixture_is_reachable_through_the_shipped_registry() {
    // The corpus registry must list only documents that load. If a hostile
    // fixture ever appeared there, loading the corpus would fail — which is the
    // point, but this catches the mistake directly.
    let raw = std::fs::read(builtin_corpus_root().join("registry.json")).expect("registry");
    let registry: Value = serde_json::from_slice(&raw).expect("registry parses");
    let paths: Vec<&str> = registry["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .collect();

    for case in manifest().cases {
        assert!(
            !paths.iter().any(|path| path.ends_with(&case.path)),
            "{} is listed in the shipped registry",
            case.id
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.contains("adversarial-parser-fixtures")),
            "the hostile directory must never be a corpus family"
        );
    }
}

#[test]
fn the_shipped_corpus_still_loads_with_the_hostile_fixtures_present() {
    // The hostile tree sits inside the corpus root. Loading must ignore it
    // entirely rather than trip over it.
    let corpus = dare_identity_security::corpus::builtin_corpus().expect("corpus loads");
    assert_eq!(corpus.corpus_id, "identity-security-v1");
    assert!(corpus.entries.len() >= 24);
}

#[test]
fn an_oversized_document_is_refused_before_it_is_parsed() {
    // Generated here rather than shipped: writing a 128KB fixture to disk to
    // prove a size bound would be its own small absurdity.
    let raw = vec![b'a'; 200_000];
    let err = parse_trace(&raw, "oversized trace").expect_err("must be refused");
    assert!(err.is_refusal());
}
