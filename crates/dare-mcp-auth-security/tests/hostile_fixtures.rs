//! Every adversarial parser fixture must fail closed.
//!
//! Ninety documents, each isolating one hostile mutation against a valid
//! baseline. The suite asserts two things about each: that it is refused, and
//! that the refusal does not repeat what it refused.
//!
//! The second is easy to overlook and matters as much as the first. A refusal
//! message that quoted the smuggled token back would persist the credential it
//! was declining to store, and an error log is a persistence surface like any
//! other.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_mcp_auth_security::schema::{
    validate_corpus_entry, validate_corpus_registry, validate_scenario_document,
    validate_trace_document,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    document_kind: String,
    reason: String,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mcp-auth-security/v1/adversarial-parser-fixtures")
}

fn manifest() -> Manifest {
    let raw = std::fs::read(fixtures_dir().join("manifest.json")).expect("manifest readable");
    serde_json::from_slice(&raw).expect("manifest parses")
}

fn document(file: &str) -> serde_json::Value {
    let raw = std::fs::read(fixtures_dir().join(file))
        .unwrap_or_else(|err| panic!("{file} is readable: {err}"));
    serde_json::from_slice(&raw).unwrap_or_else(|err| panic!("{file} is valid JSON: {err}"))
}

/// Admit a document the way the engine actually would, by kind.
///
/// For a scenario that is three stages, not one: the document gate, the typed
/// decode, then the structural checks a schema cannot express. Testing only the
/// first stage would let a fixture the engine refuses look admitted here, which
/// is how a hostile case turns into false coverage.
fn admit(kind: &str, value: &serde_json::Value) -> dare_mcp_auth_security::Result<()> {
    match kind {
        "scenario" => {
            validate_scenario_document(value)?;
            let scenario: dare_mcp_auth_security::model::McpAuthScenario =
                serde_json::from_value(value.clone())?;
            scenario.validate()
        }
        "trace" => validate_trace_document(value),
        "corpus-entry" => {
            validate_corpus_entry(value)?;
            let entry: dare_mcp_auth_security::model::McpAuthCorpusEntry =
                serde_json::from_value(value.clone())?;
            dare_mcp_auth_security::corpus::validate_entry(&entry)
        }
        "corpus-registry" => {
            validate_corpus_registry(value)?;
            for entry in value["entries"].as_array().into_iter().flatten() {
                let path = entry["path"].as_str().unwrap_or_default();
                dare_mcp_auth_security::corpus::assert_root_confined(path)?;
            }
            Ok(())
        }
        other => panic!("unknown document kind {other}"),
    }
}

#[test]
fn the_manifest_covers_every_fixture_on_disk() {
    // A fixture nobody listed would run in no test, and a listed fixture with
    // no file would pass by absence.
    let listed: BTreeSet<String> = manifest().cases.into_iter().map(|case| case.file).collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "manifest.json")
        .collect();
    assert_eq!(on_disk, listed);
    assert!(listed.len() >= 60, "only {} hostile cases", listed.len());
}

#[test]
fn every_hostile_fixture_is_refused() {
    for case in manifest().cases {
        let value = document(&case.file);
        let result = admit(&case.document_kind, &value);
        assert!(
            result.is_err(),
            "{} was admitted; it should be refused because it {}",
            case.file,
            case.reason
        );
    }
}

#[test]
fn no_refusal_echoes_what_it_refused() {
    // Reporting the attack must not perform it.
    for case in manifest().cases {
        let value = document(&case.file);
        let Err(err) = admit(&case.document_kind, &value) else {
            continue;
        };
        let message = err.to_string();
        for marker in [
            "eyJhbGci",
            "sk-live-",
            "-----BEGIN",
            "ghp_",
            "xoxb-",
            "AKIAIOSFODNN7EXAMPLE",
            "ya29.",
            "example.invalid",
            "VERDICT",
            "/etc/passwd",
        ] {
            assert!(
                !message.contains(marker),
                "the refusal for {} echoed `{marker}`",
                case.file
            );
        }
    }
}

#[test]
fn no_refusal_reads_as_a_security_verdict() {
    // A refusal is a statement about the document, never about the security of
    // the scenario it declined to evaluate. An operator scanning stderr must
    // not find a word that looks like a result.
    for case in manifest().cases {
        let value = document(&case.file);
        let Err(err) = admit(&case.document_kind, &value) else {
            continue;
        };
        let message = err.to_string();
        for verdict in ["PASS", "FAIL", "INCONCLUSIVE"] {
            assert!(
                !message.contains(verdict),
                "the refusal for {} reads as the verdict {verdict}",
                case.file
            );
        }
    }
}

#[test]
fn every_manifest_entry_says_why_rather_than_what_the_error_will_be() {
    // A fixture that recorded its expected error would let the parser agree
    // with the fixture instead of judging it, which is the same failure as a
    // fixture declaring its own verdict.
    for case in manifest().cases {
        assert!(
            !case.reason.trim().is_empty(),
            "{} has no reason",
            case.file
        );
        for banned in ["expected_error", "Refusal(", "Schema(", "error code"] {
            assert!(
                !case.reason.contains(banned),
                "{} records an expected error rather than a reason",
                case.file
            );
        }
    }
}

#[test]
fn the_hostile_fixtures_are_not_corpus_vectors() {
    // They live under the corpus root and must be invisible to the loader. A
    // fixture that loaded as a vector would put a deliberately malformed
    // document into the corpus.
    let corpus = dare_mcp_auth_security::corpus::builtin_corpus().expect("corpus loads");
    let hostile: BTreeSet<String> = manifest()
        .cases
        .into_iter()
        .map(|case| case.file.replace(".json", ""))
        .collect();
    for entry in &corpus.entries {
        assert!(
            !hostile.contains(&entry.id),
            "{} loaded as a corpus vector",
            entry.id
        );
    }
}

#[test]
fn a_credential_field_is_refused_whatever_it_holds() {
    // The field is what is wrong. Admitting the empty case would leave it
    // available for the next author to fill in.
    for file in [
        "credential-field-access-token.json",
        "credential-field-empty-value.json",
        "credential-field-nested-deeply.json",
    ] {
        let value = document(file);
        assert!(validate_scenario_document(&value).is_err(), "{file}");
    }
}

#[test]
fn a_registry_path_that_could_escape_the_root_is_refused() {
    for file in [
        "registry-path-traversal.json",
        "registry-absolute-path.json",
        "registry-backslash-path.json",
        "registry-url-path.json",
    ] {
        let value = document(file);
        assert!(validate_corpus_registry(&value).is_err(), "{file}");
    }
}

#[test]
fn a_trace_cannot_claim_a_live_mode_or_production_evidence() {
    for file in [
        "trace-live-mode.json",
        "trace-claims-production-evidence.json",
    ] {
        let value = document(file);
        assert!(validate_trace_document(&value).is_err(), "{file}");
    }
}
