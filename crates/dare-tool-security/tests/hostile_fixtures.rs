//! Cycle 014 adversarial parser fixtures.
//!
//! Every document under `adversarial-parser-fixtures/` is invalid by design.
//! This suite routes each one to the validator that owns its document kind and
//! proves it is refused *before* anything executes — nothing here loads a
//! corpus for use, opens a tool, or runs a trial.
//!
//! The manifest names the kind rather than the expected error, deliberately. A
//! fixture must not be able to tell the engine what to conclude, including
//! about itself; the assertion is only that it fails closed.

use std::path::{Path, PathBuf};

use dare_tool_security::corpus::{
    builtin_corpus_root, validate_corpus_entry, validate_corpus_registry,
};
use dare_tool_security::error::ToolSecurityError;
use dare_tool_security::replay::ToolTrace;
use dare_tool_security::schema::{
    assert_no_hostile_fields, validate_policy_document, validate_scenario_document,
    validate_tool_surface_document,
};
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
/// A `CORPUS_REGISTRY` case is checked twice: once as a document, and once by
/// actually attempting to load a corpus with it, so a path that survives static
/// validation is still refused before a file is opened.
fn refusal_for(case: &HostileCase, value: &Value) -> Result<(), ToolSecurityError> {
    match case.kind.as_str() {
        "CORPUS_ENTRY" => validate_corpus_entry(value),
        "CORPUS_REGISTRY" => validate_corpus_registry(value),
        "SCENARIO" => validate_scenario_document(value),
        "TOOL_SURFACE" => validate_tool_surface_document(value),
        "POLICY" => validate_policy_document(value),
        "TRACE" => ToolTrace::parse(value.clone()).map(|_| ()),
        other => panic!("{}: unknown fixture kind `{other}`", case.id),
    }
}

#[test]
fn the_manifest_covers_every_shipped_fixture() {
    let manifest = manifest();
    assert_eq!(manifest.schema_version, "1");
    assert!(
        manifest.cases.len() >= 30,
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
    for path in &paths {
        assert!(
            !path.contains("adversarial-parser-fixtures"),
            "{path} must not be listed in the corpus registry"
        );
    }
    dare_tool_security::corpus::builtin_corpus().expect("the shipped corpus still loads");
}

#[test]
fn executable_and_remote_fields_are_refused_at_any_depth() {
    // Named explicitly rather than only in aggregate: these are the cases that
    // would turn a data file into an execution path.
    for id in [
        "executable-shell-field",
        "executable-script-field",
        "executable-eval-field-nested",
        "executable-callback-field",
        "remote-endpoint-field",
        "remote-mcp-server-field",
    ] {
        let case = case_named(id);
        let value = document(&case.path);
        let err = assert_no_hostile_fields(&value, "hostile fixture")
            .expect_err("the sweep itself must refuse this");
        assert!(err.is_refusal(), "{id}: {err}");
    }
}

#[test]
fn expected_verdict_smuggling_is_refused_at_any_depth() {
    for id in [
        "expected-verdict-smuggling",
        "should-fail-smuggling",
        "nested-verdict-smuggling",
    ] {
        let case = case_named(id);
        let err = assert_no_hostile_fields(&document(&case.path), "hostile fixture")
            .expect_err("a fixture must never carry the verdict");
        assert!(err.is_refusal());
        assert!(
            err.to_string().contains("verdict"),
            "the refusal should name the reason: {err}"
        );
    }
}

#[test]
fn hostile_unicode_and_log_injection_text_is_refused() {
    for id in [
        "hostile-unicode-identifier",
        "zero-width-identifier",
        "log-injection-title",
        "carriage-return-payload",
    ] {
        let case = case_named(id);
        let value = document(&case.path);
        assert!(
            validate_corpus_entry(&value).is_err(),
            "{id} must be refused: {}",
            case.reason
        );
    }

    // The direction-override and control-character sweep is what catches the
    // text cases, and it must catch them on its own.
    for id in [
        "hostile-unicode-identifier",
        "log-injection-title",
        "carriage-return-payload",
    ] {
        let case = case_named(id);
        let err = assert_no_hostile_fields(&document(&case.path), "hostile fixture")
            .expect_err("hostile text must be refused");
        assert!(err.is_refusal(), "{id}: {err}");
    }
}

#[test]
fn a_traversal_or_absolute_corpus_path_is_refused_before_a_file_is_opened() {
    for id in [
        "path-traversal-registry",
        "absolute-path-registry",
        "url-path-registry",
    ] {
        let case = case_named(id);
        let value = document(&case.path);
        assert!(
            validate_corpus_registry(&value).is_err(),
            "{id} must be refused: {}",
            case.reason
        );

        // Two independent gates, and each must hold on its own: the schema's
        // path pattern, and the root-confinement check the loader relies on.
        let path = value["entries"][0]["path"].as_str().expect("a path");
        let err = dare_tool_security::corpus::assert_root_confined(path)
            .expect_err("root confinement must refuse this path on its own");
        assert!(err.is_refusal(), "{id}: {err}");
    }
}

#[test]
fn a_substituted_corpus_digest_is_refused_by_the_loader() {
    // Static validation cannot see this one: the registry is well-formed and
    // the file exists. Only the loader, comparing the canonical digest, can
    // catch a swapped fixture — so this exercises the loader itself.
    let root = std::env::temp_dir().join("dare-tool-security-digest-substitution");
    let _ = std::fs::remove_dir_all(&root);
    copy_tree(&builtin_corpus_root(), &root);

    let registry_path = root.join("registry.json");
    let raw = std::fs::read(&registry_path).expect("registry");
    let mut registry: Value = serde_json::from_slice(&raw).expect("registry parses");
    registry["entries"][0]["digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    std::fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&registry).expect("re-encode"),
    )
    .expect("write registry");

    let err = dare_tool_security::corpus::load_corpus(&root)
        .expect_err("a substituted digest must be refused");
    assert!(err.is_refusal(), "{err}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_trace_cannot_claim_a_dispatch_or_hide_a_remote_field() {
    for id in ["trace-claims-dispatch", "trace-remote-exfiltration-field"] {
        let case = case_named(id);
        let err = ToolTrace::parse(document(&case.path)).expect_err("the trace must be refused");
        assert!(
            err.is_refusal() || matches!(err, ToolSecurityError::Schema(_)),
            "{id}: {err}"
        );
    }
}

#[test]
fn cross_field_contradictions_are_refused() {
    for id in [
        "attack-declared-compliant",
        "benign-control-noncompliant",
        "poisoning-class-misuse-family",
        "missing-tools-precondition",
    ] {
        let case = case_named(id);
        assert!(
            validate_corpus_entry(&document(&case.path)).is_err(),
            "{id} must be refused: {}",
            case.reason
        );
    }
}

#[test]
fn an_oversized_document_is_refused_before_it_is_parsed() {
    // Generated here rather than shipped: the point is the byte bound, and a
    // 128 KiB fixture in the repository would prove nothing extra.
    let oversized = vec![b'x'; dare_tool_security::schema::MAX_DOCUMENT_BYTES + 1];
    let err = dare_tool_security::schema::enforce_document_size(&oversized, "corpus entry")
        .expect_err("an oversized document must be refused");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

fn case_named(id: &str) -> HostileCase {
    manifest()
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("manifest has no case `{id}`"))
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("create destination");
    for entry in std::fs::read_dir(source).expect("read source") {
        let entry = entry.expect("entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}
