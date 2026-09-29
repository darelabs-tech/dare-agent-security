//! Bundle detection, input binding and the evidence index (tasks 013–017).
use std::{
    fs,
    path::{Path, PathBuf},
};

use dare_attack_path::{
    bundle::{load_bundle, RunData},
    load, AttackPathError, EngineSlug, Refusal,
};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bundles")
        .join(name)
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A private, editable copy of a fixture bundle.
fn staged(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    copy_dir(&fixture(name), &path);
    (dir, path)
}

fn edit_json(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    edit(&mut value);
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn refusal(result: Result<impl std::fmt::Debug, AttackPathError>) -> Refusal {
    match result {
        Err(AttackPathError::Refused(r)) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

const ALL: [(&str, EngineSlug); 12] = [
    ("tool", EngineSlug::Tool),
    ("identity", EngineSlug::Identity),
    ("memory", EngineSlug::Memory),
    ("rag", EngineSlug::Rag),
    ("mcp", EngineSlug::McpAuth),
    ("sc", EngineSlug::SupplyChain),
    ("static-sc", EngineSlug::SupplyChain),
    ("a2a", EngineSlug::A2a),
    ("static-a2a", EngineSlug::A2a),
    ("pi", EngineSlug::PromptInjection),
    ("mt", EngineSlug::MultiTurn),
    ("remote", EngineSlug::Remote),
];

#[test]
fn every_fixture_bundle_binds() {
    for (name, engine) in ALL {
        let bundle = load_bundle(0, &fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(bundle.engine, engine, "{name}");
        assert_eq!(bundle.run.as_str().len(), 12);
        assert!(bundle.result_digest.starts_with("sha256:"));
        assert!(!bundle.evidence.records().is_empty(), "{name}");
        let pinned = !bundle.input_digests.is_empty();
        assert!(
            pinned || engine == EngineSlug::Remote,
            "{name} pins no input"
        );
        assert_eq!(bundle.dynamic_authorized, engine == EngineSlug::Remote);
    }
}

#[test]
fn static_bundles_verify_each_document_and_the_rebuilt_evidence() {
    let a2a = load_bundle(0, &fixture("static-a2a")).unwrap();
    assert_eq!(a2a.mode, "STATIC");
    assert!(!a2a.synthetic);
    for name in ["delegation.json", "peers.json", "trace.json", "policy.json"] {
        assert!(
            a2a.verified_inputs.contains(&format!("document {name}")),
            "{:?}",
            a2a.verified_inputs
        );
    }
    let RunData::A2a { evidence, .. } = &a2a.data else {
        panic!()
    };
    assert!(!evidence.delegation_chains.is_empty());
    let sc = load_bundle(0, &fixture("static-sc")).unwrap();
    assert!(sc
        .verified_inputs
        .contains(&"document app.cdx.json".to_owned()));
    let RunData::SupplyChain { evidence, .. } = &sc.data else {
        panic!()
    };
    assert_eq!(evidence.components.len(), 2);
}

#[test]
fn detection_needs_exactly_one_known_result() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        refusal(load_bundle(4, empty.path())),
        Refusal::UnknownBundle { index: 4 }
    );
    let (_keep, both) = staged("tool");
    fs::copy(
        fixture("rag").join("rag-security-result.json"),
        both.join("rag-security-result.json"),
    )
    .unwrap();
    assert_eq!(
        refusal(load_bundle(1, &both)),
        Refusal::UnknownBundle { index: 1 }
    );
}

#[test]
fn a_missing_scenario_is_refused_for_every_scenario_engine() {
    for name in ["tool", "identity", "memory", "rag", "mcp", "static-sc"] {
        let (_keep, dir) = staged(name);
        fs::remove_file(dir.join("inputs/scenario.json")).unwrap();
        assert_eq!(
            refusal(load_bundle(2, &dir)),
            Refusal::MissingInput {
                index: 2,
                input: "scenario"
            },
            "{name}"
        );
    }
    // The static A2A scenario keeps a corpus id, so without the file the
    // built-in scenario of that id is rebuilt, and it is not the one the
    // engine judged in static mode.
    let (_keep, dir) = staged("static-a2a");
    fs::remove_file(dir.join("inputs/scenario.json")).unwrap();
    assert_eq!(
        refusal(load_bundle(2, &dir)),
        Refusal::DigestMismatch {
            index: 2,
            input: "scenario"
        }
    );
}

/// One innocuous string field per scenario engine: still schema-valid, but
/// no longer the scenario the engine judged.
#[test]
fn an_edited_scenario_no_longer_binds() {
    let edits: [(&str, &str); 5] = [
        ("tool", "/title"),
        ("identity", "/title"),
        ("memory", "/title"),
        ("rag", "/title"),
        ("mcp", "/title"),
    ];
    for (name, pointer) in edits {
        let (_keep, dir) = staged(name);
        edit_json(&dir.join("inputs/scenario.json"), |value| {
            let field = value
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("{name} has no {pointer}"));
            *field = Value::String(format!("{} (edited)", field.as_str().unwrap_or("x")));
        });
        assert_eq!(
            refusal(load_bundle(0, &dir)),
            Refusal::DigestMismatch {
                index: 0,
                input: "scenario"
            },
            "{name}"
        );
    }
}

#[test]
fn an_edited_pinned_sub_document_names_itself() {
    // Tool: edit only the surface, keep the scenario digest honest by
    // editing the result instead, so the surface check is what fails.
    let (_keep, dir) = staged("tool");
    edit_json(&dir.join("tool-security-result.json"), |value| {
        value["surface_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::DigestMismatch {
            index: 0,
            input: "tool surface"
        }
    );
    let (_keep, dir) = staged("memory");
    edit_json(&dir.join("memory-security-result.json"), |value| {
        value["store_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::DigestMismatch {
            index: 0,
            input: "memory store"
        }
    );
}

fn flip_one_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let at = bytes.iter().position(|b| b.is_ascii_lowercase()).unwrap();
    bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
    fs::write(path, bytes).unwrap();
}

#[test]
fn a_one_byte_change_to_a_static_document_is_refused() {
    for (name, file) in [
        ("static-a2a", "inputs/evidence/delegation.json"),
        ("static-a2a", "inputs/evidence/trace.json"),
        ("static-sc", "inputs/evidence/app.cdx.json"),
    ] {
        let (_keep, dir) = staged(name);
        flip_one_byte(&dir.join(file));
        assert_eq!(
            refusal(load_bundle(0, &dir)),
            Refusal::DigestMismatch {
                index: 0,
                input: "evidence document"
            },
            "{name} {file}"
        );
    }
}

#[test]
fn a_changed_manifest_changes_the_rebuilt_evidence_and_is_refused() {
    // The manifest has no per-file digest in the 019 result (observation
    // O-3); `evidence_digest` is its only pin, and it holds.
    let (_keep, dir) = staged("static-sc");
    edit_json(&dir.join("inputs/evidence/manifest.json"), |value| {
        value["manifest_id"] = Value::String("another-deployment".into());
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::DigestMismatch {
            index: 0,
            input: "supply-chain evidence"
        }
    );
}

#[test]
fn simulated_supply_chain_and_a2a_runs_are_rebuilt_through_the_engine() {
    for (name, input) in [("sc", "supply-chain evidence"), ("a2a", "a2a evidence")] {
        let (_keep, dir) = staged(name);
        let result = if name == "sc" {
            "supply-chain-security-result.json"
        } else {
            "a2a-result.json"
        };
        edit_json(&dir.join(result), |value| {
            value["evidence_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
        });
        assert_eq!(
            refusal(load_bundle(0, &dir)),
            Refusal::DigestMismatch { index: 0, input },
            "{name}"
        );
    }
}

#[test]
fn a_multi_turn_transcript_must_match_its_result() {
    let (_keep, dir) = staged("mt");
    edit_json(&dir.join("multi-turn-conversations.json"), |value| {
        let turn = value
            .pointer_mut("/conversations/0/state/turns/0/chain_digest")
            .expect("a turn");
        let text = turn.as_str().unwrap().to_owned();
        let flipped = if text.ends_with('0') { "1" } else { "0" };
        *turn = Value::String(format!("{}{flipped}", &text[..text.len() - 1]));
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::DigestMismatch {
            index: 0,
            input: "conversations"
        }
    );
}

#[test]
fn a_remote_result_must_match_the_022_schema() {
    let (_keep, dir) = staged("remote");
    edit_json(&dir.join("remote-result.json"), |value| {
        value["origin"] = Value::String("http://plain.example".into());
    });
    assert!(matches!(
        refusal(load_bundle(0, &dir)),
        Refusal::InvalidDocument { file: "result", .. }
    ));
}

#[test]
fn the_evidence_index_validates_every_record_and_every_cited_id() {
    let (_keep, dir) = staged("tool");
    edit_json(&dir.join("tool-security-evidence.json"), |value| {
        value[0]["verdict"] = Value::String("PASSED".into());
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::InvalidEvidence {
            index: 0,
            record: 0
        }
    );
    let (_keep, dir) = staged("tool");
    edit_json(&dir.join("tool-security-result.json"), |value| {
        value["evidence_ids"][0] = Value::String("urn:dare:tool-security:evidence:absent".into());
    });
    assert_eq!(
        refusal(load_bundle(0, &dir)),
        Refusal::UnknownEvidenceId {
            index: 0,
            position: 0
        }
    );
    // The property key differs by engine; both forms are read.
    let tool = load_bundle(0, &fixture("tool")).unwrap();
    assert!(tool
        .evidence
        .records()
        .iter()
        .all(|r| r.property.starts_with("AGENT.TOOL.")));
    let a2a = load_bundle(0, &fixture("a2a")).unwrap();
    assert!(a2a
        .evidence
        .records()
        .iter()
        .all(|r| r.property.starts_with("AGENT.A2A.")));
    let remote = load_bundle(0, &fixture("remote")).unwrap();
    assert!(remote.evidence.records().iter().all(|r| r.remote));
}

/// Parity (task-013): for every scenario file the engines ship, this crate's
/// loader accepts exactly what the engine's own load sequence accepts (the
/// CLI's schema check, typed decode and `validate()`), and for an accepted
/// scenario the engine's own `bind` gives the digest this crate compares.
#[test]
fn the_loaders_match_the_engines_on_every_shipped_scenario() {
    type Loader = fn(&dare_attack_path::admit::AdmittedDir) -> Result<String, AttackPathError>;
    type Engine = fn(&[u8]) -> Option<String>;
    macro_rules! engine_side {
        ($krate:ident, $ty:ty, $validate:expr) => {
            |raw: &[u8]| {
                let value: Value = serde_json::from_slice(raw).ok()?;
                $krate::schema::validate_scenario_document(&value).ok()?;
                let scenario: $ty = serde_json::from_value(value).ok()?;
                let validate: fn(&$ty) -> bool = $validate;
                validate(&scenario)
                    .then(|| $krate::canonical::bind(&scenario).unwrap().scenario_digest)
            }
        };
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sets: [(&str, Loader, Engine); 5] = [
        (
            "fixtures/tool-security/scenarios",
            |d| {
                Ok(
                    dare_tool_security::canonical::scenario_digest(&load::load_tool(
                        d,
                        load::SCENARIO_FILE,
                    )?)
                    .unwrap(),
                )
            },
            engine_side!(
                dare_tool_security,
                dare_tool_security::model::ToolSecurityScenario,
                |_| true
            ),
        ),
        (
            "crates/dare-identity-security/tests/fixtures/scenarios",
            |d| {
                Ok(
                    dare_identity_security::canonical::digest(&load::load_identity(
                        d,
                        load::SCENARIO_FILE,
                    )?)
                    .unwrap(),
                )
            },
            engine_side!(
                dare_identity_security,
                dare_identity_security::model::IdentitySecurityScenario,
                |s| s.validate().is_ok()
            ),
        ),
        (
            "crates/dare-memory-security/tests/fixtures/scenarios",
            |d| {
                Ok(dare_memory_security::canonical::digest(&load::load_memory(
                    d,
                    load::SCENARIO_FILE,
                )?)
                .unwrap())
            },
            engine_side!(
                dare_memory_security,
                dare_memory_security::model::MemorySecurityScenario,
                |s| s.validate().is_ok()
            ),
        ),
        (
            "crates/dare-rag-security/tests/fixtures/scenarios",
            |d| {
                Ok(
                    dare_rag_security::canonical::digest(&load::load_rag(d, load::SCENARIO_FILE)?)
                        .unwrap(),
                )
            },
            engine_side!(
                dare_rag_security,
                dare_rag_security::model::RagSecurityScenario,
                |s| s.validate().is_ok()
            ),
        ),
        (
            "crates/dare-mcp-auth-security/tests/fixtures/scenarios",
            |d| {
                Ok(
                    dare_mcp_auth_security::canonical::digest(&load::load_mcp_auth(
                        d,
                        load::SCENARIO_FILE,
                    )?)
                    .unwrap(),
                )
            },
            engine_side!(
                dare_mcp_auth_security,
                dare_mcp_auth_security::model::McpAuthScenario,
                |s| s.validate().is_ok()
            ),
        ),
    ];
    let (mut accepted, mut refused) = (0, 0);
    for (dir, ours, engine) in sets {
        let mut files: Vec<_> = fs::read_dir(root.join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for file in files {
            let raw = fs::read(&file).unwrap();
            let staging = tempfile::tempdir().unwrap();
            fs::create_dir_all(staging.path().join("inputs")).unwrap();
            fs::write(staging.path().join("inputs/scenario.json"), &raw).unwrap();
            let admitted = dare_attack_path::admit::admit_dir(0, staging.path()).unwrap();
            match (ours(&admitted), engine(&raw)) {
                (Ok(mine), Some(theirs)) => {
                    assert_eq!(mine, theirs, "{}", file.display());
                    accepted += 1;
                }
                (Err(error), None) => {
                    assert!(error.is_refusal(), "{}", file.display());
                    refused += 1;
                }
                (mine, theirs) => panic!("{}: ours {mine:?}, engine {theirs:?}", file.display()),
            }
        }
    }
    assert!(accepted >= 90, "{accepted} accepted, {refused} refused");
}

#[test]
fn a_runtime_telemetry_bundle_binds_its_policy_by_digest() {
    // Cycle 025: the policy is bound only when its canonical digest is the one
    // the result recorded.
    let bundle = load_bundle(0, &fixture("rt")).unwrap();
    assert_eq!(bundle.engine, EngineSlug::RuntimeTelemetry);
    assert_eq!(bundle.verified_inputs, ["runtime policy"]);
    assert!(matches!(
        bundle.data,
        RunData::RuntimeTelemetry {
            policy: Some(_),
            ..
        }
    ));
    // Key order does not change the canonical digest.
    let (_tmp, path) = staged("rt");
    let policy = path.join("inputs/policy.json");
    let value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(load_bundle(0, &path).is_ok());
    // An edited policy is refused.
    edit_json(&policy, |p| {
        p["agents"][0]["allowed_tools"][0] = "anything".into()
    });
    assert!(matches!(
        refusal(load_bundle(0, &path)),
        Refusal::DigestMismatch { .. }
    ));
    // A policy outside its schema is refused before its digest is compared.
    edit_json(&policy, |p| p["extra"] = true.into());
    assert!(matches!(
        refusal(load_bundle(0, &path)),
        Refusal::InvalidDocument { .. }
    ));
    // Without the policy the run binds result-only and projects nothing.
    fs::remove_file(&policy).unwrap();
    let bundle = load_bundle(0, &path).unwrap();
    let facts = dare_attack_path::project::project(&bundle).unwrap();
    assert!(facts.edges.is_empty());
    assert_eq!(
        facts.unprojected.get("RUNTIME_TELEMETRY_RESULT_ONLY"),
        Some(&1)
    );
    // A result outside its schema is refused.
    let (_tmp2, path) = staged("rt");
    edit_json(&path.join("runtime-telemetry-result.json"), |r| {
        r["verdict"] = "MAYBE".into()
    });
    assert!(matches!(
        refusal(load_bundle(0, &path)),
        Refusal::InvalidDocument { .. }
    ));
}
