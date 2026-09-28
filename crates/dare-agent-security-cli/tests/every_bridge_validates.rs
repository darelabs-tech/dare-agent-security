//! Cycle 022 O-09: every evidence record every engine bridge emits is valid
//! Cycle 001 evidence, for every verdict the engine's own lab can produce.
//!
//! The test runs the built binary over each engine's whole lab corpus in its
//! default offline mode, reads the evidence artifact, and validates every
//! record with `dare_security_evidence::validate`. It then checks that the
//! verdicts the three corrected bridges (A2A, MCP Auth, supply chain) are
//! known to produce undecided records for were actually exercised, so the test
//! cannot pass by reading only PASS and FAIL records.
//!
//! Nothing here reaches the network: every command is offline by construction.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use dare_security_evidence::{validate, SecurityEvidence, Verdict};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

struct Engine {
    name: &'static str,
    subcommand: &'static str,
    evidence_file: &'static str,
    ids: Vec<String>,
}

fn engines() -> Vec<Engine> {
    vec![
        Engine {
            name: "prompt-injection",
            subcommand: "prompt-injection",
            evidence_file: "prompt-injection-evidence.json",
            ids: scenario_ids("fixtures/prompt-injection/scenarios"),
        },
        Engine {
            name: "tool-security",
            subcommand: "tool-security",
            evidence_file: "tool-security-evidence.json",
            ids: scenario_ids("fixtures/tool-security/scenarios"),
        },
        Engine {
            name: "identity-security",
            subcommand: "identity-security",
            evidence_file: "identity-security-evidence.json",
            ids: scenario_ids("crates/dare-identity-security/tests/fixtures/scenarios"),
        },
        Engine {
            name: "memory-security",
            subcommand: "memory-security",
            evidence_file: "memory-security-evidence.json",
            ids: scenario_ids("crates/dare-memory-security/tests/fixtures/scenarios"),
        },
        Engine {
            name: "rag-security",
            subcommand: "rag-security",
            evidence_file: "rag-security-evidence.json",
            ids: scenario_ids("crates/dare-rag-security/tests/fixtures/scenarios"),
        },
        Engine {
            name: "mcp-auth-security",
            subcommand: "mcp-auth-security",
            evidence_file: "mcp-auth-security-evidence.json",
            ids: scenario_ids("crates/dare-mcp-auth-security/tests/fixtures/scenarios"),
        },
        Engine {
            name: "supply-chain",
            subcommand: "supply-chain",
            evidence_file: "supply-chain-security-evidence.json",
            ids: dare_supply_chain_security::corpus::corpus()
                .into_iter()
                .map(|entry| entry.id.to_owned())
                .collect(),
        },
        Engine {
            name: "a2a",
            subcommand: "a2a",
            evidence_file: "a2a-evidence.json",
            ids: dare_a2a_security::corpus::corpus()
                .into_iter()
                .map(|entry| entry.id.to_owned())
                .collect(),
        },
        Engine {
            name: "multi-turn",
            subcommand: "multi-turn",
            evidence_file: "multi-turn-evidence.json",
            ids: dare_multi_turn_security::corpus::CORPUS
                .iter()
                .map(|entry| entry.id.to_owned())
                .collect(),
        },
    ]
}

/// The built-in scenario ids a CLI resolves from its scenarios directory.
///
/// Ids are uppercase on the command line; some directories store the files in
/// lowercase and the CLI lowercases the id to find them.
fn scenario_ids(relative_dir: &str) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(repo_root().join(relative_dir))
        .expect("scenarios directory")
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension()? == "json")
                .then(|| path.file_stem()?.to_str().map(str::to_ascii_uppercase))
                .flatten()
        })
        .collect();
    ids.sort();
    ids
}

/// The records in an evidence artifact, whichever wrapper the engine uses.
fn records(raw: &[u8]) -> Vec<SecurityEvidence> {
    let value: serde_json::Value = serde_json::from_slice(raw).expect("evidence is JSON");
    let list = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(mut map) => {
            let key = ["records", "evidence", "items"]
                .into_iter()
                .find(|key| map.get(*key).is_some_and(serde_json::Value::is_array))
                .unwrap_or_else(|| panic!("no record array in {:?}", map.keys()));
            match map.remove(key) {
                Some(serde_json::Value::Array(items)) => items,
                _ => unreachable!("checked above"),
            }
        }
        other => panic!("unexpected evidence shape: {other}"),
    };
    list.into_iter()
        .map(|item| serde_json::from_value(item).expect("record deserializes"))
        .collect()
}

fn run(engine: &Engine, id: &str, output_dir: &Path) -> Option<Vec<SecurityEvidence>> {
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir).expect("output dir");
    let output = Command::new(binary())
        .current_dir(repo_root())
        .args([
            "validate",
            engine.subcommand,
            "--scenario",
            id,
            "--output-dir",
        ])
        .arg(output_dir)
        .output()
        .expect("binary runs");
    // A run that writes nothing has no record to validate: exit 3 is a
    // refusal (the REFUSAL class of a lab), and exit 1 is a run stopped before
    // any artifact was admitted (for example an output budget a GAP entry
    // lowers on purpose). Any other exit without evidence is a defect.
    let evidence = output_dir.join(engine.evidence_file);
    if !evidence.exists() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let refused = output.status.code() == Some(3);
        let budget_stop = output.status.code() == Some(1) && stderr.contains("output budget");
        assert!(
            refused || budget_stop,
            "{} {id}: no evidence written with exit {:?}: {stderr}",
            engine.name,
            output.status.code(),
        );
        return None;
    }
    Some(records(
        &std::fs::read(&evidence).expect("evidence readable"),
    ))
}

#[test]
fn every_record_of_every_bridge_is_valid_cycle_001_evidence() {
    let scratch = std::env::temp_dir().join("dare-every-bridge-validates");
    let mut covered: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    let mut total = 0usize;

    for engine in engines() {
        assert!(
            !engine.ids.is_empty(),
            "{} has an empty corpus",
            engine.name
        );
        for id in &engine.ids {
            let dir = scratch.join(engine.name).join(id);
            let Some(records) = run(&engine, id, &dir) else {
                continue;
            };
            for record in records {
                validate(&record).unwrap_or_else(|error| {
                    panic!(
                        "{} {id}: record {} ({:?}) is not valid Cycle 001 evidence: {error}",
                        engine.name, record.id, record.verdict
                    )
                });
                if matches!(record.verdict, Verdict::Inconclusive | Verdict::Error) {
                    assert_eq!(
                        record.observed.decision, None,
                        "{} {id}: an undecided record carries a decision",
                        engine.name
                    );
                }
                covered
                    .entry(engine.name)
                    .or_default()
                    .insert(verdict_name(record.verdict));
                total += 1;
            }
        }
    }

    // Every bridge emitted records, and each one decided both ways.
    for engine in engines() {
        let seen = covered
            .get(engine.name)
            .unwrap_or_else(|| panic!("{} emitted no evidence at all", engine.name));
        assert!(
            seen.contains("PASS") && seen.contains("FAIL"),
            "{} did not produce both PASS and FAIL records: {seen:?}",
            engine.name
        );
    }
    // The three corrected bridges must have been exercised on an undecided
    // record, or this test would not cover the defect it exists for.
    for name in ["a2a", "mcp-auth-security", "supply-chain"] {
        let seen = &covered[name];
        assert!(
            seen.contains("INCONCLUSIVE") || seen.contains("ERROR"),
            "{name} produced no undecided record: {seen:?}"
        );
    }
    let cells: usize = covered.values().map(BTreeSet::len).sum();
    eprintln!("validated {total} records; bridge x verdict cells covered: {cells}; {covered:?}");
}

#[test]
fn every_engine_bridge_validates_before_returning() {
    // The fail-closed half of DESIGN §4.8: a record that fails Cycle 001
    // validation is never returned. Each bridge must call the validator and
    // propagate its error with `?`; the validator itself is tested in
    // `dare-security-evidence` (e.g. `contradictory_pass_is_rejected`).
    let root = repo_root().join("crates");
    for crate_name in [
        "dare-a2a-security",
        "dare-identity-security",
        "dare-mcp-auth-security",
        "dare-memory-security",
        "dare-multi-turn-security",
        "dare-prompt-injection",
        "dare-rag-security",
        "dare-supply-chain-security",
        "dare-tool-security",
    ] {
        let source = std::fs::read_to_string(root.join(crate_name).join("src/evidence_bridge.rs"))
            .expect("bridge source");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production part");
        let call = production
            .find("dare_security_evidence::validate(&evidence)")
            .unwrap_or_else(|| panic!("{crate_name} does not validate its records"));
        let tail = &production[call..];
        let statement_end = tail.find(";\n").expect("statement end");
        assert!(
            tail[..statement_end].trim_end().ends_with('?'),
            "{crate_name} validates but does not propagate the error"
        );
    }
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::Error => "ERROR",
    }
}
