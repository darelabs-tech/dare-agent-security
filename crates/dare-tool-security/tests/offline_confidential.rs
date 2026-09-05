//! Cycle 014 — offline, confidential and no-remote-tool regressions.
//!
//! These establish that the engine has no network or tool-execution path to
//! lose, rather than that it merely avoids using one. They require no external
//! service, no MCP server and no model, and pass with networking unavailable.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use dare_tool_security::canonical::bind;
use dare_tool_security::corpus::builtin_corpus;
use dare_tool_security::evidence_bridge::{build_evidence, SYNTHETIC_TARGET_ID};
use dare_tool_security::harness::{ToolHarnessAdapter, ToolHarnessMode};
use dare_tool_security::local_synthetic::ToolLocalSyntheticAdapter;
use dare_tool_security::model::{ToolCorpusEntry, ToolSecurityScenario};
use dare_tool_security::observation::ToolObservationEvent;
use dare_tool_security::replay::{ToolReplayAdapter, ToolTrace};
use dare_tool_security::result::{run_scenario, ToolSecurityResult};
use dare_tool_security::schema::validate_scenario_document;
use dare_tool_security::simulated::ToolSimulatedAdapter;
use dare_tool_security::source::ToolSourceKind;
use dare_tool_security::trials::ToolTrialPlan;
use dare_tool_security::Verdict;
use serde_json::Value;
use time::macros::datetime;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_scenario(id: &str) -> ToolSecurityScenario {
    let path = repo_root()
        .join("fixtures/tool-security/scenarios")
        .join(format!("{id}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {id}: {err}"));
    let value: Value = serde_json::from_slice(&raw).expect("scenario json");
    validate_scenario_document(&value).expect("schema");
    serde_json::from_value(value).expect("typed")
}

fn vector_for(scenario: &ToolSecurityScenario) -> Option<ToolCorpusEntry> {
    scenario.vector.as_ref().map(|vector| {
        builtin_corpus()
            .expect("corpus")
            .require(&vector.corpus_id)
            .expect("vector")
            .clone()
    })
}

fn run_with(id: &str, adapter: &dyn ToolHarnessAdapter) -> ToolSecurityResult {
    let scenario = load_scenario(id);
    let entry = vector_for(&scenario);
    let plan = ToolTrialPlan::from_scenario(&scenario).expect("plan");
    run_scenario(&scenario, entry.as_ref(), adapter, plan).expect("run")
}

fn simulate(id: &str) -> ToolSecurityResult {
    let scenario = load_scenario(id);
    let lab = scenario.lab.clone().expect("lab");
    run_with(id, &ToolSimulatedAdapter::new(lab))
}

#[test]
fn every_approved_mode_runs_fully_offline() {
    let simulated = simulate("TOOL-LAB-001");
    assert_eq!(simulated.mode, ToolHarnessMode::Simulated);
    assert_eq!(simulated.verdict, Verdict::Pass);
    assert!(simulated.synthetic);

    let scenario = load_scenario("TOOL-LAB-002");
    let lab = scenario.lab.clone().expect("lab");
    let local = run_with(
        "TOOL-LAB-002",
        &ToolLocalSyntheticAdapter::new(lab, SYNTHETIC_TARGET_ID, 3),
    );
    assert_eq!(local.mode, ToolHarnessMode::LocalSynthetic);
    assert!(local.synthetic);

    let trace_root = repo_root().join("fixtures/tool-security/traces");
    let replay =
        ToolReplayAdapter::load(&trace_root, Path::new("TOOL-LAB-005.json")).expect("trace loads");
    let replayed = run_with("TOOL-LAB-005", &replay);
    assert_eq!(replayed.mode, ToolHarnessMode::Replay);
    assert!(
        !replayed.synthetic,
        "a recorded trace is not synthetic; the report must not claim otherwise"
    );
}

#[test]
fn the_mode_enum_cannot_represent_a_remote_or_live_target() {
    // Not "does not use one" — cannot name one. The enum is the boundary.
    assert_eq!(ToolHarnessMode::all().len(), 3);
    for token in [
        "REMOTE",
        "REMOTE_PROVIDER",
        "LIVE",
        "LIVE_MCP",
        "MCP_SERVER",
        "PRODUCTION",
        "HTTP",
        "HTTPS",
        "AUTHORIZED_DYNAMIC",
    ] {
        let err = ToolHarnessMode::parse(token).expect_err("must be refused");
        assert!(err.is_refusal(), "{token}: {err}");
    }

    // The same holds one level down: a source cannot be a live server.
    let sources: BTreeSet<&str> = ToolSourceKind::all()
        .into_iter()
        .map(ToolSourceKind::as_str)
        .collect();
    for forbidden in [
        "LIVE_MCP_SERVER",
        "REMOTE_PROVIDER",
        "PRODUCTION_TOOL",
        "HTTP_ENDPOINT",
    ] {
        assert!(!sources.contains(forbidden), "{forbidden} must not exist");
    }
}

#[test]
fn the_engine_declares_no_transport_or_provider_dependency() {
    // The manifest is the claim. A network or MCP client crate appearing here
    // would mean the offline guarantee rests on discipline rather than on the
    // dependency graph.
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("manifest readable");

    for forbidden in [
        "reqwest",
        "hyper",
        "tokio",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "h2",
        "rustls",
        "native-tls",
        "openssl",
        "tonic",
        "tungstenite",
        "async-std",
        "rmcp",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "the engine must not depend on `{forbidden}`"
        );
    }

    // And what it does depend on is the four DARE crates plus data libraries.
    for expected in [
        "dare-adversarial",
        "dare-coverage",
        "dare-security-evidence",
        "jsonschema",
        "serde",
        "sha2",
    ] {
        assert!(
            manifest.contains(expected),
            "expected dependency {expected}"
        );
    }
}

#[test]
fn no_source_file_reaches_for_a_network_or_process_api() {
    // A grep, but an exact one over whole tokens: the point is that no code
    // path exists, and a new one would have to name a std API to be written.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut inspected = 0;
    for entry in std::fs::read_dir(&src).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable");
        // Only the shipping half of each file. Test modules legitimately name
        // a URL in order to assert that it is refused, and flagging that would
        // punish the very check being made.
        let shipping = text.split("#[cfg(test)]").next().unwrap_or_default();
        inspected += 1;
        for forbidden in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process::Command",
            "Command::new",
            "std::process::exit",
        ] {
            assert!(
                !shipping.contains(forbidden),
                "{} references `{forbidden}`",
                path.display()
            );
        }

        // URLs do appear in shipping code, as JSON Schema `$id` values. Those
        // are identifiers for schemas compiled into the binary and resolved
        // locally, never fetched — so the constraint is that every URL is one
        // of those, not that none exists.
        for url in urls_in(shipping) {
            assert!(
                url.starts_with("https://darelabs.tech/schemas/"),
                "{} names the non-schema URL `{url}`",
                path.display()
            );
        }
    }
    assert!(inspected >= 12, "the sweep must actually cover the crate");
}

#[test]
fn a_risky_operation_is_observed_and_never_performed() {
    // TOOL-LAB-010 stages a delete. It fails deterministically, and the delete
    // does not happen — there is no code path in this crate that could perform
    // it, and the recorded request says so.
    let result = simulate("TOOL-LAB-010");
    assert_eq!(result.verdict, Verdict::Fail);
    assert!(result.tool_requests() > 0);
    assert_eq!(result.budget.state_changes, 0);
    assert_eq!(result.budget.external_egress_bytes, 0);

    for trial in &result.trials {
        for event in &trial.events {
            if let ToolObservationEvent::ToolRequested(request) = event {
                assert!(!request.dispatched);
            }
        }
    }
}

#[test]
fn every_run_records_zero_state_change_and_zero_egress() {
    for id in [
        "TOOL-LAB-001",
        "TOOL-LAB-008",
        "TOOL-LAB-015",
        "TOOL-LAB-019",
    ] {
        let result = simulate(id);
        assert_eq!(result.budget.state_changes, 0, "{id}");
        assert_eq!(result.budget.external_egress_bytes, 0, "{id}");
    }
}

#[test]
fn a_canary_never_survives_into_a_persisted_artifact() {
    // TOOL-LAB-018 carries a synthetic canary through the whole pipeline. Every
    // artifact the product would persist is checked, not just the summary.
    let scenario = load_scenario("TOOL-LAB-018");
    let entry = vector_for(&scenario).expect("vector");
    assert!(
        entry
            .payload
            .as_ref()
            .expect("payload")
            .content
            .contains("DARE-SYNTHETIC-CANARY-TOOL01"),
        "the fixture must actually carry the canary"
    );

    let binding = bind(&scenario).expect("binds");
    let result = run_scenario(
        &scenario,
        Some(&entry),
        &ToolSimulatedAdapter::from_entry(&entry),
        ToolTrialPlan::from_scenario(&scenario).expect("plan"),
    )
    .expect("runs");
    let evidence = build_evidence(
        &scenario,
        Some(&entry),
        &binding,
        &result,
        datetime!(2026-09-05 12:00:00 UTC),
    )
    .expect("evidence builds");

    for (label, encoded) in [
        ("result", serde_json::to_string(&result).expect("result")),
        (
            "trials",
            serde_json::to_string(&result.trials).expect("trials"),
        ),
        (
            "evidence",
            serde_json::to_string(&evidence).expect("evidence"),
        ),
    ] {
        assert!(
            !encoded.contains("DARE-SYNTHETIC-CANARY-TOOL01"),
            "the canary survived into the {label} artifact"
        );
        assert!(encoded.contains("[REDACTED]"), "{label} shows no redaction");
    }

    assert_eq!(result.redaction_state, "REDACTED");
}

#[test]
fn credential_shaped_content_is_masked_before_it_can_be_persisted() {
    use dare_tool_security::observation::{mask_sensitive, EvidenceText, REDACTION_MARKER};

    for secret in [
        "sk-live-4f9c2ab117de",
        "xoxb-1234-5678-abcdef",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "Bearer ya29.a0ARrdaM9tokenlikevaluehere",
        "-----BEGIN PRIVATE KEY-----MIIEvQ",
    ] {
        let evidence = EvidenceText::from_raw(&format!("tool output containing {secret}"));
        assert!(evidence.redacted, "{secret} was not redacted");
        assert!(evidence.is_secret_safe(), "{secret} survived masking");
        assert!(evidence.text.contains(REDACTION_MARKER));
        // Correlation without disclosure.
        assert!(evidence.digest.starts_with("sha256:"));
    }

    // Masking scans the whole bounded value, not a prefix.
    let long = format!("{}sk-live-tail", "a".repeat(4000));
    assert!(!mask_sensitive(&long).contains("sk-live-tail"));
}

#[test]
fn no_shipped_fixture_or_corpus_entry_names_a_remote_target() {
    let mut inspected = 0;
    for root in [
        repo_root().join("corpus/tool-security/v1/poisoning"),
        repo_root().join("corpus/tool-security/v1/misuse"),
        repo_root().join("corpus/tool-security/v1/benign-controls"),
        repo_root().join("fixtures/tool-security/scenarios"),
        repo_root().join("fixtures/tool-security/traces"),
    ] {
        for entry in std::fs::read_dir(&root).expect("directory") {
            let path = entry.expect("entry").path();
            let text = std::fs::read_to_string(&path).expect("readable");
            inspected += 1;
            for forbidden in [
                "http://",
                "https://",
                "mcp://",
                "ws://",
                "localhost:",
                "127.0.0.1",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{} names `{forbidden}`",
                    path.display()
                );
            }
        }
    }
    assert!(inspected >= 45, "the sweep must cover the shipped data");
}

#[test]
fn evidence_never_names_a_production_target() {
    let scenario = load_scenario("TOOL-LAB-001");
    let entry = vector_for(&scenario);
    let binding = bind(&scenario).expect("binds");
    let result = simulate("TOOL-LAB-001");
    let evidence = build_evidence(
        &scenario,
        entry.as_ref(),
        &binding,
        &result,
        datetime!(2026-09-05 12:00:00 UTC),
    )
    .expect("evidence builds");

    for record in &evidence {
        assert_eq!(record.target.type_, "synthetic-agent");
        assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
        assert_eq!(record.target.protocol, None);
        assert_eq!(record.target.software, None);
    }
}

#[test]
fn a_trace_is_inert_data_and_starts_nothing() {
    // Replay reads a file. Loading one must not require, or provide, any way to
    // reach a server — the trace schema has no field that could name one.
    let trace_root = repo_root().join("fixtures/tool-security/traces");
    let trace = ToolTrace::load(&trace_root, Path::new("TOOL-LAB-005.json")).expect("loads");
    assert_eq!(trace.scenario_id, "TOOL-LAB-005");

    // Field names, not prose. The trace's own note legitimately contains the
    // word "server" while saying that no server is contacted; asserting over
    // raw text would flag that sentence and miss an actual field.
    let encoded = serde_json::to_value(&trace).expect("serializes");
    let mut keys = BTreeSet::new();
    collect_keys(&encoded, &mut keys);
    for forbidden in [
        "endpoint",
        "url",
        "server",
        "mcp_server",
        "transport",
        "dispatch",
        "provider",
        "host",
    ] {
        assert!(
            !keys.contains(forbidden),
            "a trace must not carry a `{forbidden}` field"
        );
    }
    assert!(keys.contains("scenario_id"), "the sweep found real fields");

    let schema: Value =
        serde_json::from_str(dare_tool_security::replay::TRACE_SCHEMA_V1_JSON).expect("schema");
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
}

/// Every field name present anywhere in a document.
fn collect_keys(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                into.insert(key.clone());
                collect_keys(child, into);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_keys(item, into);
            }
        }
        _ => {}
    }
}

/// Every URL-shaped token in a chunk of source.
fn urls_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for scheme in ["http://", "https://", "ws://", "wss://", "mcp://"] {
        let mut rest = source;
        while let Some(index) = rest.find(scheme) {
            let tail = &rest[index..];
            let end = tail
                .find(|c: char| c.is_whitespace() || c == '"')
                .unwrap_or(tail.len());
            found.push(tail[..end].to_owned());
            rest = &tail[end..];
        }
    }
    found
}
