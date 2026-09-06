//! Cycle 017 — offline, confidential and no-remote-retriever regressions.
//!
//! These establish that the engine has no network, index or embedding path to
//! lose, rather than that it merely avoids using one. They require no external
//! service, no vector database and no model, and pass with networking
//! unavailable.
//!
//! The distinction matters because "we never call out" is a claim about
//! behaviour, and behaviour changes when someone adds a feature. "There is no
//! dependency, no mode, no flag and no API call through which we could" is a
//! claim about shape, and it fails a test the moment it stops being true.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_rag_security::canonical::bind;
use dare_rag_security::corpus::builtin_corpus;
use dare_rag_security::evidence_bridge::{build_evidence, SYNTHETIC_TARGET_ID};
use dare_rag_security::harness::{HarnessAdapter, HarnessMode};
use dare_rag_security::local_synthetic::LocalSyntheticAdapter;
use dare_rag_security::model::RagSecurityScenario;
use dare_rag_security::replay::ReplayAdapter;
use dare_rag_security::result::{run_scenario, RagSecurityResult};
use dare_rag_security::schema::validate_scenario_document;
use dare_rag_security::simulated::SimulatedAdapter;
use dare_rag_security::trials::TrialPlan;
use dare_rag_security::Verdict;
use serde_json::Value;
use time::macros::datetime;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    crate_root().join("../..")
}

fn load_scenario(id: &str) -> RagSecurityScenario {
    let path = crate_root()
        .join("tests/fixtures/scenarios")
        .join(format!("{}.json", id.to_ascii_lowercase()));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {id}: {err}"));
    let value: Value = serde_json::from_slice(&raw).expect("scenario json");
    validate_scenario_document(&value).expect("schema");
    let scenario: RagSecurityScenario = serde_json::from_value(value).expect("typed");
    scenario.validate().expect("structurally valid");
    scenario
}

fn run_with(id: &str, adapter: &dyn HarnessAdapter) -> RagSecurityResult {
    let scenario = load_scenario(id);
    let entry = builtin_corpus()
        .expect("corpus")
        .resolve(scenario.vector.as_ref())
        .expect("the named vector resolves")
        .cloned();
    let plan = TrialPlan::from_scenario(&scenario).expect("plan");
    run_scenario(&scenario, entry.as_ref(), adapter, plan).expect("run")
}

fn simulate(id: &str) -> RagSecurityResult {
    run_with(id, &SimulatedAdapter::new())
}

#[test]
fn every_approved_mode_runs_fully_offline() {
    // All three modes, all reaching a verdict, none contacting anything.
    let simulated = simulate("RAG-LAB-001");
    assert_eq!(simulated.mode, HarnessMode::Simulated);
    assert_eq!(simulated.verdict, Verdict::Pass);

    let scenario = load_scenario("RAG-LAB-001");
    let local = run_with(
        "RAG-LAB-001",
        &LocalSyntheticAdapter::for_scenario(&scenario, 3),
    );
    assert_eq!(local.mode, HarnessMode::LocalSynthetic);

    let replay = run_with(
        "RAG-LAB-001",
        &ReplayAdapter::from_path(&crate_root().join("tests/fixtures/traces/rag-lab-001.json"))
            .expect("trace loads"),
    );
    assert_eq!(replay.mode, HarnessMode::Replay);

    for result in [&simulated, &local, &replay] {
        assert_eq!(result.budget.state_changes, 0);
        assert_eq!(result.budget.external_egress_bytes, 0);
        // A replayed or staged observation is synthetic, and every artifact
        // says so rather than letting a reader take it for production evidence.
        assert!(result.synthetic);
    }
}

#[test]
fn the_mode_enum_cannot_represent_a_remote_or_live_target() {
    // Three variants, and no fourth is representable. A remote mode would have
    // to be added to this enum to exist at all, which is why the enum is the
    // check rather than a runtime guard.
    let modes: BTreeSet<&str> = [
        HarnessMode::Replay,
        HarnessMode::Simulated,
        HarnessMode::LocalSynthetic,
    ]
    .iter()
    .map(|mode| mode.as_str())
    .collect();

    assert_eq!(
        modes,
        BTreeSet::from(["REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"])
    );

    for absent in [
        "LIVE",
        "REMOTE",
        "PROVIDER",
        "VECTOR_DB",
        "HTTP",
        "PRODUCTION",
    ] {
        assert!(
            !modes.contains(absent),
            "the mode enum can represent `{absent}`"
        );
        assert!(
            serde_json::from_str::<HarnessMode>(&format!("\"{absent}\"")).is_err(),
            "`{absent}` deserializes into a mode"
        );
    }
}

#[test]
fn the_engine_declares_no_transport_provider_or_embedding_dependency() {
    // The manifest is the claim. A network client, database driver,
    // vector-store SDK or embedding runtime appearing here would mean the
    // offline guarantee rests on discipline rather than on the dependency
    // graph.
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("manifest readable");

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
        "sqlx",
        "tokio-postgres",
        "redis",
        "elasticsearch",
        "opensearch",
        "qdrant",
        "pinecone",
        "weaviate",
        "candle",
        "ort",
        "tokenizers",
        "tiktoken",
        "fastembed",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "the engine must not depend on `{forbidden}`"
        );
    }

    // And what it does depend on is the DARE crates it composes with, plus
    // data libraries.
    for expected in [
        "dare-adversarial",
        "dare-coverage",
        "dare-identity-security",
        "dare-memory-security",
        "dare-prompt-injection",
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
    let src = crate_root().join("src");
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

        // Two kinds of scheme-shaped text do appear in shipping code, and
        // neither is somewhere this crate could go.
        //
        // The first is a JSON Schema `$id` — an identifier for a schema
        // compiled into the binary and resolved locally, never fetched. The
        // second is a bare scheme with no host, which is how `schema.rs`
        // spells the prefixes it *refuses*; banning those would ban the
        // refusal list itself.
        //
        // So the constraint is that every occurrence is one of those two, not
        // that none exists.
        for url in urls_in(shipping) {
            let is_schema_id = url.starts_with("https://darelabs.tech/schemas/");
            let is_bare_scheme = SCHEMES.contains(&url.as_str());
            assert!(
                is_schema_id || is_bare_scheme,
                "{} names the reachable target `{url}`",
                path.display()
            );
        }
    }
    assert!(inspected >= 15, "the sweep must actually cover the crate");

    // The exemption above is only safe while it stays narrow, so the refusal
    // list it exists for has to actually be there. If `schema.rs` stopped
    // declaring the schemes it rejects, this would be an exemption protecting
    // nothing.
    let schema_source = std::fs::read_to_string(src.join("schema.rs")).expect("schema.rs readable");
    for scheme in ["http://", "redis://", "postgresql://"] {
        assert!(
            schema_source.contains(scheme),
            "schema.rs no longer declares `{scheme}` among the schemes it refuses"
        );
    }
}

#[test]
fn a_disclosure_is_observed_and_never_performed() {
    // RAG-LAB-016 stages a protected document reaching a result. It fails
    // deterministically, and nothing is retrieved from anywhere: there is no
    // code path in this crate that could query an index, and the recorded
    // budget says so.
    let result = simulate("RAG-LAB-016");
    assert_eq!(result.verdict, Verdict::Fail);
    assert!(result.queries() > 0);
    assert!(result.results() > 0);
    assert_eq!(result.budget.state_changes, 0);
    assert_eq!(result.budget.external_egress_bytes, 0);
}

#[test]
fn every_run_records_zero_state_change_and_zero_egress() {
    for id in [
        "RAG-LAB-001",
        "RAG-LAB-008",
        "RAG-LAB-013",
        "RAG-LAB-016",
        "RAG-LAB-021",
        "RAG-LAB-022",
    ] {
        let result = simulate(id);
        assert_eq!(result.budget.state_changes, 0, "{id}");
        assert_eq!(result.budget.external_egress_bytes, 0, "{id}");
    }
}

#[test]
fn a_canary_never_survives_into_a_persisted_artifact() {
    // Confidential mode's requirement, checked against the artifacts a run
    // actually writes rather than against the renderer.
    for index in 1..=22 {
        let id = format!("RAG-LAB-{index:03}");
        let scenario = load_scenario(&id);
        let result = simulate(&id);
        let evidence = build_evidence(
            &scenario,
            None,
            &bind(&scenario).expect("binds"),
            &result,
            datetime!(2026-09-06 12:00 UTC),
        )
        .expect("evidence");

        let artifacts = [
            serde_json::to_string(&result).expect("result serializes"),
            serde_json::to_string(&result.trials).expect("trials serialize"),
            serde_json::to_string(&evidence).expect("evidence serializes"),
        ];

        for artifact in artifacts {
            for canary in &scenario.objective.protected_canaries {
                assert!(
                    !artifact.contains(canary.as_str()),
                    "{id} persisted a protected canary"
                );
            }
            for marker in ["sk-live-", "-----BEGIN", "Bearer ey", "example.invalid"] {
                assert!(!artifact.contains(marker), "{id} persisted `{marker}`");
            }
        }
    }
}

#[test]
fn no_shipped_fixture_or_corpus_entry_names_a_reachable_target() {
    // The corpus and the labs describe retrieval. Describing it must never
    // require naming somewhere a reader's tooling could follow.
    let mut inspected = 0;
    for dir in [
        repo_root().join("corpus/rag-security/v1"),
        crate_root().join("tests/fixtures/scenarios"),
        crate_root().join("tests/fixtures/traces"),
    ] {
        for path in walk(&dir) {
            // The hostile fixtures exist precisely to carry refused material.
            if path
                .to_string_lossy()
                .contains("adversarial-parser-fixtures")
            {
                continue;
            }
            // RAG-LAB-024 is the smuggling lab; being refused is its purpose.
            if path.to_string_lossy().contains("rag-lab-024") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable");
            inspected += 1;
            for url in urls_in(&text) {
                assert!(
                    url.starts_with("https://darelabs.tech/schemas/"),
                    "{} names the reachable target `{url}`",
                    path.display()
                );
            }
        }
    }
    assert!(
        inspected >= 45,
        "the sweep must actually cover the fixtures"
    );
}

#[test]
fn evidence_never_names_a_production_target() {
    // Every evidence record is filed against the synthetic lab, so a report
    // cannot present a Cycle 017 result as evidence about a real system.
    let scenario = load_scenario("RAG-LAB-001");
    let result = simulate("RAG-LAB-001");
    let evidence = build_evidence(
        &scenario,
        None,
        &bind(&scenario).expect("binds"),
        &result,
        datetime!(2026-09-06 12:00 UTC),
    )
    .expect("evidence");

    assert!(!evidence.is_empty());
    for record in &evidence {
        assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
    }
}

#[test]
fn a_trace_is_inert_data_and_starts_nothing() {
    // A trace names objects by id and nothing else. It cannot carry an
    // endpoint, and replaying it opens no connection — the adapter reads a
    // local file and hands back values.
    let path = crate_root().join("tests/fixtures/traces/rag-lab-001.json");
    let text = std::fs::read_to_string(&path).expect("readable");
    assert!(urls_in(&text).is_empty(), "the trace names a URL");

    let adapter = ReplayAdapter::from_path(&path).expect("loads");
    assert_eq!(adapter.mode(), HarnessMode::Replay);
    assert!(adapter.observations_are_synthetic());
    assert!(adapter.trial_capacity() > 0);
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            found.push(path);
        }
    }
    found
}

/// Every scheme the sweeps look for.
const SCHEMES: [&str; 9] = [
    "http://",
    "https://",
    "ws://",
    "wss://",
    "mcp://",
    "redis://",
    "postgres://",
    "postgresql://",
    "mongodb://",
];

fn urls_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for scheme in SCHEMES {
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
