//! A2A live capture decided by the Cycle 020 engine in STATIC mode.

mod common;
mod lab;

use std::collections::BTreeSet;
use std::sync::Arc;

use common::*;
use dare_a2a_security::corpus::corpus;
use dare_a2a_security::model::A2aInvariant;
use dare_remote_validation::canonical::short_hex;
use dare_remote_validation::capture::Capture;
use dare_remote_validation::engines::a2a;
use dare_remote_validation::gateway::{EgressGateway, TrustRoots};
use dare_remote_validation::protocol::Method;
use dare_security_evidence::Verdict;
use lab::{Handler, LabCa, LabReply, LabServer};
use serde_json::{json, Value};

const METHODS: [&str; 3] = ["A2A_AGENT_CARD_GET", "A2A_MESSAGE_SEND", "A2A_TASKS_GET"];

fn agent(provider: &'static str) -> Handler {
    Arc::new(move |hit| match (hit.method.as_str(), hit.path.as_str()) {
        ("GET", "/.well-known/agent-card.json") => LabReply::json(
            200,
            json!({
                "name": "lab-agent", "protocolVersion": "0.3.0", "provider": {"organization": provider},
                "url": "https://127.0.0.1/a2a/v1", "preferredTransport": "JSONRPC",
                "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
                "skills": [{"id": "summarize", "name": "Summarize"}]
            }),
        ),
        ("POST", "/a2a/v1") => {
            let request: Value = serde_json::from_slice(&hit.body).unwrap();
            LabReply::json(
                200,
                json!({"jsonrpc": "2.0", "id": request["id"], "result": {
                    "role": "agent", "messageId": "r1", "contextId": request["params"]["message"]["contextId"],
                    "parts": [{"kind": "text", "text": "I can summarize documents you are allowed to read."}]
                }}),
            )
        }
        _ => LabReply::status(404),
    })
}

async fn capture_for(ca: &LabCa, server: &LabServer, loaded: &a2a::Loaded) -> Capture {
    let auth = authorization(&server.origin, "A2A", &METHODS, json!({}));
    let plan = plan(&auth, &server.origin, "A2A", &METHODS);
    let mut verified = verified(&auth, &plan, &server.origin);
    let mut gateway = EgressGateway::new(
        &mut verified,
        &plan,
        &server.origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .unwrap();
    let methods: BTreeSet<Method> = [
        Method::A2aAgentCardGet,
        Method::A2aMessageSend,
        Method::A2aTasksGet,
    ]
    .into();
    a2a::live(&mut gateway, loaded, &methods)
        .await
        .expect("live");
    gateway.finish(None).unwrap().0
}

fn policy(dir: &std::path::Path, origin: &str, expected_provider: &str) -> std::path::PathBuf {
    let peer = format!("peer-{}", short_hex(origin.as_bytes(), 16));
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("lab-policy.json");
    std::fs::write(&path, serde_json::to_vec(&json!({
        "schema_version": "1", "policy_id": "lab-policy",
        "approved_peers": [{"peer_id": peer, "expected_provider": expected_provider, "approved_scheme_kinds": ["HTTP_BEARER"]}]
    })).unwrap()).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn every_a2a_lab_scenario_decides_from_a_live_capture_without_synthetic_evidence() {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, agent("DARE Lab")).await;
    let dir = tempfile::tempdir().unwrap();
    let policy = policy(dir.path(), &server.origin, "DARE Lab");
    let entries = corpus();
    assert!(entries.len() >= 60);
    // One live capture per scenario id is what a plan would do; the card and
    // probe are the same for every entry, so capture once and decide each.
    let first = a2a::load(entries[0].id).unwrap();
    let capture = capture_for(&ca, &server, &first).await;
    let mut verdicts = std::collections::BTreeMap::new();
    for entry in &entries {
        let loaded = a2a::load(entry.id).unwrap();
        // Re-label the capture's entries for this scenario (same exchanges).
        let mut relabelled = capture.clone();
        for e in &mut relabelled.entries {
            e.scenario_ref.scenario_id = entry.id.to_owned();
        }
        let outcome = a2a::verdict(
            &relabelled,
            &loaded,
            "/a2a/v1",
            &policy,
            &dir.path().join("work"),
            None,
        )
        .expect(entry.id);
        assert_eq!(
            outcome.result["synthetic"], false,
            "{}: STATIC evidence is not synthetic",
            entry.id
        );
        assert!(
            outcome
                .evidence
                .iter()
                .all(|e| dare_security_evidence::validate(e).is_ok()),
            "{}",
            entry.id
        );
        assert!(!outcome.not_observable.is_empty());
        assert_ne!(
            outcome.verdict,
            Verdict::Error,
            "{}: the projection must be readable: {}",
            entry.id,
            outcome.result["reason"]
        );
        *verdicts
            .entry(format!("{:?}", outcome.verdict))
            .or_insert(0) += 1;
        if matches!(
            loaded.scenario.primary_invariant,
            A2aInvariant::MessageAuthenticityEstablished
                | A2aInvariant::AuthorityPropagationBounded
                | A2aInvariant::TaskContextBindingPreserved
        ) {
            assert_ne!(
                outcome.verdict,
                Verdict::Pass,
                "{}: needs facts a live run cannot observe",
                entry.id
            );
        }
    }
    eprintln!("A2A-LAB over one live capture: {verdicts:?}");
    assert!(
        !dir.path().join("work").exists(),
        "the work directory is removed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_from_an_unexpected_provider_fails_discovery_binding_and_its_twin_does_not() {
    let ca = LabCa::generate();
    let dir = tempfile::tempdir().unwrap();
    let entry = corpus()
        .into_iter()
        .find(|e| e.invariant == A2aInvariant::DiscoveryBindingPreserved)
        .expect("a discovery-binding entry");
    let loaded = a2a::load(entry.id).unwrap();

    let attacker = LabServer::start(&ca, agent("Attacker Inc")).await;
    let policy_a = policy(&dir.path().join("a"), &attacker.origin, "DARE Lab");
    let capture = capture_for(&ca, &attacker, &loaded).await;
    let outcome = a2a::verdict(
        &capture,
        &loaded,
        "/a2a/v1",
        &policy_a,
        &dir.path().join("work"),
        None,
    )
    .unwrap();
    eprintln!(
        "{} -> {:?} {}",
        entry.id, outcome.verdict, outcome.result["reason"]
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "{}",
        outcome.result["reason"]
    );

    let secure = LabServer::start(&ca, agent("DARE Lab")).await;
    let policy_b = policy(&dir.path().join("b"), &secure.origin, "DARE Lab");
    let capture = capture_for(&ca, &secure, &loaded).await;
    let outcome = a2a::verdict(
        &capture,
        &loaded,
        "/a2a/v1",
        &policy_b,
        &dir.path().join("work"),
        None,
    )
    .unwrap();
    eprintln!(
        "{} twin -> {:?} {}",
        entry.id, outcome.verdict, outcome.result["reason"]
    );
    assert_ne!(outcome.verdict, Verdict::Fail);
    assert_ne!(outcome.verdict, Verdict::Error);
}
