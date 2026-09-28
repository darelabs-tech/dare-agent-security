//! MCP Auth metadata observed live and decided by the Cycle 018 engine.

mod common;
mod lab;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use common::*;
use dare_remote_validation::capture::Capture;
use dare_remote_validation::engines::{mcp_auth, Sources};
use dare_remote_validation::gateway::{EgressGateway, TrustRoots};
use dare_remote_validation::protocol::Method;
use dare_security_evidence::Verdict;
use lab::{Handler, LabCa, LabReply, LabServer};
use serde_json::json;

const METHODS: [&str; 2] = [
    "MCP_PROTECTED_RESOURCE_METADATA_GET",
    "MCP_AUTH_SERVER_METADATA_GET",
];

fn sources() -> Sources {
    Sources {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
    }
}

async fn run(resource_suffix: &'static str, issuer_suffix: &'static str) -> (LabServer, LabCa) {
    let ca = LabCa::generate();
    // The handler names its own origin, which it learns after binding.
    let port_cell: Arc<std::sync::Mutex<u16>> = Arc::new(std::sync::Mutex::new(0));
    let cell = port_cell.clone();
    let handler: Handler = Arc::new(move |hit| {
        let origin = format!("https://127.0.0.1:{}", *cell.lock().unwrap());
        match hit.path.as_str() {
            "/.well-known/oauth-protected-resource" => LabReply::json(
                200,
                json!({
                    "resource": format!("{origin}{resource_suffix}"), "authorization_servers": [origin.clone()], "scopes_supported": ["tools.read"]
                }),
            ),
            "/.well-known/oauth-authorization-server" => LabReply::json(
                200,
                json!({
                    "issuer": format!("{origin}{issuer_suffix}"), "token_endpoint": format!("{origin}/token"), "code_challenge_methods_supported": ["S256"]
                }),
            ),
            _ => LabReply::status(404),
        }
    });
    let server = LabServer::start(&ca, handler).await;
    *port_cell.lock().unwrap() = server.addr.port();
    (server, ca)
}

async fn capture(ca: &LabCa, server: &LabServer, loaded: &mcp_auth::Loaded) -> Capture {
    let auth = authorization(&server.origin, "MCP", &METHODS, json!({}));
    let plan = plan(&auth, &server.origin, "MCP", &METHODS);
    let mut verified = verified(&auth, &plan, &server.origin);
    let mut gateway = EgressGateway::new(
        &mut verified,
        &plan,
        &server.origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .unwrap();
    let methods: BTreeSet<Method> = [
        Method::McpProtectedResourceMetadataGet,
        Method::McpAuthServerMetadataGet,
    ]
    .into();
    mcp_auth::live(&mut gateway, loaded, &methods)
        .await
        .expect("live");
    gateway.finish(None).unwrap().0
}

fn relabel(capture: &Capture, id: &str) -> Capture {
    let mut c = capture.clone();
    for e in &mut c.entries {
        e.scenario_ref.scenario_id = id.to_owned();
    }
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn coherent_metadata_never_fails_any_mcp_auth_lab_scenario() {
    let (server, ca) = run("/mcp", "").await;
    let first = mcp_auth::load(&sources(), "MCP-AUTH-LAB-001").unwrap();
    let live = capture(&ca, &server, &first).await;
    let paths: Vec<String> = server.hits().iter().map(|h| h.path.clone()).collect();
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server"
        ]
    );
    let expected = format!("{}/mcp", server.origin);
    let mut verdicts = BTreeMap::new();
    for n in 1..=35 {
        let id = format!("MCP-AUTH-LAB-{n:03}");
        let loaded = match mcp_auth::load(&sources(), &id) {
            Ok(loaded) => loaded,
            // MCP-AUTH-LAB-022 is a deliberate over-budget fixture: the
            // engine refuses it before any digest exists, so no
            // authorization can ever grant it.
            Err(error) => {
                assert_eq!(id, "MCP-AUTH-LAB-022", "{id}: {error}");
                *verdicts.entry("REFUSED".to_owned()).or_insert(0) += 1;
                continue;
            }
        };
        let outcome = mcp_auth::verdict(&relabel(&live, &id), &loaded, &expected, None).expect(&id);
        assert_ne!(
            outcome.verdict,
            Verdict::Fail,
            "{id}: coherent live metadata must not fail: {}",
            outcome.result["reason"]
        );
        assert_ne!(
            outcome.verdict,
            Verdict::Error,
            "{id}: {}",
            outcome.result["reason"]
        );
        assert!(
            outcome
                .evidence
                .iter()
                .all(|e| dare_security_evidence::validate(e).is_ok()),
            "{id}"
        );
        *verdicts
            .entry(format!("{:?}", outcome.verdict))
            .or_insert(0) += 1;
    }
    eprintln!("MCP-AUTH-LAB over coherent live metadata: {verdicts:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_for_another_resource_fails_resource_binding() {
    let (server, ca) = run("/somewhere-else", "").await;
    let loaded = mcp_auth::load(&sources(), "MCP-AUTH-LAB-005").unwrap();
    let live = capture(&ca, &server, &loaded).await;
    let outcome =
        mcp_auth::verdict(&live, &loaded, &format!("{}/mcp", server.origin), None).unwrap();
    eprintln!(
        "005 mismatch -> {:?} {}",
        outcome.verdict, outcome.result["reason"]
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "{}",
        outcome.result["reason"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_that_is_not_the_advertised_server_fails_issuer_binding() {
    let (server, ca) = run("/mcp", "/rogue").await;
    let loaded = mcp_auth::load(&sources(), "MCP-AUTH-LAB-007").unwrap();
    let live = capture(&ca, &server, &loaded).await;
    let outcome =
        mcp_auth::verdict(&live, &loaded, &format!("{}/mcp", server.origin), None).unwrap();
    eprintln!(
        "007 rogue issuer -> {:?} {}",
        outcome.verdict, outcome.result["reason"]
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Fail,
        "{}",
        outcome.result["reason"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_metadata_is_never_a_pass() {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, lab::always(LabReply::status(404))).await;
    let loaded = mcp_auth::load(&sources(), "MCP-AUTH-LAB-005").unwrap();
    let live = capture(&ca, &server, &loaded).await;
    let outcome =
        mcp_auth::verdict(&live, &loaded, &format!("{}/mcp", server.origin), None).unwrap();
    assert_ne!(outcome.verdict, Verdict::Pass);
    assert_eq!(
        server.hits().len(),
        1,
        "no AS fetch without advertised metadata"
    );
}
