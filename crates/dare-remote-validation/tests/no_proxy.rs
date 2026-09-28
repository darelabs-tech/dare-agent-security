//! The gateway ignores proxy environment variables (BLUEPRINT AD-03).
//!
//! A proxy would move the TCP peer away from the pinned address, so the
//! client is built with `no_proxy()`. This test lives in its own binary
//! because it sets process-wide environment variables.

mod common;
mod lab;

use common::*;
use dare_remote_validation::capture::ScenarioRef;
use dare_remote_validation::gateway::{EgressGateway, OutboundRequest, TrustRoots};
use dare_remote_validation::plan::EngineKind;
use dare_remote_validation::protocol::Method;
use lab::{always, LabCa, LabReply, LabServer};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn proxy_variables_pointing_at_a_dead_port_do_not_affect_the_gateway() {
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // Port 9 (discard) on loopback: nothing listens there.
        std::env::set_var(name, "http://127.0.0.1:9");
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, always(LabReply::json(200, json!({"ok": true})))).await;
    let auth = authorization(
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
        json!({}),
    );
    let plan = plan(
        &auth,
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
    );
    let mut verified = verified(&auth, &plan, &server.origin);
    let mut gw = EgressGateway::new(
        &mut verified,
        &plan,
        &server.origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .unwrap();
    let reply = gw
        .send(OutboundRequest {
            method: Method::DareConversationTurn,
            body: Some(b"{}".to_vec()),
            scenario_ref: ScenarioRef {
                engine: EngineKind::PromptInjection,
                scenario_id: "PI-LAB-001".into(),
                conversation_id: None,
                node_id: None,
                step: Some(0),
            },
            challenge_expected: false,
        })
        .await
        .expect("send");
    assert_eq!(
        reply.status,
        Some(200),
        "went direct, not through the proxy"
    );
    assert_eq!(server.hits().len(), 1);
}
