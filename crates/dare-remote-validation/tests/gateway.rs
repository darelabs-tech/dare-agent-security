//! EgressGateway against the REMOTE-LAB: each step of BLUEPRINT §4.8.

mod common;
mod lab;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use dare_adversarial::KillTrigger;
use dare_remote_validation::address::NetworkScope;
use dare_remote_validation::capture::{EntryOutcome, ScenarioRef};
use dare_remote_validation::credential::REDACTED_CREDENTIAL;
use dare_remote_validation::error::EgressRefusal;
use dare_remote_validation::gateway::{EgressGateway, OutboundRequest, TrustRoots};
use dare_remote_validation::outcome::{StopReason, TransportOutcome};
use dare_remote_validation::plan::EngineKind;
use dare_remote_validation::protocol::Method;
use dare_remote_validation::resolver::PinnedResolver;
use dare_remote_validation::RemoteError;
use lab::{always, Handler, LabCa, LabReply, LabServer};
use serde_json::{json, Value};

const TURN: &str = "DARE_CONVERSATION_TURN";

fn request(step: u32, body: &[u8]) -> OutboundRequest {
    OutboundRequest {
        method: Method::DareConversationTurn,
        body: Some(body.to_vec()),
        scenario_ref: ScenarioRef {
            engine: EngineKind::PromptInjection,
            scenario_id: "PI-LAB-001".into(),
            conversation_id: None,
            node_id: None,
            step: Some(step),
        },
        challenge_expected: false,
    }
}

fn gateway(ca: &LabCa, origin: &str, limits: Value) -> EgressGateway {
    let auth = authorization(origin, "DARE_CONVERSATION", &[TURN], limits);
    let plan = plan(&auth, origin, "DARE_CONVERSATION", &[TURN]);
    let mut verified = verified(&auth, &plan, origin);
    EgressGateway::new(
        &mut verified,
        &plan,
        origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .expect("gateway")
}

async fn serve(ca: &LabCa, handler: Handler) -> LabServer {
    LabServer::start(ca, handler).await
}

fn ok() -> Handler {
    always(LabReply::json(200, json!({"ok": true})))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_reaches_the_authorized_path_with_only_the_fixed_headers() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{\"x\":1}")).await.expect("send");
    assert_eq!(reply.status, Some(200));
    assert_eq!(reply.transport, None);
    let hit = &server.hits()[0];
    assert_eq!(
        (hit.method.as_str(), hit.path.as_str()),
        ("POST", "/dare/v1/turn")
    );
    assert_eq!(
        hit.authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let allowed = [
        "accept",
        "user-agent",
        "content-type",
        "authorization",
        "host",
        "content-length",
    ];
    for name in &hit.header_names {
        assert!(allowed.contains(&name.as_str()), "unexpected header {name}");
    }
    let (capture, audit) = gw.finish(None).expect("finish");
    capture.verify().expect("capture chain");
    audit.verify(&capture).expect("audit chain");
    assert_eq!(capture.entries.len(), 1);
    assert_eq!(capture.stop_reason, StopReason::Completed);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_method_outside_the_plan_is_refused_before_anything_is_sent() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let mut req = request(0, b"{}");
    req.method = Method::A2aMessageSend;
    assert!(matches!(
        gw.send(req).await,
        Err(RemoteError::Egress(EgressRefusal::MethodNotPlanned))
    ));
    assert!(server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_request_is_refused_before_anything_is_sent() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({"max_request_bytes": 16}));
    assert!(matches!(
        gw.send(request(0, &[b'a'; 17])).await,
        Err(RemoteError::Egress(EgressRefusal::RequestTooLarge))
    ));
    assert!(server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_request_after_the_budget_is_never_sent() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({"max_requests": 2}));
    for step in 0..2 {
        gw.send(request(step, b"{}")).await.expect("within budget");
    }
    assert!(matches!(
        gw.send(request(2, b"{}")).await,
        Err(RemoteError::BudgetExhausted("requests"))
    ));
    assert_eq!(server.hits().len(), 2);
    assert_eq!(gw.stop_reason(), Some(StopReason::BudgetExhausted));
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_are_spaced_by_the_rate_limit() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    for step in 0..3 {
        gw.send(request(step, b"{}")).await.expect("send");
    }
    let hits = server.hits();
    for pair in hits.windows(2) {
        let gap = pair[1].at - pair[0].at;
        assert!(gap >= Duration::from_millis(495), "gap {gap:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_response_is_dropped_and_never_captured() {
    let ca = LabCa::generate();
    let big = LabReply {
        body: vec![b'x'; 5_000],
        ..LabReply::json(200, json!({}))
    };
    let server = serve(&ca, always(big)).await;
    let mut gw = gateway(&ca, &server.origin, json!({"max_response_bytes": 1000}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::Oversize));
    assert_eq!(reply.body, None);
    let (capture, _) = gw.finish(None).unwrap();
    assert_eq!(capture.entries[0].outcome, EntryOutcome::TransportError);
    assert_eq!(capture.entries[0].response_body, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_echoed_credential_is_scrubbed_and_kills_the_run() {
    let ca = LabCa::generate();
    let echo: Handler = Arc::new(|hit| LabReply::json(200, json!({"you_sent": hit.authorization})));
    let server = serve(&ca, echo).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    let body = reply.body.expect("body");
    assert!(!body.contains(TOKEN), "{body}");
    assert!(body.contains(REDACTED_CREDENTIAL));
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::SecretDetected))
    ));
    assert_eq!(server.hits().len(), 1, "the next request never left");
    let (capture, audit) = gw.finish(None).unwrap();
    let text = serde_json::to_string(&(&capture, &audit)).unwrap();
    assert!(!text.contains(TOKEN));
    assert_eq!(capture.stop_reason, StopReason::KillSwitch);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_not_followed_and_kills_the_run() {
    let ca = LabCa::generate();
    let elsewhere = serve(&ca, ok()).await;
    let location = format!("{}/stolen", elsewhere.origin);
    let server = serve(
        &ca,
        always(LabReply::status(302).with_header("location", &location)),
    )
    .await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.status, Some(302));
    assert_eq!(reply.transport, Some(TransportOutcome::ProtocolViolation));
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::UnexpectedTarget))
    ));
    assert!(
        elsewhere.hits().is_empty(),
        "0 bytes to the redirect target"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_for_another_name_is_a_tls_error() {
    let ca = LabCa::generate();
    let server = LabServer::start_with_names(&ca, &["wrong.example.test"], ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::Tls));
    assert!(server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_port_is_a_connection_error() {
    let ca = LabCa::generate();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let origin = format!("https://127.0.0.1:{port}");
    let mut gw = gateway(&ca, &origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::Connection));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resolution_to_a_forbidden_address_sends_nothing() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let origin = format!("https://localhost:{}", server.addr.port());
    let auth = authorization(&origin, "DARE_CONVERSATION", &[TURN], json!({}));
    let plan = plan(&auth, &origin, "DARE_CONVERSATION", &[TURN]);
    let mut verified = verified(&auth, &plan, &origin);
    // "localhost" answers with a private address: refused before connecting.
    let resolver = PinnedResolver::with_lookup("localhost", NetworkScope::LoopbackLab, |_| {
        vec!["10.0.0.7".parse().unwrap()]
    });
    let mut gw = EgressGateway::with_test_resolver(
        &mut verified,
        &plan,
        &origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
        resolver,
    )
    .unwrap();
    assert!(matches!(
        gw.send(request(0, b"{}")).await,
        Err(RemoteError::Egress(EgressRefusal::AddressNotPermitted))
    ));
    assert!(server.hits().is_empty());
    let (capture, _) = gw.finish(None).unwrap();
    assert!(capture.entries.is_empty(), "nothing was exchanged");
    assert_eq!(capture.stop_reason, StopReason::TransportError);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_hostname_is_used_for_every_request() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let origin = format!("https://localhost:{}", server.addr.port());
    let auth = authorization(&origin, "DARE_CONVERSATION", &[TURN], json!({}));
    let plan = plan(&auth, &origin, "DARE_CONVERSATION", &[TURN]);
    let mut verified = verified(&auth, &plan, &origin);
    let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = calls.clone();
    let resolver = PinnedResolver::with_lookup("localhost", NetworkScope::LoopbackLab, move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        vec!["127.0.0.1".parse().unwrap()]
    });
    let mut gw = EgressGateway::with_test_resolver(
        &mut verified,
        &plan,
        &origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
        resolver,
    )
    .unwrap();
    for step in 0..2 {
        assert_eq!(
            gw.send(request(step, b"{}")).await.unwrap().status,
            Some(200)
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "resolved once, pinned after"
    );
    let (capture, _) = gw.finish(None).unwrap();
    assert_eq!(capture.pinned_addresses, vec!["127.0.0.1".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn instability_stops_the_run_on_first_fail() {
    let ca = LabCa::generate();
    let server = serve(&ca, always(LabReply::status(503))).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::ServerError));
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::TargetInstability))
    ));
    assert_eq!(server.hits().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unexpected_401_kills_on_identity() {
    let ca = LabCa::generate();
    let server = serve(
        &ca,
        always(LabReply::status(401).with_header("www-authenticate", "Bearer realm=\"lab\"")),
    )
    .await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::UnexpectedAuth));
    assert_eq!(
        reply.www_authenticate.as_deref(),
        Some("Bearer realm=\"lab\"")
    );
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::UnexpectedIdentity))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operator_stop_flag_blocks_the_next_send() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    gw.send(request(0, b"{}")).await.unwrap();
    gw.operator_stop_flag().store(true, Ordering::SeqCst);
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::OperatorStop))
    ));
    assert_eq!(server.hits().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_during_the_rate_wait_keeps_the_request_from_leaving() {
    // At 2 rps the second send waits about 500 ms for its slot. The flag is
    // clear when the send starts and set while it waits.
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    gw.send(request(0, b"{}")).await.unwrap();
    let flag = gw.operator_stop_flag();
    let setter = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        flag.store(true, Ordering::SeqCst);
    });
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::OperatorStop))
    ));
    setter.await.unwrap();
    assert_eq!(server.hits().len(), 1, "nothing left after the stop");
    let (_, audit) = gw.finish(None).unwrap();
    assert!(serde_json::to_string(&audit)
        .unwrap()
        .contains("OPERATOR_STOP"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_held_flag_is_the_one_the_gateway_obeys() {
    let ca = LabCa::generate();
    let server = serve(&ca, ok()).await;
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut gw = gateway(&ca, &server.origin, json!({})).with_operator_stop(flag.clone());
    gw.send(request(0, b"{}")).await.unwrap();
    flag.store(true, Ordering::SeqCst);
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::OperatorStop))
    ));
    assert_eq!(server.hits().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn control_and_bidi_characters_in_a_response_are_neutralized() {
    let ca = LabCa::generate();
    let hostile = LabReply {
        body: "{\"t\":\"a\u{202e}b\"}".as_bytes().to_vec(),
        ..LabReply::json(200, json!({}))
    };
    let server = serve(&ca, always(hostile)).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.unwrap();
    assert_eq!(reply.body.as_deref(), Some("{\"t\":\"a\u{fffd}b\"}"));
    let (capture, _) = gw.finish(None).unwrap();
    assert_eq!(capture.entries[0].neutralized_chars, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_echoed_in_the_challenge_header_is_scrubbed_and_kills() {
    let ca = LabCa::generate();
    let echo: Handler = Arc::new(|hit| {
        LabReply::status(401).with_header(
            "www-authenticate",
            &format!(
                "Bearer error=\"invalid\", seen=\"{}\"",
                hit.authorization.clone().unwrap_or_default()
            ),
        )
    });
    let server = serve(&ca, echo).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    let challenge = reply.www_authenticate.expect("kept");
    assert!(
        !challenge.contains(TOKEN) && challenge.contains(REDACTED_CREDENTIAL),
        "{challenge}"
    );
    assert!(matches!(
        gw.send(request(1, b"{}")).await,
        Err(RemoteError::Killed(KillTrigger::SecretDetected))
    ));
    let (capture, audit) = gw.finish(None).unwrap();
    assert!(!serde_json::to_string(&(&capture, &audit))
        .unwrap()
        .contains(TOKEN));
    assert_eq!(capture.entries[0].scrubbed_credential, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_slower_than_the_read_timeout_is_a_timeout_never_a_pass() {
    let ca = LabCa::generate();
    let slow = LabReply::json(200, json!({"ok": true})).delayed(Duration::from_millis(16_000));
    let server = serve(&ca, always(slow)).await;
    let mut gw = gateway(&ca, &server.origin, json!({}));
    let started = std::time::Instant::now();
    let reply = gw.send(request(0, b"{}")).await.expect("recorded");
    assert_eq!(reply.transport, Some(TransportOutcome::ReadTimeout));
    assert!(
        started.elapsed() < Duration::from_millis(16_000),
        "the client gave up first"
    );
    assert_eq!(reply.body, None);
}
