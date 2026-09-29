//! Rate and budget at the gateway (BLUEPRINT §7.3).

mod common;
mod lab;

use common::*;
use dare_remote_validation::capture::ScenarioRef;
use dare_remote_validation::control::{request_step, RemoteBudget};
use dare_remote_validation::gateway::{EgressGateway, OutboundRequest, TrustRoots};
use dare_remote_validation::limits::{EffectiveLimits, MAX_REQUESTS};
use dare_remote_validation::outcome::StopReason;
use dare_remote_validation::plan::EngineKind;
use dare_remote_validation::protocol::Method;
use dare_remote_validation::RemoteError;
use lab::{always, LabCa, LabReply, LabServer};
use serde_json::json;
use std::time::Duration;

fn request(step: u32) -> OutboundRequest {
    OutboundRequest {
        method: Method::DareConversationTurn,
        body: Some(b"{}".to_vec()),
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

async fn gateway(limits: serde_json::Value) -> (LabServer, EgressGateway) {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, always(LabReply::json(200, json!({})))).await;
    let auth = authorization(
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
        limits,
    );
    let plan = plan(
        &auth,
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
    );
    let mut verified = verified(&auth, &plan, &server.origin);
    let gw = EgressGateway::new(
        &mut verified,
        &plan,
        &server.origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .unwrap();
    (server, gw)
}

/// Arrival-time jitter the lab server may add to one request: TLS handshake
/// and scheduling on a loaded CI runner. The limiter spaces the *sends*; the
/// server sees *arrivals*, so a late arrival shortens one gap and lengthens
/// the next by the same amount (Cycle 025 R-11: observed up to ~12 ms under
/// load, on `main` as on the PR). A burst would put gaps near zero.
const ARRIVAL_JITTER: Duration = Duration::from_millis(25);

#[tokio::test(flavor = "multi_thread")]
async fn at_two_per_second_consecutive_requests_are_at_least_500_ms_apart() {
    let (server, mut gw) = gateway(json!({"max_rps": 2})).await;
    for step in 0..5 {
        gw.send(request(step)).await.unwrap();
    }
    let hits = server.hits();
    assert_eq!(hits.len(), 5);
    let interval = Duration::from_millis(500);
    // No burst: every gap is the interval, less at most one arrival's jitter.
    for pair in hits.windows(2) {
        assert!(
            pair[1].at - pair[0].at >= interval - ARRIVAL_JITTER,
            "{:?}",
            pair[1].at - pair[0].at
        );
    }
    // No drift: jitter cancels between neighbours, so the whole run spans
    // four intervals, less at most one arrival's jitter. A limiter that is
    // systematically fast by more than ~6 ms per request fails here.
    let span = hits[4].at - hits[0].at;
    assert!(span >= interval * 4 - ARRIVAL_JITTER, "{span:?}");
}

#[test]
fn request_501_is_never_admitted() {
    let mut budget = RemoteBudget::new(&EffectiveLimits::HARD);
    let step = request_step("DARE_CONVERSATION_TURN", "DareConversation", 16);
    for _ in 0..MAX_REQUESTS {
        budget.check(&step).expect("within the hard ceiling");
        budget.consume(&step, 0);
    }
    assert_eq!(budget.requests(), 500);
    assert!(matches!(
        budget.check(&step),
        Err(RemoteError::BudgetExhausted("requests"))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_duration_limit_stops_the_run_before_the_next_slot() {
    let (server, mut gw) = gateway(json!({"max_rps": 2, "max_duration_s": 1})).await;
    let mut sent = 0;
    for step in 0..5 {
        match gw.send(request(step)).await {
            Ok(_) => sent += 1,
            Err(error) => {
                assert!(
                    matches!(error, RemoteError::BudgetExhausted(_)),
                    "{error:?}"
                );
                break;
            }
        }
    }
    assert_eq!(
        sent, 2,
        "slots at 0 and 500 ms; the 1000 ms slot is the deadline"
    );
    assert_eq!(server.hits().len(), 2);
    assert_eq!(gw.stop_reason(), Some(StopReason::BudgetExhausted));
}
