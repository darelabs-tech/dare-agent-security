//! A run stops when its authorization window closes (rule 7, at send time).

mod common;
mod lab;

use common::*;
use dare_remote_validation::authorization::verify;
use dare_remote_validation::capture::ScenarioRef;
use dare_remote_validation::gateway::{EgressGateway, OutboundRequest, TrustRoots};
use dare_remote_validation::outcome::StopReason;
use dare_remote_validation::plan::EngineKind;
use dare_remote_validation::protocol::Method;
use dare_remote_validation::RemoteError;
use lab::{always, LabCa, LabReply, LabServer};
use serde_json::json;
use time::{Duration, OffsetDateTime};

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

#[tokio::test(flavor = "multi_thread")]
async fn no_request_leaves_after_the_window_closes() {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, always(LabReply::json(200, json!({})))).await;
    let mut auth = authorization(
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
        json!({}),
    );
    auth.not_after = stamp(Duration::seconds(2));
    let plan = plan(
        &auth,
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
    );
    let mut verified = verify(
        &auth,
        &plan,
        &server.origin,
        OffsetDateTime::now_utc(),
        &Fixed,
        &env,
    )
    .expect("verifies");
    let mut gw = EgressGateway::new(
        &mut verified,
        &plan,
        &server.origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .unwrap();
    gw.send(request(0)).await.expect("inside the window");
    tokio::time::sleep(std::time::Duration::from_millis(2_200)).await;
    assert!(matches!(
        gw.send(request(1)).await,
        Err(RemoteError::BudgetExhausted("window"))
    ));
    assert_eq!(server.hits().len(), 1);
    let (capture, _) = gw.finish(None).unwrap();
    assert_eq!(capture.stop_reason, StopReason::WindowExpired);
}
