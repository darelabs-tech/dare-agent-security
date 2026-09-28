//! Replay equivalence (O-03). Every non-refusal REMOTE-LAB entry asserts
//! byte-identical replay in `remote_lab.rs::Lab::decided`; this file proves
//! the other half: any change to a stored capture or audit is refused.

mod common;
mod lab;

use common::sim::{real, sources, Answers};
use common::*;
use dare_remote_validation::gateway::TrustRoots;
use dare_remote_validation::runner::{replay_capture, run_remote, RemoteRun};
use dare_remote_validation::RemoteError;
use lab::{LabCa, LabServer};
use serde_json::{json, Value};
use time::OffsetDateTime;

async fn live() -> (
    RemoteRun,
    dare_remote_validation::authorization::Authorization,
    dare_remote_validation::plan::RemotePlan,
    tempfile::TempDir,
) {
    let mut answers = Answers::default();
    answers.multi_turn("multiturn-lab-001");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    std::env::set_var(TOKEN_ENV, TOKEN);
    let work = tempfile::tempdir().unwrap();
    let run = run_remote(
        &auth,
        &plan,
        &plan.origin,
        None,
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        work.path(),
    )
    .unwrap();
    (run, auth, plan, work)
}

#[tokio::test(flavor = "multi_thread")]
async fn every_field_of_every_entry_is_bound_by_the_chain() {
    let (run, auth, plan, work) = live().await;
    let original = serde_json::to_value(&run.capture).unwrap();
    let entries = original["entries"].as_array().unwrap().len();
    assert!(entries >= 2);
    let mut refused = 0;
    for index in 0..entries {
        for field in [
            "response_body",
            "request_digest",
            "status",
            "elapsed_ms",
            "method",
            "scenario_ref",
        ] {
            let mut value = original.clone();
            let slot = &mut value["entries"][index][field];
            *slot = match slot.clone() {
                Value::String(s) => Value::String(format!("{s}x")),
                Value::Number(n) => Value::from(n.as_u64().unwrap_or(0) + 1),
                Value::Object(mut o) => {
                    o.insert("step".into(), Value::from(99));
                    Value::Object(o)
                }
                other => other,
            };
            if field == "method" {
                value["entries"][index][field] = "A2A_TASKS_GET".into();
            }
            let Ok(capture) = serde_json::from_value(value) else {
                continue;
            };
            let result = replay_capture(
                &auth,
                &plan,
                &capture,
                &run.audit,
                None,
                &sources(),
                work.path(),
            );
            assert!(
                matches!(result, Err(RemoteError::CaptureTampered(i)) if i as usize == index),
                "{field}@{index}: {:?}",
                result.err()
            );
            refused += 1;
        }
    }
    assert!(refused >= entries * 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_audit_or_a_changed_header_is_refused() {
    let (run, auth, plan, work) = live().await;
    let mut audit = run.audit.clone();
    audit.events[1].status = Some(599);
    assert!(replay_capture(
        &auth,
        &plan,
        &run.capture,
        &audit,
        None,
        &sources(),
        work.path()
    )
    .is_err());
    let mut capture = run.capture.clone();
    capture.origin = "https://127.0.0.1:1".into();
    assert!(replay_capture(
        &auth,
        &plan,
        &capture,
        &run.audit,
        None,
        &sources(),
        work.path()
    )
    .is_err());
    let mut capture = run.capture.clone();
    capture.entries.pop();
    assert!(
        replay_capture(
            &auth,
            &plan,
            &capture,
            &run.audit,
            None,
            &sources(),
            work.path()
        )
        .is_err(),
        "a dropped entry no longer matches the audit totals"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_replays_of_one_capture_are_byte_identical() {
    let (run, auth, plan, work) = live().await;
    let first = serde_json::to_vec(&run.result).unwrap();
    for _ in 0..10 {
        let replay = replay_capture(
            &auth,
            &plan,
            &run.capture,
            &run.audit,
            None,
            &sources(),
            work.path(),
        )
        .unwrap();
        assert_eq!(serde_json::to_vec(&replay.result).unwrap(), first);
        assert_eq!(
            serde_json::to_vec(&replay.evidence).unwrap(),
            serde_json::to_vec(&run.evidence).unwrap()
        );
        let artifacts = replay.artifacts().unwrap();
        assert_eq!(artifacts.len(), 5);
    }
}
