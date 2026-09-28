//! `run_remote` end to end, and `replay_capture` equivalence (O-03).

mod common;
mod lab;

use std::collections::BTreeSet;

use common::sim::{real, sources, Answers};
use common::*;
use dare_remote_validation::capture::Capture;
use dare_remote_validation::gateway::TrustRoots;
use dare_remote_validation::outcome::StopReason;
use dare_remote_validation::result::{
    AUDIT_FILE, CAPTURE_FILE, EVIDENCE_FILE, RESULT_FILE, SUMMARY_FILE,
};
use dare_remote_validation::runner::{replay_capture, run_remote, RemoteRun};
use dare_remote_validation::RemoteError;
use dare_security_evidence::{ObservationSource, Verdict};
use lab::{LabCa, LabServer};
use serde_json::json;
use time::OffsetDateTime;

const TURN: &str = "DARE_CONVERSATION_TURN";

fn set_token() {
    std::env::set_var(TOKEN_ENV, TOKEN);
}

fn run(
    auth: &dare_remote_validation::authorization::Authorization,
    plan: &dare_remote_validation::plan::RemotePlan,
    ca: &LabCa,
    work: &std::path::Path,
) -> RemoteRun {
    set_token();
    run_remote(
        auth,
        plan,
        &plan.origin,
        None,
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        work,
    )
    .expect("run")
}

fn bytes(run: &RemoteRun) -> Vec<u8> {
    serde_json::to_vec(&run.result).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_live_run_and_its_replay_are_byte_identical_and_the_artifacts_are_clean() {
    let mut answers = Answers::default();
    let offline = answers.multi_turn("multiturn-lab-002");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-002", None)],
        json!({}),
        true,
    );
    let work = tempfile::tempdir().unwrap();
    let live = run(&auth, &plan, &ca, work.path());
    assert_eq!(live.result.verdict, offline);
    assert_eq!(live.result.verdict, Verdict::Fail, "an eroding refusal");

    let replay = replay_capture(
        &auth,
        &plan,
        &live.capture,
        &live.audit,
        None,
        &sources(),
        work.path(),
    )
    .unwrap();
    assert_eq!(bytes(&live), bytes(&replay), "O-03");
    for (kind, value) in [
        (
            dare_remote_validation::schema::DocumentKind::Result,
            serde_json::to_value(&live.result).unwrap(),
        ),
        (
            dare_remote_validation::schema::DocumentKind::Capture,
            serde_json::to_value(&live.capture).unwrap(),
        ),
        (
            dare_remote_validation::schema::DocumentKind::Audit,
            serde_json::to_value(&live.audit).unwrap(),
        ),
    ] {
        dare_remote_validation::schema::validate(&value, kind)
            .expect("each artifact validates against its schema");
    }
    assert_eq!(
        serde_json::to_vec(&live.evidence).unwrap(),
        serde_json::to_vec(&replay.evidence).unwrap()
    );

    let artifacts = live.artifacts().unwrap();
    let names: BTreeSet<&str> = artifacts.iter().map(|a| a.name).collect();
    assert_eq!(
        names,
        [
            RESULT_FILE,
            CAPTURE_FILE,
            EVIDENCE_FILE,
            AUDIT_FILE,
            SUMMARY_FILE
        ]
        .into()
    );
    for artifact in &artifacts {
        assert!(
            !String::from_utf8_lossy(&artifact.bytes).contains(TOKEN),
            "{}",
            artifact.name
        );
    }
    assert!(live
        .evidence
        .iter()
        .all(|e| e.observed.source == ObservationSource::ProtocolResponse));
    assert!(live
        .evidence
        .iter()
        .all(|e| dare_security_evidence::validate(e).is_ok()));
    let summary = String::from_utf8(
        artifacts
            .iter()
            .find(|a| a.name == SUMMARY_FILE)
            .unwrap()
            .bytes
            .clone(),
    )
    .unwrap();
    assert!(
        summary.contains("**FAIL**") && summary.contains("not a claim that the target is secure")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pass_says_which_target_reported_fields_it_relies_on() {
    let mut answers = Answers::default();
    assert_eq!(answers.multi_turn("multiturn-lab-001"), Verdict::Pass);
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    let work = tempfile::tempdir().unwrap();
    let live = run(&auth, &plan, &ca, work.path());
    assert_eq!(live.result.verdict, Verdict::Pass);
    assert!(live.result.runs[0].self_reported_fields.contains("refusal"));
    let summary = live
        .artifacts()
        .unwrap()
        .into_iter()
        .find(|a| a.name == SUMMARY_FILE)
        .unwrap();
    assert!(String::from_utf8(summary.bytes)
        .unwrap()
        .contains("PASS relies on target-reported `refusal`"));
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_first_failure_later_scenarios_are_never_sent() {
    let mut answers = Answers::default();
    // Distinct conversation ids, so the simulated answers cannot collide.
    assert_eq!(answers.prompt_injection("PI-LAB-002"), Verdict::Fail);
    answers.multi_turn("multiturn-lab-001");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[
            ("PROMPT_INJECTION", "PI-LAB-002", None),
            ("MULTI_TURN", "multiturn-lab-001", None),
        ],
        json!({}),
        true,
    );
    let work = tempfile::tempdir().unwrap();
    let live = run(&auth, &plan, &ca, work.path());
    assert_eq!(live.capture.stop_reason, StopReason::FirstFail);
    assert_eq!(live.result.runs[0].verdict, Verdict::Fail);
    assert_eq!(live.result.runs[1].unfinished, Some(StopReason::FirstFail));
    assert_eq!(live.result.runs[1].verdict, Verdict::Inconclusive);
    assert_eq!(live.result.runs[1].exchanges, 0);
    assert!(live
        .capture
        .entries
        .iter()
        .all(|e| e.scenario_ref.scenario_id == "PI-LAB-002"));
    let replay = replay_capture(
        &auth,
        &plan,
        &live.capture,
        &live.audit,
        None,
        &sources(),
        work.path(),
    )
    .unwrap();
    assert_eq!(bytes(&live), bytes(&replay));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budget_stop_leaves_the_running_scenario_inconclusive_never_pass() {
    let mut answers = Answers::default();
    assert_eq!(answers.multi_turn("multiturn-lab-004"), Verdict::Pass);
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-004", None)],
        json!({"max_requests": 2}),
        true,
    );
    let work = tempfile::tempdir().unwrap();
    let live = run(&auth, &plan, &ca, work.path());
    assert_eq!(server.hits().len(), 2);
    assert_eq!(live.capture.stop_reason, StopReason::BudgetExhausted);
    assert_eq!(
        live.result.runs[0].unfinished,
        Some(StopReason::BudgetExhausted)
    );
    assert_ne!(live.result.verdict, Verdict::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_refuses_a_tampered_capture_and_a_foreign_authorization() {
    let mut answers = Answers::default();
    answers.multi_turn("multiturn-lab-001");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    let work = tempfile::tempdir().unwrap();
    let live = run(&auth, &plan, &ca, work.path());

    let mut tampered: Capture = live.capture.clone();
    let body = tampered.entries[0].response_body.clone().unwrap();
    tampered.entries[0].response_body = Some(body.replacen("true", "fals", 1));
    assert!(matches!(
        replay_capture(
            &auth,
            &plan,
            &tampered,
            &live.audit,
            None,
            &sources(),
            work.path()
        ),
        Err(RemoteError::CaptureTampered(0))
    ));

    let mut other = auth.clone();
    other.target_owner = "Someone Else".into();
    assert!(matches!(
        replay_capture(
            &other,
            &plan,
            &live.capture,
            &live.audit,
            None,
            &sources(),
            work.path()
        ),
        Err(RemoteError::Refused(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_authorization_sends_nothing() {
    let answers = Answers::default();
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, mut plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    plan.runs[0].scenario_digest = D2.into();
    set_token();
    let work = tempfile::tempdir().unwrap();
    let refused = run_remote(
        &auth,
        &plan,
        &plan.origin,
        None,
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        work.path(),
    );
    assert!(matches!(refused, Err(RemoteError::Authorization(_))));
    assert!(server.hits().is_empty());
}
