//! Live pass + verdict pass for Cycles 013 and 021 against REMOTE-LAB targets
//! whose answers are the engines' own simulated reference agents (O-07).
//!
//! Each lab target replays, turn by turn, exactly what the engine's simulated
//! reference agent answered offline for the same scenario. The live verdict,
//! decided only from the capture, must then equal the offline verdict. Each
//! scenario is its own test so the 2 req/s limit does not serialize them.

mod common;
mod lab;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use common::*;
use dare_multi_turn_security::conversation::ConversationState;
use dare_multi_turn_security::corpus::{adapter_for, graph_set, Source};
use dare_multi_turn_security::graph::StrategyNode;
use dare_multi_turn_security::harness::ConversationAdapter;
use dare_multi_turn_security::model::{HarnessMode, PolicyDecision};
use dare_multi_turn_security::observation::{RawHarnessError, RawTurnOutput};
use dare_prompt_injection::harness::{HarnessAdapter, RawTrialOutput, TrialRequest};
use dare_prompt_injection::observation::PolicyOutcome;
use dare_prompt_injection::simulated::SimulatedAdapter;
use dare_remote_validation::capture::Capture;
use dare_remote_validation::engines::{multi_turn, prompt_injection, SharedGateway, Sources};
use dare_remote_validation::gateway::{EgressGateway, TrustRoots};
use dare_remote_validation::protocol::Protocol;
use dare_security_evidence::Verdict;
use lab::{Handler, LabCa, LabReply, LabServer};
use serde_json::{json, Value};

const TURN: &str = "DARE_CONVERSATION_TURN";

fn sources() -> Sources {
    Sources {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
    }
}

async fn gateway_for(ca: &LabCa, server: &LabServer) -> SharedGateway {
    let auth = authorization(&server.origin, "DARE_CONVERSATION", &[TURN], json!({}));
    let plan = plan(&auth, &server.origin, "DARE_CONVERSATION", &[TURN]);
    let mut verified = verified(&auth, &plan, &server.origin);
    Arc::new(tokio::sync::Mutex::new(
        EgressGateway::new(
            &mut verified,
            &plan,
            &server.origin,
            TrustRoots::LabRoot(ca.root.to_vec()),
        )
        .expect("gateway"),
    ))
}

fn finish(gateway: SharedGateway) -> Capture {
    let gateway = Arc::try_unwrap(gateway)
        .ok()
        .expect("sole owner")
        .into_inner();
    let (capture, audit) = gateway.finish(None).expect("finish");
    capture.verify().expect("capture chain");
    audit.verify(&capture).expect("audit chain");
    capture
}

fn authority(a: Option<dare_multi_turn_security::model::AuthorityLevel>) -> Value {
    a.map_or(Value::Null, |a| serde_json::to_value(a).unwrap())
}

// ---------------- multi-turn ----------------

struct Recording {
    inner: Box<dyn ConversationAdapter>,
    log: Arc<Mutex<BTreeMap<(String, u32), RawTurnOutput>>>,
}

impl ConversationAdapter for Recording {
    fn mode(&self) -> HarnessMode {
        self.inner.mode()
    }
    fn respond(
        &mut self,
        state: &ConversationState,
        node: &StrategyNode,
    ) -> Result<RawTurnOutput, RawHarnessError> {
        let out = self.inner.respond(state, node)?;
        self.log.lock().unwrap().insert(
            (
                state.conversation_id.as_str().to_owned(),
                state.turns.len() as u32,
            ),
            out.clone(),
        );
        Ok(out)
    }
}

fn mt_reply(conversation: &str, turn: u32, out: &RawTurnOutput) -> Value {
    json!({
        "schema_version": "1", "conversation_id": conversation, "turn_index": turn,
        "output_text": out.output_text, "refusal": out.refusal,
        "decision": out.decision.map(|d| match d { PolicyDecision::Allow => "ALLOW", PolicyDecision::Deny => "DENY" }),
        "fulfillment": serde_json::to_value(out.fulfillment).unwrap(),
        "accepted_authority": authority(out.accepted_authority),
        "actions": out.actions.iter().map(|a| json!({
            "action_id": a.action_id.as_str(), "action_class": a.action_class.as_str(), "executed": a.executed,
            "approval_ref": a.approval_ref.as_ref().map(|r| r.as_str()), "action_digest": a.action_digest,
            "required_authority": serde_json::to_value(a.required_authority).unwrap(), "argument_text": a.argument_text
        })).collect::<Vec<_>>()
    })
}

async fn multi_turn_parity(id: &str) {
    let loaded = multi_turn::load(id).expect("load");
    assert!(
        matches!(loaded.case.source, Source::Agent(_)),
        "{id} is agent-driven"
    );
    // Offline, with the engine's own simulated agent, recording its answers.
    let log = Arc::new(Mutex::new(BTreeMap::new()));
    let mut recorder = Recording {
        inner: adapter_for(&loaded.case, HarnessMode::Simulated).unwrap(),
        log: log.clone(),
    };
    let graphs = graph_set(&loaded.case).unwrap();
    let mut ledger = dare_multi_turn_security::budget::OutputLedger::new(
        loaded.case.scenario.effective_bounds().unwrap(),
    );
    let (offline, _) = dare_multi_turn_security::result::run_scenario(
        &loaded.case.scenario,
        &graphs,
        &mut recorder,
        &mut ledger,
        "offline",
    )
    .unwrap();

    // The lab target answers exactly as the simulated agent did.
    let answers = log.lock().unwrap().clone();
    let handler: Handler = Arc::new(move |hit| {
        let request: Value = serde_json::from_slice(&hit.body).unwrap();
        let conversation = request["conversation_id"].as_str().unwrap().to_owned();
        let turn = request["turn_index"].as_u64().unwrap() as u32;
        match answers.get(&(conversation.clone(), turn)) {
            Some(out) => LabReply::json(200, mt_reply(&conversation, turn, out)),
            None => LabReply::status(500),
        }
    });
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, handler).await;
    let gateway = gateway_for(&ca, &server).await;
    multi_turn::live(
        gateway.clone(),
        tokio::runtime::Handle::current(),
        &loaded,
        Protocol::DareConversation,
        "",
    )
    .expect("live pass");
    let capture = finish(gateway);
    let outcome =
        multi_turn::verdict(&capture, &loaded, Protocol::DareConversation, None).expect("verdict");
    assert_eq!(
        outcome.engine_verdict, offline.verdict,
        "{id}: live {:?} vs offline {:?}",
        outcome.engine_verdict, offline.verdict
    );
    assert_eq!(
        outcome.verdict, offline.verdict,
        "{id}: no transport outcome, so the final verdict is the engine's"
    );
    // Decided twice from the same capture: identical.
    let again = multi_turn::verdict(&capture, &loaded, Protocol::DareConversation, None).unwrap();
    assert_eq!(
        serde_json::to_vec(&outcome.result).unwrap(),
        serde_json::to_vec(&again.result).unwrap()
    );
    assert!(outcome
        .evidence
        .iter()
        .all(|e| dare_security_evidence::validate(e).is_ok()));
    if outcome.verdict == Verdict::Pass {
        assert!(
            !outcome.self_reported_fields.is_empty(),
            "{id}: a PASS over dare-conversation relies on self-reports"
        );
    }
}

macro_rules! mt {
    ($($name:ident => $id:literal),* $(,)?) => { $(
        #[tokio::test(flavor = "multi_thread")]
        async fn $name() { multi_turn_parity($id).await }
    )* };
}

mt! {
    mt_001_control_refusal => "multiturn-lab-001",
    mt_002_attack_eroding_refusal => "multiturn-lab-002",
    mt_005_gap_missing_edge => "multiturn-lab-005",
    mt_007_control_fragmentation => "multiturn-lab-007",
    mt_008_attack_fragmentation => "multiturn-lab-008",
    mt_013_control_grooming => "multiturn-lab-013",
    mt_014_attack_grooming => "multiturn-lab-014",
    mt_025_control_approval => "multiturn-lab-025",
    mt_026_attack_approval_swap => "multiturn-lab-026",
    mt_034_control_isolation => "multiturn-lab-034",
    mt_035_attack_isolation_leak => "multiturn-lab-035",
}

// ---------------- prompt injection ----------------

struct RecordingPi {
    inner: SimulatedAdapter,
    log: Arc<Mutex<BTreeMap<u32, RawTrialOutput>>>,
}

impl HarnessAdapter for RecordingPi {
    fn mode(&self) -> dare_prompt_injection::harness::HarnessMode {
        self.inner.mode()
    }
    fn observe(&self, request: &TrialRequest<'_>) -> dare_prompt_injection::Result<RawTrialOutput> {
        let out = self.inner.observe(request)?;
        self.log
            .lock()
            .unwrap()
            .insert(request.trial_index, out.clone());
        Ok(out)
    }
}

fn pi_reply(conversation: &str, turn: u32, out: &RawTrialOutput) -> Value {
    let outcome = |o: PolicyOutcome| match o {
        PolicyOutcome::Allow => "ALLOW",
        PolicyOutcome::Deny => "DENY",
        PolicyOutcome::NotEvaluated => "NOT_EVALUATED",
    };
    json!({
        "schema_version": "1", "conversation_id": conversation, "turn_index": turn,
        "output_text": out.output_text, "refusal": false, "decision": null,
        "fulfillment": "NO_FULFILLMENT", "accepted_authority": null,
        "goal_id": out.goal_id, "emitted_fields": out.emitted_fields,
        "policy_decisions": out.policy_decisions.iter().map(|d| json!({"operation": d.operation, "outcome": outcome(d.outcome)})).collect::<Vec<_>>(),
        "actions": out.actions.iter().enumerate().map(|(i, a)| json!({
            "action_id": format!("a{i}"), "action_class": a.action, "executed": true, "approval_ref": null,
            "action_digest": a.arguments_digest.clone().unwrap_or_else(|| format!("sha256:{}", "0".repeat(64))),
            "required_authority": "NONE", "argument_text": ""
        })).collect::<Vec<_>>()
    })
}

async fn prompt_injection_parity(id: &str) {
    let loaded = prompt_injection::load(&sources(), id).expect("load");
    let profile = loaded.scenario.lab.as_ref().expect("lab profile").profile();
    let log = Arc::new(Mutex::new(BTreeMap::new()));
    let recorder = RecordingPi {
        inner: SimulatedAdapter::new(profile),
        log: log.clone(),
    };
    let plan = dare_prompt_injection::trials::TrialPlan::from_scenario(&loaded.scenario).unwrap();
    let offline = dare_prompt_injection::result::run_scenario(
        &loaded.scenario,
        &loaded.entry,
        &recorder,
        plan,
    )
    .unwrap();
    let answers = log.lock().unwrap().clone();
    let handler: Handler = Arc::new(move |hit| {
        let request: Value = serde_json::from_slice(&hit.body).unwrap();
        let conversation = request["conversation_id"].as_str().unwrap().to_owned();
        let turn = request["turn_index"].as_u64().unwrap() as u32;
        match answers.get(&turn) {
            Some(out) => LabReply::json(200, pi_reply(&conversation, turn, out)),
            None => LabReply::status(500),
        }
    });
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, handler).await;
    let gateway = gateway_for(&ca, &server).await;
    prompt_injection::live(gateway.clone(), tokio::runtime::Handle::current(), &loaded)
        .expect("live pass");
    let capture = finish(gateway);
    let outcome = prompt_injection::verdict(&capture, &loaded, None).expect("verdict");
    assert_eq!(outcome.engine_verdict, offline.verdict, "{id}");
    assert_eq!(
        serde_json::to_value(&offline).unwrap()["trials_executed"],
        outcome.result["trials_executed"],
        "{id}"
    );
    assert!(outcome
        .evidence
        .iter()
        .all(|e| dare_security_evidence::validate(e).is_ok()));
    // The payload that went out is the vector, byte for byte.
    let sent: Value = serde_json::from_slice(&server.hits()[0].body).unwrap();
    assert_eq!(sent["content"], loaded.entry.content.payload.as_str());
}

macro_rules! pi {
    ($($name:ident => $id:literal),* $(,)?) => { $(
        #[tokio::test(flavor = "multi_thread")]
        async fn $name() { prompt_injection_parity($id).await }
    )* };
}

pi! {
    pi_001 => "PI-LAB-001",
    pi_002 => "PI-LAB-002",
    pi_008 => "PI-LAB-008",
    pi_010 => "PI-LAB-010",
}
