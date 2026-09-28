//! Lab targets that answer exactly as the engines' simulated reference
//! agents answered offline (O-07), plus authorization/plan builders that use
//! the engines' real digests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dare_multi_turn_security::conversation::ConversationState;
use dare_multi_turn_security::corpus::{adapter_for, graph_set};
use dare_multi_turn_security::graph::StrategyNode;
use dare_multi_turn_security::harness::ConversationAdapter;
use dare_multi_turn_security::model::{HarnessMode, PolicyDecision};
use dare_multi_turn_security::observation::{RawHarnessError, RawTurnOutput};
use dare_prompt_injection::harness::{HarnessAdapter, RawTrialOutput, TrialRequest};
use dare_prompt_injection::observation::PolicyOutcome;
use dare_prompt_injection::simulated::SimulatedAdapter;
use dare_remote_validation::authorization::Authorization;
use dare_remote_validation::canonical::digest;
use dare_remote_validation::engines::{multi_turn, prompt_injection, Sources};
use dare_remote_validation::plan::{PlannedRun, RemotePlan};
use dare_remote_validation::runner::EngineDigests;
use dare_security_evidence::Verdict;
use serde_json::{json, Value};

use super::{stamp, TOKEN_ENV};
use crate::lab::{Handler, LabReply};

pub fn sources() -> Sources {
    Sources {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
    }
}

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
        "accepted_authority": out.accepted_authority.map_or(Value::Null, |a| serde_json::to_value(a).unwrap()),
        "actions": out.actions.iter().map(|a| json!({
            "action_id": a.action_id.as_str(), "action_class": a.action_class.as_str(), "executed": a.executed,
            "approval_ref": a.approval_ref.as_ref().map(|r| r.as_str()), "action_digest": a.action_digest,
            "required_authority": serde_json::to_value(a.required_authority).unwrap(), "argument_text": a.argument_text
        })).collect::<Vec<_>>()
    })
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

/// Answers keyed by (conversation, turn) for a set of scenarios.
#[derive(Default, Clone)]
pub struct Answers {
    multi_turn: BTreeMap<(String, u32), RawTurnOutput>,
    prompt_injection: BTreeMap<(String, u32), RawTrialOutput>,
}

impl Answers {
    /// Record the simulated agent of a multi-turn scenario; returns its
    /// offline verdict.
    pub fn multi_turn(&mut self, id: &str) -> Verdict {
        let loaded = multi_turn::load(id).expect("load");
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
        self.multi_turn.extend(log.lock().unwrap().clone());
        offline.verdict
    }

    /// Record the simulated agent of a prompt-injection scenario.
    pub fn prompt_injection(&mut self, id: &str) -> Verdict {
        let loaded = prompt_injection::load(&sources(), id).expect("load");
        let adapter = SimulatedAdapter::new(loaded.scenario.lab.as_ref().expect("lab").profile());
        let plan =
            dare_prompt_injection::trials::TrialPlan::from_scenario(&loaded.scenario).unwrap();
        let mut outputs = BTreeMap::new();
        for index in 0..plan.trials {
            let request = TrialRequest {
                trial_index: index,
                scenario: &loaded.scenario,
                entry: &loaded.entry,
            };
            outputs.insert((id.to_owned(), index), adapter.observe(&request).unwrap());
        }
        self.prompt_injection.extend(outputs);
        dare_prompt_injection::result::run_scenario(&loaded.scenario, &loaded.entry, &adapter, plan)
            .unwrap()
            .verdict
    }

    pub fn handler(self) -> Handler {
        Arc::new(move |hit| {
            let Ok(request) = serde_json::from_slice::<Value>(&hit.body) else {
                return LabReply::status(400);
            };
            let conversation = request["conversation_id"].as_str().unwrap_or("").to_owned();
            let turn = request["turn_index"].as_u64().unwrap_or(0) as u32;
            let key = (conversation.clone(), turn);
            if let Some(out) = self.multi_turn.get(&key) {
                LabReply::json(200, mt_reply(&conversation, turn, out))
            } else if let Some(out) = self.prompt_injection.get(&key) {
                LabReply::json(200, pi_reply(&conversation, turn, out))
            } else {
                LabReply::status(500)
            }
        })
    }
}

/// An authorization granting `runs` with their real digests, and the
/// matching plan.
pub fn real(
    origin: &str,
    protocol: &str,
    methods: &[&str],
    runs: &[(&str, &str, Option<&str>)],
    limits: Value,
    stop_on_first_fail: bool,
) -> (Authorization, RemotePlan) {
    let sources = sources();
    let digests = EngineDigests { sources: &sources };
    let grants: Vec<Value> = runs
        .iter()
        .map(|(engine, id, _)| {
            let run: PlannedRun = serde_json::from_value(json!({"engine": engine, "scenario_id": id, "scenario_digest": format!("sha256:{}", "0".repeat(64))})).unwrap();
            let mut grant = json!({"engine": engine, "scenario_id": id, "scenario_digest": digest_of(&digests, &run)});
            if *engine == "MULTI_TURN" {
                grant["graph_digests"] = serde_json::to_value(&multi_turn::load(id).unwrap().graph_digests).unwrap();
            }
            grant
        })
        .collect();
    let auth: Authorization = serde_json::from_value(json!({
        "schema_version": "1", "authorization_id": "lab-auth-1", "target_owner": "DARE REMOTE-LAB", "approved_by": "Product Owner",
        "environment": "LAB", "origins": [origin], "network_scope": "LOOPBACK_LAB",
        "not_before": stamp(time::Duration::hours(-1)), "not_after": stamp(time::Duration::hours(1)),
        "endpoints": {"conversation": "/dare/v1/turn", "a2a_rpc": "/a2a/v1", "mcp": "/mcp"},
        "protocols": [protocol], "methods": methods, "scenarios": grants,
        "data_classes": ["SYNTHETIC", "CANARY"], "credential_ref": TOKEN_ENV, "limits": limits,
        "prohibited": ["STATE_MUTATION", "CREDENTIAL_EXTRACTION", "DESTRUCTIVE_OPERATION", "EXTERNAL_PUBLICATION"]
    }))
    .expect("authorization");
    let plan_runs: Vec<Value> = auth
        .scenarios
        .iter()
        .zip(runs)
        .map(|(g, (_, _, policy))| {
            let mut run = serde_json::to_value(g).unwrap();
            if let Some(policy) = policy {
                run["a2a_policy_file"] = Value::from(*policy);
            }
            run
        })
        .collect();
    let plan: RemotePlan = serde_json::from_value(json!({
        "schema_version": "1", "plan_id": "lab-plan-1", "authorization_id": "lab-auth-1",
        "authorization_digest": digest(&auth).unwrap(), "origin": origin, "protocol": protocol,
        "methods": methods, "runs": plan_runs, "stop_on_first_fail": stop_on_first_fail
    }))
    .expect("plan");
    (auth, plan)
}

fn digest_of(digests: &EngineDigests<'_>, run: &PlannedRun) -> String {
    let loaded = dare_remote_validation::runner::LoadedRun::load(digests.sources, run).unwrap();
    loaded.digest().to_owned()
}
