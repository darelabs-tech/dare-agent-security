//! Prompt injection (Cycle 013) over `dare-conversation`.
//!
//! Live: each trial sends the vector's payload as one turn. Verdict: the
//! capture becomes a 013 transcript and the engine's `ReplayAdapter` decides.

use std::collections::BTreeSet;
use std::fs;

use dare_prompt_injection::canonical::{bind, scenario_digest};
use dare_prompt_injection::corpus::{builtin_corpus_root, load_corpus};
use dare_prompt_injection::evidence_bridge::build_evidence;
use dare_prompt_injection::harness::{
    HarnessAdapter, HarnessMode, RawAction, RawHarnessError, RawPolicyDecision, RawTrialOutput,
    TrialRequest,
};
use dare_prompt_injection::model::{CorpusEntry, PromptInjectionScenario};
use dare_prompt_injection::observation::{HarnessErrorKind, PolicyOutcome};
use dare_prompt_injection::replay::{ReplayAdapter, Transcript, TranscriptTrial};
use dare_prompt_injection::result::run_scenario;
use dare_prompt_injection::schema::{enforce_document_size, validate_scenario_document};
use dare_prompt_injection::trials::TrialPlan;

use crate::capture::{Capture, ScenarioRef};
use crate::engines::{
    block_on, entries_for, evidence_time, final_verdict, first_transport, EngineOutcome,
    SharedGateway, Sources, DEFAULT_PRINCIPAL,
};
use crate::error::{RemoteError, Result};
use crate::outcome::{StopReason, TransportOutcome};
use crate::plan::EngineKind;
use crate::protocol::conversation::{
    parse_reply, send_turn, ConversationReply, ConversationTurn, ReplyDecision, ReplyPolicyOutcome,
};

/// A loaded scenario and its vector.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub scenario: PromptInjectionScenario,
    pub entry: CorpusEntry,
    pub digest: String,
}

fn engine(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Engine(format!("prompt-injection: {error}"))
}

/// Load a built-in scenario by id, as `validate prompt-injection` does.
pub fn load(sources: &Sources, id: &str) -> Result<Loaded> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(RemoteError::Refused(
            "a prompt-injection scenario id is uppercase with dashes",
        ));
    }
    let path = sources
        .root
        .join("fixtures/prompt-injection/scenarios")
        .join(format!("{id}.json"));
    let raw = fs::read(&path)
        .map_err(|_| RemoteError::Refused("the prompt-injection scenario is not available"))?;
    enforce_document_size(&raw, "scenario").map_err(engine)?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| RemoteError::Refused("scenario is not JSON"))?;
    validate_scenario_document(&value).map_err(engine)?;
    let scenario: PromptInjectionScenario = serde_json::from_value(value).map_err(engine)?;
    let corpus = load_corpus(&builtin_corpus_root()).map_err(engine)?;
    let entry = corpus
        .get(&scenario.vector.corpus_id)
        .cloned()
        .ok_or_else(|| engine("vector not in the corpus"))?;
    let digest = scenario_digest(&scenario).map_err(engine)?;
    Ok(Loaded {
        scenario,
        entry,
        digest,
    })
}

/// The conversation reply as 013's raw output.
pub fn to_trial_output(reply: &ConversationReply) -> RawTrialOutput {
    // Per-operation decisions when the target reports them; otherwise the
    // single turn decision, recorded against the operation "turn".
    let policy_decisions = if reply.policy_decisions.is_empty() {
        reply
            .decision
            .map(|d| RawPolicyDecision {
                operation: "turn".to_owned(),
                outcome: match d {
                    ReplyDecision::Allow => PolicyOutcome::Allow,
                    ReplyDecision::Deny => PolicyOutcome::Deny,
                },
                policy_id: None,
            })
            .into_iter()
            .collect()
    } else {
        reply
            .policy_decisions
            .iter()
            .map(|d| RawPolicyDecision {
                operation: d.operation.clone(),
                outcome: match d.outcome {
                    ReplyPolicyOutcome::Allow => PolicyOutcome::Allow,
                    ReplyPolicyOutcome::Deny => PolicyOutcome::Deny,
                    ReplyPolicyOutcome::NotEvaluated => PolicyOutcome::NotEvaluated,
                },
                policy_id: None,
            })
            .collect()
    };
    RawTrialOutput {
        output_text: reply.output_text.clone(),
        goal_id: reply.goal_id.clone(),
        actions: reply
            .actions
            .iter()
            .map(|a| RawAction {
                action: a.action_class.clone(),
                arguments_digest: Some(a.action_digest.clone()),
            })
            .collect(),
        policy_decisions,
        emitted_fields: reply.emitted_fields.clone(),
        harness_error: None,
    }
}

fn failure(outcome: TransportOutcome) -> RawTrialOutput {
    RawTrialOutput {
        output_text: None,
        goal_id: None,
        actions: Vec::new(),
        policy_decisions: Vec::new(),
        emitted_fields: Vec::new(),
        harness_error: Some(RawHarnessError {
            kind: match outcome {
                TransportOutcome::ConnectTimeout | TransportOutcome::ReadTimeout => {
                    HarnessErrorKind::Timeout
                }
                TransportOutcome::ProtocolViolation => HarnessErrorKind::SchemaViolation,
                _ => HarnessErrorKind::AdapterFailure,
            },
            detail: outcome.as_str().to_owned(),
        }),
    }
}

/// Sends each trial through the gateway. Its results are never a verdict.
pub struct LiveTrialAdapter {
    pub gateway: SharedGateway,
    pub handle: tokio::runtime::Handle,
    pub loaded: Loaded,
}

impl HarnessAdapter for LiveTrialAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn observe(&self, request: &TrialRequest<'_>) -> dare_prompt_injection::Result<RawTrialOutput> {
        let turn = ConversationTurn {
            conversation_id: self.loaded.scenario.id.clone(),
            turn_index: request.trial_index,
            principal_id: DEFAULT_PRINCIPAL.to_owned(),
            content: self.loaded.entry.content.payload.clone(),
        };
        let scenario_ref = ScenarioRef {
            engine: EngineKind::PromptInjection,
            scenario_id: self.loaded.scenario.id.clone(),
            conversation_id: None,
            node_id: None,
            step: Some(request.trial_index),
        };
        let sent = block_on(&self.handle, async {
            let mut gateway = self.gateway.lock().await;
            send_turn(&mut gateway, &turn, scenario_ref).await
        });
        Ok(match sent {
            Ok((_, Ok(reply))) => to_trial_output(&reply),
            Ok((_, Err(outcome))) => failure(outcome),
            // Nothing was sent (budget, kill, window): the verdict pass sees
            // the missing trial and the unfinished-run rule applies.
            Err(_) => failure(TransportOutcome::Connection),
        })
    }
}

/// Drive the engine live. The engine's result is discarded.
pub fn live(gateway: SharedGateway, handle: tokio::runtime::Handle, loaded: &Loaded) -> Result<()> {
    let plan = TrialPlan::from_scenario(&loaded.scenario).map_err(engine)?;
    let adapter = LiveTrialAdapter {
        gateway,
        handle,
        loaded: loaded.clone(),
    };
    let _discarded =
        run_scenario(&loaded.scenario, &loaded.entry, &adapter, plan).map_err(engine)?;
    Ok(())
}

/// The 013 transcript a capture describes.
pub fn transcript(capture: &Capture, loaded: &Loaded) -> Transcript {
    let id = &loaded.scenario.id;
    let trials = entries_for(capture, EngineKind::PromptInjection, id)
        .filter_map(|entry| {
            let index = entry.scenario_ref.step?;
            let output = match entry.transport_error {
                Some(outcome) => failure(outcome),
                None => match parse_reply(entry.response_body.as_deref(), id, index) {
                    Ok(reply) => to_trial_output(&reply),
                    Err(outcome) => failure(outcome),
                },
            };
            Some(TranscriptTrial {
                index,
                output_text: output.output_text,
                goal_id: output.goal_id,
                actions: output.actions,
                policy_decisions: output.policy_decisions,
                emitted_fields: output.emitted_fields,
                harness_error: output.harness_error,
            })
        })
        .collect();
    Transcript {
        schema_version: "1".to_owned(),
        scenario_id: id.clone(),
        recorded_at: Some(capture.started_at.clone()),
        note: Some(format!("live capture {}", capture.capture_id)),
        trials,
    }
}

/// Decide from the capture alone.
pub fn verdict(
    capture: &Capture,
    loaded: &Loaded,
    unfinished: Option<StopReason>,
) -> Result<EngineOutcome> {
    let plan = TrialPlan::from_scenario(&loaded.scenario).map_err(engine)?;
    let adapter = ReplayAdapter::new(transcript(capture, loaded));
    adapter.bind_scenario(&loaded.scenario.id).map_err(engine)?;
    let result = run_scenario(&loaded.scenario, &loaded.entry, &adapter, plan).map_err(engine)?;
    let binding = bind(&loaded.scenario, &loaded.entry).map_err(engine)?;
    let evidence = build_evidence(
        &loaded.scenario,
        &loaded.entry,
        &binding,
        &result,
        evidence_time(capture),
    )
    .map_err(engine)?;
    let transport = first_transport(capture, EngineKind::PromptInjection, &loaded.scenario.id);
    let engine_verdict = result.verdict;
    let verdict = final_verdict(engine_verdict, transport, unfinished);
    // 013 reads the target's goal, emitted fields and policy decisions, all
    // self-reported (Review BQ-2).
    let mut self_reported = BTreeSet::new();
    if verdict == dare_security_evidence::Verdict::Pass {
        for entry in entries_for(capture, EngineKind::PromptInjection, &loaded.scenario.id) {
            if let Ok(reply) = parse_reply(
                entry.response_body.as_deref(),
                &loaded.scenario.id,
                entry.scenario_ref.step.unwrap_or(0),
            ) {
                if reply.decision.is_some() || !reply.policy_decisions.is_empty() {
                    self_reported.insert("policy_decisions");
                }
                if reply.goal_id.is_some() {
                    self_reported.insert("goal_id");
                }
                if !reply.emitted_fields.is_empty() {
                    self_reported.insert("emitted_fields");
                }
            }
        }
    }
    Ok(EngineOutcome {
        engine: EngineKind::PromptInjection,
        scenario_id: loaded.scenario.id.clone(),
        engine_verdict,
        verdict,
        transport,
        unfinished,
        self_reported_fields: self_reported,
        not_observable: Vec::new(),
        result: serde_json::to_value(&result)
            .map_err(|_| RemoteError::Serialization("prompt-injection result"))?,
        evidence,
    })
}
