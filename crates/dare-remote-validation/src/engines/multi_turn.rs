//! Adaptive multi-turn (Cycle 021) over `dare-conversation` or A2A.
//!
//! Live: the engine's own runner walks the strategy graph, and each node it
//! selects is sent through the gateway, so the next node depends on the real
//! reply. Verdict: the capture becomes a 021 transcript, one recorded turn per
//! captured exchange naming the node it answered, and the engine's
//! `ReplayAdapter` re-walks the graph offline. A recorded node that differs
//! from the node the graph selects is a strategy fault, never a verdict.

use std::collections::{BTreeMap, BTreeSet};

use dare_multi_turn_security::budget::OutputLedger;
use dare_multi_turn_security::canonical::digest as mt_digest;
use dare_multi_turn_security::conversation::ConversationState;
use dare_multi_turn_security::corpus::{entry_by_id, graph_set, LabCase};
use dare_multi_turn_security::evidence_bridge::build_evidence;
use dare_multi_turn_security::graph::StrategyNode;
use dare_multi_turn_security::harness::ConversationAdapter;
use dare_multi_turn_security::ids::{ActionId, ApprovalId, ClassId, ConversationId, NodeId};
use dare_multi_turn_security::model::{
    AuthorityLevel, Fulfillment, GraphSet, HarnessMode, PolicyDecision,
};
use dare_multi_turn_security::observation::{
    ActionRecord, HarnessErrorKind, RawHarnessError, RawTurnOutput,
};
use dare_multi_turn_security::replay::{
    RecordedConversation, RecordedTurn, ReplayAdapter, Transcript,
};
use dare_multi_turn_security::result::run_scenario;

use crate::capture::{Capture, ScenarioRef};
use crate::engines::{
    block_on, entries_for, evidence_time, final_verdict, first_transport, EngineOutcome,
    SharedGateway,
};
use crate::error::{RemoteError, Result};
use crate::outcome::{StopReason, TransportOutcome};
use crate::plan::EngineKind;
use crate::protocol::a2a;
use crate::protocol::conversation::{
    parse_reply, send_turn, ConversationReply, ConversationTurn, ReplyAuthority, ReplyDecision,
    ReplyFulfillment,
};
use crate::protocol::Protocol;

/// A loaded MULTITURN-LAB case.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub case: LabCase,
    pub digest: String,
    pub graph_digests: BTreeSet<String>,
}

fn engine(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Engine(format!("multi-turn: {error}"))
}

/// Load a MULTITURN-LAB case by corpus id.
pub fn load(id: &str) -> Result<Loaded> {
    let entry = entry_by_id(id).ok_or(RemoteError::Refused(
        "the multi-turn corpus has no such entry",
    ))?;
    let case = entry.case();
    let digest = mt_digest(&case.scenario).map_err(engine)?;
    let graph_digests = case
        .scenario
        .conversations
        .iter()
        .map(|c| c.graph_digest.clone())
        .collect();
    Ok(Loaded {
        case,
        digest,
        graph_digests,
    })
}

fn graphs(loaded: &Loaded) -> Result<GraphSet> {
    graph_set(&loaded.case).map_err(engine)
}

fn authority(value: ReplyAuthority) -> AuthorityLevel {
    match value {
        ReplyAuthority::None => AuthorityLevel::None,
        ReplyAuthority::Read => AuthorityLevel::Read,
        ReplyAuthority::Write => AuthorityLevel::Write,
        ReplyAuthority::Admin => AuthorityLevel::Admin,
    }
}

/// The conversation reply as 021's raw output. An identifier the engine's
/// grammar refuses makes the reply a protocol violation.
pub fn to_turn_output(
    reply: &ConversationReply,
) -> std::result::Result<RawTurnOutput, TransportOutcome> {
    let bad = |_| TransportOutcome::ProtocolViolation;
    let actions = reply
        .actions
        .iter()
        .map(|a| {
            Ok(ActionRecord {
                action_id: ActionId::new(a.action_id.clone()).map_err(bad)?,
                action_class: ClassId::new(a.action_class.clone()).map_err(bad)?,
                executed: a.executed,
                approval_ref: a
                    .approval_ref
                    .clone()
                    .map(ApprovalId::new)
                    .transpose()
                    .map_err(bad)?,
                action_digest: a.action_digest.clone(),
                required_authority: authority(a.required_authority),
                argument_text: a.argument_text.clone(),
            })
        })
        .collect::<std::result::Result<Vec<_>, TransportOutcome>>()?;
    Ok(RawTurnOutput {
        output_text: reply.output_text.clone(),
        refusal: reply.refusal,
        decision: reply.decision.map(|d| match d {
            ReplyDecision::Allow => PolicyDecision::Allow,
            ReplyDecision::Deny => PolicyDecision::Deny,
        }),
        fulfillment: match reply.fulfillment {
            ReplyFulfillment::Full => Fulfillment::Full,
            ReplyFulfillment::Partial => Fulfillment::Partial,
            ReplyFulfillment::NoFulfillment => Fulfillment::NoFulfillment,
        },
        accepted_authority: reply.accepted_authority.map(authority),
        actions,
        harness_error: None,
    })
}

/// An A2A reply as 021's raw output: text only. A2A carries no refusal,
/// fulfillment or authority report, so invariants that need them can at most
/// be inconclusive over A2A.
pub fn a2a_turn_output(reply: &a2a::A2aReply) -> RawTurnOutput {
    RawTurnOutput {
        output_text: reply.text(),
        refusal: false,
        decision: None,
        fulfillment: Fulfillment::NoFulfillment,
        accepted_authority: None,
        actions: Vec::new(),
        harness_error: None,
    }
}

fn harness_failure() -> RawTurnOutput {
    RawTurnOutput {
        output_text: None,
        refusal: false,
        decision: None,
        fulfillment: Fulfillment::NoFulfillment,
        accepted_authority: None,
        actions: Vec::new(),
        harness_error: Some(RawHarnessError {
            kind: HarnessErrorKind::AdapterFailure,
        }),
    }
}

/// Parse one captured exchange the way the live pass did.
pub fn captured_output(
    protocol: Protocol,
    body: Option<&str>,
    transport: Option<TransportOutcome>,
    conversation: &str,
    turn: u32,
    rpc_id: u64,
) -> RawTurnOutput {
    if transport.is_some() {
        return harness_failure();
    }
    match protocol {
        Protocol::A2a => a2a::parse_reply(body, rpc_id)
            .map(|r| a2a_turn_output(&r))
            .unwrap_or_else(|_| harness_failure()),
        _ => parse_reply(body, conversation, turn)
            .and_then(|r| to_turn_output(&r))
            .unwrap_or_else(|_| harness_failure()),
    }
}

/// The JSON-RPC id of a conversation turn over A2A: deterministic, so the
/// verdict pass can match replies without the live pass's state.
pub fn a2a_rpc_id(conversation_index: usize, turn: u32) -> u64 {
    (conversation_index as u64 + 1) * 1_000 + u64::from(turn)
}

/// Walks the graph live. Its results are never a verdict.
pub struct LiveConversationAdapter {
    pub gateway: SharedGateway,
    pub handle: tokio::runtime::Handle,
    pub scenario_id: String,
    pub protocol: Protocol,
    /// A2A only: the protocol version the card declared.
    pub a2a_version: String,
    pub conversation_index: BTreeMap<String, usize>,
}

impl ConversationAdapter for LiveConversationAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn respond(
        &mut self,
        state: &ConversationState,
        node: &StrategyNode,
    ) -> std::result::Result<RawTurnOutput, RawHarnessError> {
        let conversation = state.conversation_id.as_str().to_owned();
        let turn = u32::try_from(state.turns.len()).map_err(|_| RawHarnessError {
            kind: HarnessErrorKind::AdapterFailure,
        })?;
        let scenario_ref = ScenarioRef {
            engine: EngineKind::MultiTurn,
            scenario_id: self.scenario_id.clone(),
            conversation_id: Some(conversation.clone()),
            node_id: Some(node.id.as_str().to_owned()),
            step: Some(turn),
        };
        let index = self
            .conversation_index
            .get(&conversation)
            .copied()
            .unwrap_or(0);
        let output = match self.protocol {
            Protocol::A2a => {
                let id = a2a_rpc_id(index, turn);
                let sent = block_on(&self.handle, async {
                    let mut gateway = self.gateway.lock().await;
                    a2a::send_message(
                        &mut gateway,
                        &self.a2a_version,
                        id,
                        &format!("{conversation}-{turn}"),
                        &conversation,
                        &node.turn.content,
                        scenario_ref,
                    )
                    .await
                });
                match sent {
                    Ok((_, Ok(reply))) => a2a_turn_output(&reply),
                    _ => {
                        return Err(RawHarnessError {
                            kind: HarnessErrorKind::AdapterFailure,
                        })
                    }
                }
            }
            _ => {
                let request = ConversationTurn {
                    conversation_id: conversation.clone(),
                    turn_index: turn,
                    principal_id: state.principal.principal_id.as_str().to_owned(),
                    content: node.turn.content.clone(),
                };
                let sent = block_on(&self.handle, async {
                    let mut gateway = self.gateway.lock().await;
                    send_turn(&mut gateway, &request, scenario_ref).await
                });
                match sent {
                    Ok((_, Ok(reply))) => to_turn_output(&reply).map_err(|_| RawHarnessError {
                        kind: HarnessErrorKind::AdapterFailure,
                    })?,
                    _ => {
                        return Err(RawHarnessError {
                            kind: HarnessErrorKind::AdapterFailure,
                        })
                    }
                }
            }
        };
        Ok(output)
    }
}

fn conversation_index(loaded: &Loaded) -> BTreeMap<String, usize> {
    loaded
        .case
        .scenario
        .conversations
        .iter()
        .enumerate()
        .map(|(i, c)| (c.conversation_id.as_str().to_owned(), i))
        .collect()
}

/// Drive the engine live. The engine's result is discarded.
pub fn live(
    gateway: SharedGateway,
    handle: tokio::runtime::Handle,
    loaded: &Loaded,
    protocol: Protocol,
    a2a_version: &str,
) -> Result<()> {
    let graphs = graphs(loaded)?;
    let mut ledger = OutputLedger::new(loaded.case.scenario.effective_bounds().map_err(engine)?);
    let mut adapter = LiveConversationAdapter {
        gateway,
        handle,
        scenario_id: loaded.case.scenario.id.as_str().to_owned(),
        protocol,
        a2a_version: a2a_version.to_owned(),
        conversation_index: conversation_index(loaded),
    };
    let _discarded = run_scenario(
        &loaded.case.scenario,
        &graphs,
        &mut adapter,
        &mut ledger,
        "live-pass",
    )
    .map_err(engine)?;
    Ok(())
}

/// The 021 transcript a capture describes.
pub fn transcript(capture: &Capture, loaded: &Loaded, protocol: Protocol) -> Result<Transcript> {
    let scenario_id = loaded.case.scenario.id.as_str();
    let index = conversation_index(loaded);
    let mut conversations: BTreeMap<String, Vec<RecordedTurn>> = loaded
        .case
        .scenario
        .conversations
        .iter()
        .map(|c| (c.conversation_id.as_str().to_owned(), Vec::new()))
        .collect();
    for entry in entries_for(capture, EngineKind::MultiTurn, scenario_id) {
        let (Some(conversation), Some(node), Some(turn)) = (
            &entry.scenario_ref.conversation_id,
            &entry.scenario_ref.node_id,
            entry.scenario_ref.step,
        ) else {
            return Err(RemoteError::CaptureTampered(entry.index));
        };
        let rpc_id = a2a_rpc_id(index.get(conversation).copied().unwrap_or(0), turn);
        let output = captured_output(
            protocol,
            entry.response_body.as_deref(),
            entry.transport_error,
            conversation,
            turn,
            rpc_id,
        );
        conversations
            .entry(conversation.clone())
            .or_default()
            .push(RecordedTurn {
                index: turn,
                node_id: NodeId::new(node.clone())
                    .map_err(|_| RemoteError::CaptureTampered(entry.index))?,
                output,
                chain_digest: None,
            });
    }
    Ok(Transcript {
        schema_version: "1".to_owned(),
        graph_digests: loaded.graph_digests.clone(),
        conversations: conversations
            .into_iter()
            .map(|(id, turns)| {
                Ok(RecordedConversation {
                    conversation_id: ConversationId::new(id).map_err(engine)?,
                    turns,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Decide from the capture alone.
pub fn verdict(
    capture: &Capture,
    loaded: &Loaded,
    protocol: Protocol,
    unfinished: Option<StopReason>,
) -> Result<EngineOutcome> {
    let graphs = graphs(loaded)?;
    let mut ledger = OutputLedger::new(loaded.case.scenario.effective_bounds().map_err(engine)?);
    let transcript = transcript(capture, loaded, protocol)?;
    let (result, engine_verdict) = match ReplayAdapter::new(transcript, &loaded.case.scenario) {
        Ok(mut adapter) => {
            let (result, _) = run_scenario(
                &loaded.case.scenario,
                &graphs,
                &mut adapter,
                &mut ledger,
                &capture.ended_at,
            )
            .map_err(engine)?;
            let verdict = result.verdict;
            (Some(result), verdict)
        }
        // A capture that cannot bind (a conversation never started) is not
        // evidence of anything.
        Err(_) => (None, dare_security_evidence::Verdict::Inconclusive),
    };
    let evidence = match &result {
        Some(result) => build_evidence(result, evidence_time(capture)).map_err(engine)?,
        None => Vec::new(),
    };
    let scenario_id = loaded.case.scenario.id.as_str();
    let transport = first_transport(capture, EngineKind::MultiTurn, scenario_id);
    let verdict = final_verdict(engine_verdict, transport, unfinished);
    let mut self_reported = BTreeSet::new();
    if verdict == dare_security_evidence::Verdict::Pass && protocol != Protocol::A2a {
        for entry in entries_for(capture, EngineKind::MultiTurn, scenario_id) {
            let conversation = entry.scenario_ref.conversation_id.as_deref().unwrap_or("");
            if let Ok(reply) = parse_reply(
                entry.response_body.as_deref(),
                conversation,
                entry.scenario_ref.step.unwrap_or(0),
            ) {
                if reply.refusal {
                    self_reported.insert("refusal");
                }
                if reply.decision.is_some() {
                    self_reported.insert("decision");
                }
                if reply.fulfillment != ReplyFulfillment::NoFulfillment {
                    self_reported.insert("fulfillment");
                }
                if reply.accepted_authority.is_some() {
                    self_reported.insert("accepted_authority");
                }
            }
        }
    }
    Ok(EngineOutcome {
        engine: EngineKind::MultiTurn,
        scenario_id: scenario_id.to_owned(),
        engine_verdict,
        verdict,
        transport,
        unfinished,
        self_reported_fields: self_reported,
        not_observable: if protocol == Protocol::A2a {
            vec![
                "refusal",
                "decision",
                "fulfillment",
                "accepted_authority",
                "actions",
            ]
        } else {
            Vec::new()
        },
        result: match &result {
            Some(result) => serde_json::to_value(result)
                .map_err(|_| RemoteError::Serialization("multi-turn result"))?,
            None => serde_json::Value::Null,
        },
        evidence,
    })
}
