//! Multi-turn projector (Cycle 021, BLUEPRINT §6.8): entry facts.
//!
//! One channel node per turn role that carries untrusted input. The 021
//! invariants guard every channel edge; a delegated finding adds an
//! ENTITY-scope FAIL for its owning property on the channel of the turn it
//! names. 021 reports executed actions, so CALLS and CAN_INVOKE stay
//! distinct here.
use std::collections::BTreeMap;

use dare_attack_graph::{v2::EntryClass, EdgeType, NodeType};
use dare_multi_turn_security::{model::TurnRole, result::MultiTurnResult, runner::ConversationRun};

use super::{edge, enum_name, plain, sut};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts, MULTI_TURN_DELEGATED},
};

fn entry_class(role: TurnRole) -> Option<EntryClass> {
    match role {
        TurnRole::User => Some(EntryClass::UntrustedInput),
        TurnRole::Tool => Some(EntryClass::ExternalContent),
        TurnRole::Retrieved => Some(EntryClass::RetrievedDocument),
        TurnRole::Memory => Some(EntryClass::MemoryWrite),
        TurnRole::Approval => None,
    }
}

fn channel_ref(role: TurnRole) -> NodeRef {
    NodeRef::new(
        NodeType::Data,
        format!("channel.{}", enum_name(&role).to_ascii_lowercase()),
    )
}

pub fn project(
    bundle: &LoadedBundle,
    result: &MultiTurnResult,
    conversations: Option<&Vec<ConversationRun>>,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let Some(conversations) = conversations else {
        sink.unprojected("MULTI_TURN_RESULT_ONLY");
        return;
    };
    let agent = sink.node(sut(), "agent under test", plain(), "multi-turn target", "/");
    let ids = bundle.evidence.all_ids();
    let mut roles: BTreeMap<(String, u32), TurnRole> = BTreeMap::new();
    let mut channels: BTreeMap<String, NodeRef> = BTreeMap::new();
    for (conversation_index, run) in conversations.iter().enumerate() {
        for (turn_index, turn) in run.state.turns.iter().enumerate() {
            let body = &turn.body;
            let locator = format!(
                "conversations#/conversations/{conversation_index}/state/turns/{turn_index}"
            );
            roles.insert(
                (run.state.conversation_id.as_str().to_owned(), body.index),
                body.role,
            );
            if let Some(class) = entry_class(body.role) {
                let node = sink.node(
                    channel_ref(body.role),
                    &format!("{} channel", enum_name(&body.role).to_ascii_lowercase()),
                    plain(),
                    &format!("TurnRole::{}", enum_name(&body.role)),
                    &locator,
                );
                sink.designate(&node, Designation::Entry(class));
                channels.entry(node.local_id.clone()).or_insert(node);
            } else {
                sink.unprojected("TurnRole::APPROVAL");
            }
            for action in &body.observation.actions {
                let class = action.action_class.as_str();
                let tool = sink.node(
                    NodeRef::new(NodeType::Tool, class),
                    class,
                    plain(),
                    "NormalizedAction.action_class",
                    &locator,
                );
                let (edge_type, role, kind) = if action.executed {
                    (
                        EdgeType::Calls,
                        Some(Role::MultiTurnCalls),
                        "NormalizedAction (executed)",
                    )
                } else {
                    (EdgeType::CanInvoke, None, "NormalizedAction (requested)")
                };
                edge(
                    sink,
                    verdicts,
                    role,
                    edge_type,
                    &agent,
                    &tool,
                    FactAuthority::default(),
                    observed(ids.clone()),
                    kind,
                    &locator,
                );
            }
        }
    }
    for finding in &result.delegated_findings {
        let key = (
            finding.turn.conversation_id.as_str().to_owned(),
            finding.turn.index,
        );
        let channel = roles
            .get(&key)
            .and_then(|role| entry_class(*role).map(|_| channel_ref(*role)));
        match channel {
            Some(channel) if MULTI_TURN_DELEGATED.contains(&finding.owning_property.as_str()) => {
                verdicts.delegated_fail(&finding.owning_property, channel, ids.clone());
            }
            _ => sink.unprojected("DelegatedFinding::unprojectable"),
        }
    }
    for channel in channels.values() {
        edge(
            sink,
            verdicts,
            Some(Role::MultiTurnChannel),
            EdgeType::TransfersTo,
            channel,
            &agent,
            FactAuthority::default(),
            observed(ids.clone()),
            "conversation turn",
            "conversations#/conversations",
        );
    }
}
