//! Replay: evaluating what a recorded transcript says the target did.
//!
//! Replay sends nothing. Each recorded turn names the strategy node it
//! answered, and the adapter hands it back only when the runner selects that
//! exact node at that exact index. Anything else is a strategy fault (I08):
//!
//! - a recorded index that is not the next one (reordered or inserted turns);
//! - a recorded node that is not the one the graph selected;
//! - the runner asking for a turn the transcript does not have (dropped turns);
//! - recorded turns left over after the run (unconsumed turns).
//!
//! A recorded `chain_digest` is checked by the runner against the recomputed
//! chain; a mismatch is refused as `TranscriptTampered`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::conversation::ConversationState;
use crate::error::{MultiTurnError, Result};
use crate::graph::StrategyNode;
use crate::harness::ConversationAdapter;
use crate::ids::{ConversationId, NodeId};
use crate::model::{HarnessMode, MultiTurnScenario};
use crate::observation::{HarnessErrorKind, RawHarnessError, RawTurnOutput};
use crate::schema::SUPPORTED_SCHEMA_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedTurn {
    pub index: u32,
    pub node_id: NodeId,
    pub output: RawTurnOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedConversation {
    pub conversation_id: ConversationId,
    pub turns: Vec<RecordedTurn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub schema_version: String,
    pub graph_digests: BTreeSet<String>,
    pub conversations: Vec<RecordedConversation>,
}

#[derive(Debug, Clone)]
pub struct ReplayAdapter {
    transcript: Transcript,
    cursors: BTreeMap<ConversationId, usize>,
}

fn fault() -> RawHarnessError {
    RawHarnessError {
        kind: HarnessErrorKind::StrategyFault,
    }
}

impl ReplayAdapter {
    /// Bind a transcript to the scenario it claims to record.
    pub fn new(transcript: Transcript, scenario: &MultiTurnScenario) -> Result<Self> {
        if transcript.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(MultiTurnError::Schema(
                "unsupported transcript version".into(),
            ));
        }
        let pinned: BTreeSet<String> = scenario
            .conversations
            .iter()
            .map(|c| c.graph_digest.clone())
            .collect();
        if transcript.graph_digests != pinned {
            return Err(MultiTurnError::GraphDigestMismatch {
                conversation: "transcript".into(),
            });
        }
        let mut seen = BTreeSet::new();
        for conversation in &transcript.conversations {
            if !seen.insert(&conversation.conversation_id) {
                return Err(MultiTurnError::Schema(
                    "transcript repeats a conversation".into(),
                ));
            }
            // Indices must be exactly 0, 1, 2, … in order. A duplicate, a gap or
            // a reordering is visible without running anything, so it is refused
            // here (DESIGN RF-10) rather than discovered as a strategy fault.
            let misplaced = conversation
                .turns
                .iter()
                .enumerate()
                .find(|(position, turn)| turn.index as usize != *position);
            if let Some((_, turn)) = misplaced {
                return Err(MultiTurnError::TranscriptTampered {
                    conversation: conversation.conversation_id.to_string(),
                    index: turn.index,
                });
            }
        }
        Ok(Self {
            transcript,
            cursors: BTreeMap::new(),
        })
    }

    fn recorded(&self, conversation: &str) -> Option<&RecordedConversation> {
        self.transcript
            .conversations
            .iter()
            .find(|c| c.conversation_id.as_str() == conversation)
    }
}

impl ConversationAdapter for ReplayAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn respond(
        &mut self,
        state: &ConversationState,
        node: &StrategyNode,
    ) -> std::result::Result<RawTurnOutput, RawHarnessError> {
        let recorded = self
            .recorded(state.conversation_id.as_str())
            .ok_or_else(fault)?;
        let cursor = self
            .cursors
            .get(&state.conversation_id)
            .copied()
            .unwrap_or(0);
        let turn = recorded.turns.get(cursor).ok_or_else(fault)?;
        if turn.index as usize != state.turns.len() || turn.node_id != node.id {
            return Err(fault());
        }
        let output = turn.output.clone();
        self.cursors
            .insert(state.conversation_id.clone(), cursor + 1);
        Ok(output)
    }

    fn finish(&mut self) -> std::result::Result<(), RawHarnessError> {
        let unconsumed =
            self.transcript.conversations.iter().any(|c| {
                self.cursors.get(&c.conversation_id).copied().unwrap_or(0) < c.turns.len()
            });
        if unconsumed {
            Err(fault())
        } else {
            Ok(())
        }
    }

    fn recorded_chain_digest(&self, conversation: &str, index: u32) -> Option<String> {
        self.recorded(conversation)?
            .turns
            .iter()
            .find(|t| t.index == index)
            .and_then(|t| t.chain_digest.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::tests::node;
    use crate::model::fixtures::{graph_set, principal, scenario, two_step_graph};
    use crate::model::{AuthorityLevel, MultiTurnInvariant};
    use crate::observation::tests::raw;

    fn setup(turns: &[(u32, &str)]) -> (ReplayAdapter, ConversationState) {
        let graphs = graph_set(&[two_step_graph()]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let transcript = Transcript {
            schema_version: "1".into(),
            graph_digests: graphs.keys().cloned().collect(),
            conversations: vec![RecordedConversation {
                conversation_id: ConversationId::new("conv-a").expect("valid"),
                turns: turns
                    .iter()
                    .map(|(i, n)| RecordedTurn {
                        index: *i,
                        node_id: NodeId::new(*n).expect("valid"),
                        output: raw(),
                        chain_digest: None,
                    })
                    .collect(),
            }],
        };
        let state = ConversationState::new(
            ConversationId::new("conv-a").expect("valid"),
            principal("alice", AuthorityLevel::Read),
        );
        (ReplayAdapter::new(transcript, &s).expect("binds"), state)
    }

    fn step(
        adapter: &mut ReplayAdapter,
        state: &mut ConversationState,
        name: &str,
    ) -> std::result::Result<(), RawHarnessError> {
        let n = node(name, false);
        let out = adapter.respond(state, &n)?;
        let obs = crate::observation::normalize(&out, &[], AuthorityLevel::Read);
        let index = state.turns.len() as u32;
        state
            .push(crate::conversation::TurnBody::from_node(index, &n, obs))
            .map_err(|_| fault())?;
        Ok(())
    }

    #[test]
    fn a_faithful_transcript_replays_and_is_fully_consumed() {
        let (mut a, mut s) = setup(&[(0, "a"), (1, "b")]);
        step(&mut a, &mut s, "a").expect("turn 0");
        step(&mut a, &mut s, "b").expect("turn 1");
        assert_eq!(a.finish(), Ok(()));
    }

    #[test]
    fn a_turn_for_a_different_node_is_a_strategy_fault() {
        let (mut a, mut s) = setup(&[(0, "b")]);
        assert_eq!(step(&mut a, &mut s, "a"), Err(fault()));
    }

    #[test]
    fn reordered_duplicated_and_gapped_indices_are_refused_at_binding() {
        for (turns, bad) in [
            (vec![(1, "a"), (0, "b")], 1),
            (vec![(0, "a"), (0, "x"), (1, "b")], 0),
            (vec![(0, "a"), (2, "b")], 2),
        ] {
            let graphs = graph_set(&[two_step_graph()]);
            let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
            let t = Transcript {
                schema_version: "1".into(),
                graph_digests: graphs.keys().cloned().collect(),
                conversations: vec![RecordedConversation {
                    conversation_id: ConversationId::new("conv-a").expect("valid"),
                    turns: turns
                        .iter()
                        .map(|(i, n)| RecordedTurn {
                            index: *i,
                            node_id: NodeId::new(*n).expect("valid"),
                            output: raw(),
                            chain_digest: None,
                        })
                        .collect(),
                }],
            };
            match ReplayAdapter::new(t, &s) {
                Err(MultiTurnError::TranscriptTampered { index, .. }) => assert_eq!(index, bad),
                other => panic!("{turns:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_dropped_turn_is_a_strategy_fault() {
        let (mut a, mut s) = setup(&[(0, "a")]);
        step(&mut a, &mut s, "a").expect("turn 0");
        assert_eq!(step(&mut a, &mut s, "b"), Err(fault()));
    }

    #[test]
    fn unconsumed_turns_are_a_strategy_fault() {
        let (mut a, mut s) = setup(&[(0, "a"), (1, "b")]);
        step(&mut a, &mut s, "a").expect("turn 0");
        assert_eq!(a.finish(), Err(fault()));
    }

    #[test]
    fn a_transcript_for_other_graphs_is_refused_at_binding() {
        let graphs = graph_set(&[two_step_graph()]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let t = Transcript {
            schema_version: "1".into(),
            graph_digests: BTreeSet::from([format!("sha256:{}", "e".repeat(64))]),
            conversations: vec![],
        };
        assert!(matches!(
            ReplayAdapter::new(t, &s),
            Err(MultiTurnError::GraphDigestMismatch { .. })
        ));
    }
}
