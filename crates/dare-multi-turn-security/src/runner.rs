//! Driving each conversation through its strategy graph.
//!
//! For every conversation, in declared order, the runner starts at the root
//! and repeats: admit the turn, ask the adapter, normalize, record, then stop
//! or follow the edge the observation class selects. Every turn it sends is a
//! node of the approved graph and every step follows a declared edge, so I08
//! (strategy integrity) holds by construction for simulated runs and is
//! checked turn by turn for replay.
//!
//! Before the first turn, a problem is a refusal (`Err`, no result). After it,
//! every problem becomes a [`StopReason`] inside the outcome, with one
//! exception: a replayed chain digest that disagrees with the recomputed one
//! is refused as tampering, because nothing a tampered transcript says can be
//! evaluated.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::budget::{BudgetSnapshot, OutputLedger};
use crate::canonical::canonical_bytes;
use crate::conversation::{ConversationState, TurnBody};
use crate::error::{MultiTurnError, Result};
use crate::harness::{ConversationAdapter, MultiTurnControlSnapshot};
use crate::ids::NodeId;
use crate::invariant;
use crate::model::{GraphSet, MultiTurnScenario, ObservationClass, StopReason};
use crate::observation::{normalize, HarnessErrorKind, RawTurnOutput};

/// One conversation after it stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationRun {
    pub state: ConversationState,
    pub stop: StopReason,
    pub graph_digest: String,
    pub unreached_nodes: BTreeSet<NodeId>,
}

impl ConversationRun {
    pub fn path(&self) -> Vec<(NodeId, ObservationClass)> {
        self.state
            .turns
            .iter()
            .map(|t| (t.body.node_id.clone(), t.body.observation.class))
            .collect()
    }
}

/// Every conversation of one scenario, plus run-level facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub runs: Vec<ConversationRun>,
    /// The adapter reported a strategy fault after the last conversation
    /// (unconsumed replay turns).
    pub finish_fault: bool,
    pub control: Option<MultiTurnControlSnapshot>,
    pub budget: BudgetSnapshot,
}

fn stop_for(kind: HarnessErrorKind) -> StopReason {
    match kind {
        HarnessErrorKind::BudgetExhausted => StopReason::BudgetExhausted,
        HarnessErrorKind::StrategyFault => StopReason::StrategyFault,
        HarnessErrorKind::AdapterFailure
        | HarnessErrorKind::ControlTriggered
        | HarnessErrorKind::OutputTooLarge => StopReason::HarnessError,
    }
}

/// Run every conversation of a validated scenario.
pub fn run_conversations(
    scenario: &MultiTurnScenario,
    graphs: &GraphSet,
    adapter: &mut dyn ConversationAdapter,
    ledger: &mut OutputLedger,
) -> Result<RunOutcome> {
    scenario.validate(graphs)?;
    let mut runs: Vec<ConversationRun> = Vec::with_capacity(scenario.conversations.len());

    for spec in &scenario.conversations {
        let graph = scenario.graph_for(spec, graphs).ok_or_else(|| {
            MultiTurnError::GraphDigestMismatch {
                conversation: spec.conversation_id.to_string(),
            }
        })?;
        ledger.begin_conversation();
        let mut state =
            ConversationState::new(spec.conversation_id.clone(), spec.principal.clone());
        let mut node = graph.root();

        let stop = loop {
            if ledger.admit_turn().is_err() {
                break StopReason::BudgetExhausted;
            }
            let raw = match adapter.respond(&state, node) {
                Ok(raw) => raw,
                Err(error) if error.kind == HarnessErrorKind::BudgetExhausted => {
                    break StopReason::BudgetExhausted
                }
                Err(error) => RawTurnOutput::harness_failure(error.kind),
            };
            let observation =
                normalize(&raw, &scenario.canaries, state.principal.verified_authority);
            let class = observation.class;
            let harness_error = observation.harness_error;
            let index = state.turns.len() as u32;
            let body = TurnBody::from_node(index, node, observation);
            if ledger
                .admit_evidence(canonical_bytes(&body)?.len())
                .is_err()
            {
                break StopReason::BudgetExhausted;
            }
            let chain = state.push(body)?.chain_digest.clone();
            if let Some(recorded) =
                adapter.recorded_chain_digest(state.conversation_id.as_str(), index)
            {
                if recorded != chain {
                    return Err(MultiTurnError::TranscriptTampered {
                        conversation: state.conversation_id.to_string(),
                        index,
                    });
                }
            }
            if let Some(kind) = harness_error {
                break stop_for(kind);
            }
            if scenario.stop_on_first_fail {
                let partial = ConversationRun {
                    state: state.clone(),
                    stop: StopReason::FirstFail,
                    graph_digest: spec.graph_digest.clone(),
                    unreached_nodes: BTreeSet::new(),
                };
                let mut so_far = runs.clone();
                so_far.push(partial);
                if invariant::any_fail(scenario, graphs, &so_far) {
                    break StopReason::FirstFail;
                }
            }
            if node.terminal {
                break StopReason::TerminalReached;
            }
            if class == ObservationClass::Unclassifiable {
                break StopReason::Unclassifiable;
            }
            match graph.transition(&node.id, class) {
                Some(next) => node = next,
                None => break StopReason::NoTransition,
            }
        };

        let visited: BTreeSet<&NodeId> = state.turns.iter().map(|t| &t.body.node_id).collect();
        let unreached_nodes = graph
            .node_ids()
            .filter(|id| !visited.contains(id))
            .cloned()
            .collect();
        runs.push(ConversationRun {
            state,
            stop,
            graph_digest: spec.graph_digest.clone(),
            unreached_nodes,
        });
    }

    let finish_fault = adapter.finish().is_err();
    Ok(RunOutcome {
        runs,
        finish_fault,
        control: adapter.control_snapshot(),
        budget: ledger.snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::tests::{edge, graph, node};
    use crate::limits::EffectiveBounds;
    use crate::model::fixtures::{class, graph_set, scenario};
    use crate::model::MultiTurnInvariant;
    use crate::replay::{RecordedConversation, RecordedTurn, ReplayAdapter, Transcript};
    use crate::simulated::{ReferenceAgent, SimulatedAdapter};
    use ObservationClass::*;

    /// a -REFUSED-> b -REFUSED-> c(terminal); a -COMPLIED-> done(terminal)
    fn refusal_graph() -> crate::graph::StrategyGraph {
        graph(
            vec![
                node("a", false),
                node("b", false),
                node("c", true),
                node("done", true),
            ],
            vec![
                edge("a", Refused, "b"),
                edge("b", Refused, "c"),
                edge("a", Complied, "done"),
                edge("b", Complied, "done"),
            ],
        )
    }

    fn run(agent: ReferenceAgent, stop_on_first_fail: bool) -> RunOutcome {
        let graphs = graph_set(&[refusal_graph()]);
        let mut s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        s.stop_on_first_fail = stop_on_first_fail;
        let mut adapter = SimulatedAdapter::new(agent, &s);
        let mut ledger = OutputLedger::new(EffectiveBounds::default());
        run_conversations(&s, &graphs, &mut adapter, &mut ledger).expect("runs")
    }

    #[test]
    fn a_secure_agent_walks_the_refusal_path_to_the_terminal() {
        let o = run(ReferenceAgent::SecureRefuser, false);
        assert_eq!(o.runs[0].stop, StopReason::TerminalReached);
        let path: Vec<_> = o.runs[0]
            .path()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        assert_eq!(
            path,
            [
                ("a".into(), Refused),
                ("b".into(), Refused),
                ("c".into(), Refused)
            ]
        );
        assert_eq!(
            o.runs[0]
                .unreached_nodes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["done"]
        );
    }

    #[test]
    fn the_observation_selects_the_next_node() {
        let o = run(
            ReferenceAgent::ErodingRefusal {
                refusals_before_comply: 1,
            },
            false,
        );
        let nodes: Vec<_> = o.runs[0]
            .path()
            .into_iter()
            .map(|(n, _)| n.to_string())
            .collect();
        assert_eq!(
            nodes,
            ["a", "b", "done"],
            "the second ask was complied with, so the graph went to `done`"
        );
    }

    #[test]
    fn stop_on_first_fail_stops_at_the_deciding_turn() {
        let o = run(
            ReferenceAgent::ErodingRefusal {
                refusals_before_comply: 1,
            },
            true,
        );
        assert_eq!(o.runs[0].stop, StopReason::FirstFail);
        assert_eq!(o.runs[0].state.turns.len(), 2);
    }

    #[test]
    fn a_missing_edge_stops_with_no_transition() {
        let graphs = graph_set(&[graph(
            vec![node("a", false), node("b", true)],
            vec![edge("a", Complied, "b")],
        )]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let mut adapter = SimulatedAdapter::new(ReferenceAgent::SecureRefuser, &s);
        let o = run_conversations(
            &s,
            &graphs,
            &mut adapter,
            &mut OutputLedger::new(EffectiveBounds::default()),
        )
        .expect("runs");
        assert_eq!(o.runs[0].stop, StopReason::NoTransition);
    }

    #[test]
    fn harness_failure_ambiguity_and_budget_each_have_their_stop_reason() {
        assert_eq!(
            run(ReferenceAgent::HarnessFailsAt { turn: 1 }, false).runs[0].stop,
            StopReason::HarnessError
        );
        assert_eq!(
            run(ReferenceAgent::AmbiguousResponder, false).runs[0].stop,
            StopReason::Unclassifiable
        );
        let graphs = graph_set(&[refusal_graph()]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let mut adapter = SimulatedAdapter::new(ReferenceAgent::SecureRefuser, &s);
        let mut ledger = OutputLedger::new(EffectiveBounds {
            max_turns_per_conversation: 2,
            ..EffectiveBounds::default()
        });
        let o = run_conversations(&s, &graphs, &mut adapter, &mut ledger).expect("runs");
        assert_eq!(o.runs[0].stop, StopReason::BudgetExhausted);
        assert_eq!(o.runs[0].state.turns.len(), 2);
    }

    #[test]
    fn every_executed_turn_is_a_graph_node_reached_by_a_declared_edge() {
        let graphs = graph_set(&[refusal_graph()]);
        let g = graphs.values().next().expect("graph");
        for agent in [
            ReferenceAgent::SecureRefuser,
            ReferenceAgent::ErodingRefusal {
                refusals_before_comply: 1,
            },
        ] {
            let o = run(agent, false);
            let path = o.runs[0].path();
            assert_eq!(path[0].0, g.graph().root);
            for pair in path.windows(2) {
                let next = g.transition(&pair[0].0, pair[0].1).expect("declared edge");
                assert_eq!(next.id, pair[1].0);
            }
        }
    }

    fn replay_run(transcript_turns: Vec<RecordedTurn>) -> Result<RunOutcome> {
        let graphs = graph_set(&[refusal_graph()]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let transcript = Transcript {
            schema_version: "1".into(),
            graph_digests: graphs.keys().cloned().collect(),
            conversations: vec![RecordedConversation {
                conversation_id: s.conversations[0].conversation_id.clone(),
                turns: transcript_turns,
            }],
        };
        let mut adapter = ReplayAdapter::new(transcript, &s)?;
        run_conversations(
            &s,
            &graphs,
            &mut adapter,
            &mut OutputLedger::new(EffectiveBounds::default()),
        )
    }

    fn recorded_refusals() -> Vec<RecordedTurn> {
        ["a", "b", "c"]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let mut output = crate::observation::tests::raw();
                output.refusal = true;
                RecordedTurn {
                    index: i as u32,
                    node_id: NodeId::new(*n).expect("valid"),
                    output,
                    chain_digest: None,
                }
            })
            .collect()
    }

    #[test]
    fn a_faithful_replay_reaches_the_terminal_and_a_short_one_is_a_strategy_fault() {
        let o = replay_run(recorded_refusals()).expect("runs");
        assert_eq!(o.runs[0].stop, StopReason::TerminalReached);
        assert!(!o.finish_fault);
        let mut short = recorded_refusals();
        short.pop();
        assert_eq!(
            replay_run(short).expect("runs").runs[0].stop,
            StopReason::StrategyFault
        );
        let mut long = recorded_refusals();
        long.push(RecordedTurn {
            index: 3,
            ..long[0].clone()
        });
        assert!(
            replay_run(long).expect("runs").finish_fault,
            "unconsumed turn"
        );
    }

    #[test]
    fn a_recorded_chain_digest_that_disagrees_is_refused_as_tampering() {
        let honest = replay_run(recorded_refusals()).expect("runs");
        let mut turns = recorded_refusals();
        for (turn, real) in turns.iter_mut().zip(&honest.runs[0].state.turns) {
            turn.chain_digest = Some(real.chain_digest.clone());
        }
        assert!(replay_run(turns.clone()).is_ok(), "the true chain replays");
        turns[1].chain_digest = Some(format!("sha256:{}", "0".repeat(64)));
        assert!(matches!(
            replay_run(turns),
            Err(MultiTurnError::TranscriptTampered { index: 1, .. })
        ));
    }

    #[test]
    fn a_scenario_that_does_not_validate_is_refused_before_any_turn() {
        let graphs = graph_set(&[refusal_graph()]);
        let mut s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        s.prohibited.composite = Some(vec![class("only-one")]);
        let mut adapter = SimulatedAdapter::new(ReferenceAgent::SecureRefuser, &s);
        assert!(run_conversations(
            &s,
            &graphs,
            &mut adapter,
            &mut OutputLedger::new(EffectiveBounds::default())
        )
        .is_err());
    }
}
