//! A conversation as a chain of turns.
//!
//! Each turn is bound to everything before it: its `chain_digest` is the
//! digest of the previous chain value followed by the turn's own canonical
//! bytes. A replayed transcript whose turns were reordered, edited, inserted
//! or dropped cannot reproduce the chain, and turn indices can only grow by
//! one. Raw turn content is never stored: only its digest, plus the template
//! facts invariants decide from (planted canary, claimed authority, approval
//! disclosure, proposed action class).

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_bytes, digest_bytes};
use crate::error::{MultiTurnError, Result};
use crate::graph::{ApprovalDisclosure, StrategyNode};
use crate::ids::{CanaryId, ClassId, ConversationId, NodeId};
use crate::model::{AuthorityLevel, PrincipalSpec, TurnRole};
use crate::observation::TurnObservation;

/// Everything about a turn except its chain link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnBody {
    pub index: u32,
    pub node_id: NodeId,
    pub role: TurnRole,
    pub request_class: ClassId,
    pub content_digest: String,
    pub plants_canary: Option<CanaryId>,
    pub claimed_authority: Option<AuthorityLevel>,
    pub approval: Option<ApprovalDisclosure>,
    pub proposes_action_class: Option<ClassId>,
    pub observation: TurnObservation,
}

impl TurnBody {
    /// Bind a node's template facts to the observation it produced.
    pub fn from_node(index: u32, node: &StrategyNode, observation: TurnObservation) -> Self {
        Self {
            index,
            node_id: node.id.clone(),
            role: node.turn.role,
            request_class: node.turn.request_class.clone(),
            content_digest: digest_bytes(node.turn.content.as_bytes()),
            plants_canary: node.turn.plants_canary.clone(),
            claimed_authority: node.turn.claimed_authority,
            approval: node.turn.approval.clone(),
            proposes_action_class: node.turn.proposes_action_class.clone(),
            observation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Turn {
    #[serde(flatten)]
    pub body: TurnBody,
    pub chain_digest: String,
}

/// The seed every conversation's chain starts from.
pub fn chain_seed(conversation_id: &ConversationId) -> String {
    digest_bytes(format!("dare-multi-turn/v1|{conversation_id}").as_bytes())
}

/// The next chain value after `previous` for `body`.
pub fn chain_next(previous: &str, body: &TurnBody) -> Result<String> {
    let mut bytes = previous.as_bytes().to_vec();
    bytes.push(b'|');
    bytes.extend(canonical_bytes(body)?);
    Ok(digest_bytes(&bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationState {
    pub conversation_id: ConversationId,
    pub principal: PrincipalSpec,
    pub turns: Vec<Turn>,
}

impl ConversationState {
    pub fn new(conversation_id: ConversationId, principal: PrincipalSpec) -> Self {
        Self {
            conversation_id,
            principal,
            turns: Vec::new(),
        }
    }

    /// The chain value after the last turn (the seed when there is none).
    pub fn head(&self) -> String {
        self.turns
            .last()
            .map(|t| t.chain_digest.clone())
            .unwrap_or_else(|| chain_seed(&self.conversation_id))
    }

    /// Append a turn. The index must be exactly the next one.
    pub fn push(&mut self, body: TurnBody) -> Result<&Turn> {
        let expected = self.turns.len() as u32;
        if body.index != expected {
            return Err(MultiTurnError::StrategyFault(format!(
                "turn index {} where {expected} was expected",
                body.index
            )));
        }
        let chain_digest = chain_next(&self.head(), &body)?;
        self.turns.push(Turn { body, chain_digest });
        Ok(&self.turns[self.turns.len() - 1])
    }

    /// Recompute the whole chain; the index of the first altered turn on mismatch.
    pub fn verify_chain(&self) -> std::result::Result<(), u32> {
        let mut head = chain_seed(&self.conversation_id);
        for turn in &self.turns {
            let recomputed = chain_next(&head, &turn.body).map_err(|_| turn.body.index)?;
            if recomputed != turn.chain_digest {
                return Err(turn.body.index);
            }
            head = recomputed;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::tests::node;
    use crate::model::fixtures::principal;
    use crate::observation::normalize;
    use crate::observation::tests::raw;

    fn state() -> ConversationState {
        ConversationState::new(
            ConversationId::new("conv-a").expect("valid"),
            principal("alice", AuthorityLevel::Read),
        )
    }

    fn body(index: u32, name: &str) -> TurnBody {
        TurnBody::from_node(
            index,
            &node(name, false),
            normalize(&raw(), &[], AuthorityLevel::Read),
        )
    }

    #[test]
    fn the_chain_starts_from_a_per_conversation_seed() {
        let a = state();
        let mut b = state();
        b.conversation_id = ConversationId::new("conv-b").expect("valid");
        assert_ne!(a.head(), b.head());
        assert_eq!(a.head(), chain_seed(&a.conversation_id));
    }

    #[test]
    fn each_turn_links_to_the_previous_one() {
        let mut s = state();
        let first = s.push(body(0, "a")).expect("push").chain_digest.clone();
        let second = s.push(body(1, "b")).expect("push").chain_digest.clone();
        assert_ne!(first, second);
        assert_eq!(second, chain_next(&first, &s.turns[1].body).expect("chain"));
        assert_eq!(s.verify_chain(), Ok(()));
    }

    #[test]
    fn an_out_of_order_index_is_a_strategy_fault() {
        let mut s = state();
        assert!(matches!(
            s.push(body(1, "a")),
            Err(MultiTurnError::StrategyFault(_))
        ));
        s.push(body(0, "a")).expect("push");
        assert!(matches!(
            s.push(body(0, "b")),
            Err(MultiTurnError::StrategyFault(_))
        ));
    }

    #[test]
    fn tampering_is_detected_at_the_first_altered_turn() {
        let mut s = state();
        for (i, n) in ["a", "b", "c"].iter().enumerate() {
            s.push(body(i as u32, n)).expect("push");
        }
        let mut edited = s.clone();
        edited.turns[1].body.observation.refusal = true;
        assert_eq!(edited.verify_chain(), Err(1));
        let mut swapped = s.clone();
        swapped.turns.swap(0, 1);
        assert_eq!(
            swapped.verify_chain(),
            Err(1),
            "turn with index 1 now sits first"
        );
        let mut dropped = s;
        dropped.turns.remove(1);
        assert_eq!(dropped.verify_chain(), Err(2));
    }

    #[test]
    fn raw_content_is_never_stored_only_its_digest() {
        let mut n = node("a", false);
        n.turn.content = "SECRET-PLAN-TEXT".into();
        let b = TurnBody::from_node(0, &n, normalize(&raw(), &[], AuthorityLevel::Read));
        let json = serde_json::to_string(&b).expect("json");
        assert!(!json.contains("SECRET-PLAN-TEXT"));
        assert_eq!(b.content_digest, digest_bytes(b"SECRET-PLAN-TEXT"));
    }
}
