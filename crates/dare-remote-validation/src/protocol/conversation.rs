//! `dare-conversation` v1 (BLUEPRINT §5.3).
//!
//! One pre-approved turn out, one self-report back. Parsing is a pure
//! function of the captured body, so the live pass and the offline replay
//! decide identically whether a reply is usable.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::capture::ScenarioRef;
use crate::error::Result;
use crate::gateway::{EgressGateway, InboundResponse, OutboundRequest};
use crate::outcome::TransportOutcome;
use crate::protocol::Method;
use crate::schema::{validate, DocumentKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplyFulfillment {
    Full,
    Partial,
    NoFulfillment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplyAuthority {
    None,
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyAction {
    pub action_id: String,
    pub action_class: String,
    pub executed: bool,
    #[serde(default)]
    pub approval_ref: Option<String>,
    pub action_digest: String,
    pub required_authority: ReplyAuthority,
    pub argument_text: String,
}

/// The target's self-report for one turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationReply {
    pub schema_version: String,
    pub conversation_id: String,
    pub turn_index: u32,
    pub output_text: Option<String>,
    pub refusal: bool,
    pub decision: Option<ReplyDecision>,
    pub fulfillment: ReplyFulfillment,
    pub accepted_authority: Option<ReplyAuthority>,
    pub actions: Vec<ReplyAction>,
}

/// One turn to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTurn {
    pub conversation_id: String,
    pub turn_index: u32,
    pub principal_id: String,
    pub content: String,
}

impl ConversationTurn {
    /// The request body. It never names a node, invariant, canary or expected
    /// outcome.
    pub fn body(&self) -> Vec<u8> {
        let value = json!({
            "schema_version": "1",
            "conversation_id": self.conversation_id,
            "turn_index": self.turn_index,
            "principal_id": self.principal_id,
            "content": self.content,
        });
        serde_json::to_vec(&value).unwrap_or_default()
    }
}

/// Parse a captured response body for the turn it answers.
pub fn parse_reply(
    body: Option<&str>,
    conversation_id: &str,
    turn_index: u32,
) -> std::result::Result<ConversationReply, TransportOutcome> {
    let body = body.ok_or(TransportOutcome::ProtocolViolation)?;
    let value: Value =
        serde_json::from_str(body).map_err(|_| TransportOutcome::ProtocolViolation)?;
    crate::source::check_depth(&value).map_err(|_| TransportOutcome::ProtocolViolation)?;
    validate(&value, DocumentKind::ConversationResponse)
        .map_err(|_| TransportOutcome::ProtocolViolation)?;
    let reply: ConversationReply =
        serde_json::from_value(value).map_err(|_| TransportOutcome::ProtocolViolation)?;
    if reply.conversation_id != conversation_id || reply.turn_index != turn_index {
        return Err(TransportOutcome::ProtocolViolation);
    }
    Ok(reply)
}

/// Send one turn and parse the reply.
pub async fn send_turn(
    gateway: &mut EgressGateway,
    turn: &ConversationTurn,
    scenario_ref: ScenarioRef,
) -> Result<(
    InboundResponse,
    std::result::Result<ConversationReply, TransportOutcome>,
)> {
    let response = gateway
        .send(OutboundRequest {
            method: Method::DareConversationTurn,
            body: Some(turn.body()),
            scenario_ref,
            challenge_expected: false,
        })
        .await?;
    let parsed = match response.transport {
        Some(outcome) => Err(outcome),
        None => parse_reply(
            response.body.as_deref(),
            &turn.conversation_id,
            turn.turn_index,
        ),
    };
    Ok((response, parsed))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn reply_json(conversation: &str, turn: u32, refusal: bool) -> String {
        json!({
            "schema_version": "1", "conversation_id": conversation, "turn_index": turn,
            "output_text": if refusal { "I can't help with that." } else { "Sure." },
            "refusal": refusal, "decision": if refusal { "DENY" } else { "ALLOW" },
            "fulfillment": if refusal { "NO_FULFILLMENT" } else { "FULL" },
            "accepted_authority": null, "actions": []
        })
        .to_string()
    }

    #[test]
    fn the_request_validates_and_reveals_nothing_about_the_test() {
        let turn = ConversationTurn {
            conversation_id: "conv-a".into(),
            turn_index: 2,
            principal_id: "p-analyst".into(),
            content: "hello".into(),
        };
        let value: Value = serde_json::from_slice(&turn.body()).unwrap();
        validate(&value, DocumentKind::ConversationRequest).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
    }

    #[test]
    fn a_well_formed_reply_parses() {
        let reply = parse_reply(Some(&reply_json("conv-a", 1, true)), "conv-a", 1).unwrap();
        assert!(reply.refusal);
        assert_eq!(reply.decision, Some(ReplyDecision::Deny));
    }

    #[test]
    fn echo_mismatch_unknown_fields_and_garbage_are_protocol_violations() {
        for (body, conv, turn) in [
            (reply_json("conv-b", 1, true), "conv-a", 1),
            (reply_json("conv-a", 2, true), "conv-a", 1),
            (
                reply_json("conv-a", 1, true)
                    .replace("\"actions\"", "\"verdict\":\"PASS\",\"actions\""),
                "conv-a",
                1,
            ),
            ("not json".to_owned(), "conv-a", 1),
            ("{}".to_owned(), "conv-a", 1),
        ] {
            assert_eq!(
                parse_reply(Some(&body), conv, turn),
                Err(TransportOutcome::ProtocolViolation),
                "{body}"
            );
        }
        assert_eq!(
            parse_reply(None, "conv-a", 1),
            Err(TransportOutcome::ProtocolViolation)
        );
    }
}
