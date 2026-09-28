//! A2A client (BLUEPRINT §5.4): Agent Card, one message per probe, task
//! status. Parsing is a pure function of the captured bodies.
//!
//! A2A documents are in two shapes in the field: 0.3-era (`url`,
//! `preferredTransport`, `message/send`) and 1.0 (`supportedInterfaces`,
//! `SendMessage`). Upstream re-verification was not possible in this cycle
//! (standards provenance); the client selects the JSON-RPC method names from
//! the card's declared `protocolVersion` and the projection accepts both card
//! shapes.

use serde_json::{json, Value};

use crate::capture::ScenarioRef;
use crate::error::Result;
use crate::gateway::{EgressGateway, InboundResponse, OutboundRequest};
use crate::outcome::TransportOutcome;
use crate::protocol::Method;

/// Largest Agent Card accepted, after the gateway's own response bound.
pub const MAX_CARD_BYTES: usize = 262_144;

/// JSON-RPC method names for a card's declared protocol version.
pub fn rpc_names(protocol_version: &str) -> (&'static str, &'static str) {
    if protocol_version.starts_with("0.") {
        ("message/send", "tasks/get")
    } else {
        ("SendMessage", "GetTask")
    }
}

/// The `protocolVersion` a card declares (1.0 `supportedInterfaces[0]` or the
/// 0.3-era top-level field); `"1.0.0"` when absent.
pub fn declared_version(card: &Value) -> String {
    card.get("supportedInterfaces")
        .and_then(|v| v.get(0))
        .and_then(|i| i.get("protocolVersion"))
        .or_else(|| card.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or("1.0.0")
        .to_owned()
}

/// Parse a captured Agent Card body.
pub fn parse_card(body: Option<&str>) -> std::result::Result<Value, TransportOutcome> {
    let body = body.ok_or(TransportOutcome::ProtocolViolation)?;
    if body.len() > MAX_CARD_BYTES {
        return Err(TransportOutcome::Oversize);
    }
    let value: Value =
        serde_json::from_str(body).map_err(|_| TransportOutcome::ProtocolViolation)?;
    crate::source::check_depth(&value).map_err(|_| TransportOutcome::ProtocolViolation)?;
    if !value.is_object() || value.get("name").and_then(Value::as_str).is_none() {
        return Err(TransportOutcome::ProtocolViolation);
    }
    Ok(value)
}

/// A message/send request body.
pub fn message_body(
    id: u64,
    method_name: &str,
    message_id: &str,
    context_id: &str,
    text: &str,
) -> Vec<u8> {
    let value = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method_name,
        "params": { "message": {
            "role": "user",
            "messageId": message_id,
            "contextId": context_id,
            "parts": [ { "kind": "text", "text": text } ]
        } }
    });
    serde_json::to_vec(&value).unwrap_or_default()
}

/// A tasks/get request body.
pub fn task_get_body(id: u64, method_name: &str, task_id: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"jsonrpc": "2.0", "id": id, "method": method_name, "params": {"id": task_id}}),
    )
    .unwrap_or_default()
}

/// One part of a reply: its kind and size; text parts keep their text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyPart {
    pub kind: String,
    pub bytes: usize,
    pub text: Option<String>,
}

/// What an A2A reply showed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct A2aReply {
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub state: Option<String>,
    pub parts: Vec<ReplyPart>,
    /// A JSON-RPC error code, when the agent refused at the protocol level.
    pub error_code: Option<i64>,
}

impl A2aReply {
    /// All text parts, joined with a newline.
    pub fn text(&self) -> Option<String> {
        let texts: Vec<&str> = self
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect();
        (!texts.is_empty()).then(|| texts.join("\n"))
    }
}

fn parts_of(value: Option<&Value>) -> Vec<ReplyPart> {
    value
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .take(64)
                .map(|part| {
                    let text = part.get("text").and_then(Value::as_str).map(str::to_owned);
                    let kind = part
                        .get("kind")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            if text.is_some() {
                                "text".into()
                            } else {
                                "data".into()
                            }
                        });
                    let bytes = text
                        .as_ref()
                        .map_or_else(|| part.to_string().len(), String::len);
                    ReplyPart { kind, bytes, text }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a captured JSON-RPC reply for request `id`.
pub fn parse_reply(body: Option<&str>, id: u64) -> std::result::Result<A2aReply, TransportOutcome> {
    let body = body.ok_or(TransportOutcome::ProtocolViolation)?;
    let value: Value =
        serde_json::from_str(body).map_err(|_| TransportOutcome::ProtocolViolation)?;
    crate::source::check_depth(&value).map_err(|_| TransportOutcome::ProtocolViolation)?;
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || value.get("id").and_then(Value::as_u64) != Some(id)
    {
        return Err(TransportOutcome::ProtocolViolation);
    }
    if let Some(error) = value.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(TransportOutcome::ProtocolViolation)?;
        return Ok(A2aReply {
            error_code: Some(code),
            ..A2aReply::default()
        });
    }
    let result = value
        .get("result")
        .ok_or(TransportOutcome::ProtocolViolation)?;
    // Either a Message or a Task (possibly wrapped as `{"task": …}` /
    // `{"message": …}` in 1.0 documents).
    let result = result
        .get("task")
        .or_else(|| result.get("message"))
        .unwrap_or(result);
    let text = |key: &str| result.get(key).and_then(Value::as_str).map(str::to_owned);
    if result.get("parts").is_some() {
        return Ok(A2aReply {
            task_id: text("taskId"),
            context_id: text("contextId"),
            state: None,
            parts: parts_of(result.get("parts")),
            error_code: None,
        });
    }
    let status = result.get("status");
    let message_parts = status
        .and_then(|s| s.get("message"))
        .and_then(|m| m.get("parts"));
    let mut parts = parts_of(message_parts);
    if let Some(artifacts) = result.get("artifacts").and_then(Value::as_array) {
        for artifact in artifacts.iter().take(16) {
            parts.extend(parts_of(artifact.get("parts")));
        }
    }
    Ok(A2aReply {
        task_id: text("id"),
        context_id: text("contextId"),
        state: status
            .and_then(|s| s.get("state"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        parts,
        error_code: None,
    })
}

/// GET the Agent Card.
pub async fn fetch_card(
    gateway: &mut EgressGateway,
    scenario_ref: ScenarioRef,
) -> Result<(
    InboundResponse,
    std::result::Result<Value, TransportOutcome>,
)> {
    let response = gateway
        .send(OutboundRequest {
            method: Method::A2aAgentCardGet,
            body: None,
            scenario_ref,
            challenge_expected: false,
        })
        .await?;
    let parsed = match response.transport {
        Some(outcome) => Err(outcome),
        None => parse_card(response.body.as_deref()),
    };
    Ok((response, parsed))
}

/// Send one message.
pub async fn send_message(
    gateway: &mut EgressGateway,
    protocol_version: &str,
    id: u64,
    message_id: &str,
    context_id: &str,
    text: &str,
    scenario_ref: ScenarioRef,
) -> Result<(
    InboundResponse,
    std::result::Result<A2aReply, TransportOutcome>,
)> {
    let (send, _) = rpc_names(protocol_version);
    let response = gateway
        .send(OutboundRequest {
            method: Method::A2aMessageSend,
            body: Some(message_body(id, send, message_id, context_id, text)),
            scenario_ref,
            challenge_expected: false,
        })
        .await?;
    let parsed = match response.transport {
        Some(outcome) => Err(outcome),
        None => parse_reply(response.body.as_deref(), id),
    };
    Ok((response, parsed))
}

/// Fetch a task's status.
pub async fn get_task(
    gateway: &mut EgressGateway,
    protocol_version: &str,
    id: u64,
    task_id: &str,
    scenario_ref: ScenarioRef,
) -> Result<(
    InboundResponse,
    std::result::Result<A2aReply, TransportOutcome>,
)> {
    let (_, get) = rpc_names(protocol_version);
    let response = gateway
        .send(OutboundRequest {
            method: Method::A2aTasksGet,
            body: Some(task_get_body(id, get, task_id)),
            scenario_ref,
            challenge_expected: false,
        })
        .await?;
    let parsed = match response.transport {
        Some(outcome) => Err(outcome),
        None => parse_reply(response.body.as_deref(), id),
    };
    Ok((response, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_follow_the_declared_version() {
        assert_eq!(rpc_names("0.3.0"), ("message/send", "tasks/get"));
        assert_eq!(rpc_names("1.0.0"), ("SendMessage", "GetTask"));
        assert_eq!(
            declared_version(&json!({"protocolVersion": "0.3.0"})),
            "0.3.0"
        );
        assert_eq!(
            declared_version(&json!({"supportedInterfaces": [{"protocolVersion": "1.0.0"}]})),
            "1.0.0"
        );
        assert_eq!(declared_version(&json!({})), "1.0.0");
    }

    #[test]
    fn a_card_needs_a_name_and_must_be_an_object() {
        assert!(parse_card(Some("{\"name\":\"agent\"}")).is_ok());
        for bad in ["[]", "{}", "{\"name\":1}", "nope"] {
            assert_eq!(
                parse_card(Some(bad)),
                Err(TransportOutcome::ProtocolViolation),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_message_reply_and_a_task_reply_both_parse() {
        let message = json!({"jsonrpc":"2.0","id":7,"result":{"role":"agent","messageId":"m","contextId":"c","parts":[{"kind":"text","text":"no"}]}});
        let reply = parse_reply(Some(&message.to_string()), 7).unwrap();
        assert_eq!(reply.text().as_deref(), Some("no"));
        assert_eq!(reply.context_id.as_deref(), Some("c"));
        let task = json!({"jsonrpc":"2.0","id":8,"result":{"id":"t1","contextId":"c","status":{"state":"completed","message":{"parts":[{"kind":"text","text":"done"}]}},"artifacts":[{"parts":[{"kind":"data","data":{"k":1}}]}]}});
        let reply = parse_reply(Some(&task.to_string()), 8).unwrap();
        assert_eq!(reply.task_id.as_deref(), Some("t1"));
        assert_eq!(reply.state.as_deref(), Some("completed"));
        assert_eq!(reply.parts.len(), 2);
    }

    #[test]
    fn a_jsonrpc_error_is_an_observation_and_a_wrong_id_is_not() {
        let error = json!({"jsonrpc":"2.0","id":3,"error":{"code":-32001,"message":"denied"}});
        assert_eq!(
            parse_reply(Some(&error.to_string()), 3).unwrap().error_code,
            Some(-32001)
        );
        assert_eq!(
            parse_reply(Some(&error.to_string()), 4),
            Err(TransportOutcome::ProtocolViolation)
        );
    }

    #[test]
    fn request_bodies_have_the_documented_shape() {
        let body: Value =
            serde_json::from_slice(&message_body(1, "message/send", "conv-0", "conv", "hi"))
                .unwrap();
        assert_eq!(body["params"]["message"]["parts"][0]["text"], "hi");
        let body: Value = serde_json::from_slice(&task_get_body(2, "GetTask", "t1")).unwrap();
        assert_eq!(body["params"]["id"], "t1");
    }
}
