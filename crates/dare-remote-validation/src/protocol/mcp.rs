//! MCP client over streamable HTTP (BLUEPRINT §5.4, AD-09).
//!
//! A thin JSON-RPC client through the gateway rather than `rmcp`, so that
//! every request is counted, rate limited, classified and captured. Only
//! read-only methods exist. `resources/read` and `prompts/get` accept only a
//! URI or name the server listed earlier in the same run, so the client never
//! asks for something the target did not offer.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::capture::ScenarioRef;
use crate::error::{EgressRefusal, RemoteError, Result};
use crate::gateway::{EgressGateway, InboundResponse, OutboundRequest, MCP_PROTOCOL_VERSION};
use crate::outcome::TransportOutcome;
use crate::protocol::Method;

/// Most pages followed for one `*/list`.
pub const MAX_PAGES: usize = 5;

/// A JSON-RPC request body.
pub fn request_body(id: u64, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .unwrap_or_default()
}

/// Find the JSON-RPC response with `id` in a body that is either JSON or a
/// single `text/event-stream`.
pub fn parse_response(
    body: Option<&str>,
    content_type: Option<&str>,
    id: u64,
) -> std::result::Result<Value, TransportOutcome> {
    let body = body.ok_or(TransportOutcome::ProtocolViolation)?;
    let is_sse =
        content_type.is_some_and(|ct| ct.to_ascii_lowercase().starts_with("text/event-stream"));
    let candidates: Vec<Value> = if is_sse {
        let mut events = Vec::new();
        let mut data = String::new();
        for line in body.lines().chain(std::iter::once("")) {
            if line.is_empty() {
                if !data.is_empty() {
                    if let Ok(value) = serde_json::from_str::<Value>(&data) {
                        events.push(value);
                    }
                    data.clear();
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            }
        }
        events
    } else {
        vec![serde_json::from_str(body).map_err(|_| TransportOutcome::ProtocolViolation)?]
    };
    let response = candidates
        .into_iter()
        .find(|v| {
            v.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && v.get("id").and_then(Value::as_u64) == Some(id)
        })
        .ok_or(TransportOutcome::ProtocolViolation)?;
    crate::source::check_depth(&response).map_err(|_| TransportOutcome::ProtocolViolation)?;
    Ok(response)
}

/// Parse a metadata document (RFC 9728 / RFC 8414): a JSON object.
pub fn parse_metadata(body: Option<&str>) -> std::result::Result<Value, TransportOutcome> {
    let value: Value = serde_json::from_str(body.ok_or(TransportOutcome::ProtocolViolation)?)
        .map_err(|_| TransportOutcome::ProtocolViolation)?;
    crate::source::check_depth(&value).map_err(|_| TransportOutcome::ProtocolViolation)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(TransportOutcome::ProtocolViolation)
    }
}

/// The session state one run keeps.
#[derive(Debug, Default)]
pub struct McpClient {
    next_id: u64,
    listed_uris: BTreeSet<String>,
    listed_prompts: BTreeSet<String>,
}

pub type Exchange = (
    InboundResponse,
    std::result::Result<Value, TransportOutcome>,
);

impl McpClient {
    pub fn new() -> McpClient {
        McpClient {
            next_id: 1,
            ..McpClient::default()
        }
    }

    async fn call(
        &mut self,
        gateway: &mut EgressGateway,
        method: Method,
        name: &str,
        params: Value,
        scenario_ref: ScenarioRef,
    ) -> Result<Exchange> {
        let id = self.next_id;
        self.next_id += 1;
        let response = gateway
            .send(OutboundRequest {
                method,
                body: Some(request_body(id, name, params)),
                scenario_ref,
                challenge_expected: false,
            })
            .await?;
        let parsed = match response.transport {
            Some(outcome) => Err(outcome),
            None => parse_response(
                response.body.as_deref(),
                response.content_type.as_deref(),
                id,
            ),
        };
        Ok((response, parsed))
    }

    /// `initialize`, then the `notifications/initialized` notification.
    pub async fn initialize(
        &mut self,
        gateway: &mut EgressGateway,
        scenario_ref: ScenarioRef,
    ) -> Result<Exchange> {
        let params = json!({"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "dare-agent-security", "version": env!("CARGO_PKG_VERSION")}});
        let exchange = self
            .call(
                gateway,
                Method::McpInitialize,
                "initialize",
                params,
                scenario_ref.clone(),
            )
            .await?;
        if exchange.1.is_ok() {
            let body = serde_json::to_vec(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .unwrap_or_default();
            gateway
                .send(OutboundRequest {
                    method: Method::McpInitialized,
                    body: Some(body),
                    scenario_ref,
                    challenge_expected: false,
                })
                .await?;
        }
        Ok(exchange)
    }

    /// `tools/list`, `resources/list` or `prompts/list`, following at most
    /// five pages. Every page is its own counted request.
    pub async fn list(
        &mut self,
        gateway: &mut EgressGateway,
        method: Method,
        scenario_ref: ScenarioRef,
    ) -> Result<Vec<Exchange>> {
        let (name, key) = match method {
            Method::McpToolsList => ("tools/list", "tools"),
            Method::McpResourcesList => ("resources/list", "resources"),
            Method::McpPromptsList => ("prompts/list", "prompts"),
            _ => return Err(RemoteError::Egress(EgressRefusal::MethodNotPlanned)),
        };
        let mut pages = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |c| json!({"cursor": c}));
            let exchange = self
                .call(gateway, method, name, params, scenario_ref.clone())
                .await?;
            let result = exchange
                .1
                .as_ref()
                .ok()
                .and_then(|v| v.get("result"))
                .cloned();
            if let Some(items) = result
                .as_ref()
                .and_then(|r| r.get(key))
                .and_then(Value::as_array)
            {
                for item in items.iter().take(1_000) {
                    match method {
                        Method::McpResourcesList => {
                            if let Some(uri) = item.get("uri").and_then(Value::as_str) {
                                self.listed_uris.insert(uri.to_owned());
                            }
                        }
                        Method::McpPromptsList => {
                            if let Some(n) = item.get("name").and_then(Value::as_str) {
                                self.listed_prompts.insert(n.to_owned());
                            }
                        }
                        _ => {}
                    }
                }
            }
            cursor = result
                .as_ref()
                .and_then(|r| r.get("nextCursor"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            pages.push(exchange);
            if cursor.is_none() {
                break;
            }
        }
        Ok(pages)
    }

    /// `resources/read`, only for a URI listed earlier in this run.
    pub async fn read_resource(
        &mut self,
        gateway: &mut EgressGateway,
        uri: &str,
        scenario_ref: ScenarioRef,
    ) -> Result<Exchange> {
        if !self.listed_uris.contains(uri) {
            return Err(RemoteError::Refused(
                "resources/read is only sent for a URI the server listed",
            ));
        }
        self.call(
            gateway,
            Method::McpResourcesRead,
            "resources/read",
            json!({"uri": uri}),
            scenario_ref,
        )
        .await
    }

    /// `prompts/get`, only for a name listed earlier in this run, with no
    /// arguments.
    pub async fn get_prompt(
        &mut self,
        gateway: &mut EgressGateway,
        name: &str,
        scenario_ref: ScenarioRef,
    ) -> Result<Exchange> {
        if !self.listed_prompts.contains(name) {
            return Err(RemoteError::Refused(
                "prompts/get is only sent for a prompt the server listed",
            ));
        }
        self.call(
            gateway,
            Method::McpPromptsGet,
            "prompts/get",
            json!({"name": name, "arguments": {}}),
            scenario_ref,
        )
        .await
    }

    /// GET a metadata document. A 401/403 here is an observation.
    pub async fn metadata(
        &mut self,
        gateway: &mut EgressGateway,
        method: Method,
        scenario_ref: ScenarioRef,
    ) -> Result<Exchange> {
        if !matches!(
            method,
            Method::McpProtectedResourceMetadataGet | Method::McpAuthServerMetadataGet
        ) {
            return Err(RemoteError::Egress(EgressRefusal::MethodNotPlanned));
        }
        let response = gateway
            .send(OutboundRequest {
                method,
                body: None,
                scenario_ref,
                challenge_expected: true,
            })
            .await?;
        let parsed = match response.transport {
            Some(outcome) => Err(outcome),
            None if response.status.is_some_and(|s| (200..300).contains(&s)) => {
                parse_metadata(response.body.as_deref())
            }
            None => Err(TransportOutcome::NotFound),
        };
        Ok((response, parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_response_is_found_by_id() {
        let body = json!({"jsonrpc":"2.0","id":4,"result":{"tools":[]}}).to_string();
        assert!(parse_response(Some(&body), Some("application/json"), 4).is_ok());
        assert_eq!(
            parse_response(Some(&body), Some("application/json"), 5),
            Err(TransportOutcome::ProtocolViolation)
        );
    }

    #[test]
    fn an_event_stream_response_is_found_among_events() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\n data: \"result\":{}}\n\n";
        // Second event spans two data lines.
        let body = body.replace("\n data:", "\ndata:");
        assert!(parse_response(Some(&body), Some("text/event-stream; charset=utf-8"), 9).is_ok());
        assert_eq!(
            parse_response(Some(&body), Some("text/event-stream"), 1),
            Err(TransportOutcome::ProtocolViolation)
        );
    }

    #[test]
    fn metadata_must_be_an_object() {
        assert!(parse_metadata(Some("{\"resource\":\"x\"}")).is_ok());
        assert_eq!(
            parse_metadata(Some("[]")),
            Err(TransportOutcome::ProtocolViolation)
        );
        assert_eq!(
            parse_metadata(None),
            Err(TransportOutcome::ProtocolViolation)
        );
    }
}
