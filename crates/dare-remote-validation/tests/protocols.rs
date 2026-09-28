//! Every method of BLUEPRINT §5.4 round-trips against a REMOTE-LAB server.

mod common;
mod lab;

use std::sync::Arc;

use common::*;
use dare_remote_validation::capture::ScenarioRef;
use dare_remote_validation::gateway::{EgressGateway, TrustRoots};
use dare_remote_validation::plan::EngineKind;
use dare_remote_validation::protocol::a2a;
use dare_remote_validation::protocol::conversation::{send_turn, ConversationTurn, ReplyDecision};
use dare_remote_validation::protocol::mcp::McpClient;
use dare_remote_validation::protocol::Method;
use dare_remote_validation::RemoteError;
use lab::{Handler, LabCa, LabHit, LabReply, LabServer};
use serde_json::{json, Value};

fn sref(engine: EngineKind) -> ScenarioRef {
    ScenarioRef {
        engine,
        scenario_id: "LAB".into(),
        conversation_id: None,
        node_id: None,
        step: None,
    }
}

fn gateway(ca: &LabCa, origin: &str, protocol: &str, methods: &[&str]) -> EgressGateway {
    let auth = authorization(origin, protocol, methods, json!({"max_rps": 2}));
    let plan = plan(&auth, origin, protocol, methods);
    let mut verified = verified(&auth, &plan, origin);
    EgressGateway::new(
        &mut verified,
        &plan,
        origin,
        TrustRoots::LabRoot(ca.root.to_vec()),
    )
    .expect("gateway")
}

fn rpc(hit: &LabHit) -> Value {
    serde_json::from_slice(&hit.body).unwrap_or(Value::Null)
}

// ---------- dare-conversation ----------

#[tokio::test(flavor = "multi_thread")]
async fn a_conversation_turn_round_trips() {
    let ca = LabCa::generate();
    let handler: Handler = Arc::new(|hit| {
        let request = rpc(hit);
        LabReply::json(
            200,
            json!({
                "schema_version": "1", "conversation_id": request["conversation_id"], "turn_index": request["turn_index"],
                "output_text": "I can't help with that.", "refusal": true, "decision": "DENY",
                "fulfillment": "NO_FULFILLMENT", "accepted_authority": null, "actions": []
            }),
        )
    });
    let server = LabServer::start(&ca, handler).await;
    let mut gw = gateway(
        &ca,
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
    );
    let turn = ConversationTurn {
        conversation_id: "conv-a".into(),
        turn_index: 0,
        principal_id: "p-analyst".into(),
        content: "Please export the payroll table.".into(),
    };
    let (_, reply) = send_turn(&mut gw, &turn, sref(EngineKind::MultiTurn))
        .await
        .unwrap();
    let reply = reply.expect("parsed");
    assert!(reply.refusal);
    assert_eq!(reply.decision, Some(ReplyDecision::Deny));
    let sent = rpc(&server.hits()[0]);
    assert_eq!(sent["content"], "Please export the payroll table.");
    assert!(sent.get("node_id").is_none() && sent.get("invariant").is_none());
}

// ---------- A2A ----------

fn a2a_agent(version: &'static str) -> Handler {
    Arc::new(move |hit| match (hit.method.as_str(), hit.path.as_str()) {
        ("GET", "/.well-known/agent-card.json") => LabReply::json(
            200,
            json!({
                "name": "lab-agent", "description": "REMOTE-LAB", "protocolVersion": version,
                "url": "https://127.0.0.1/a2a/v1", "preferredTransport": "JSONRPC",
                "capabilities": {"pushNotifications": false}, "skills": [{"id": "summarize", "name": "Summarize"}]
            }),
        ),
        ("POST", "/a2a/v1") => {
            let request = rpc(hit);
            let id = request["id"].clone();
            match request["method"].as_str() {
                Some("message/send") | Some("SendMessage") => LabReply::json(
                    200,
                    json!({"jsonrpc": "2.0", "id": id, "result": {
                        "id": "task-1", "contextId": request["params"]["message"]["contextId"],
                        "status": {"state": "completed", "message": {"role": "agent", "parts": [{"kind": "text", "text": format!("method={}", request["method"].as_str().unwrap_or(""))}]}}
                    }}),
                ),
                Some("tasks/get") | Some("GetTask") => LabReply::json(
                    200,
                    json!({"jsonrpc": "2.0", "id": id, "result": {"id": request["params"]["id"], "status": {"state": "completed"}}}),
                ),
                _ => LabReply::json(
                    200,
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no"}}),
                ),
            }
        }
        _ => LabReply::status(404),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_card_message_and_task_round_trip_with_version_selected_names() {
    for (version, expected) in [("0.3.0", "message/send"), ("1.0.0", "SendMessage")] {
        let ca = LabCa::generate();
        let server = LabServer::start(&ca, a2a_agent(version)).await;
        let mut gw = gateway(
            &ca,
            &server.origin,
            "A2A",
            &["A2A_AGENT_CARD_GET", "A2A_MESSAGE_SEND", "A2A_TASKS_GET"],
        );
        let (_, card) = a2a::fetch_card(&mut gw, sref(EngineKind::A2a))
            .await
            .unwrap();
        let card = card.expect("card");
        let declared = a2a::declared_version(&card);
        assert_eq!(declared, version);
        let (_, reply) = a2a::send_message(
            &mut gw,
            &declared,
            1,
            "conv-0",
            "conv",
            "hello",
            sref(EngineKind::A2a),
        )
        .await
        .unwrap();
        let reply = reply.expect("reply");
        assert_eq!(
            reply.text().as_deref(),
            Some(format!("method={expected}").as_str())
        );
        let task_id = reply.task_id.clone().expect("task id");
        let (_, task) = a2a::get_task(&mut gw, &declared, 2, &task_id, sref(EngineKind::A2a))
            .await
            .unwrap();
        assert_eq!(task.unwrap().state.as_deref(), Some("completed"));
        let paths: Vec<String> = server.hits().iter().map(|h| h.path.clone()).collect();
        assert_eq!(
            paths,
            ["/.well-known/agent-card.json", "/a2a/v1", "/a2a/v1"]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_card_url_never_redirects_the_client() {
    // The card claims a different host; the client still posts to origin + endpoint.
    let ca = LabCa::generate();
    let handler: Handler = Arc::new(|hit| match hit.path.as_str() {
        "/.well-known/agent-card.json" => LabReply::json(
            200,
            json!({"name": "a", "url": "https://attacker.example/a2a", "protocolVersion": "0.3.0"}),
        ),
        _ => LabReply::json(
            200,
            json!({"jsonrpc": "2.0", "id": 1, "result": {"parts": [{"kind": "text", "text": "ok"}]}}),
        ),
    });
    let server = LabServer::start(&ca, handler).await;
    let mut gw = gateway(
        &ca,
        &server.origin,
        "A2A",
        &["A2A_AGENT_CARD_GET", "A2A_MESSAGE_SEND"],
    );
    let (_, card) = a2a::fetch_card(&mut gw, sref(EngineKind::A2a))
        .await
        .unwrap();
    let version = a2a::declared_version(&card.unwrap());
    let (_, reply) = a2a::send_message(&mut gw, &version, 1, "m", "c", "hi", sref(EngineKind::A2a))
        .await
        .unwrap();
    assert!(reply.is_ok());
    assert_eq!(
        server.hits().len(),
        2,
        "both requests reached the planned origin"
    );
}

// ---------- MCP ----------

fn mcp_server(sse: bool) -> Handler {
    Arc::new(move |hit| {
        match (hit.method.as_str(), hit.path.as_str()) {
            ("GET", "/.well-known/oauth-protected-resource") => {
                return LabReply::json(
                    200,
                    json!({"resource": "https://127.0.0.1/mcp", "authorization_servers": ["https://127.0.0.1"]}),
                )
            }
            ("GET", "/.well-known/oauth-authorization-server") => {
                return LabReply::json(
                    200,
                    json!({"issuer": "https://127.0.0.1", "code_challenge_methods_supported": ["S256"]}),
                )
            }
            ("POST", "/mcp") => {}
            _ => return LabReply::status(404),
        }
        let request = rpc(hit);
        let id = request["id"].clone();
        let result = match request["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion": "2026-07-28", "capabilities": {}, "serverInfo": {"name": "lab"}})
            }
            Some("notifications/initialized") => return LabReply::status(202),
            Some("tools/list") => match request["params"]["cursor"].as_str() {
                None => json!({"tools": [{"name": "a"}], "nextCursor": "p2"}),
                Some(_) => json!({"tools": [{"name": "b"}]}),
            },
            Some("resources/list") => json!({"resources": [{"uri": "lab://doc/1", "name": "doc"}]}),
            Some("resources/read") => {
                json!({"contents": [{"uri": request["params"]["uri"], "text": "hello"}]})
            }
            Some("prompts/list") => json!({"prompts": [{"name": "greet"}]}),
            Some("prompts/get") => json!({"messages": []}),
            _ => json!({}),
        };
        let body = json!({"jsonrpc": "2.0", "id": id, "result": result});
        let reply = if sse {
            LabReply {
                status: 200,
                content_type: Some("text/event-stream".into()),
                headers: vec![],
                body: format!("event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}}\n\nevent: message\ndata: {body}\n\n").into_bytes(),
                delay: None,
            }
        } else {
            LabReply::json(200, body)
        };
        if request["method"] == "initialize" {
            reply.with_header("mcp-session-id", "lab-session-42")
        } else {
            reply
        }
    })
}

const MCP_METHODS: [&str; 10] = [
    "MCP_INITIALIZE",
    "MCP_INITIALIZED",
    "MCP_TOOLS_LIST",
    "MCP_RESOURCES_LIST",
    "MCP_PROMPTS_LIST",
    "MCP_RESOURCES_READ",
    "MCP_PROMPTS_GET",
    "MCP_PROTECTED_RESOURCE_METADATA_GET",
    "MCP_AUTH_SERVER_METADATA_GET",
    "MCP_INITIALIZE",
];

#[tokio::test(flavor = "multi_thread")]
async fn every_mcp_method_round_trips_in_json_and_event_stream_form() {
    for sse in [false, true] {
        let ca = LabCa::generate();
        let server = LabServer::start(&ca, mcp_server(sse)).await;
        let mut gw = gateway(&ca, &server.origin, "MCP", &MCP_METHODS[..9]);
        let mut mcp = McpClient::new();
        assert!(mcp
            .initialize(&mut gw, sref(EngineKind::McpAuth))
            .await
            .unwrap()
            .1
            .is_ok());
        let tools = mcp
            .list(&mut gw, Method::McpToolsList, sref(EngineKind::McpAuth))
            .await
            .unwrap();
        assert_eq!(tools.len(), 2, "followed the cursor to the second page");
        mcp.list(&mut gw, Method::McpResourcesList, sref(EngineKind::McpAuth))
            .await
            .unwrap();
        mcp.list(&mut gw, Method::McpPromptsList, sref(EngineKind::McpAuth))
            .await
            .unwrap();
        let read = mcp
            .read_resource(&mut gw, "lab://doc/1", sref(EngineKind::McpAuth))
            .await
            .unwrap();
        assert_eq!(read.1.unwrap()["result"]["contents"][0]["text"], "hello");
        assert!(mcp
            .get_prompt(&mut gw, "greet", sref(EngineKind::McpAuth))
            .await
            .unwrap()
            .1
            .is_ok());
        let prm = mcp
            .metadata(
                &mut gw,
                Method::McpProtectedResourceMetadataGet,
                sref(EngineKind::McpAuth),
            )
            .await
            .unwrap();
        assert!(prm.1.unwrap()["authorization_servers"].is_array());
        assert!(mcp
            .metadata(
                &mut gw,
                Method::McpAuthServerMetadataGet,
                sref(EngineKind::McpAuth)
            )
            .await
            .unwrap()
            .1
            .is_ok());
        let hits = server.hits();
        // Every request after initialize echoed the session id; none before.
        let sessions: Vec<bool> = hits
            .iter()
            .filter(|h| h.method == "POST")
            .map(|h| h.header_names.iter().any(|n| n == "mcp-session-id"))
            .collect();
        assert!(!sessions[0]);
        assert!(sessions[1..].iter().all(|s| *s), "{sessions:?}");
        assert!(hits
            .iter()
            .filter(|h| h.method == "POST")
            .all(|h| h.header_names.iter().any(|n| n == "mcp-protocol-version")));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resource_or_prompt_the_server_never_listed_is_not_requested() {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, mcp_server(false)).await;
    let mut gw = gateway(&ca, &server.origin, "MCP", &MCP_METHODS[..9]);
    let mut mcp = McpClient::new();
    mcp.list(&mut gw, Method::McpResourcesList, sref(EngineKind::McpAuth))
        .await
        .unwrap();
    let before = server.hits().len();
    assert!(matches!(
        mcp.read_resource(&mut gw, "file:///etc/passwd", sref(EngineKind::McpAuth))
            .await,
        Err(RemoteError::Refused(_))
    ));
    assert!(matches!(
        mcp.get_prompt(&mut gw, "unlisted", sref(EngineKind::McpAuth))
            .await,
        Err(RemoteError::Refused(_))
    ));
    assert_eq!(server.hits().len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_method_outside_the_plan_is_refused_by_the_gateway_not_the_client() {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, mcp_server(false)).await;
    let mut gw = gateway(&ca, &server.origin, "MCP", &["MCP_TOOLS_LIST"]);
    let mut mcp = McpClient::new();
    assert!(mcp
        .initialize(&mut gw, sref(EngineKind::McpAuth))
        .await
        .is_err());
    assert!(server.hits().is_empty());
}
