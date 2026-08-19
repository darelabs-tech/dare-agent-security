//! Passive-safety proofs owned by the synthetic lab.

use std::net::SocketAddr;

use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation, ProtocolVersion,
};
use rmcp::service::RunningService;
use rmcp::{ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient, ServiceExt};
use synthetic_mcp::{parse_loopback_bind, serve_loopback_http, MethodTrace, SyntheticMcpLab};

const CURRENT_ALLOWLIST: &[&str] = &[
    "server/discover",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];
const FORBIDDEN: &[&str] = &["tools/call", "resources/read", "prompts/get", "ping"];

struct LabClient;

impl ClientHandler for LabClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("synthetic-mcp-passive-proof", "0.1.0"),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }
}

fn discover_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Discover {
        preferred_versions: vec![ProtocolVersion::V_2026_07_28],
    }
}

async fn connect(
    lab: SyntheticMcpLab,
) -> (
    RunningService<RoleClient, LabClient>,
    tokio::task::JoinHandle<
        Result<
            rmcp::service::RunningService<rmcp::RoleServer, SyntheticMcpLab>,
            rmcp::service::ServerInitializeError,
        >,
    >,
) {
    let (server_transport, client_transport) = tokio::io::duplex(16_384);
    let server_task = tokio::spawn(async move { lab.serve(server_transport).await });
    let client = LabClient
        .serve_with_lifecycle(client_transport, discover_lifecycle())
        .await
        .expect("client handshake");
    (client, server_task)
}

fn assert_allowlisted(methods: &[String]) {
    for method in methods {
        assert!(
            CURRENT_ALLOWLIST.contains(&method.as_str()),
            "lab received {method} outside Cycle002 current allowlist; trace={methods:?}"
        );
        assert!(
            !FORBIDDEN.contains(&method.as_str()),
            "forbidden method {method} in {methods:?}"
        );
    }
}

#[tokio::test]
async fn list_only_client_stays_inside_current_allowlist() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) = connect(lab).await;
    let _ = client.list_tools(None).await.expect("tools");
    let _ = client.list_resources(None).await.expect("resources");
    let _ = client
        .list_resource_templates(None)
        .await
        .expect("templates");
    let _ = client.list_prompts(None).await.expect("prompts");
    let methods = trace.snapshot();
    assert_allowlisted(&methods);
    assert!(methods.iter().any(|method| method == "server/discover"));
    assert!(methods.iter().any(|method| method == "tools/list"));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn tools_call_is_recorded_when_an_active_client_invokes_it() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) = connect(lab).await;
    let _ = client
        .call_tool(CallToolRequestParams::new("customer.lookup"))
        .await
        .expect("call");
    let methods = trace.snapshot();
    assert!(methods.iter().any(|method| method == "tools/call"));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn http_mode_binds_loopback_only() {
    assert!(parse_loopback_bind("8.8.8.8:80").is_err());
    let bind: SocketAddr = parse_loopback_bind("127.0.0.1:0").expect("loopback");
    let server = serve_loopback_http(bind, SyntheticMcpLab::new())
        .await
        .expect("http lab");
    assert!(server.bind.ip().is_loopback());
    assert!(server.url.starts_with("http://127.0.0.1:"));
    server.shutdown().await;
}
