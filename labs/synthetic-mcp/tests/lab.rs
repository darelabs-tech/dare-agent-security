//! Lab starts, exposes the declared catalog, paginates, and traces methods.

use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation, PaginatedRequestParams,
    ProtocolVersion,
};
use rmcp::service::{RunningService, ServerInitializeError};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient, RoleServer, ServiceExt,
};
use synthetic_mcp::{
    method_trace, reset_method_trace, MethodTrace, SyntheticMcpLab, PROMPT_NAMES, RESOURCE_URIS,
    SERVER_NAME, TOOL_NAMES, TOOL_PAGE_SIZE, VEHICLE_TEMPLATE,
};
use tokio::process::Command;
use tokio::task::JoinHandle;

const CANARY: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

struct LabClient {
    version: ProtocolVersion,
}

impl LabClient {
    fn current() -> Self {
        Self {
            version: ProtocolVersion::V_2026_07_28,
        }
    }

    fn legacy() -> Self {
        Self {
            version: ProtocolVersion::V_2024_11_05,
        }
    }
}

impl ClientHandler for LabClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("synthetic-mcp-test", "0.1.0"),
        )
        .with_protocol_version(self.version.clone())
    }
}

async fn connect_in_process(
    lab: SyntheticMcpLab,
    client: LabClient,
    lifecycle: ClientLifecycleMode,
) -> (
    RunningService<RoleClient, LabClient>,
    JoinHandle<Result<RunningService<RoleServer, SyntheticMcpLab>, ServerInitializeError>>,
) {
    let (server_transport, client_transport) = tokio::io::duplex(16_384);
    let server_task = tokio::spawn(async move { lab.serve(server_transport).await });
    let client = client
        .serve_with_lifecycle(client_transport, lifecycle)
        .await
        .expect("client handshake");
    (client, server_task)
}

fn discover_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Discover {
        preferred_versions: vec![ProtocolVersion::V_2026_07_28],
    }
}

#[tokio::test]
async fn lab_starts_and_exposes_declared_catalog() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) =
        connect_in_process(lab, LabClient::current(), discover_lifecycle()).await;

    let tools = collect_tools(&client).await;
    for name in TOOL_NAMES {
        assert!(
            tools.iter().any(|tool| tool.name.as_ref() == *name),
            "missing tool {name}"
        );
    }
    assert!(tools.len() >= 8);

    let resources = client
        .list_resources(None)
        .await
        .expect("resources")
        .resources;
    for uri in RESOURCE_URIS {
        assert!(resources.iter().any(|resource| resource.uri == *uri));
    }
    assert!(resources.len() >= 3);

    let templates = client
        .list_resource_templates(None)
        .await
        .expect("templates")
        .resource_templates;
    assert!(templates
        .iter()
        .any(|template| template.uri_template == VEHICLE_TEMPLATE));

    let prompts = client.list_prompts(None).await.expect("prompts").prompts;
    for name in PROMPT_NAMES {
        assert!(prompts.iter().any(|prompt| prompt.name == *name));
    }
    assert!(prompts.len() >= 2);

    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn tools_list_paginates_predictably() {
    let (client, server_task) = connect_in_process(
        SyntheticMcpLab::new(),
        LabClient::current(),
        discover_lifecycle(),
    )
    .await;

    let page0 = client.list_tools(None).await.expect("page0");
    assert_eq!(page0.tools.len(), TOOL_PAGE_SIZE);
    assert_eq!(page0.next_cursor.as_deref(), Some("tools:3"));
    assert_eq!(page0.tools[0].name.as_ref(), "customer.lookup");

    let page1 = client
        .list_tools(Some(
            PaginatedRequestParams::default().with_cursor(Some("tools:3".to_owned())),
        ))
        .await
        .expect("page1");
    assert_eq!(page1.tools.len(), TOOL_PAGE_SIZE);
    assert_eq!(page1.next_cursor.as_deref(), Some("tools:6"));

    let page2 = client
        .list_tools(Some(
            PaginatedRequestParams::default().with_cursor(Some("tools:6".to_owned())),
        ))
        .await
        .expect("page2");
    assert_eq!(page2.tools.len(), 2);
    assert_eq!(page2.next_cursor, None);
    assert_eq!(page2.tools[1].name.as_ref(), "legacy.ambiguous");

    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn listing_tools_records_method_names_reproducibly() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) =
        connect_in_process(lab, LabClient::current(), discover_lifecycle()).await;
    let _ = client.list_tools(None).await.expect("tools/list");
    let names = trace.snapshot();
    assert!(
        names.iter().any(|method| method == "tools/list"),
        "expected tools/list in {names:?}"
    );
    assert!(
        names.iter().any(|method| method == "server/discover"),
        "current protocol should use server/discover, got {names:?}"
    );
    assert!(!names.iter().any(|method| method.contains(CANARY)));
    assert!(!names.iter().any(|method| method.contains('{')));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn global_method_trace_helper_is_public() {
    reset_method_trace();
    let (client, server_task) = connect_in_process(
        SyntheticMcpLab::new(),
        LabClient::current(),
        discover_lifecycle(),
    )
    .await;
    let _ = client.list_tools(None).await.expect("tools/list");
    let names = method_trace();
    assert!(names.iter().any(|method| method == "tools/list"));
    assert!(!names.join(" ").contains(CANARY));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn legacy_initialize_path_is_accepted() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) =
        connect_in_process(lab, LabClient::legacy(), ClientLifecycleMode::Initialize).await;
    let info = client.peer_info().expect("legacy peer info");
    assert_eq!(info.protocol_version.as_str(), "2024-11-05");
    let _ = client.list_tools(None).await.expect("legacy tools/list");
    let names = trace.snapshot();
    assert!(names.iter().any(|method| method == "initialize"));
    assert!(names
        .iter()
        .any(|method| method == "notifications/initialized"));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn tool_call_arguments_do_not_enter_the_method_trace() {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let (client, server_task) =
        connect_in_process(lab, LabClient::current(), discover_lifecycle()).await;
    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "synthetic_customer_id".to_owned(),
        serde_json::Value::String(CANARY.to_owned()),
    );
    let _ = client
        .call_tool(CallToolRequestParams::new("customer.lookup").with_arguments(arguments))
        .await
        .expect("tools/call completeness");
    let dump = trace.snapshot().join("\n");
    assert!(dump.contains("tools/call"));
    assert!(!dump.contains(CANARY));
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn stdio_binary_starts_and_lists_tools() {
    let transport = TokioChildProcess::new(Command::new(env!("CARGO_BIN_EXE_synthetic-mcp")))
        .expect("spawn synthetic-mcp");
    let client = LabClient::current()
        .serve_with_lifecycle(transport, discover_lifecycle())
        .await
        .expect("stdio handshake");
    let info = client.peer_info().expect("stdio peer info");
    assert_eq!(
        info.server_info.as_ref().map(|server| server.name.as_str()),
        Some(SERVER_NAME)
    );
    let tools = collect_tools(&client).await;
    assert!(tools.len() >= 8);
    drop(client);
}

async fn collect_tools(client: &RunningService<RoleClient, LabClient>) -> Vec<rmcp::model::Tool> {
    let mut cursor = None;
    let mut all = Vec::new();
    loop {
        let page = client
            .list_tools(
                cursor.map(|value| PaginatedRequestParams::default().with_cursor(Some(value))),
            )
            .await
            .expect("tools page");
        all.extend(page.tools);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    all
}
