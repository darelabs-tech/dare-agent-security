//! rmcp `ServerHandler` with method tracing (stdio and Streamable HTTP).

use std::borrow::Cow;
use std::future::Future;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, DiscoverResult,
    GetPromptRequestParams, GetPromptResponse, GetPromptResult, Implementation,
    InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, PromptMessage, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Role, ServerCapabilities,
    ServerInfo,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;

use crate::catalog::{
    self, prompt_title, resource_body, resource_templates, resources, slice_page, tools,
    CatalogError, SERVER_NAME, SERVER_VERSION, TOOL_CURSOR_PREFIX, TOOL_PAGE_SIZE,
};
use crate::trace::{global_trace, MethodTrace};

/// Synthetic vehicle-rental MCP server with method tracing.
#[derive(Clone)]
pub struct SyntheticMcpLab {
    handler: LabHandler,
    trace: MethodTrace,
}

impl SyntheticMcpLab {
    /// Lab that records into the process-wide [`crate::method_trace`] log.
    #[must_use]
    pub fn new() -> Self {
        Self::with_trace(global_trace().clone())
    }

    /// Lab that records into an isolated trace (preferred for parallel tests).
    #[must_use]
    pub fn with_trace(trace: MethodTrace) -> Self {
        Self {
            handler: LabHandler,
            trace,
        }
    }

    /// Snapshot of methods received by this lab instance.
    #[must_use]
    pub fn recorded_methods(&self) -> Vec<String> {
        self.trace.snapshot()
    }
}

impl Default for SyntheticMcpLab {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct LabHandler;

impl LabHandler {
    fn info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_instructions(
            "Synthetic vehicle-rental MCP lab. Auth metadata is fictional; use environment variable names only. No live credentials.",
        )
    }
}

impl ServerHandler for LabHandler {
    fn get_info(&self) -> ServerInfo {
        self.info()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2024_11_05])
    }

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(page_tools(request))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListResourcesResult::with_all_items(resources())))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListResourceTemplatesResult::with_all_items(
            resource_templates(),
        )))
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListPromptsResult::with_all_items(catalog::prompts())))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, McpError>> + Send + '_ {
        let known = tools()
            .iter()
            .any(|tool| tool.name.as_ref() == request.name);
        let result = if known {
            CallToolResult::success(vec![ContentBlock::text(format!(
                "synthetic-ack:{}",
                request.name
            ))])
        } else {
            CallToolResult::error(vec![ContentBlock::text("unknown synthetic tool")])
        };
        std::future::ready(Ok(result.into()))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, McpError>> + Send + '_ {
        std::future::ready(match prompt_title(&request.name) {
            Some(title) => Ok(GetPromptResult::new(vec![PromptMessage::new_text(
                Role::Assistant,
                format!("{title} uses synthetic lab identifiers only."),
            )])
            .into()),
            None => Err(McpError::invalid_params("unknown synthetic prompt", None)),
        })
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, McpError>> + Send + '_ {
        std::future::ready(match resource_body(&request.uri) {
            Some(contents) => Ok(ReadResourceResult::new(vec![contents]).into()),
            None => Err(McpError::invalid_params("unknown synthetic resource", None)),
        })
    }
}

impl ServerHandler for SyntheticMcpLab {
    fn get_info(&self) -> ServerInfo {
        self.handler.get_info()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.handler.supported_protocol_versions()
    }

    fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        self.trace.record("initialize");
        self.handler.initialize(request, context)
    }

    fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, McpError>> + Send + '_ {
        self.trace.record("server/discover");
        self.handler.discover(context)
    }

    fn ping(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + Send + '_ {
        self.trace.record("ping");
        self.handler.ping(context)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.trace.record("notifications/initialized");
        self.handler.on_initialized(context)
    }

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        self.trace.record("tools/list");
        self.handler.list_tools(request, context)
    }

    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        self.trace.record("resources/list");
        self.handler.list_resources(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_ {
        self.trace.record("resources/templates/list");
        self.handler.list_resource_templates(request, context)
    }

    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, McpError>> + Send + '_ {
        self.trace.record("prompts/list");
        self.handler.list_prompts(request, context)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, McpError>> + Send + '_ {
        self.trace.record("tools/call");
        self.handler.call_tool(request, context)
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, McpError>> + Send + '_ {
        self.trace.record("prompts/get");
        self.handler.get_prompt(request, context)
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, McpError>> + Send + '_ {
        self.trace.record("resources/read");
        self.handler.read_resource(request, context)
    }
}

fn page_tools(request: Option<PaginatedRequestParams>) -> Result<ListToolsResult, McpError> {
    let cursor = request.as_ref().and_then(|params| params.cursor.as_deref());
    let (items, next) =
        slice_page(&tools(), cursor, TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX).map_err(catalog_error)?;
    let mut result = ListToolsResult::with_all_items(items);
    result.next_cursor = next;
    Ok(result)
}

fn catalog_error(error: CatalogError) -> McpError {
    match error {
        CatalogError::UnknownCursor => McpError::invalid_params("unknown pagination cursor", None),
    }
}
