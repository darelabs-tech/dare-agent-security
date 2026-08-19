//! Deterministic synthetic MCP lab for Cycle 002 discovery proofs.
//!
//! Domain: fictional vehicle rental. No customer data, live URLs, or credentials.

mod catalog;
mod http;
mod server;
mod trace;

pub use catalog::{
    prompt_title, prompts, resource_body, resource_templates, resources, slice_page, tools,
    CatalogError, EXTERNAL_SCHEMA_REF, PROMPT_NAMES, RESOURCE_URIS, SERVER_NAME, SERVER_VERSION,
    TOOL_CURSOR_PREFIX, TOOL_NAMES, TOOL_PAGE_SIZE, VEHICLE_TEMPLATE,
};
pub use http::{parse_loopback_bind, serve_loopback_http, LoopbackHttpServer};
pub use server::SyntheticMcpLab;
pub use trace::{flush_trace_file, method_trace, reset_method_trace, MethodTrace, TRACE_PATH_ENV};
