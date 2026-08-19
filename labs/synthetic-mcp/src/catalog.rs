//! Deterministic synthetic vehicle-rental catalog.
//!
//! Identifiers and copy are fictional. No customer names, live URLs, or
//! credentials appear in advertised metadata.

use std::sync::Arc;

use rmcp::model::{
    JsonObject, Prompt, Resource, ResourceContents, ResourceTemplate, Tool, ToolAnnotations,
};
use serde_json::{Map, Value};

/// Tools advertised on the first `tools/list` page.
pub const TOOL_PAGE_SIZE: usize = 3;

/// Prefix for opaque tool-list cursors (`tools:<offset>`).
pub const TOOL_CURSOR_PREFIX: &str = "tools:";

/// Required named tools plus extras so the lab exposes at least eight tools.
pub const TOOL_NAMES: &[&str] = &[
    "customer.lookup",
    "fleet.list",
    "vehicle.search",
    "reservation.update",
    "booking.create",
    "lot.assign",
    "reservation.delete",
    "legacy.ambiguous",
];

/// Resource URIs advertised by `resources/list`.
pub const RESOURCE_URIS: &[&str] = &[
    "synthetic://fleet/catalog",
    "synthetic://reservation/policy",
    "synthetic://notice/board",
];

/// Resource template advertised by `resources/templates/list`.
pub const VEHICLE_TEMPLATE: &str = "synthetic://vehicle/{id}";

/// Advertised external JSON Schema `$ref`. Discovery must record it and never fetch it.
pub const EXTERNAL_SCHEMA_REF: &str = "https://schemas.example.test/synthetic-vehicle.json";

/// Prompt names advertised by `prompts/list` (bodies are not required for discovery).
pub const PROMPT_NAMES: &[&str] = &["booking-summary", "fleet-support"];

/// Server implementation name on the wire.
pub const SERVER_NAME: &str = "synthetic-rental-mcp";

/// Server implementation version.
pub const SERVER_VERSION: &str = "0.1.0";

/// Cursor/catalog failure that maps to JSON-RPC invalid params.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// Cursor is missing the expected prefix or offset.
    UnknownCursor,
}

/// Slice `items` using an opaque `{prefix}{offset}` cursor.
pub fn slice_page<T: Clone>(
    items: &[T],
    cursor: Option<&str>,
    page_size: usize,
    prefix: &str,
) -> Result<(Vec<T>, Option<String>), CatalogError> {
    let start = parse_offset_cursor(cursor, prefix)?;
    if start > items.len() {
        return Err(CatalogError::UnknownCursor);
    }
    let end = (start + page_size).min(items.len());
    let page = items[start..end].to_vec();
    let next = if end < items.len() {
        Some(format!("{prefix}{end}"))
    } else {
        None
    };
    Ok((page, next))
}

fn parse_offset_cursor(cursor: Option<&str>, prefix: &str) -> Result<usize, CatalogError> {
    match cursor {
        None => Ok(0),
        Some("") => Err(CatalogError::UnknownCursor),
        Some(value) => {
            let rest = value
                .strip_prefix(prefix)
                .ok_or(CatalogError::UnknownCursor)?;
            rest.parse::<usize>()
                .map_err(|_| CatalogError::UnknownCursor)
        }
    }
}

/// Full deterministic tool catalog in advertisement order.
#[must_use]
pub fn tools() -> Vec<Tool> {
    vec![
        annotated_tool(
            "customer.lookup",
            "Look up a synthetic reservation holder by lab identifier.",
            object_schema(&["synthetic_customer_id"]),
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        ),
        annotated_tool(
            "fleet.list",
            "List synthetic fleet lots and vehicle counts.",
            object_schema(&[]),
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        ),
        annotated_tool(
            "vehicle.search",
            "Search the synthetic fleet catalog by class or lot.",
            object_schema(&["synthetic_query"]),
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(true),
        ),
        annotated_tool(
            "reservation.update",
            "Update a synthetic reservation window.",
            object_schema(&["synthetic_reservation_id"]),
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        annotated_tool(
            "booking.create",
            "Create a synthetic booking against the lab fleet.",
            object_schema(&["synthetic_vehicle_id"]),
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        annotated_tool(
            "lot.assign",
            "Assign a synthetic vehicle to a lab lot.",
            object_schema(&["synthetic_vehicle_id", "synthetic_lot_id"]),
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        ),
        annotated_tool(
            "reservation.delete",
            "Permanently remove a synthetic reservation.",
            object_schema(&["synthetic_reservation_id"]),
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            "legacy.ambiguous",
            "Undocumented legacy lab operation with no reliable hints.",
            ambiguous_schema(),
        ),
    ]
}

fn annotated_tool(
    name: &'static str,
    description: &'static str,
    schema: Arc<JsonObject>,
    annotations: ToolAnnotations,
) -> Tool {
    Tool::new(name, description, schema).annotate(annotations)
}

fn object_schema(properties: &[&str]) -> Arc<JsonObject> {
    let mut props = Map::new();
    for name in properties {
        let mut field = Map::new();
        field.insert("type".to_owned(), Value::String("string".to_owned()));
        props.insert((*name).to_owned(), Value::Object(field));
    }
    let mut schema = Map::new();
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert("properties".to_owned(), Value::Object(props));
    Arc::new(schema)
}

fn ambiguous_schema() -> Arc<JsonObject> {
    let mut schema = (*object_schema(&["payload"])).clone();
    let mut vehicle = Map::new();
    vehicle.insert(
        "$ref".to_owned(),
        Value::String(EXTERNAL_SCHEMA_REF.to_owned()),
    );
    match schema.get_mut("properties") {
        Some(Value::Object(props)) => {
            props.insert("vehicle".to_owned(), Value::Object(vehicle));
        }
        _ => {
            schema.insert("properties".to_owned(), Value::Object(vehicle));
        }
    }
    Arc::new(schema)
}

/// Full resource catalog.
#[must_use]
pub fn resources() -> Vec<Resource> {
    vec![
        Resource::new("synthetic://fleet/catalog", "fleet-catalog")
            .with_title("Synthetic fleet catalog")
            .with_description("Fictional vehicle classes and lot identifiers.")
            .with_mime_type("application/json"),
        Resource::new("synthetic://reservation/policy", "reservation-policy")
            .with_title("Synthetic reservation policy")
            .with_description("Lab-only booking rules. No live customer policy.")
            .with_mime_type("text/plain"),
        Resource::new("synthetic://notice/board", "notice-board")
            .with_title("Synthetic notice board")
            .with_description("Public lab notices for the fictional rental fleet.")
            .with_mime_type("text/plain"),
    ]
}

/// Resource templates.
#[must_use]
pub fn resource_templates() -> Vec<ResourceTemplate> {
    vec![ResourceTemplate::new(VEHICLE_TEMPLATE, "synthetic-vehicle")
        .with_title("Synthetic vehicle")
        .with_description("Lab vehicle card addressed by synthetic id.")
        .with_mime_type("application/json")]
}

/// Prompt list entries. Discovery must not fetch bodies.
#[must_use]
pub fn prompts() -> Vec<Prompt> {
    vec![
        Prompt::new(
            "booking-summary",
            Some("Summarize a synthetic booking using lab identifiers only."),
            None,
        )
        .with_title("Booking summary"),
        Prompt::new(
            "fleet-support",
            Some("Draft a synthetic fleet-support reply with lab identifiers."),
            None,
        )
        .with_title("Fleet support"),
    ]
}

/// Synthetic resource body for advertised URIs and the vehicle template.
#[must_use]
pub fn resource_body(uri: &str) -> Option<ResourceContents> {
    match uri {
        "synthetic://fleet/catalog" => Some(ResourceContents::text(
            r#"{"lots":["SYN-LOT-A","SYN-LOT-B"],"vehicles":["SYN-VEH-001","SYN-VEH-002"]}"#,
            uri,
        )),
        "synthetic://reservation/policy" => Some(ResourceContents::text(
            "Synthetic lab policy: holds expire after two lab ticks.",
            uri,
        )),
        "synthetic://notice/board" => Some(ResourceContents::text(
            "SYN-NOTICE-01: lot SYN-LOT-A is a lab fixture.",
            uri,
        )),
        other if other.starts_with("synthetic://vehicle/") => {
            let id = other.trim_start_matches("synthetic://vehicle/");
            if id.is_empty() || id.contains('/') {
                return None;
            }
            Some(ResourceContents::text(
                format!(r#"{{"id":"{id}","class":"SYN-COMPACT","lot":"SYN-LOT-A"}}"#),
                other,
            ))
        }
        _ => None,
    }
}

/// Prompt titles only; bodies stay synthetic and free of customer data.
#[must_use]
pub fn prompt_title(name: &str) -> Option<&'static str> {
    match name {
        "booking-summary" => Some("Booking summary"),
        "fleet-support" => Some("Fleet support"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_meets_design_minimums() {
        assert!(tools().len() >= 8);
        assert!(resources().len() >= 3);
        assert!(prompts().len() >= 2);
        assert_eq!(TOOL_NAMES.len(), tools().len());
        for (expected, tool) in TOOL_NAMES.iter().zip(tools()) {
            assert_eq!(tool.name.as_ref(), *expected);
        }
    }

    #[test]
    fn tools_paginate_after_three_items() {
        let all = tools();
        let (page0, next0) =
            slice_page(&all, None, TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX).expect("page0");
        assert_eq!(page0.len(), 3);
        assert_eq!(next0.as_deref(), Some("tools:3"));
        let (page1, next1) =
            slice_page(&all, next0.as_deref(), TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX).expect("page1");
        assert_eq!(page1.len(), 3);
        assert_eq!(next1.as_deref(), Some("tools:6"));
        let (page2, next2) =
            slice_page(&all, next1.as_deref(), TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX).expect("page2");
        assert_eq!(page2.len(), 2);
        assert_eq!(next2, None);
    }

    #[test]
    fn unknown_cursor_fails_closed() {
        let all = tools();
        let err = slice_page(&all, Some("nope"), TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX)
            .expect_err("unknown");
        assert_eq!(err, CatalogError::UnknownCursor);
        let empty =
            slice_page(&all, Some(""), TOOL_PAGE_SIZE, TOOL_CURSOR_PREFIX).expect_err("empty");
        assert_eq!(empty, CatalogError::UnknownCursor);
    }

    #[test]
    fn ambiguous_tool_advertises_external_ref_without_live_url_in_name() {
        let tool = tools()
            .into_iter()
            .find(|tool| tool.name.as_ref() == "legacy.ambiguous")
            .expect("ambiguous");
        let encoded = serde_json::to_string(&*tool.input_schema).expect("schema json");
        assert!(encoded.contains(EXTERNAL_SCHEMA_REF));
        assert!(!encoded.contains("sk_live_"));
    }
}
