//! Bounded, pagination-aware MCP catalog enumeration.
//!
//! The engine pages tools, resources, resource templates and prompts through
//! [`PagingCatalog`]. Every outbound method is authorized by [`PassivePolicy`]
//! before a page is requested. Content-fetch methods are never invoked.

use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::time::Instant;

use crate::adapter::{
    DiscoveryClient, PromptSnapshot, ResourceSnapshot, ResourceTemplateSnapshot, ToolSnapshot,
    DEFAULT_MAX_RESPONSE_BYTES, ENUMERATION_METHODS,
};
use crate::inventory::{
    AuthMechanism, AuthSnapshot, AuthState, CapabilitySnapshot, Completeness, DiscoveryInventory,
    DiscoveryRedaction, DiscoveryTarget, DiscoveryWarning, PromptInventory, ProtocolSnapshot,
    RedactionStrategy, ResourceInventory, ResourceTemplateInventory, ScannerMetadata,
    ServerSnapshot, ToolInventory, TransportKind, TransportSnapshot, WarningCode,
};
use crate::inventory_schema::INVENTORY_SCHEMA_ID;
use crate::inventory_validation::MAX_INPUT_SCHEMA_DEPTH;
use crate::inventory_version::InventorySchemaVersion;
use crate::policy::{DefaultPolicy, PassivePolicy, PolicyProfile};
use time::OffsetDateTime;

#[path = "enumerate_error.rs"]
mod enumerate_error;
#[path = "enumerate_loop.rs"]
mod enumerate_loop;
#[path = "enumerate_schema.rs"]
mod enumerate_schema;

pub use enumerate_error::{CollectionKind, EnumerateError};

use enumerate_loop::{paginate_prompts, paginate_resources, paginate_templates, paginate_tools};
use enumerate_schema::bound_input_schema;

/// Wire methods the enumeration engine is allowed to request.
pub const ENGINE_LIST_METHODS: &[&str] = ENUMERATION_METHODS;

/// One catalog page: items plus an optional opaque next cursor.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Page<T> {
    /// Items advertised on this page.
    pub items: Vec<T>,
    /// Opaque pagination cursor. `None` ends the collection.
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Page with items and no further cursor.
    pub fn complete(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
        }
    }

    /// Page that continues at `next_cursor`.
    pub fn continuing(items: Vec<T>, next_cursor: impl Into<String>) -> Self {
        Self {
            items,
            next_cursor: Some(next_cursor.into()),
        }
    }
}

/// Testable catalog that yields one page per call. Implementations must not
/// fetch resource contents, prompt bodies, or remote JSON Schema `$ref`s.
#[async_trait]
pub trait PagingCatalog: Send {
    /// Next `tools/list` page.
    async fn next_tools_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ToolSnapshot>, EnumerateError>;
    /// Next `resources/list` page.
    async fn next_resources_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceSnapshot>, EnumerateError>;
    /// Next `resources/templates/list` page.
    async fn next_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceTemplateSnapshot>, EnumerateError>;
    /// Next `prompts/list` page. Prompt bodies are never requested.
    async fn next_prompts_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<PromptSnapshot>, EnumerateError>;
}

/// Safe-by-default enumeration bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumerationBounds {
    /// Maximum list pages fetched per catalog.
    pub max_pages_per_collection: usize,
    /// Maximum items retained per catalog.
    pub max_items_per_collection: usize,
    /// Maximum in-memory JSON Schema nesting to capture.
    pub max_schema_depth: usize,
    /// Maximum serialized page size in bytes.
    pub max_response_bytes: usize,
    /// Timeout wrapping a single page request.
    pub request_timeout: Duration,
    /// Timeout wrapping the whole enumeration.
    pub overall_timeout: Duration,
}

impl EnumerationBounds {
    /// Conservative defaults for untrusted MCP catalogs.
    pub const fn new() -> Self {
        Self {
            max_pages_per_collection: 32,
            max_items_per_collection: 256,
            max_schema_depth: MAX_INPUT_SCHEMA_DEPTH,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            request_timeout: Duration::from_secs(15),
            overall_timeout: Duration::from_secs(30),
        }
    }

    fn validate(&self) -> Result<(), EnumerateError> {
        if self.max_pages_per_collection == 0 {
            return Err(EnumerateError::invalid_bounds("max-pages"));
        }
        if self.max_items_per_collection == 0 {
            return Err(EnumerateError::invalid_bounds("max-items"));
        }
        if self.max_schema_depth == 0 {
            return Err(EnumerateError::invalid_bounds("max-schema-depth"));
        }
        if self.max_response_bytes == 0 {
            return Err(EnumerateError::invalid_bounds("max-response-bytes"));
        }
        if self.request_timeout.is_zero() {
            return Err(EnumerateError::invalid_bounds("request-timeout"));
        }
        if self.overall_timeout.is_zero() {
            return Err(EnumerateError::invalid_bounds("overall-timeout"));
        }
        Ok(())
    }
}

impl Default for EnumerationBounds {
    fn default() -> Self {
        Self::new()
    }
}

/// Operator-safe identity used to build the inventory envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationContext {
    /// Target identity.
    pub target: DiscoveryTarget,
    /// Protocol snapshot.
    pub protocol: ProtocolSnapshot,
    /// Transport snapshot.
    pub transport: TransportSnapshot,
    /// Server identity, when known.
    pub server: Option<ServerSnapshot>,
    /// Advertised catalog capabilities.
    pub capabilities: CapabilitySnapshot,
    /// Auth observation (never credentials).
    pub auth: AuthSnapshot,
    /// Inventory timestamp.
    pub generated_at: OffsetDateTime,
    /// Optional scanner metadata.
    pub scanner: Option<ScannerMetadata>,
    /// Passive policy profile used to authorize list methods.
    pub policy_profile: PolicyProfile,
}

impl EnumerationContext {
    /// Synthetic envelope for tests and local fixtures.
    pub fn synthetic(generated_at: OffsetDateTime) -> Self {
        Self {
            target: DiscoveryTarget {
                id: "synthetic-rental-mcp".to_owned(),
                display_name: Some("synthetic rental lab".to_owned()),
                endpoint_fingerprint: Some("mcp.example.test/mcp".to_owned()),
            },
            protocol: ProtocolSnapshot {
                revision: "2026-07-28".to_owned(),
                negotiated: true,
                client_name: Some("dare-agent-security".to_owned()),
                client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            },
            transport: TransportSnapshot {
                kind: TransportKind::StreamableHttp,
                identity: Some("mcp.example.test/mcp".to_owned()),
            },
            server: Some(ServerSnapshot {
                name: "synthetic-rental-mcp".to_owned(),
                version: Some("1.0.0".to_owned()),
                title: Some("Synthetic Rental MCP".to_owned()),
            }),
            capabilities: CapabilitySnapshot {
                tools: true,
                resources: true,
                resource_templates: true,
                prompts: true,
            },
            auth: AuthSnapshot {
                state: AuthState::NotApplicable,
                mechanism: AuthMechanism::NoneObserved,
            },
            generated_at,
            scanner: Some(ScannerMetadata {
                name: "dare-agent-security".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }),
            policy_profile: PolicyProfile::Current2026_07_28,
        }
    }
}

/// Result of bounded catalog enumeration.
#[derive(Clone, Debug, PartialEq)]
pub struct EnumerationOutcome {
    /// Inventory record. Completeness is also stored here.
    pub inventory: DiscoveryInventory,
    /// Completeness mirrored from the inventory for callers that match on it.
    pub completeness: Completeness,
    /// Wire methods authorized and requested by the engine, in order.
    pub invoked_methods: Vec<String>,
}

/// Enumerate all four catalogs using [`DefaultPolicy`] for `context.policy_profile`.
pub async fn enumerate_inventory<C: PagingCatalog>(
    catalog: &mut C,
    bounds: &EnumerationBounds,
    context: EnumerationContext,
) -> Result<EnumerationOutcome, EnumerateError> {
    let policy = DefaultPolicy::new(context.policy_profile);
    enumerate_inventory_with_policy(catalog, &policy, bounds, context).await
}

/// Enumerate all four catalogs, authorizing each page through `policy`.
pub async fn enumerate_inventory_with_policy<C, P>(
    catalog: &mut C,
    policy: &P,
    bounds: &EnumerationBounds,
    context: EnumerationContext,
) -> Result<EnumerationOutcome, EnumerateError>
where
    C: PagingCatalog,
    P: PassivePolicy,
{
    bounds.validate()?;
    let deadline = Instant::now() + bounds.overall_timeout;

    let tools = paginate_tools(catalog, bounds, deadline, policy).await?;
    let resources = paginate_resources(catalog, bounds, deadline, policy).await?;
    let templates = paginate_templates(catalog, bounds, deadline, policy).await?;
    let prompts = paginate_prompts(catalog, bounds, deadline, policy).await?;

    let mut warnings = Vec::new();
    warnings.extend(tools.warnings);
    warnings.extend(resources.warnings);
    warnings.extend(templates.warnings);
    warnings.extend(prompts.warnings);

    let mut invoked_methods = Vec::new();
    invoked_methods.extend(tools.invoked_methods);
    invoked_methods.extend(resources.invoked_methods);
    invoked_methods.extend(templates.invoked_methods);
    invoked_methods.extend(prompts.invoked_methods);

    let mut schema_warnings = Vec::new();
    let tool_inventory = tools
        .items
        .into_iter()
        .filter_map(|tool| tool_inventory(tool, bounds.max_schema_depth, &mut schema_warnings))
        .collect();
    warnings.extend(schema_warnings);

    let resource_inventory = resources
        .items
        .into_iter()
        .filter_map(resource_inventory)
        .collect();
    let template_inventory = templates
        .items
        .into_iter()
        .filter_map(template_inventory)
        .collect();
    let prompt_inventory = prompts
        .items
        .into_iter()
        .filter_map(prompt_inventory)
        .collect();

    if remaining_deadline(deadline).is_none()
        && !warnings
            .iter()
            .any(|warning| warning.code.implies_partial())
    {
        warnings.push(DiscoveryWarning {
            code: WarningCode::Timeout,
            message: "enumeration stopped after the configured overall timeout".to_owned(),
        });
    }

    let completeness = if warnings
        .iter()
        .any(|warning| warning.code.implies_partial())
    {
        Completeness::Partial
    } else {
        Completeness::Complete
    };

    let mut inventory = DiscoveryInventory {
        schema: crate::inventory::InventorySchemaRef {
            id: INVENTORY_SCHEMA_ID.to_owned(),
            version: InventorySchemaVersion::V1,
        },
        generated_at: context.generated_at,
        completeness,
        target: context.target,
        protocol: context.protocol,
        transport: context.transport,
        server: context.server,
        capabilities: context.capabilities,
        auth: context.auth,
        tools: tool_inventory,
        resources: resource_inventory,
        resource_templates: template_inventory,
        prompts: prompt_inventory,
        indicators: Vec::new(),
        warnings,
        redaction: DiscoveryRedaction {
            applied: false,
            strategy: RedactionStrategy::None,
        },
        hashes: Vec::new(),
        scanner: context.scanner,
    };

    let mut hashes = Vec::new();
    for tool in &inventory.tools {
        if let Some(digest) = &tool.input_schema_digest {
            if !hashes.iter().any(|existing| existing == digest) {
                hashes.push(digest.clone());
            }
        }
    }
    inventory.hashes = hashes;
    inventory.normalize();

    Ok(EnumerationOutcome {
        completeness: inventory.completeness,
        inventory,
        invoked_methods,
    })
}

fn remaining_deadline(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    if now >= deadline {
        None
    } else {
        Some(deadline - now)
    }
}

fn tool_inventory(
    tool: ToolSnapshot,
    max_schema_depth: usize,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Option<ToolInventory> {
    if tool.name.trim().is_empty() {
        warnings.push(DiscoveryWarning {
            code: WarningCode::MalformedMetadata,
            message: "tools/list stopped after malformed metadata".to_owned(),
        });
        return None;
    }
    let (input_schema, input_schema_digest) = match tool.input_schema {
        Some(schema) => {
            let bounded = bound_input_schema(&schema, max_schema_depth);
            if bounded.depth_exceeded || bounded.nodes_exceeded {
                warnings.push(DiscoveryWarning {
                    code: WarningCode::MalformedMetadata,
                    message: "tools/list stopped after malformed metadata".to_owned(),
                });
            }
            (bounded.object, bounded.digest)
        }
        None => (None, None),
    };
    Some(ToolInventory {
        name: tool.name,
        title: tool.title,
        description: tool.description,
        input_schema_digest,
        input_schema,
        annotations: tool.annotations,
        classification: None,
    })
}

fn resource_inventory(resource: ResourceSnapshot) -> Option<ResourceInventory> {
    if resource.uri.trim().is_empty() {
        return None;
    }
    Some(ResourceInventory {
        uri: resource.uri,
        name: resource.name,
        description: resource.description,
        mime_type: None,
    })
}

fn template_inventory(template: ResourceTemplateSnapshot) -> Option<ResourceTemplateInventory> {
    if template.uri_template.trim().is_empty() {
        return None;
    }
    Some(ResourceTemplateInventory {
        uri_template: template.uri_template,
        name: template.name,
        description: template.description,
    })
}

fn prompt_inventory(prompt: PromptSnapshot) -> Option<PromptInventory> {
    if prompt.name.trim().is_empty() {
        return None;
    }
    Some(PromptInventory {
        name: prompt.name,
        title: prompt.title,
        description: prompt.description,
    })
}

#[async_trait]
impl PagingCatalog for DiscoveryClient {
    async fn next_tools_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ToolSnapshot>, EnumerateError> {
        let (items, next_cursor) = self.list_tools_page(cursor).await?;
        Ok(Page { items, next_cursor })
    }

    async fn next_resources_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceSnapshot>, EnumerateError> {
        let (items, next_cursor) = self.list_resources_page(cursor).await?;
        Ok(Page { items, next_cursor })
    }

    async fn next_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceTemplateSnapshot>, EnumerateError> {
        let (items, next_cursor) = self.list_resource_templates_page(cursor).await?;
        Ok(Page { items, next_cursor })
    }

    async fn next_prompts_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<PromptSnapshot>, EnumerateError> {
        let (items, next_cursor) = self.list_prompts_page(cursor).await?;
        Ok(Page { items, next_cursor })
    }
}

/// Methods the engine will authorize. Always a subset of the profile allowlist.
pub fn engine_outbound_methods(profile: PolicyProfile) -> Vec<&'static str> {
    ENGINE_LIST_METHODS
        .iter()
        .copied()
        .filter(|method| profile.allows(method))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_methods_are_the_list_allowlist() {
        assert_eq!(
            ENGINE_LIST_METHODS,
            &[
                "tools/list",
                "resources/list",
                "resources/templates/list",
                "prompts/list",
            ]
        );
        for profile in [
            PolicyProfile::Current2026_07_28,
            PolicyProfile::Legacy2024_11_05,
        ] {
            let allow = PolicyProfile::allowlisted_methods(profile);
            for method in engine_outbound_methods(profile) {
                assert!(allow.contains(&method));
                assert_ne!(method, "tools/call");
                assert_ne!(method, "resources/read");
                assert_ne!(method, "prompts/get");
            }
        }
    }

    #[test]
    fn default_bounds_are_nonzero() {
        let bounds = EnumerationBounds::new();
        assert!(bounds.validate().is_ok());
        assert!(bounds.max_pages_per_collection >= 1);
        assert!(bounds.max_schema_depth <= MAX_INPUT_SCHEMA_DEPTH);
    }
}
