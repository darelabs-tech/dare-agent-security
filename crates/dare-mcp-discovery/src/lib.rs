//! Passive MCP discovery library for DARE Agent Security.
//!
//! This crate hosts Cycle 002 discovery contracts and engines. It may depend
//! inward on `dare-security-evidence`. Protocol-specific SDK types must not
//! leak into the public inventory contract. Active/adversarial operations are
//! out of scope. Outbound protocol methods are allowlisted by [`policy`].

pub mod adapter;
pub mod classification;
pub mod enumerate;
pub mod evidence_bridge;
mod inventory;
mod inventory_error;
mod inventory_schema;
mod inventory_validation;
mod inventory_version;
pub mod policy;
pub mod sanitize;

pub use adapter::{
    documented_wire_revision, lifecycle_mode_for, planned_outbound_methods, AdapterError,
    DiscoveryClient, DiscoveryLifecycleMode, DiscoveryTargetKind, DiscoveryTargetSpec,
    DiscoveryTimeouts, HttpTransportConfig, McpDiscoveryClient, PromptSnapshot, ResourceSnapshot,
    ResourceTemplateSnapshot, StdioLaunch, TimeoutPhase, ToolSnapshot, CURRENT_WIRE_REVISION,
    DEFAULT_MAX_RESPONSE_BYTES, ENUMERATION_METHODS, LEGACY_WIRE_REVISION,
};
pub use classification::classify_tool;
pub use enumerate::{
    engine_outbound_methods, enumerate_inventory, enumerate_inventory_with_policy, CollectionKind,
    EnumerateError, EnumerationBounds, EnumerationContext, EnumerationOutcome, Page, PagingCatalog,
    ENGINE_LIST_METHODS,
};
pub use evidence_bridge::{
    emit_baseline_evidence, emit_completeness_evidence, emit_policy_evidence,
    emit_protocol_evidence, emit_redaction_evidence, DiscoveryObservation, EvidenceBridgeError,
    EXTENSION_KEY, VECTOR_COMPLETENESS, VECTOR_POLICY, VECTOR_PROTOCOL, VECTOR_REDACTION,
    VECTOR_VERSION,
};
pub use inventory::{
    AuthMechanism, AuthSnapshot, AuthState, BaselineIndicator, CapabilitySnapshot,
    ClassificationSource, Completeness, DiscoveryHashRef, DiscoveryInventory, DiscoveryRedaction,
    DiscoveryTarget, DiscoveryWarning, InventorySchemaRef, OperationClass, PromptInventory,
    ProtocolSnapshot, RedactionStrategy, ResourceInventory, ResourceTemplateInventory,
    ScannerMetadata, ServerSnapshot, ToolAnnotations, ToolClassification, ToolInventory,
    TransportKind, TransportSnapshot, WarningCode,
};
pub use inventory_error::InventoryError;
pub use inventory_schema::{
    inventory_schema_v1, inventory_schema_v1_path, validate_instance, INVENTORY_SCHEMA_ID,
    INVENTORY_SCHEMA_V1_ID, INVENTORY_SCHEMA_V1_JSON,
};
pub use inventory_validation::{
    validate, MAX_INPUT_SCHEMA_DEPTH, MAX_INPUT_SCHEMA_NODES, SUPPORTED_SCHEMA_MAJOR,
};
pub use inventory_version::{InventorySchemaVersion, VersionParseError};
pub use policy::{
    DefaultPolicy, DiscoveryMethod, OutboundTransport, PassivePolicy, PolicyError,
    PolicyGuardedTransport, PolicyProfile, PolicyRefusal, RefusalReason,
};
pub use sanitize::{
    looks_like_secret, looks_like_secret_value, redact_text, sanitize_error_display,
    sanitize_inventory, sanitize_inventory_target, sanitize_stream, sanitize_url_identity,
    REDACTED,
};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-mcp-discovery";

/// CLI binary name that consumes this library.
pub const CLI_BIN_NAME: &str = "dare-agent-security";

/// Confirms the inward Cycle 001 evidence kernel dependency without exposing
/// protocol-specific types from this crate into the evidence crate.
pub fn evidence_kernel_name() -> &'static str {
    dare_security_evidence::CRATE_NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
        assert!(env!("CARGO_MANIFEST_DIR").ends_with("dare-mcp-discovery"));
        assert_eq!(CLI_BIN_NAME, "dare-agent-security");
    }

    #[test]
    fn depends_inward_on_evidence_kernel() {
        assert_eq!(evidence_kernel_name(), "dare-security-evidence");
        assert_eq!(dare_security_evidence::CRATE_NAME, "dare-security-evidence");
    }

    #[test]
    fn evidence_manifest_does_not_depend_on_discovery_or_cli() {
        let evidence_manifest = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dare-security-evidence/Cargo.toml"
        ));
        assert!(
            !evidence_manifest.contains("dare-mcp-discovery"),
            "evidence crate must remain a dependency leaf"
        );
        assert!(
            !evidence_manifest.contains("dare-agent-security"),
            "evidence crate must not depend on the CLI crate"
        );
    }
}
