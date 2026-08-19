//! Canonical public discovery inventory types.
//!
//! Field names are observation metadata only. Credential-bearing URLs, tokens,
//! headers, API keys and private keys are not part of this contract.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::inventory_version::InventorySchemaVersion;

/// Top-level canonical MCP discovery inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryInventory {
    /// Schema identifier and version for this record.
    pub schema: InventorySchemaRef,
    /// RFC 3339 timestamp for when this inventory was generated.
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    /// Explicit completeness. Required; there is no implicit default.
    pub completeness: Completeness,
    /// Operator-safe target identity.
    pub target: DiscoveryTarget,
    /// Negotiated or selected protocol snapshot.
    pub protocol: ProtocolSnapshot,
    /// Observed transport snapshot.
    pub transport: TransportSnapshot,
    /// Server identity metadata, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerSnapshot>,
    /// Declared/observed catalog capabilities.
    pub capabilities: CapabilitySnapshot,
    /// Authentication observation metadata (never credentials).
    pub auth: AuthSnapshot,
    /// Inventoried tools.
    pub tools: Vec<ToolInventory>,
    /// Inventoried resources (URIs only; no content).
    pub resources: Vec<ResourceInventory>,
    /// Inventoried resource templates.
    pub resource_templates: Vec<ResourceTemplateInventory>,
    /// Inventoried prompts (names only; no bodies/messages).
    pub prompts: Vec<PromptInventory>,
    /// Baseline observations, not vulnerability claims.
    pub indicators: Vec<BaselineIndicator>,
    /// Structured discovery warnings.
    pub warnings: Vec<DiscoveryWarning>,
    /// Mandatory redaction declaration.
    pub redaction: DiscoveryRedaction,
    /// Hash metadata (algorithm + lowercase hex digest).
    pub hashes: Vec<DiscoveryHashRef>,
    /// Optional scanner/spec revision metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner: Option<ScannerMetadata>,
}

impl DiscoveryInventory {
    /// Sort catalog collections into the deterministic public order.
    pub fn normalize(&mut self) {
        self.tools.sort_by(|a, b| a.name.cmp(&b.name));
        for tool in &mut self.tools {
            if let Some(classification) = &mut tool.classification {
                classification.heuristic_indicators.sort();
            }
        }
        self.resources.sort_by(|a, b| a.uri.cmp(&b.uri));
        self.resource_templates
            .sort_by(|a, b| a.uri_template.cmp(&b.uri_template));
        self.prompts.sort_by(|a, b| a.name.cmp(&b.name));
        self.indicators.sort_by(|a, b| {
            a.id.cmp(&b.id)
                .then_with(|| a.code.cmp(&b.code))
                .then_with(|| a.message.cmp(&b.message))
        });
        self.warnings.sort_by(|a, b| {
            a.code
                .as_str()
                .cmp(b.code.as_str())
                .then_with(|| a.message.cmp(&b.message))
        });
        self.hashes
            .sort_by(|a, b| a.alg.cmp(&b.alg).then_with(|| a.digest.cmp(&b.digest)));
    }
}

/// Schema identity for an inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySchemaRef {
    /// Canonical schema identifier URI (`https://darelabs.tech/schemas/discovery`).
    pub id: String,
    /// Schema version (`MAJOR.MINOR.PATCH`).
    pub version: InventorySchemaVersion,
}

/// Discovery completeness. Required; no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Completeness {
    /// Enumeration finished within configured bounds.
    Complete,
    /// Enumeration stopped early or observed incomplete metadata.
    Partial,
}

/// Operator-safe target of a discovery scan.
///
/// Never a credential-bearing URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryTarget {
    /// Operator-safe identifier.
    pub id: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Sanitized host/path identity or digest. Never userinfo/query/fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_fingerprint: Option<String>,
}

/// Protocol revision snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSnapshot {
    /// Selected or negotiated MCP revision (e.g. `2026-07-28`).
    pub revision: String,
    /// Whether the revision was negotiated rather than operator-fixed.
    pub negotiated: bool,
    /// Client name presented during discovery, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Client version presented during discovery, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

/// Transport observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSnapshot {
    /// Transport kind. Required; no default.
    pub kind: TransportKind,
    /// Sanitized host/path identity or fingerprint. Never secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// Supported discovery transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportKind {
    /// Local stdio child process.
    Stdio,
    /// Streamable HTTP.
    StreamableHttp,
}

/// Observed server identity. Self-reported; not a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSnapshot {
    /// Server name.
    pub name: String,
    /// Server version, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional human title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Declared catalog capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySnapshot {
    /// Tools catalog is advertised.
    pub tools: bool,
    /// Resources catalog is advertised.
    pub resources: bool,
    /// Resource templates catalog is advertised.
    pub resource_templates: bool,
    /// Prompts catalog is advertised.
    pub prompts: bool,
}

/// Authentication observation. Identifiers/mechanisms only — never credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSnapshot {
    /// How the auth state was obtained. Required; no default.
    pub state: AuthState,
    /// Observed or declared mechanism. Required; no default.
    pub mechanism: AuthMechanism,
}

/// Provenance of the auth observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthState {
    /// Directly observed on the wire/config surface.
    Observed,
    /// Declared by server metadata.
    Declared,
    /// Insufficient metadata to classify.
    Unknown,
    /// Auth is not applicable to this transport/target.
    NotApplicable,
}

/// Auth mechanism vocabulary. Values describe configuration presence, not secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthMechanism {
    /// No authentication material was observed.
    NoneObserved,
    /// OAuth metadata was advertised.
    OauthMetadata,
    /// A bearer credential source was configured (value never stored).
    BearerConfigured,
    /// An API-key credential source was configured (value never stored).
    ApiKeyConfigured,
    /// Mutual TLS was configured.
    MutualTlsConfigured,
    /// A mechanism was observed that is not in this vocabulary.
    Other,
    /// Mechanism could not be determined.
    Unknown,
}

/// Inventoried tool descriptor. Never executed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInventory {
    /// Tool name.
    pub name: String,
    /// Optional title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description (untrusted data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Digest of the advertised input schema, when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_digest: Option<DiscoveryHashRef>,
    /// Bounded JSON object copy of the input schema. Never executed as a validator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Map<String, Value>>,
    /// Self-reported annotations (untrusted hints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Deterministic classification with provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<ToolClassification>,
}

/// MCP-style tool annotation hints. Untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

/// Conservative tool operation classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolClassification {
    /// Operation class. Required; no default.
    pub class: OperationClass,
    /// Provenance of the classification. Required; no default.
    pub source: ClassificationSource,
    /// Stable rationale code.
    pub rationale_code: String,
    /// Non-authoritative heuristic indicators.
    pub heuristic_indicators: Vec<String>,
}

/// Tool operation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationClass {
    /// Declared or derived read-only behavior.
    ReadOnly,
    /// Declared or derived state-changing behavior.
    StateChanging,
    /// Declared or derived destructive behavior.
    Destructive,
    /// Insufficient metadata to classify.
    Unknown,
}

/// Where a classification decision came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassificationSource {
    /// Taken from protocol annotations (untrusted hint).
    ProtocolAnnotation,
    /// Taken from explicit operator/scanner configuration.
    ExplicitConfiguration,
    /// Derived by a pure deterministic rule.
    DeterministicDerivation,
    /// Metadata was insufficient; class should be `UNKNOWN`.
    InsufficientMetadata,
}

/// Inventoried resource descriptor. Content is never retrieved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceInventory {
    /// Resource URI.
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Inventoried resource template. Templates are not expanded against live hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTemplateInventory {
    /// URI template.
    pub uri_template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Inventoried prompt descriptor. Bodies and messages are never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInventory {
    /// Prompt name.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Baseline observation (not a vulnerability finding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineIndicator {
    /// Indicator identifier.
    pub id: String,
    /// Stable observation code.
    pub code: String,
    /// Human-readable observation.
    pub message: String,
}

/// Structured discovery warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryWarning {
    /// Warning code. Required; no default.
    pub code: WarningCode,
    /// Human-readable warning without secrets.
    pub message: String,
}

/// Structured warning vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WarningCode {
    /// Item count bound was reached.
    ItemLimitReached,
    /// Server metadata could not be parsed safely.
    MalformedMetadata,
    /// Pagination page bound was reached.
    PaginationLimitReached,
    /// Redaction transformed one or more fields.
    RedactionApplied,
    /// Response size bound was reached.
    ResponseLimitReached,
    /// A request or overall timeout fired.
    Timeout,
    /// A catalog capability is unsupported by this scanner revision.
    UnsupportedCapability,
    /// Protocol revision is unsupported.
    UnsupportedProtocol,
}

impl WarningCode {
    /// Wire token for this warning code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemLimitReached => "ITEM_LIMIT_REACHED",
            Self::MalformedMetadata => "MALFORMED_METADATA",
            Self::PaginationLimitReached => "PAGINATION_LIMIT_REACHED",
            Self::RedactionApplied => "REDACTION_APPLIED",
            Self::ResponseLimitReached => "RESPONSE_LIMIT_REACHED",
            Self::Timeout => "TIMEOUT",
            Self::UnsupportedCapability => "UNSUPPORTED_CAPABILITY",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
        }
    }

    /// Whether this code implies a partial (bounded/incomplete) inventory.
    pub fn implies_partial(self) -> bool {
        matches!(
            self,
            Self::PaginationLimitReached
                | Self::ItemLimitReached
                | Self::ResponseLimitReached
                | Self::Timeout
                | Self::MalformedMetadata
        )
    }
}

/// Redaction declaration for the inventory payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRedaction {
    /// Whether any redaction transform was applied.
    pub applied: bool,
    /// Strategy used. Required; no default.
    pub strategy: RedactionStrategy,
}

/// Inventory redaction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedactionStrategy {
    /// No redaction was required or applied.
    None,
    /// Some sensitive material was redacted.
    Partial,
    /// The payload was fully redacted to safe identifiers.
    Full,
}

/// Hash algorithm + lowercase hex digest (no signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryHashRef {
    /// Hash algorithm (`sha256`, `sha384`, or `sha512`).
    pub alg: String,
    /// Lowercase hexadecimal digest.
    pub digest: String,
}

/// Scanner/spec revision metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerMetadata {
    /// Scanner name.
    pub name: String,
    /// Scanner version string.
    pub version: String,
}

#[cfg(test)]
pub(crate) fn sample_hash() -> DiscoveryHashRef {
    DiscoveryHashRef {
        alg: "sha256".to_owned(),
        digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    }
}

/// Representative COMPLETE inventory used by crate tests. Synthetic identifiers only.
#[cfg(test)]
pub(crate) fn sample_complete_inventory() -> DiscoveryInventory {
    use crate::inventory_schema::INVENTORY_SCHEMA_ID;
    use serde_json::json;
    use time::macros::datetime;

    let input_schema = json!({
        "type": "object",
        "properties": {
            "vehicle_id": { "type": "string" }
        }
    })
    .as_object()
    .cloned();

    DiscoveryInventory {
        schema: InventorySchemaRef {
            id: INVENTORY_SCHEMA_ID.to_owned(),
            version: InventorySchemaVersion::V1,
        },
        generated_at: datetime!(2026-08-18 15:00:00 UTC),
        completeness: Completeness::Complete,
        target: DiscoveryTarget {
            id: "synthetic-rental-mcp".to_owned(),
            display_name: Some("synthetic rental lab".to_owned()),
            endpoint_fingerprint: Some("mcp.example.test/mcp".to_owned()),
        },
        protocol: ProtocolSnapshot {
            revision: "2026-07-28".to_owned(),
            negotiated: true,
            client_name: Some("dare-agent-security".to_owned()),
            client_version: Some("0.1.0".to_owned()),
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
            state: AuthState::Observed,
            mechanism: AuthMechanism::NoneObserved,
        },
        tools: vec![
            ToolInventory {
                name: "customer.lookup".to_owned(),
                title: Some("Lookup vehicle customer record".to_owned()),
                description: Some("Read synthetic reservation holder metadata.".to_owned()),
                input_schema_digest: Some(sample_hash()),
                input_schema,
                annotations: Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: Some(false),
                    idempotent_hint: Some(true),
                    open_world_hint: Some(false),
                }),
                classification: Some(ToolClassification {
                    class: OperationClass::ReadOnly,
                    source: ClassificationSource::ProtocolAnnotation,
                    rationale_code: "PROTOCOL_READ_ONLY_HINT".to_owned(),
                    heuristic_indicators: vec!["read_only_hint".to_owned()],
                }),
            },
            ToolInventory {
                name: "legacy.ambiguous".to_owned(),
                title: None,
                description: Some("Undocumented legacy helper.".to_owned()),
                input_schema_digest: None,
                input_schema: None,
                annotations: None,
                classification: Some(ToolClassification {
                    class: OperationClass::Unknown,
                    source: ClassificationSource::InsufficientMetadata,
                    rationale_code: "INSUFFICIENT_METADATA".to_owned(),
                    heuristic_indicators: Vec::new(),
                }),
            },
        ],
        resources: vec![ResourceInventory {
            uri: "synthetic://fleet/catalog".to_owned(),
            name: Some("fleet-catalog".to_owned()),
            description: Some("Synthetic fleet catalog.".to_owned()),
            mime_type: Some("application/json".to_owned()),
        }],
        resource_templates: vec![ResourceTemplateInventory {
            uri_template: "synthetic://vehicle/{id}".to_owned(),
            name: Some("vehicle".to_owned()),
            description: Some("Synthetic vehicle record template.".to_owned()),
        }],
        prompts: vec![PromptInventory {
            name: "booking-summary".to_owned(),
            title: Some("Booking summary".to_owned()),
            description: Some("Summarize a synthetic reservation.".to_owned()),
        }],
        indicators: vec![BaselineIndicator {
            id: "MCP-DISCOVERY-001".to_owned(),
            code: "PROTOCOL_NEGOTIATED".to_owned(),
            message: "MCP revision 2026-07-28 was negotiated.".to_owned(),
        }],
        warnings: Vec::new(),
        redaction: DiscoveryRedaction {
            applied: false,
            strategy: RedactionStrategy::None,
        },
        hashes: vec![sample_hash()],
        scanner: Some(ScannerMetadata {
            name: "dare-agent-security".to_owned(),
            version: "0.1.0".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn canonical_model_json_round_trips() {
        let original = sample_complete_inventory();
        let encoded = serde_json::to_string(&original).expect("serialize");
        let decoded: DiscoveryInventory = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, original);
    }

    #[test]
    fn missing_completeness_is_rejected_with_no_default() {
        let mut value = serde_json::to_value(sample_complete_inventory()).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .remove("completeness");
        assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut value = serde_json::to_value(sample_complete_inventory()).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("customer_tenant".to_owned(), json!("acme"));
        assert!(serde_json::from_value::<DiscoveryInventory>(value).is_err());
    }

    #[test]
    fn normalize_sorts_catalogs_deterministically() {
        let mut inventory = sample_complete_inventory();
        inventory.tools.reverse();
        inventory.normalize();
        let names: Vec<&str> = inventory
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(names, vec!["customer.lookup", "legacy.ambiguous"]);
    }

    fn collect_keys(value: &Value, keys: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    keys.push(key.to_lowercase());
                    collect_keys(child, keys);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_keys(item, keys);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn public_model_has_no_credential_fields() {
        let schema = serde_json::to_value(sample_complete_inventory()).expect("json");
        let mut keys = Vec::new();
        collect_keys(&schema, &mut keys);
        for forbidden in [
            "password",
            "token",
            "authorization",
            "api_key",
            "private_key",
        ] {
            assert!(
                !keys.iter().any(|key| key == forbidden),
                "sample inventory must not expose credential field {forbidden}"
            );
        }
    }

    #[test]
    fn wire_enums_use_screaming_snake_case() {
        assert_eq!(
            serde_json::to_value(Completeness::Complete).expect("json"),
            json!("COMPLETE")
        );
        assert_eq!(
            serde_json::to_value(Completeness::Partial).expect("json"),
            json!("PARTIAL")
        );
        assert_eq!(
            serde_json::to_value(TransportKind::Stdio).expect("json"),
            json!("STDIO")
        );
        assert_eq!(
            serde_json::to_value(TransportKind::StreamableHttp).expect("json"),
            json!("STREAMABLE_HTTP")
        );
        assert_eq!(
            serde_json::to_value(AuthState::NotApplicable).expect("json"),
            json!("NOT_APPLICABLE")
        );
        assert_eq!(
            serde_json::to_value(AuthMechanism::ApiKeyConfigured).expect("json"),
            json!("API_KEY_CONFIGURED")
        );
        assert_eq!(
            serde_json::to_value(OperationClass::ReadOnly).expect("json"),
            json!("READ_ONLY")
        );
        assert_eq!(
            serde_json::to_value(OperationClass::StateChanging).expect("json"),
            json!("STATE_CHANGING")
        );
        assert_eq!(
            serde_json::to_value(OperationClass::Destructive).expect("json"),
            json!("DESTRUCTIVE")
        );
        assert_eq!(
            serde_json::to_value(OperationClass::Unknown).expect("json"),
            json!("UNKNOWN")
        );
        assert_eq!(
            serde_json::to_value(ClassificationSource::ProtocolAnnotation).expect("json"),
            json!("PROTOCOL_ANNOTATION")
        );
        assert_eq!(
            serde_json::to_value(RedactionStrategy::None).expect("json"),
            json!("NONE")
        );
        assert_eq!(
            serde_json::to_value(WarningCode::PaginationLimitReached).expect("json"),
            json!("PAGINATION_LIMIT_REACHED")
        );
        assert!(serde_json::from_str::<Completeness>("\"DONE\"").is_err());
        assert!(serde_json::from_str::<TransportKind>("\"TCP\"").is_err());
        assert!(serde_json::from_str::<AuthMechanism>("\"BASIC\"").is_err());
    }

    #[test]
    fn prompt_inventory_has_no_body_or_messages_fields() {
        let prompt = serde_json::to_value(PromptInventory {
            name: "booking-summary".to_owned(),
            title: None,
            description: None,
        })
        .expect("json");
        let obj = prompt.as_object().expect("object");
        assert!(!obj.contains_key("body"));
        assert!(!obj.contains_key("messages"));
        assert!(!obj.contains_key("prompt"));
    }
}
