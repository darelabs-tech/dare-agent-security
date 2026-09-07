//! Protocol revision, request routing metadata and the JSON-RPC operation.
//!
//! The modern MCP transport carries routing metadata alongside the JSON-RPC
//! body, and a gateway may act on either. That makes them two independently
//! observed sides of the same request, and the security question is whether
//! they agree about what is being done.
//!
//! They are compared on **normalized semantics, never raw bytes**. A difference
//! in casing or surrounding whitespace does not change which tool runs; a
//! difference in the tool name does. Comparing bytes would report findings
//! about formatting, and an engine that cries wolf about whitespace is one
//! whose real findings stop being read.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::source::ProtocolRevisionClass;

/// A synthetic, non-fetchable identifier.
///
/// Issuers, resources and endpoints in this cycle are *identities*, not
/// addresses. Representing them as opaque ids rather than URLs is what makes
/// the offline guarantee structural: there is nothing in a fixture that could
/// be fetched even by a future caller who wanted to, because nothing in a
/// fixture is a URL.
///
/// The constructor refuses anything scheme-shaped for that reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SyntheticUri(String);

/// Deserialization runs the same check the constructor does.
///
/// Deriving `Deserialize` alongside `serde(transparent)` would let any string
/// through, which would make the type a comment rather than a guarantee: the
/// constructor would be enforced only on values this crate built, and every
/// value that actually matters arrives by deserializing a fixture.
impl<'de> Deserialize<'de> for SyntheticUri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

impl SyntheticUri {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        assert_non_fetchable(&value, "synthetic identifier")?;
        crate::canonical::assert_safe_identifier(&value, "synthetic identifier")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SyntheticUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Schemes that would make a value reachable.
///
/// Checked as a prefix-or-substring rather than parsed, because the goal is not
/// to decide whether something is a *valid* URL but to refuse anything that
/// looks like one at all.
const FETCHABLE_MARKERS: [&str; 10] = [
    "://", "http:", "https:", "ws:", "wss:", "ftp:", "file:", "data:", "mailto:", "//",
];

/// Refuse a value that names something reachable.
pub fn assert_non_fetchable(value: &str, where_found: &str) -> Result<()> {
    let lowered = value.to_ascii_lowercase();
    for marker in FETCHABLE_MARKERS {
        if lowered.contains(marker) {
            return Err(McpAuthSecurityError::refusal(format!(
                "{where_found} looks like a reachable target; Cycle 018 identifiers are \
                 synthetic identities, never addresses"
            )));
        }
    }
    Ok(())
}

/// The protocol context a request ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolContext {
    /// The revision string as recorded. Classified rather than trusted.
    pub declared_revision: String,
    /// Whether the transport was HTTP, where the modern auth surface lives.
    #[serde(default)]
    pub http_transport: bool,
}

impl ProtocolContext {
    pub fn revision_class(&self) -> ProtocolRevisionClass {
        ProtocolRevisionClass::classify(&self.declared_revision)
    }

    pub fn validate(&self) -> Result<()> {
        if self.declared_revision.trim().is_empty() {
            return Err(McpAuthSecurityError::invalid(
                "protocol context declares no revision",
            ));
        }
        crate::canonical::assert_safe_identifier(&self.declared_revision, "protocol revision")?;
        Ok(())
    }
}

/// The routing metadata the transport carried.
///
/// Both fields are optional because a transport may carry neither, and the
/// absence of routing metadata is a different situation from routing metadata
/// that disagrees with the body. The first is nothing to compare; the second is
/// a finding.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpHeaderProjection {
    /// The method the transport routed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The operation name the transport routed on, where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl McpHeaderProjection {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [(&self.method, "header method"), (&self.name, "header name")] {
            if let Some(value) = value {
                crate::canonical::assert_safe_identifier(value, label)?;
            }
        }
        Ok(())
    }
}

/// The operation the JSON-RPC body actually requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcOperation {
    /// The JSON-RPC method.
    pub method: String,
    /// The tool or operation name, where the method carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl JsonRpcOperation {
    pub fn validate(&self) -> Result<()> {
        if self.method.trim().is_empty() {
            return Err(McpAuthSecurityError::invalid(
                "json-rpc operation declares no method",
            ));
        }
        crate::canonical::assert_safe_identifier(&self.method, "json-rpc method")?;
        if let Some(name) = &self.name {
            crate::canonical::assert_safe_identifier(name, "json-rpc name")?;
        }
        Ok(())
    }
}

/// Normalize a routing value for semantic comparison.
///
/// Case and surrounding whitespace do not change which operation runs, so they
/// are removed before comparison. Nothing else is: an engine that normalized
/// away punctuation or separators would start treating `tools/call` and
/// `tools.call` as the same routed operation, and a mismatch that changes
/// routing is exactly what this module exists to catch.
pub fn normalize_routing_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Whether two routing values name the same operation.
pub fn routing_values_agree(left: &str, right: &str) -> bool {
    normalize_routing_value(left) == normalize_routing_value(right)
}

/// One observed request: the protocol it ran under, what the transport routed
/// on, and what the body asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub protocol: ProtocolContext,
    #[serde(default)]
    pub headers: McpHeaderProjection,
    pub operation: JsonRpcOperation,
}

impl RequestEnvelope {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.request_id, "request id")?;
        self.protocol.validate()?;
        self.headers.validate()?;
        self.operation.validate()?;
        Ok(())
    }

    /// Whether the routed method and the body method agree.
    ///
    /// `None` when the transport carried no method to compare — nothing to
    /// judge, which the evaluator turns into missing coverage rather than a
    /// pass.
    pub fn method_binding_holds(&self) -> Option<bool> {
        self.headers
            .method
            .as_ref()
            .map(|routed| routing_values_agree(routed, &self.operation.method))
    }

    /// Whether the routed name and the body name agree.
    ///
    /// Three outcomes rather than two, and the third is the interesting one: a
    /// header that names an operation the body does not is a mismatch, because
    /// the transport routed on something the body never asked for.
    pub fn name_binding_holds(&self) -> Option<bool> {
        match (&self.headers.name, &self.operation.name) {
            (None, _) => None,
            (Some(routed), Some(body)) => Some(routing_values_agree(routed, body)),
            (Some(_), None) => Some(false),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn envelope() -> RequestEnvelope {
        RequestEnvelope {
            request_id: "req-1".to_owned(),
            protocol: ProtocolContext {
                declared_revision: crate::CURRENT_WIRE_REVISION.to_owned(),
                http_transport: true,
            },
            headers: McpHeaderProjection {
                method: Some("tools/call".to_owned()),
                name: Some("create-invoice".to_owned()),
            },
            operation: JsonRpcOperation {
                method: "tools/call".to_owned(),
                name: Some("create-invoice".to_owned()),
            },
        }
    }

    #[test]
    fn the_fixture_envelope_validates_and_binds() {
        let envelope = envelope();
        envelope.validate().expect("valid");
        assert_eq!(envelope.method_binding_holds(), Some(true));
        assert_eq!(envelope.name_binding_holds(), Some(true));
        assert_eq!(
            envelope.protocol.revision_class(),
            ProtocolRevisionClass::Current
        );
    }

    #[test]
    fn a_routed_method_that_differs_from_the_body_does_not_bind() {
        let mut envelope = envelope();
        envelope.headers.method = Some("resources/read".to_owned());
        assert_eq!(envelope.method_binding_holds(), Some(false));
    }

    #[test]
    fn a_routed_name_that_differs_from_the_body_does_not_bind() {
        let mut envelope = envelope();
        envelope.headers.name = Some("delete-invoice".to_owned());
        assert_eq!(envelope.name_binding_holds(), Some(false));
    }

    #[test]
    fn a_header_naming_an_operation_the_body_does_not_is_a_mismatch() {
        // The transport routed on a name the body never asked for. Treating
        // that as "nothing to compare" would let a gateway route one operation
        // while the server executed another.
        let mut envelope = envelope();
        envelope.operation.name = None;
        assert_eq!(envelope.name_binding_holds(), Some(false));
    }

    #[test]
    fn an_absent_header_is_nothing_to_compare_rather_than_agreement() {
        // The distinction that keeps a missing channel out of PASS. No routing
        // metadata means the question was not observed, not that it held.
        let mut envelope = envelope();
        envelope.headers = McpHeaderProjection::default();
        assert_eq!(envelope.method_binding_holds(), None);
        assert_eq!(envelope.name_binding_holds(), None);
    }

    #[test]
    fn comparison_is_semantic_rather_than_byte_exact() {
        // Casing and padding do not change which tool runs. An engine that
        // reported these would train its readers to ignore it.
        let mut envelope = envelope();
        envelope.headers.method = Some("  Tools/Call  ".to_owned());
        envelope.headers.name = Some("Create-Invoice".to_owned());
        assert_eq!(envelope.method_binding_holds(), Some(true));
        assert_eq!(envelope.name_binding_holds(), Some(true));
    }

    #[test]
    fn normalization_does_not_erase_a_separator() {
        // `tools/call` and `tools.call` route differently. Normalizing
        // punctuation away would silently merge them.
        assert!(!routing_values_agree("tools/call", "tools.call"));
        assert!(!routing_values_agree("tools/call", "toolscall"));
    }

    #[test]
    fn a_synthetic_identifier_can_never_be_a_reachable_target() {
        for hostile in [
            "https://as.example.com",
            "http://localhost:8080",
            "//cdn.example",
            "file:///etc/passwd",
            "data:text/plain;base64,AAAA",
            "ws://socket",
            "mailto:someone@example.com",
        ] {
            let err = SyntheticUri::new(hostile).expect_err("must be refused");
            assert!(err.is_refusal(), "`{hostile}` produced {err}");
        }
    }

    #[test]
    fn an_ordinary_synthetic_identity_is_accepted() {
        for ok in [
            "as-primary",
            "resource.mcp.invoices",
            "issuer-alpha",
            "client_public_01",
        ] {
            SyntheticUri::new(ok).unwrap_or_else(|err| panic!("`{ok}` refused: {err}"));
        }
    }

    #[test]
    fn an_unsupported_revision_classifies_closed() {
        let mut envelope = envelope();
        envelope.protocol.declared_revision = "2025-03-26".to_owned();
        assert_eq!(
            envelope.protocol.revision_class(),
            ProtocolRevisionClass::Unsupported
        );
        assert!(!envelope
            .protocol
            .revision_class()
            .carries_modern_auth_surface());
    }

    #[test]
    fn the_envelope_rejects_unknown_and_executable_fields() {
        let hostile = serde_json::json!({
            "request_id": "req-1",
            "protocol": { "declared_revision": "2026-07-28", "http_transport": true },
            "headers": { "method": "tools/call" },
            "operation": { "method": "tools/call" },
            "callback_url": "https://evil.example/hook"
        });
        assert!(serde_json::from_value::<RequestEnvelope>(hostile).is_err());
    }
}
