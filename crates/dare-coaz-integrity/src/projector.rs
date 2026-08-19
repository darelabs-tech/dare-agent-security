//! Authorization projection boundary for Cycle 003 synthetic mappings.
//!
//! Projectors translate MCP operations and trusted context into sanitized
//! AuthZEN-shaped requests without a general CEL interpreter.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};

use crate::canonical::{CanonicalError, CanonicalValue};
use crate::result::{AuthorizationProjection, MappingIdentity};
use crate::vector::{McpOperation, TrustedAuthorizationContext};

#[path = "projector_default.rs"]
mod projector_default;
#[path = "projector_rental.rs"]
mod projector_rental;

pub use projector_default::DefaultToolsCallProjector;
pub use projector_rental::RentalQuoteProjector;

/// Deterministic projection failure without echoing operation payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    UnknownFixture { id: String },
    UnsupportedMethod { method: String },
    InvalidOperation { reason: String },
    MissingMappedValue { field: String },
    MissingTrustedValue { field: String },
    Canonicalization,
}

impl ProjectionError {
    pub(crate) fn invalid_operation(reason: impl Into<String>) -> Self {
        Self::InvalidOperation {
            reason: reason.into(),
        }
    }
}

impl From<CanonicalError> for ProjectionError {
    fn from(_: CanonicalError) -> Self {
        Self::Canonicalization
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFixture { id } => write!(f, "unknown projector fixture id {id}"),
            Self::UnsupportedMethod { method } => {
                write!(f, "unsupported MCP method for projection: {method}")
            }
            Self::InvalidOperation { reason } => {
                write!(f, "invalid MCP operation for projection: {reason}")
            }
            Self::MissingMappedValue { field } => {
                write!(f, "missing required mapped value: {field}")
            }
            Self::MissingTrustedValue { field } => {
                write!(f, "missing required trusted value: {field}")
            }
            Self::Canonicalization => f.write_str("canonicalization failed during projection"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Project-owned authorization projector boundary.
pub trait AuthorizationProjector: Send + Sync {
    /// Stable projector fixture identifier used by vector definitions.
    fn fixture_id(&self) -> &'static str;

    /// Projects an MCP operation and trusted context into a sanitized authorization snapshot.
    fn project(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
    ) -> Result<AuthorizationProjection, ProjectionError>;
}

/// Resolves a reference projector implementation from a vector fixture id.
pub fn projector_for_fixture(id: &str) -> Result<Box<dyn AuthorizationProjector>, ProjectionError> {
    match id {
        DefaultToolsCallProjector::FIXTURE_ID => Ok(Box::new(DefaultToolsCallProjector)),
        RentalQuoteProjector::FIXTURE_ID => Ok(Box::new(RentalQuoteProjector)),
        _ => Err(ProjectionError::UnknownFixture { id: id.to_owned() }),
    }
}

pub(crate) const TOOLS_CALL_METHOD: &str = "tools/call";

pub(crate) fn mapping_identity(
    kind: &str,
    id: &str,
    revision: Option<&str>,
) -> Result<MappingIdentity, ProjectionError> {
    let mut descriptor = BTreeMap::new();
    descriptor.insert("kind".to_owned(), json!(kind));
    descriptor.insert("id".to_owned(), json!(id));
    if let Some(revision) = revision {
        descriptor.insert("revision".to_owned(), json!(revision));
    }
    let digest =
        CanonicalValue::normalize(&Value::Object(descriptor.into_iter().collect()))?.digest();

    Ok(MappingIdentity {
        kind: kind.to_owned(),
        id: id.to_owned(),
        revision: revision.map(str::to_owned),
        digest,
    })
}

pub(crate) fn require_tools_call(operation: &McpOperation) -> Result<(), ProjectionError> {
    if operation.method != TOOLS_CALL_METHOD {
        return Err(ProjectionError::UnsupportedMethod {
            method: operation.method.clone(),
        });
    }
    Ok(())
}

pub(crate) fn parse_tools_call(
    operation: &McpOperation,
) -> Result<(&str, &Value), ProjectionError> {
    require_tools_call(operation)?;
    let params = operation
        .params
        .as_object()
        .ok_or_else(|| ProjectionError::invalid_operation("params must be a JSON object"))?;
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ProjectionError::invalid_operation("params.name must be a string"))?;
    let arguments = params
        .get("arguments")
        .ok_or_else(|| ProjectionError::invalid_operation("params.arguments is required"))?;
    if !arguments.is_object() {
        return Err(ProjectionError::invalid_operation(
            "params.arguments must be a JSON object",
        ));
    }
    Ok((tool_name, arguments))
}

pub(crate) fn require_string_field<'a>(
    object: &'a Value,
    field: &str,
) -> Result<&'a str, ProjectionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProjectionError::MissingMappedValue {
            field: field.to_owned(),
        })
}

pub(crate) fn build_trusted_inputs(
    trusted: &TrustedAuthorizationContext,
) -> Result<Value, ProjectionError> {
    if trusted.subject_id.trim().is_empty() {
        return Err(ProjectionError::MissingTrustedValue {
            field: "subject_id".to_owned(),
        });
    }

    let mut inputs = BTreeMap::new();
    inputs.insert("subject_id".to_owned(), json!(trusted.subject_id.as_str()));
    if let Some(agent_id) = trusted.agent_id.as_deref() {
        if agent_id.trim().is_empty() {
            return Err(ProjectionError::MissingTrustedValue {
                field: "agent_id".to_owned(),
            });
        }
        inputs.insert("agent_id".to_owned(), json!(agent_id));
    }

    canonicalize_json(&Value::Object(inputs.into_iter().collect()))
}

pub(crate) fn build_authzen_request(subject_id: &str, tool_name: &str) -> Value {
    json!({
        "action": { "name": "invoke" },
        "resource": { "id": tool_name, "type": "mcp-tool" },
        "subject": { "id": subject_id, "type": "user" }
    })
}

pub(crate) fn build_declared_authzen_request(
    subject_id: &str,
    tool_name: &str,
    mapped_inputs: &Value,
    agent_id: Option<&str>,
) -> Result<Value, ProjectionError> {
    let customer_id = require_string_field(mapped_inputs, "customer_id")?;
    let vehicle_id = require_string_field(mapped_inputs, "vehicle_id")?;
    let daily_rate =
        mapped_inputs
            .get("daily_rate")
            .ok_or_else(|| ProjectionError::MissingMappedValue {
                field: "daily_rate".to_owned(),
            })?;

    let mut context = BTreeMap::new();
    context.insert("customer_id".to_owned(), json!(customer_id));
    context.insert("vehicle_id".to_owned(), json!(vehicle_id));
    context.insert("daily_rate".to_owned(), daily_rate.clone());
    if let Some(agent_id) = agent_id {
        context.insert("agent_id".to_owned(), json!(agent_id));
    }

    Ok(json!({
        "action": { "name": "invoke" },
        "context": Value::Object(context.into_iter().collect()),
        "resource": { "id": tool_name, "type": "mcp-tool" },
        "subject": { "id": subject_id, "type": "user" }
    }))
}

pub(crate) fn canonicalize_json(value: &Value) -> Result<Value, ProjectionError> {
    let canonical = CanonicalValue::normalize(value)?;
    serde_json::from_str(&canonical.canonical_string())
        .map_err(|_| ProjectionError::Canonicalization)
}

pub(crate) fn finalize_projection(
    mapping: MappingIdentity,
    mapped_inputs: Value,
    trusted_inputs: Value,
    authzen_request: Value,
) -> Result<AuthorizationProjection, ProjectionError> {
    Ok(AuthorizationProjection {
        mapping,
        mapped_inputs: canonicalize_json(&mapped_inputs)?,
        trusted_inputs: canonicalize_json(&trusted_inputs)?,
        authzen_request: canonicalize_json(&authzen_request)?,
    })
}
