//! Versioned security property registry. Data only — no executable fields.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::CoverageError;

pub const PROPERTY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/coverage/v1/property.schema.json");
pub const REGISTRY_JSON: &str = include_str!("../../../schemas/coverage/v1/registry.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyCategory {
    Discovery,
    Identity,
    Authentication,
    Authorization,
    AuthzExecutionIntegrity,
    CapabilityExposure,
    CredentialBoundaries,
    Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    ToolsPresent,
    ResourcesPresent,
    PromptsPresent,
    TransportHttp,
    TransportStdio,
    AuthorizationPresent,
    DynamicAuthorizationAllowed,
    ExecutionIntegritySupported,
    ConfusedDeputySupported,
}

impl Predicate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolsPresent => "tools_present",
            Self::ResourcesPresent => "resources_present",
            Self::PromptsPresent => "prompts_present",
            Self::TransportHttp => "transport_http",
            Self::TransportStdio => "transport_stdio",
            Self::AuthorizationPresent => "authorization_present",
            Self::DynamicAuthorizationAllowed => "dynamic_authorization_allowed",
            Self::ExecutionIntegritySupported => "execution_integrity_supported",
            Self::ConfusedDeputySupported => "confused_deputy_supported",
        }
    }

    /// Target-shape predicates yield NOT_APPLICABLE when false.
    pub fn is_target_shape(self) -> bool {
        matches!(
            self,
            Self::ToolsPresent
                | Self::ResourcesPresent
                | Self::PromptsPresent
                | Self::TransportHttp
                | Self::TransportStdio
                | Self::AuthorizationPresent
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedMode {
    Static,
    Dynamic,
    Passive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicabilitySpec {
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSpec {
    pub required_for_confirmed_verdict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyDefinition {
    pub id: String,
    pub title: String,
    pub category: PropertyCategory,
    pub description: String,
    pub applicability: ApplicabilitySpec,
    pub supported_modes: Vec<SupportedMode>,
    pub evidence: EvidenceSpec,
    pub standards: Vec<StandardRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyRegistry {
    pub schema: crate::profile::SchemaRef,
    pub properties: Vec<PropertyDefinition>,
}

pub fn property_schema_v1() -> Result<Value, CoverageError> {
    serde_json::from_str(PROPERTY_SCHEMA_V1_JSON).map_err(|_| CoverageError::Serialization {
        kind: "property-schema",
    })
}

pub fn validate_property_instance(instance: &Value) -> Result<(), CoverageError> {
    let schema = property_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| CoverageError::schema("/", err.to_string()))?;
    if validator.is_valid(instance) {
        return Ok(());
    }
    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(CoverageError::schema(
            err.instance_path().to_string(),
            err.to_string(),
        )),
        None => Err(CoverageError::schema("/", "property failed schema")),
    }
}

pub fn load_registry(raw: &str) -> Result<PropertyRegistry, CoverageError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| CoverageError::Serialization {
        kind: "registry-parse",
    })?;
    let properties = value
        .get("properties")
        .and_then(Value::as_array)
        .ok_or_else(|| CoverageError::schema("/properties", "missing array"))?;
    for (i, prop) in properties.iter().enumerate() {
        validate_property_instance(prop)
            .map_err(|err| CoverageError::schema(format!("/properties/{i}"), err.to_string()))?;
    }
    let registry: PropertyRegistry =
        serde_json::from_value(value).map_err(|_| CoverageError::Serialization {
            kind: "registry-typed",
        })?;
    validate_registry(&registry)?;
    Ok(registry)
}

pub fn validate_registry(registry: &PropertyRegistry) -> Result<(), CoverageError> {
    let mut seen = HashSet::new();
    for prop in &registry.properties {
        if !seen.insert(prop.id.clone()) {
            return Err(CoverageError::DuplicateProperty(prop.id.clone()));
        }
        if prop.applicability.predicates.is_empty() {
            return Err(CoverageError::schema(
                format!("/{}/predicates", prop.id),
                "empty predicates",
            ));
        }
    }
    Ok(())
}

pub fn builtin_registry() -> Result<PropertyRegistry, CoverageError> {
    load_registry(REGISTRY_JSON)
}

impl PropertyRegistry {
    pub fn get(&self, id: &str) -> Option<&PropertyDefinition> {
        self.properties.iter().find(|p| p.id == id)
    }

    pub fn require(&self, id: &str) -> Result<&PropertyDefinition, CoverageError> {
        self.get(id)
            .ok_or_else(|| CoverageError::UnknownProperty(id.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_loads_and_ids_are_unique() {
        let registry = builtin_registry().expect("registry");
        assert!(registry.get("MCP.DISCOVERY.PASSIVE_BOUNDARY").is_some());
        assert!(registry
            .get("MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME")
            .is_some());
        assert_eq!(registry.properties.len(), 10);
    }

    #[test]
    fn unknown_predicate_rejected_by_schema() {
        let mut value: Value = serde_json::from_str(REGISTRY_JSON).unwrap();
        value["properties"][0]["applicability"]["predicates"] = serde_json::json!(["eval(1+1)"]);
        assert!(validate_property_instance(&value["properties"][0]).is_err());
    }
}
