//! Versioned security property registry. Data only — no executable fields.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::CoverageError;

pub const PROPERTY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/coverage/v1/property.schema.json");
pub const PROPERTY_SCHEMA_V2_JSON: &str =
    include_str!("../../../schemas/coverage/v2/property.schema.json");
pub const REGISTRY_SCHEMA_V2_JSON: &str =
    include_str!("../../../schemas/coverage/v2/registry.schema.json");
pub const REGISTRY_JSON: &str = include_str!("../../../schemas/coverage/v1/registry.json");
pub const AGENTIC_REGISTRY_JSON: &str =
    include_str!("../../../schemas/coverage/v2/registry.json");

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
    GoalIntegrity,
    ToolSecurity,
    Delegation,
    Privilege,
    SupplyChain,
    CodeExecution,
    MemoryContext,
    InterAgent,
    FailureContainment,
    HumanOversight,
    RogueBehavior,
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
    AgentPresent,
    MemoryPresent,
    RagPresent,
    MultiAgentPresent,
    CodeExecutionPresent,
    HumanApprovalPresent,
    DelegatedIdentityPresent,
    ExternalComponentsPresent,
    StatefulAgentPresent,
    RuntimeDynamicAllowed,
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
            Self::AgentPresent => "agent_present",
            Self::MemoryPresent => "memory_present",
            Self::RagPresent => "rag_present",
            Self::MultiAgentPresent => "multi_agent_present",
            Self::CodeExecutionPresent => "code_execution_present",
            Self::HumanApprovalPresent => "human_approval_present",
            Self::DelegatedIdentityPresent => "delegated_identity_present",
            Self::ExternalComponentsPresent => "external_components_present",
            Self::StatefulAgentPresent => "stateful_agent_present",
            Self::RuntimeDynamicAllowed => "runtime_dynamic_allowed",
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
                | Self::AgentPresent
                | Self::MemoryPresent
                | Self::RagPresent
                | Self::MultiAgentPresent
                | Self::CodeExecutionPresent
                | Self::HumanApprovalPresent
                | Self::DelegatedIdentityPresent
                | Self::ExternalComponentsPresent
                | Self::StatefulAgentPresent
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskFamily {
    AgentGoalHijacking,
    ToolMisuseExploitation,
    IdentityPrivilegeAbuse,
    AgenticSupplyChain,
    UnexpectedCodeExecution,
    MemoryContextPoisoning,
    InsecureInterAgentCommunication,
    CascadingFailures,
    HumanAgentTrustExploitation,
    RogueAgents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyMaturity {
    Experimental,
    Stable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClass {
    Static,
    PassiveRuntime,
    DynamicAuthorized,
    Synthetic,
    Policy,
    Trace,
    Configuration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedMode {
    Static,
    Dynamic,
    Passive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilitySpec {
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpec {
    pub required_for_confirmed_verdict: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_classes: Vec<EvidenceClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyDefinition {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_family: Option<RiskFamily>,
    pub category: PropertyCategory,
    pub description: String,
    pub applicability: ApplicabilitySpec,
    pub supported_modes: Vec<SupportedMode>,
    pub evidence: EvidenceSpec,
    pub standards: Vec<StandardRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<PropertyMaturity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyRegistry {
    pub schema: crate::profile::SchemaRef,
    pub properties: Vec<PropertyDefinition>,
}

pub fn property_schema_v1() -> Result<Value, CoverageError> {
    serde_json::from_str(PROPERTY_SCHEMA_V1_JSON).map_err(|_| CoverageError::Serialization {
        kind: "property-schema-v1",
    })
}

pub fn property_schema_v2() -> Result<Value, CoverageError> {
    serde_json::from_str(PROPERTY_SCHEMA_V2_JSON).map_err(|_| CoverageError::Serialization {
        kind: "property-schema-v2",
    })
}

pub fn registry_schema_v2() -> Result<Value, CoverageError> {
    serde_json::from_str(REGISTRY_SCHEMA_V2_JSON).map_err(|_| CoverageError::Serialization {
        kind: "registry-schema-v2",
    })
}

fn validate_against_schema(instance: &Value, schema: Value) -> Result<(), CoverageError> {
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
        None => Err(CoverageError::schema("/", "instance failed schema")),
    }
}

pub fn validate_property_instance(instance: &Value) -> Result<(), CoverageError> {
    validate_against_schema(instance, property_schema_v1()?)
}

pub fn validate_property_instance_v2(instance: &Value) -> Result<(), CoverageError> {
    validate_against_schema(instance, property_schema_v2()?)
}

fn registry_major(value: &Value) -> Result<u64, CoverageError> {
    let version = value
        .get("schema")
        .and_then(|schema| schema.get("version"))
        .and_then(Value::as_str)
        .ok_or_else(|| CoverageError::schema("/schema/version", "missing registry version"))?;
    let major = version
        .split('.')
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .ok_or_else(|| CoverageError::schema("/schema/version", "invalid registry version"))?;
    match major {
        1 | 2 => Ok(major),
        _ => Err(CoverageError::schema(
            "/schema/version",
            format!("unsupported registry schema major {major}"),
        )),
    }
}

pub fn load_registry(raw: &str) -> Result<PropertyRegistry, CoverageError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| CoverageError::Serialization {
        kind: "registry-parse",
    })?;
    let major = registry_major(&value)?;
    if major == 2 {
        validate_against_schema(&value, registry_schema_v2()?)?;
    }
    let properties = value
        .get("properties")
        .and_then(Value::as_array)
        .ok_or_else(|| CoverageError::schema("/properties", "missing array"))?;
    for (i, prop) in properties.iter().enumerate() {
        let result = match major {
            1 => validate_property_instance(prop),
            2 => validate_property_instance_v2(prop),
            _ => unreachable!("registry_major rejects unsupported major"),
        };
        result.map_err(|err| CoverageError::schema(format!("/properties/{i}"), err.to_string()))?;
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
        if prop.id.starts_with("AGENT.") && prop.risk_family.is_none() {
            return Err(CoverageError::schema(
                format!("/{}/risk_family", prop.id),
                "AGENT property requires risk_family",
            ));
        }
        if prop.id.starts_with("AGENT.") && prop.maturity.is_none() {
            return Err(CoverageError::schema(
                format!("/{}/maturity", prop.id),
                "AGENT property requires maturity",
            ));
        }
        if prop.evidence.required_for_confirmed_verdict && prop.standards.is_empty() {
            return Err(CoverageError::schema(
                format!("/{}/standards", prop.id),
                "evidence-backed property requires standards provenance",
            ));
        }
    }
    Ok(())
}

pub fn builtin_registry() -> Result<PropertyRegistry, CoverageError> {
    load_registry(REGISTRY_JSON)
}

pub fn agentic_registry() -> Result<PropertyRegistry, CoverageError> {
    load_registry(AGENTIC_REGISTRY_JSON)
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
    fn agentic_registry_loads_and_all_families_are_represented() {
        let registry = agentic_registry().expect("agentic registry");
        assert_eq!(registry.properties.len(), 20);
        let families: HashSet<_> = registry
            .properties
            .iter()
            .filter_map(|property| property.risk_family)
            .collect();
        assert_eq!(families.len(), 10);
        assert!(registry.get("AGENT.GOAL.INSTRUCTION_INTEGRITY").is_some());
        assert!(registry.get("AGENT.ROGUE.CAPABILITY_DRIFT").is_some());
    }

    #[test]
    fn unknown_predicate_rejected_by_schema() {
        let mut value: Value = serde_json::from_str(REGISTRY_JSON).unwrap();
        value["properties"][0]["applicability"]["predicates"] = serde_json::json!(["eval(1+1)"]);
        assert!(validate_property_instance(&value["properties"][0]).is_err());
    }

    #[test]
    fn v2_accepts_mcp_and_agent_namespaces_and_rejects_unknown_namespace() {
        let base = serde_json::json!({
            "id":"MCP.TEST.PROPERTY",
            "title":"test",
            "category":"EVIDENCE",
            "description":"test property",
            "applicability":{"predicates":["tools_present"]},
            "supported_modes":["static"],
            "evidence":{"required_for_confirmed_verdict":true},
            "standards":[{"source":"DARE","reference":"test","status":"INFORMATIVE"}]
        });
        assert!(validate_property_instance_v2(&base).is_ok());

        let mut agent = base.clone();
        agent["id"] = serde_json::json!("AGENT.TEST.PROPERTY");
        agent["risk_family"] = serde_json::json!("ROGUE_AGENTS");
        agent["maturity"] = serde_json::json!("EXPERIMENTAL");
        assert!(validate_property_instance_v2(&agent).is_ok());

        let mut future = agent;
        future["id"] = serde_json::json!("RAG.TEST.PROPERTY");
        assert!(validate_property_instance_v2(&future).is_err());
    }

    #[test]
    fn unknown_registry_major_fails_closed() {
        let raw = r#"{"schema":{"id":"x","version":"3.0.0"},"properties":[]}"#;
        assert!(load_registry(raw).is_err());
    }
}
