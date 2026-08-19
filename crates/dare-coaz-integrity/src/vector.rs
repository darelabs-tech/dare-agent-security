//! Portable authorization-integrity vector definition contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::standards::StandardsSnapshot;
use crate::version::SchemaVersion;

/// Top-level reusable vector definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorDefinition {
    pub schema_version: SchemaVersion,
    pub vector_id: String,
    pub title: String,
    pub standards: StandardsSnapshot,
    pub initial_operation: McpOperation,
    pub trusted_context: TrustedAuthorizationContext,
    pub projector_fixture: ProjectorFixture,
    pub pdp_fixture: PdpFixture,
    pub mutation: IntegrityMutation,
    pub expected: VectorExpectation,
    pub safety: SafetyConstraints,
}

/// MCP operation under test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpOperation {
    pub method: String,
    pub params: Value,
}

/// Trusted authorization context supplied to the projector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAuthorizationContext {
    pub subject_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub claims: Value,
}

/// Projector fixture identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorFixture {
    pub id: String,
}

/// PDP fixture identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdpFixture {
    pub id: String,
}

/// Deterministic mutation applied between authorization and forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityMutation {
    pub kind: MutationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Supported deterministic mutation kinds for Cycle 003.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MutationKind {
    None,
    ToolName,
    MappedArgument,
    Method,
    MappedTrustedContext,
    JsonReorderOnly,
    UnmappedField,
}

/// Expected secure enforcement behavior for this vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorExpectation {
    pub enforcement: ExpectedEnforcement,
}

/// Expected enforcement enum from the Cycle 003 blueprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpectedEnforcement {
    ForwardWithExistingPermit,
    ReevaluateOrRefuse,
    PermitRemainsBound,
}

/// Safety constraints for vector execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyConstraints {
    pub synthetic_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_mode: Option<ReferencePepMode>,
}

/// Reference PEP execution mode for synthetic harness runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferencePepMode {
    SecureReevaluate,
    SecureRefuse,
    VulnerableReuse,
}

/// Sample vector used by contract tests.
pub fn sample_vector_definition() -> VectorDefinition {
    VectorDefinition {
        schema_version: SchemaVersion::V1,
        vector_id: "COAZ-INTEGRITY-001".to_owned(),
        title: "unchanged tools/call after permit".to_owned(),
        standards: crate::cycle003_standards_snapshot(),
        initial_operation: McpOperation {
            method: "tools/call".to_owned(),
            params: serde_json::json!({
                "name": "rental.quote",
                "arguments": {
                    "customer_id": "cust-synthetic-001",
                    "vehicle_id": "vehicle-synthetic-001",
                    "daily_rate": 50,
                    "days": 3
                }
            }),
        },
        trusted_context: TrustedAuthorizationContext {
            subject_id: "subject-synthetic-001".to_owned(),
            agent_id: Some("agent-synthetic-001".to_owned()),
            claims: serde_json::json!({ "role": "standard" }),
        },
        projector_fixture: ProjectorFixture {
            id: "default-tools-call".to_owned(),
        },
        pdp_fixture: PdpFixture {
            id: "synthetic-rental-policy-v1".to_owned(),
        },
        mutation: IntegrityMutation {
            kind: MutationKind::None,
            detail: None,
        },
        expected: VectorExpectation {
            enforcement: ExpectedEnforcement::ForwardWithExistingPermit,
        },
        safety: SafetyConstraints {
            synthetic_only: true,
            reference_mode: Some(ReferencePepMode::SecureReevaluate),
        },
    }
}
