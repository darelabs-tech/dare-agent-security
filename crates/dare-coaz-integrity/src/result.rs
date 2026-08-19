//! Portable authorization-integrity vector execution result contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::standards::StandardsSnapshot;
use crate::vector::{
    ExpectedEnforcement, IntegrityMutation, McpOperation, ReferencePepMode, VectorExpectation,
};
use crate::version::SchemaVersion;

/// Top-level vector execution result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorResult {
    pub schema_version: SchemaVersion,
    pub vector_id: String,
    pub standards: StandardsSnapshot,
    pub initial_operation: McpOperation,
    pub initial_projection: AuthorizationProjection,
    pub initial_binding: AuthorizationBinding,
    pub initial_decision: AuthorizationDecision,
    pub mutation: IntegrityMutation,
    pub final_operation: McpOperation,
    pub final_projection: AuthorizationProjection,
    pub final_binding: AuthorizationBinding,
    pub enforcement_trace: EnforcementTrace,
    pub sink_receipt: SinkReceipt,
    pub expected: VectorExpectation,
    pub observed: ObservedEnforcement,
    pub verdict: IntegrityVerdict,
    pub redaction: RedactionMetadata,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
}

/// Authorization projection snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProjection {
    pub mapping: MappingIdentity,
    pub mapped_inputs: Value,
    pub trusted_inputs: Value,
    pub authzen_request: Value,
}

/// Mapping identity included in binding material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingIdentity {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub digest: String,
}

/// Authorization binding digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationBinding {
    pub algorithm: String,
    pub digest: String,
}

/// PDP decision bound to a projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub decision: Decision,
    pub bound_to: AuthorizationBinding,
}

/// Permit/deny decision vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Permit,
    Deny,
}

/// Reference PEP enforcement trace metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementTrace {
    pub reference_mode: ReferencePepMode,
    pub binding_changed: bool,
    pub reevaluated: bool,
}

/// Synthetic execution sink receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkReceipt {
    pub forwarded: bool,
    pub operation_method: String,
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

/// Observed enforcement enum from the Cycle 003 blueprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedEnforcement {
    ForwardedWithExistingPermit,
    ForwardedAfterReevaluation,
    RefusedAfterBindingChange,
    DeniedAfterReevaluation,
    ForwardedWithStalePermit,
    NoForwardInitialDeny,
    InconclusiveProjection,
    HarnessError,
}

/// Deterministic integrity verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityVerdict {
    Pass,
    Fail,
    Inconclusive,
    Error,
}

/// Mandatory redaction declaration on every result record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionMetadata {
    pub applied: bool,
    pub strategy: RedactionStrategy,
    #[serde(default)]
    pub fields: Vec<String>,
}

/// How sensitive values were handled before serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedactionStrategy {
    NoneRequired,
    Remove,
    Mask,
    Hash,
    Tokenize,
    Mixed,
}

const SAMPLE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn sample_binding() -> AuthorizationBinding {
    AuthorizationBinding {
        algorithm: "coaz-binding-v1".to_owned(),
        digest: SAMPLE_DIGEST.to_owned(),
    }
}

fn sample_projection() -> AuthorizationProjection {
    AuthorizationProjection {
        mapping: MappingIdentity {
            kind: "default".to_owned(),
            id: "default-tools-call".to_owned(),
            revision: None,
            digest: SAMPLE_DIGEST.to_owned(),
        },
        mapped_inputs: serde_json::json!({
            "customer_id": "cust-synthetic-001",
            "vehicle_id": "vehicle-synthetic-001",
            "daily_rate": 50,
            "days": 3
        }),
        trusted_inputs: serde_json::json!({
            "subject_id": "subject-synthetic-001",
            "agent_id": "agent-synthetic-001"
        }),
        authzen_request: serde_json::json!({
            "subject": { "type": "user", "id": "subject-synthetic-001" },
            "resource": { "type": "mcp-tool", "id": "rental.quote" },
            "action": { "name": "invoke" }
        }),
    }
}

/// Sample PASS result used by contract tests.
pub fn sample_vector_result_pass() -> VectorResult {
    let operation = crate::vector::sample_vector_definition().initial_operation;
    let binding = sample_binding();
    let started_at = time::macros::datetime!(2026-08-19 12:00:00 UTC);
    let finished_at = time::macros::datetime!(2026-08-19 12:00:01 UTC);
    VectorResult {
        schema_version: SchemaVersion::V1,
        vector_id: "COAZ-INTEGRITY-001".to_owned(),
        standards: crate::cycle003_standards_snapshot(),
        initial_operation: operation.clone(),
        initial_projection: sample_projection(),
        initial_binding: binding.clone(),
        initial_decision: AuthorizationDecision {
            decision_id: "decision-synthetic-001".to_owned(),
            decision: Decision::Permit,
            bound_to: binding.clone(),
        },
        mutation: crate::vector::sample_vector_definition().mutation,
        final_operation: operation,
        final_projection: sample_projection(),
        final_binding: binding,
        enforcement_trace: EnforcementTrace {
            reference_mode: ReferencePepMode::SecureReevaluate,
            binding_changed: false,
            reevaluated: false,
        },
        sink_receipt: SinkReceipt {
            forwarded: true,
            operation_method: "tools/call".to_owned(),
            operation_name: "rental.quote".to_owned(),
            params_digest: Some(SAMPLE_DIGEST.to_owned()),
            sequence: Some(1),
        },
        expected: VectorExpectation {
            enforcement: ExpectedEnforcement::ForwardWithExistingPermit,
        },
        observed: ObservedEnforcement::ForwardedWithExistingPermit,
        verdict: IntegrityVerdict::Pass,
        redaction: RedactionMetadata {
            applied: false,
            strategy: RedactionStrategy::NoneRequired,
            fields: Vec::new(),
        },
        started_at,
        finished_at,
    }
}

/// Sample FAIL result for stale permit forwarding.
pub fn sample_vector_result_stale_permit_fail() -> VectorResult {
    let mut result = sample_vector_result_pass();
    result.vector_id = "COAZ-INTEGRITY-003".to_owned();
    result.expected.enforcement = ExpectedEnforcement::ReevaluateOrRefuse;
    result.mutation = crate::vector::IntegrityMutation {
        kind: crate::vector::MutationKind::MappedArgument,
        detail: Some("daily_rate 50 -> 5000".to_owned()),
    };
    result.final_binding = AuthorizationBinding {
        algorithm: "coaz-binding-v1".to_owned(),
        digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
    };
    result.enforcement_trace = EnforcementTrace {
        reference_mode: ReferencePepMode::VulnerableReuse,
        binding_changed: true,
        reevaluated: false,
    };
    result.observed = ObservedEnforcement::ForwardedWithStalePermit;
    result.verdict = IntegrityVerdict::Fail;
    result
}

/// Sample INCONCLUSIVE result when projection cannot be determined.
pub fn sample_vector_result_inconclusive() -> VectorResult {
    let mut result = sample_vector_result_pass();
    result.vector_id = "COAZ-INTEGRITY-INCONCLUSIVE-SAMPLE".to_owned();
    result.observed = ObservedEnforcement::InconclusiveProjection;
    result.verdict = IntegrityVerdict::Inconclusive;
    result
}

/// Sample ERROR result for harness infrastructure failure.
pub fn sample_vector_result_harness_error() -> VectorResult {
    let mut result = sample_vector_result_pass();
    result.vector_id = "COAZ-INTEGRITY-ERROR-SAMPLE".to_owned();
    result.observed = ObservedEnforcement::HarnessError;
    result.verdict = IntegrityVerdict::Error;
    result
}
