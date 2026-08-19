//! COAZ-MCP authorization-to-execution integrity harness (Cycle 003).
//!
//! Dependency direction:
//! ```text
//! dare-agent-security-cli -> dare-coaz-integrity -> dare-security-evidence
//! ```
//!
//! Cycle 002 discovery remains passive and MUST NOT depend on this crate.

pub mod binding;
pub mod canonical;
pub mod enforcement;
pub mod error;
pub mod evidence_bridge;
pub mod mutation;
pub mod pdp;
pub mod projector;
pub mod result;
pub mod result_schema;
pub mod result_validation;
pub mod runner;
pub mod secret_safety;
pub mod sink;
pub mod standards;
pub mod vector;
pub mod vector_schema;
pub mod vector_validation;
pub mod version;

pub use binding::{
    binding_material_v1, bindings_equal, compute_authorization_binding, digest_json_value,
    BindingError, BindingMaterialV1, BINDING_ALGORITHM, BINDING_MATERIAL_VERSION,
};
pub use canonical::{CanonicalError, CanonicalNumber, CanonicalValue};
pub use enforcement::{enforcement_satisfies, validate_verdict_consistency};
pub use error::IntegrityError;
pub use evidence_bridge::{
    emit_integrity_evidence, EmitOptions, EvidenceBridgeError, EXTENSION_KEY, VECTOR_VERSION,
};
pub use mutation::{
    apply_mutation, changed_operation_fields, changed_trusted_fields, DeterministicMutator,
    MutationError, MutationResult, OperationMutator,
};
pub use pdp::{
    bind_decision, pdp_for_fixture, stable_decision_id, BoundDecision, DecisionError,
    DecisionProvider, SyntheticRentalPolicyV1,
};
pub use projector::{
    projector_for_fixture, AuthorizationProjector, DefaultToolsCallProjector, ProjectionError,
    RentalQuoteProjector,
};
pub use result::{
    sample_vector_result_harness_error, sample_vector_result_inconclusive,
    sample_vector_result_pass, sample_vector_result_stale_permit_fail, AuthorizationBinding,
    AuthorizationDecision, AuthorizationProjection, Decision, EnforcementTrace, IntegrityVerdict,
    MappingIdentity, ObservedEnforcement, RedactionMetadata, RedactionStrategy, SinkReceipt,
    VectorResult,
};
pub use result_schema::{
    result_schema_v1, result_schema_v1_path, validate_result_instance, RESULT_SCHEMA_V1_ID,
    RESULT_SCHEMA_V1_JSON, SUPPORTED_RESULT_SCHEMA_MAJOR,
};
pub use result_validation::{parse_and_validate_result, validate_result};
pub use runner::{
    builtin_vectors_root, execute_builtin_vector, execute_vector, load_all_builtin_vectors,
    load_builtin_vector, result_deterministic_signature, BuiltinRunError,
    ResultDeterministicSignature, RunError, RunOptions, BUILTIN_VECTORS_DIR, BUILTIN_VECTOR_IDS,
};
pub use secret_safety::{validate_result_secret_safety, validate_vector_secret_safety};
pub use sink::{
    binding_from_projection, enforce_reference_pep, AuthorizationDecider, EnforcementOutcome,
    ExecutionSink, PepEnforcementRequest, PepError, ReferencePepGateway, SinkAuthorizationContext,
    SinkError, SinkRecord, SyntheticExecutionSink, SECURE_REFUSE_ON_CHANGE,
    VULNERABLE_REUSE_PERMIT,
};
pub use standards::{
    cycle003_standards_snapshot, reference_key, required_reference_keys, ExecutableScopeNote,
    StandardReference, StandardStatus, StandardsSnapshot, STANDARDS_SNAPSHOT_FIXTURE_ID,
};
pub use vector::{
    sample_vector_definition, ExpectedEnforcement, IntegrityMutation, McpOperation, MutationKind,
    PdpFixture, ProjectorFixture, ReferencePepMode, SafetyConstraints, TrustedAuthorizationContext,
    VectorDefinition, VectorExpectation,
};
pub use vector_schema::{
    validate_vector_instance, vector_schema_v1, vector_schema_v1_path,
    SUPPORTED_VECTOR_SCHEMA_MAJOR, VECTOR_SCHEMA_V1_ID, VECTOR_SCHEMA_V1_JSON,
};
pub use vector_validation::{parse_and_validate_vector, validate_vector};
pub use version::{SchemaVersion, VersionParseError};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-coaz-integrity";

/// Confirms the inward Cycle 001 evidence kernel dependency.
pub fn evidence_kernel_name() -> &'static str {
    dare_security_evidence::CRATE_NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
        assert_eq!(evidence_kernel_name(), "dare-security-evidence");
    }

    #[test]
    fn evidence_manifest_does_not_depend_on_integrity_or_cli() {
        let evidence_manifest = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dare-security-evidence/Cargo.toml"
        ));
        assert!(!evidence_manifest.contains("dare-coaz-integrity"));
        assert!(!evidence_manifest.contains("dare-agent-security"));
    }
}
