//! Integrity vector runner: projector → binding → PDP → mutation → reference PEP → sink.
//!
//! Executes portable Cycle 003 vector definitions deterministically without external I/O.

use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::binding::{compute_authorization_binding, BindingMaterialV1};
use crate::enforcement::enforcement_satisfies;
use crate::error::IntegrityError;
use crate::mutation::apply_mutation;
use crate::pdp::{pdp_for_fixture, DecisionProvider};
use crate::projector::{parse_tools_call, projector_for_fixture, ProjectionError};
use crate::result::{
    AuthorizationBinding, AuthorizationDecision, AuthorizationProjection, Decision,
    IntegrityVerdict, ObservedEnforcement, RedactionMetadata, RedactionStrategy, SinkReceipt,
    VectorResult,
};
use crate::sink::{
    binding_from_projection, enforce_reference_pep, AuthorizationDecider, PepEnforcementRequest,
    PepError, ReferencePepGateway, SyntheticExecutionSink,
};
use crate::vector::{MutationKind, ReferencePepMode, VectorDefinition};
use crate::vector_validation::parse_and_validate_vector;
use crate::version::SchemaVersion;

const DETERMINISTIC_STARTED: OffsetDateTime = time::macros::datetime!(2026-08-19 12:00:00 UTC);
const DETERMINISTIC_FINISHED: OffsetDateTime = time::macros::datetime!(2026-08-19 12:00:01 UTC);

/// Relative path from workspace root to built-in vector fixtures.
pub const BUILTIN_VECTORS_DIR: &str = "vectors/coaz-mcp/authorization-integrity/v1";

/// Stable identifiers for all Cycle 003 built-in vectors.
pub const BUILTIN_VECTOR_IDS: &[&str] = &[
    "COAZ-INTEGRITY-001",
    "COAZ-INTEGRITY-002",
    "COAZ-INTEGRITY-003",
    "COAZ-INTEGRITY-004",
    "COAZ-INTEGRITY-005",
    "COAZ-INTEGRITY-006",
    "COAZ-INTEGRITY-007",
];

/// Execution options for a single vector run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    pub reference_mode: ReferencePepMode,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            reference_mode: ReferencePepMode::SecureReevaluate,
        }
    }
}

impl RunOptions {
    /// Resolves reference PEP mode from vector safety metadata with a secure default.
    #[must_use]
    pub fn from_vector(vector: &VectorDefinition) -> Self {
        Self {
            reference_mode: vector
                .safety
                .reference_mode
                .unwrap_or(ReferencePepMode::SecureReevaluate),
        }
    }

    /// Overrides the reference PEP mode for proof runs (for example vulnerable stale-permit).
    #[must_use]
    pub fn with_reference_mode(mut self, mode: ReferencePepMode) -> Self {
        self.reference_mode = mode;
        self
    }
}

/// Errors raised while executing a vector through the integrity pipeline.
#[derive(Debug)]
pub enum RunError {
    Projection(ProjectionError),
    Binding(crate::binding::BindingError),
    Mutation(crate::mutation::MutationError),
    Pdp(crate::pdp::DecisionError),
    Pep(PepError),
    InitialDecisionNotPermit,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Projection(err) => write!(f, "projection failed: {err}"),
            Self::Binding(err) => write!(f, "binding failed: {err}"),
            Self::Mutation(err) => write!(f, "mutation failed: {err}"),
            Self::Pdp(err) => write!(f, "pdp failed: {err}"),
            Self::Pep(err) => write!(f, "reference pep failed: {err}"),
            Self::InitialDecisionNotPermit => {
                f.write_str("initial PDP decision must be PERMIT for integrity vectors")
            }
        }
    }
}

impl std::error::Error for RunError {}

/// Returns the absolute path to built-in vector fixtures relative to this crate.
#[must_use]
pub fn builtin_vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(BUILTIN_VECTORS_DIR)
}

/// Loads and validates a built-in vector fixture by id.
pub fn load_builtin_vector(vector_id: &str) -> Result<VectorDefinition, IntegrityError> {
    let path = builtin_vectors_root().join(format!("{vector_id}.json"));
    let json = std::fs::read_to_string(&path).map_err(|_| IntegrityError::Serialization {
        kind: format!("read-vector:{vector_id}"),
    })?;
    parse_and_validate_vector(&json)
}

/// Loads all built-in vector fixtures in stable id order.
pub fn load_all_builtin_vectors() -> Result<Vec<VectorDefinition>, IntegrityError> {
    BUILTIN_VECTOR_IDS
        .iter()
        .map(|id| load_builtin_vector(id))
        .collect()
}

/// Executes one vector definition through the full integrity pipeline.
pub fn execute_vector(
    vector: &VectorDefinition,
    options: &RunOptions,
) -> Result<VectorResult, RunError> {
    let projector =
        projector_for_fixture(&vector.projector_fixture.id).map_err(RunError::Projection)?;
    let pdp = pdp_for_fixture(&vector.pdp_fixture.id).map_err(RunError::Pdp)?;

    let (initial_projection, initial_binding) = project_and_bind(
        projector.as_ref(),
        &vector.initial_operation,
        &vector.trusted_context,
    )?;

    let initial_bound = pdp
        .evaluate(&initial_projection, &initial_binding)
        .map_err(RunError::Pdp)?;
    let decider = FixturePdpDecider { provider: pdp };
    if initial_bound.decision != Decision::Permit {
        return Err(RunError::InitialDecisionNotPermit);
    }
    let initial_decision = initial_bound.into_authorization_decision();

    let mutation_result = apply_mutation(
        &vector.initial_operation,
        &vector.trusted_context,
        &vector.mutation,
    )
    .map_err(RunError::Mutation)?;

    let (final_projection, final_binding) = resolve_final_projection_and_binding(
        projector.as_ref(),
        &initial_projection,
        &mutation_result.operation,
        &mutation_result.trusted,
        vector.mutation.kind,
    )?;

    let gateway = ReferencePepGateway::new(options.reference_mode, vector.safety.synthetic_only);
    let mut sink = SyntheticExecutionSink::new();

    let enforcement = enforce_reference_pep(PepEnforcementRequest {
        gateway: &gateway,
        initial_decision: &initial_decision,
        initial_binding: &initial_binding,
        final_binding: &final_binding,
        final_operation: &mutation_result.operation,
        final_projection: &final_projection,
        decider: &decider,
        sink: &mut sink,
    })
    .map_err(RunError::Pep)?;

    let observed = enforcement.observed;
    let verdict = derive_verdict(vector.expected.enforcement, observed);

    let sink_receipt = enforcement
        .record
        .map(|record| record.receipt)
        .unwrap_or_else(|| empty_sink_receipt(&mutation_result.operation));

    Ok(VectorResult {
        schema_version: SchemaVersion::V1,
        vector_id: vector.vector_id.clone(),
        standards: vector.standards.clone(),
        initial_operation: vector.initial_operation.clone(),
        initial_projection,
        initial_binding,
        initial_decision,
        mutation: vector.mutation.clone(),
        final_operation: mutation_result.operation,
        final_projection,
        final_binding,
        enforcement_trace: enforcement.trace,
        sink_receipt,
        expected: vector.expected.clone(),
        observed,
        verdict,
        redaction: RedactionMetadata {
            applied: false,
            strategy: RedactionStrategy::NoneRequired,
            fields: Vec::new(),
        },
        started_at: DETERMINISTIC_STARTED,
        finished_at: DETERMINISTIC_FINISHED,
    })
}

/// Executes a built-in vector fixture by id.
/// Errors loading or executing a built-in vector fixture.
#[derive(Debug)]
pub enum BuiltinRunError {
    Load(IntegrityError),
    Run(RunError),
}

impl std::fmt::Display for BuiltinRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(err) => write!(f, "failed to load built-in vector: {err}"),
            Self::Run(err) => write!(f, "vector execution failed: {err}"),
        }
    }
}

impl std::error::Error for BuiltinRunError {}

/// Executes a built-in vector fixture by id.
pub fn execute_builtin_vector(
    vector_id: &str,
    options: &RunOptions,
) -> Result<VectorResult, BuiltinRunError> {
    let vector = load_builtin_vector(vector_id).map_err(BuiltinRunError::Load)?;
    execute_vector(&vector, options).map_err(BuiltinRunError::Run)
}

struct FixturePdpDecider {
    provider: Box<dyn DecisionProvider>,
}

impl AuthorizationDecider for FixturePdpDecider {
    fn decide(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> AuthorizationDecision {
        self.provider
            .evaluate(projection, binding)
            .map(Into::into)
            .unwrap_or_else(|_| AuthorizationDecision {
                decision_id: "decision-harness-deny".to_owned(),
                decision: Decision::Deny,
                bound_to: binding.clone(),
            })
    }
}

fn project_and_bind(
    projector: &dyn crate::projector::AuthorizationProjector,
    operation: &crate::vector::McpOperation,
    trusted: &crate::vector::TrustedAuthorizationContext,
) -> Result<(AuthorizationProjection, AuthorizationBinding), RunError> {
    let projection = projector
        .project(operation, trusted)
        .map_err(RunError::Projection)?;
    let binding = binding_from_projection(operation, &projection).map_err(RunError::Binding)?;
    Ok((projection, binding))
}

fn resolve_final_projection_and_binding(
    projector: &dyn crate::projector::AuthorizationProjector,
    initial_projection: &AuthorizationProjection,
    final_operation: &crate::vector::McpOperation,
    final_trusted: &crate::vector::TrustedAuthorizationContext,
    mutation_kind: MutationKind,
) -> Result<(AuthorizationProjection, AuthorizationBinding), RunError> {
    match projector.project(final_operation, final_trusted) {
        Ok(final_projection) => {
            let binding = binding_from_projection(final_operation, &final_projection)
                .map_err(RunError::Binding)?;
            Ok((final_projection, binding))
        }
        Err(ProjectionError::UnsupportedMethod { .. }) if mutation_kind == MutationKind::Method => {
            let operation_name = operation_tool_name(final_operation);
            let material = BindingMaterialV1::from_projection(
                final_operation.method.as_str(),
                operation_name.as_deref(),
                initial_projection,
            )
            .map_err(RunError::Binding)?;
            let binding = compute_authorization_binding(&material);
            Ok((initial_projection.clone(), binding))
        }
        Err(err) => Err(RunError::Projection(err)),
    }
}

fn operation_tool_name(operation: &crate::vector::McpOperation) -> Option<String> {
    if operation.method == "tools/call" {
        parse_tools_call(operation)
            .ok()
            .map(|(name, _)| name.to_owned())
    } else {
        operation
            .params
            .get("name")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    }
}

fn empty_sink_receipt(operation: &crate::vector::McpOperation) -> SinkReceipt {
    let operation_name = operation_tool_name(operation).unwrap_or_else(|| "unknown".to_owned());
    SinkReceipt {
        forwarded: false,
        operation_method: operation.method.clone(),
        operation_name,
        params_digest: None,
        sequence: None,
    }
}

fn derive_verdict(
    expected: crate::vector::ExpectedEnforcement,
    observed: ObservedEnforcement,
) -> IntegrityVerdict {
    match enforcement_satisfies(expected, observed) {
        Some(true) => IntegrityVerdict::Pass,
        Some(false) => IntegrityVerdict::Fail,
        None => IntegrityVerdict::Inconclusive,
    }
}

/// Strips non-deterministic fields for repeated-run comparison.
#[must_use]
pub fn result_deterministic_signature(result: &VectorResult) -> ResultDeterministicSignature {
    ResultDeterministicSignature {
        vector_id: result.vector_id.clone(),
        initial_binding_digest: result.initial_binding.digest.clone(),
        final_binding_digest: result.final_binding.digest.clone(),
        binding_changed: result.enforcement_trace.binding_changed,
        reevaluated: result.enforcement_trace.reevaluated,
        reference_mode: result.enforcement_trace.reference_mode,
        observed: result.observed,
        verdict: result.verdict,
        sink_forwarded: result.sink_receipt.forwarded,
        sink_params_digest: result.sink_receipt.params_digest.clone(),
        sink_sequence: result.sink_receipt.sequence,
    }
}

/// Deterministic subset of a vector result (excludes timestamps and run-local ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultDeterministicSignature {
    pub vector_id: String,
    pub initial_binding_digest: String,
    pub final_binding_digest: String,
    pub binding_changed: bool,
    pub reevaluated: bool,
    pub reference_mode: ReferencePepMode,
    pub observed: ObservedEnforcement,
    pub verdict: IntegrityVerdict,
    pub sink_forwarded: bool,
    pub sink_params_digest: Option<String>,
    pub sink_sequence: Option<u64>,
}

/// Returns true when `path` points at the built-in vectors directory.
#[must_use]
pub fn is_builtin_vectors_dir(path: &Path) -> bool {
    path.ends_with(BUILTIN_VECTORS_DIR) || path.file_name().is_some_and(|name| name == "v1")
}
