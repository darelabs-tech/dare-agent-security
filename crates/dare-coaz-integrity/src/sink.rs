//! In-process synthetic execution sink and reference PEP gateway (Cycle 003 task-007).
//!
//! The sink records sanitized operations without external side effects.
//! Reference PEP modes model secure re-evaluation/refusal versus intentional
//! stale-permit forwarding for synthetic proof fixtures only.

use std::fmt;

use crate::binding::{bindings_equal, compute_authorization_binding, BindingMaterialV1};
use crate::canonical::CanonicalValue;
use crate::projector::parse_tools_call;
use crate::result::{
    AuthorizationBinding, AuthorizationDecision, AuthorizationProjection, Decision,
    EnforcementTrace, ObservedEnforcement, SinkReceipt,
};
use crate::vector::{McpOperation, ReferencePepMode};

/// Errors raised by the synthetic execution sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError {
    InvalidOperation { reason: String },
    Canonicalization,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperation { reason } => {
                write!(f, "invalid operation for sink: {reason}")
            }
            Self::Canonicalization => f.write_str("canonicalization failed for sink digest"),
        }
    }
}

impl std::error::Error for SinkError {}

/// Errors raised by the reference PEP gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PepError {
    Sink(SinkError),
    SyntheticOnlyRequired,
    InitialDecisionNotPermit,
}

impl fmt::Display for PepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sink(err) => write!(f, "sink error: {err}"),
            Self::SyntheticOnlyRequired => {
                f.write_str("VulnerableReusePermit requires synthetic_only fixtures")
            }
            Self::InitialDecisionNotPermit => {
                f.write_str("forwarding requires an initial PERMIT decision")
            }
        }
    }
}

impl std::error::Error for PepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sink(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SinkError> for PepError {
    fn from(value: SinkError) -> Self {
        Self::Sink(value)
    }
}

/// Authorization context forwarded to the synthetic sink when an operation is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkAuthorizationContext {
    pub decision_id: String,
    pub binding: AuthorizationBinding,
}

/// Full sink record including binding/decision trace metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkRecord {
    pub receipt: SinkReceipt,
    pub authorization: SinkAuthorizationContext,
}

/// Outcome of reference PEP enforcement at the authorization-to-execution boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementOutcome {
    pub trace: EnforcementTrace,
    pub observed: ObservedEnforcement,
    pub record: Option<SinkRecord>,
    pub binding_used: Option<AuthorizationBinding>,
    pub decision_id_used: Option<String>,
}

/// Local, non-destructive execution sink.
pub trait ExecutionSink {
    fn forward(
        &mut self,
        operation: &McpOperation,
        authorization: &SinkAuthorizationContext,
    ) -> Result<SinkRecord, SinkError>;
}

/// Deterministic authorization decision source for secure re-evaluation paths.
pub trait AuthorizationDecider: Send + Sync {
    fn decide(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> AuthorizationDecision;
}

/// In-memory synthetic sink that records sanitized operations only.
#[derive(Debug, Clone, Default)]
pub struct SyntheticExecutionSink {
    records: Vec<SinkRecord>,
    next_sequence: u64,
}

impl SyntheticExecutionSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn records(&self) -> &[SinkRecord] {
        &self.records
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl ExecutionSink for SyntheticExecutionSink {
    fn forward(
        &mut self,
        operation: &McpOperation,
        authorization: &SinkAuthorizationContext,
    ) -> Result<SinkRecord, SinkError> {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let (operation_name, params_digest) = sanitize_operation(operation)?;
        let receipt = SinkReceipt {
            forwarded: true,
            operation_method: operation.method.clone(),
            operation_name,
            params_digest: Some(params_digest),
            sequence: Some(self.next_sequence),
        };
        let record = SinkRecord {
            receipt: receipt.clone(),
            authorization: authorization.clone(),
        };
        self.records.push(record.clone());
        Ok(record)
    }
}

/// Reference PEP gateway configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferencePepGateway {
    pub mode: ReferencePepMode,
    pub synthetic_only: bool,
}

impl ReferencePepGateway {
    #[must_use]
    pub const fn new(mode: ReferencePepMode, synthetic_only: bool) -> Self {
        Self {
            mode,
            synthetic_only,
        }
    }

    /// Validates that vulnerable reuse is restricted to synthetic fixtures.
    pub fn validate_mode(&self) -> Result<(), PepError> {
        if self.mode == ReferencePepMode::VulnerableReuse && !self.synthetic_only {
            return Err(PepError::SyntheticOnlyRequired);
        }
        Ok(())
    }
}

/// Computes the authorization binding for a projected operation snapshot.
pub fn binding_from_projection(
    operation: &McpOperation,
    projection: &AuthorizationProjection,
) -> Result<AuthorizationBinding, crate::binding::BindingError> {
    let operation_name = operation_tool_name(operation).ok();
    let material = BindingMaterialV1::from_projection(
        operation.method.as_str(),
        operation_name.as_deref(),
        projection,
    )?;
    Ok(compute_authorization_binding(&material))
}

/// Inputs for reference PEP enforcement at the authorization-to-execution boundary.
pub struct PepEnforcementRequest<'a> {
    pub gateway: &'a ReferencePepGateway,
    pub initial_decision: &'a AuthorizationDecision,
    pub initial_binding: &'a AuthorizationBinding,
    pub final_binding: &'a AuthorizationBinding,
    pub final_operation: &'a McpOperation,
    pub final_projection: &'a AuthorizationProjection,
    pub decider: &'a dyn AuthorizationDecider,
    pub sink: &'a mut SyntheticExecutionSink,
}

/// Applies reference PEP behavior and optionally forwards to the synthetic sink.
pub fn enforce_reference_pep(
    request: PepEnforcementRequest<'_>,
) -> Result<EnforcementOutcome, PepError> {
    request.gateway.validate_mode()?;

    let binding_changed = !bindings_equal(request.initial_binding, request.final_binding);

    if request.initial_decision.decision != Decision::Permit {
        return Ok(EnforcementOutcome {
            trace: EnforcementTrace {
                reference_mode: request.gateway.mode,
                binding_changed,
                reevaluated: false,
            },
            observed: ObservedEnforcement::NoForwardInitialDeny,
            record: None,
            binding_used: None,
            decision_id_used: None,
        });
    }

    match request.gateway.mode {
        ReferencePepMode::SecureReevaluate => enforce_secure_reevaluate(SecureReevaluateContext {
            mode: request.gateway.mode,
            binding_changed,
            initial_decision: request.initial_decision,
            initial_binding: request.initial_binding,
            final_binding: request.final_binding,
            final_operation: request.final_operation,
            final_projection: request.final_projection,
            decider: request.decider,
            sink: request.sink,
        }),
        ReferencePepMode::SecureRefuse => enforce_secure_refuse(
            request.gateway.mode,
            binding_changed,
            request.initial_decision,
            request.initial_binding,
            request.final_operation,
            request.sink,
        ),
        ReferencePepMode::VulnerableReuse => enforce_vulnerable_reuse(
            request.gateway.mode,
            binding_changed,
            request.initial_decision,
            request.initial_binding,
            request.final_operation,
            request.sink,
        ),
    }
}

struct SecureReevaluateContext<'a> {
    mode: ReferencePepMode,
    binding_changed: bool,
    initial_decision: &'a AuthorizationDecision,
    initial_binding: &'a AuthorizationBinding,
    final_binding: &'a AuthorizationBinding,
    final_operation: &'a McpOperation,
    final_projection: &'a AuthorizationProjection,
    decider: &'a dyn AuthorizationDecider,
    sink: &'a mut SyntheticExecutionSink,
}

fn enforce_secure_reevaluate(
    ctx: SecureReevaluateContext<'_>,
) -> Result<EnforcementOutcome, PepError> {
    if !ctx.binding_changed {
        let auth = SinkAuthorizationContext {
            decision_id: ctx.initial_decision.decision_id.clone(),
            binding: ctx.initial_binding.clone(),
        };
        let record = ctx.sink.forward(ctx.final_operation, &auth)?;
        return Ok(EnforcementOutcome {
            trace: EnforcementTrace {
                reference_mode: ctx.mode,
                binding_changed: false,
                reevaluated: false,
            },
            observed: ObservedEnforcement::ForwardedWithExistingPermit,
            binding_used: Some(ctx.initial_binding.clone()),
            decision_id_used: Some(ctx.initial_decision.decision_id.clone()),
            record: Some(record),
        });
    }

    let reevaluated = ctx.decider.decide(ctx.final_projection, ctx.final_binding);
    if reevaluated.decision == Decision::Permit {
        let auth = SinkAuthorizationContext {
            decision_id: reevaluated.decision_id.clone(),
            binding: ctx.final_binding.clone(),
        };
        let record = ctx.sink.forward(ctx.final_operation, &auth)?;
        return Ok(EnforcementOutcome {
            trace: EnforcementTrace {
                reference_mode: ctx.mode,
                binding_changed: true,
                reevaluated: true,
            },
            observed: ObservedEnforcement::ForwardedAfterReevaluation,
            binding_used: Some(ctx.final_binding.clone()),
            decision_id_used: Some(reevaluated.decision_id.clone()),
            record: Some(record),
        });
    }

    Ok(EnforcementOutcome {
        trace: EnforcementTrace {
            reference_mode: ctx.mode,
            binding_changed: true,
            reevaluated: true,
        },
        observed: ObservedEnforcement::DeniedAfterReevaluation,
        record: None,
        binding_used: None,
        decision_id_used: None,
    })
}

fn enforce_secure_refuse(
    mode: ReferencePepMode,
    binding_changed: bool,
    initial_decision: &AuthorizationDecision,
    initial_binding: &AuthorizationBinding,
    final_operation: &McpOperation,
    sink: &mut SyntheticExecutionSink,
) -> Result<EnforcementOutcome, PepError> {
    if binding_changed {
        return Ok(EnforcementOutcome {
            trace: EnforcementTrace {
                reference_mode: mode,
                binding_changed: true,
                reevaluated: false,
            },
            observed: ObservedEnforcement::RefusedAfterBindingChange,
            record: None,
            binding_used: None,
            decision_id_used: None,
        });
    }

    let auth = SinkAuthorizationContext {
        decision_id: initial_decision.decision_id.clone(),
        binding: initial_binding.clone(),
    };
    let record = sink.forward(final_operation, &auth)?;
    Ok(EnforcementOutcome {
        trace: EnforcementTrace {
            reference_mode: mode,
            binding_changed: false,
            reevaluated: false,
        },
        observed: ObservedEnforcement::ForwardedWithExistingPermit,
        binding_used: Some(initial_binding.clone()),
        decision_id_used: Some(initial_decision.decision_id.clone()),
        record: Some(record),
    })
}

fn enforce_vulnerable_reuse(
    mode: ReferencePepMode,
    binding_changed: bool,
    initial_decision: &AuthorizationDecision,
    initial_binding: &AuthorizationBinding,
    final_operation: &McpOperation,
    sink: &mut SyntheticExecutionSink,
) -> Result<EnforcementOutcome, PepError> {
    let auth = SinkAuthorizationContext {
        decision_id: initial_decision.decision_id.clone(),
        binding: initial_binding.clone(),
    };
    let record = sink.forward(final_operation, &auth)?;
    let observed = if binding_changed {
        ObservedEnforcement::ForwardedWithStalePermit
    } else {
        ObservedEnforcement::ForwardedWithExistingPermit
    };

    Ok(EnforcementOutcome {
        trace: EnforcementTrace {
            reference_mode: mode,
            binding_changed,
            reevaluated: false,
        },
        observed,
        binding_used: Some(initial_binding.clone()),
        decision_id_used: Some(initial_decision.decision_id.clone()),
        record: Some(record),
    })
}

fn sanitize_operation(operation: &McpOperation) -> Result<(String, String), SinkError> {
    let operation_name = operation_tool_name(operation)?;
    let digest = CanonicalValue::normalize(&operation.params)
        .map_err(|_| SinkError::Canonicalization)?
        .digest();
    Ok((operation_name, digest))
}

fn operation_tool_name(operation: &McpOperation) -> Result<String, SinkError> {
    if operation.method == "tools/call" {
        let (name, _) = parse_tools_call(operation).map_err(|err| SinkError::InvalidOperation {
            reason: err.to_string(),
        })?;
        return Ok(name.to_owned());
    }

    operation
        .params
        .get("name")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| SinkError::InvalidOperation {
            reason: "operation name could not be derived".into(),
        })
}

/// Alias documenting blueprint terminology for secure refusal mode.
pub const SECURE_REFUSE_ON_CHANGE: ReferencePepMode = ReferencePepMode::SecureRefuse;

/// Alias documenting blueprint terminology for vulnerable stale-permit mode.
pub const VULNERABLE_REUSE_PERMIT: ReferencePepMode = ReferencePepMode::VulnerableReuse;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::McpOperation;
    use serde_json::json;

    #[test]
    fn sink_trace_is_deterministic() {
        let operation = McpOperation {
            method: "tools/call".to_owned(),
            params: json!({
                "name": "rental.quote",
                "arguments": {
                    "customer_id": "cust-synthetic-001",
                    "vehicle_id": "vehicle-synthetic-001",
                    "daily_rate": 50,
                    "days": 3
                }
            }),
        };
        let auth = SinkAuthorizationContext {
            decision_id: "decision-synthetic-001".to_owned(),
            binding: AuthorizationBinding {
                algorithm: "coaz-binding-v1".to_owned(),
                digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            },
        };

        let mut first = SyntheticExecutionSink::new();
        let mut second = SyntheticExecutionSink::new();
        let left = first.forward(&operation, &auth).expect("first");
        let right = second.forward(&operation, &auth).expect("second");
        assert_eq!(left.receipt, right.receipt);
        assert_eq!(left.authorization, right.authorization);
    }
}
