//! Deterministic post-authorization mutation stage (Cycle 003 task-007).
//!
//! Mutations model the authorization-to-execution gap under controlled,
//! non-destructive conditions. Each kind changes only the fixture fields
//! relevant to its semantic class.

use serde_json::{json, Map, Value};

use crate::vector::{IntegrityMutation, McpOperation, MutationKind, TrustedAuthorizationContext};

/// Output of applying a deterministic mutation to an operation and trusted context.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationResult {
    pub operation: McpOperation,
    pub trusted: TrustedAuthorizationContext,
    pub applied: IntegrityMutation,
}

/// Errors raised while applying a controlled mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    UnsupportedKind { kind: MutationKind },
    InvalidOperation { reason: String },
    InvalidTrustedContext { field: String },
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedKind { kind } => write!(f, "unsupported mutation kind: {kind:?}"),
            Self::InvalidOperation { reason } => {
                write!(f, "invalid operation for mutation: {reason}")
            }
            Self::InvalidTrustedContext { field } => {
                write!(f, "invalid trusted context field: {field}")
            }
        }
    }
}

impl std::error::Error for MutationError {}

/// Controlled mutation boundary between authorization and execution.
pub trait OperationMutator: Send + Sync {
    /// Applies the supplied mutation spec to the operation and trusted context.
    fn mutate(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
        spec: &IntegrityMutation,
    ) -> Result<MutationResult, MutationError>;
}

/// Built-in deterministic mutator for Cycle 003 synthetic vectors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeterministicMutator;

impl OperationMutator for DeterministicMutator {
    fn mutate(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
        spec: &IntegrityMutation,
    ) -> Result<MutationResult, MutationError> {
        apply_mutation(operation, trusted, spec)
    }
}

/// Applies a deterministic mutation, returning sanitized before/after artifacts.
pub fn apply_mutation(
    operation: &McpOperation,
    trusted: &TrustedAuthorizationContext,
    spec: &IntegrityMutation,
) -> Result<MutationResult, MutationError> {
    let (mut op, mut ctx) = (operation.clone(), trusted.clone());
    let detail = spec.detail.as_deref();

    match spec.kind {
        MutationKind::None => {}
        MutationKind::ToolName => {
            mutate_tool_name(&mut op, detail)?;
        }
        MutationKind::MappedArgument => {
            mutate_mapped_argument(&mut op, detail)?;
        }
        MutationKind::Method => {
            mutate_method(&mut op, detail)?;
        }
        MutationKind::MappedTrustedContext => {
            mutate_mapped_trusted_context(&mut ctx, detail)?;
        }
        MutationKind::JsonReorderOnly => {
            reorder_json_only(&mut op)?;
        }
        MutationKind::UnmappedField => {
            mutate_unmapped_field(&mut op, detail)?;
        }
    }

    Ok(MutationResult {
        operation: op,
        trusted: ctx,
        applied: spec.clone(),
    })
}

fn mutate_tool_name(
    operation: &mut McpOperation,
    detail: Option<&str>,
) -> Result<(), MutationError> {
    let params = require_params_object(operation)?;
    let current = require_tool_name(params)?;
    let next = detail
        .and_then(parse_arrow_target)
        .unwrap_or_else(|| "rental.confirm".to_owned());
    if next == current {
        return Err(MutationError::InvalidOperation {
            reason: "tool name mutation produced no change".into(),
        });
    }
    params.insert("name".to_owned(), json!(next));
    Ok(())
}

fn mutate_mapped_argument(
    operation: &mut McpOperation,
    detail: Option<&str>,
) -> Result<(), MutationError> {
    let params = require_params_object(operation)?;
    let arguments = require_arguments_object(params)?;
    let current = arguments
        .get("daily_rate")
        .and_then(Value::as_i64)
        .ok_or_else(|| MutationError::InvalidOperation {
            reason: "daily_rate is required for mapped argument mutation".into(),
        })?;
    let next = detail
        .and_then(parse_arrow_target)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(5000);
    if next == current {
        return Err(MutationError::InvalidOperation {
            reason: "mapped argument mutation produced no change".into(),
        });
    }
    arguments.insert("daily_rate".to_owned(), json!(next));
    Ok(())
}

fn mutate_method(operation: &mut McpOperation, detail: Option<&str>) -> Result<(), MutationError> {
    let next = detail.unwrap_or("tools/list");
    if next == operation.method {
        return Err(MutationError::InvalidOperation {
            reason: "method mutation produced no change".into(),
        });
    }
    operation.method = next.to_owned();
    Ok(())
}

fn mutate_mapped_trusted_context(
    trusted: &mut TrustedAuthorizationContext,
    detail: Option<&str>,
) -> Result<(), MutationError> {
    let current =
        trusted
            .agent_id
            .as_deref()
            .ok_or_else(|| MutationError::InvalidTrustedContext {
                field: "agent_id".into(),
            })?;
    let next = detail
        .and_then(parse_arrow_target)
        .unwrap_or_else(|| "agent-synthetic-002".to_owned());
    if next == current {
        return Err(MutationError::InvalidTrustedContext {
            field: "agent_id".into(),
        });
    }
    trusted.agent_id = Some(next);
    Ok(())
}

fn reorder_json_only(operation: &mut McpOperation) -> Result<(), MutationError> {
    let params = require_params_object(operation)?;
    let name = params
        .get("name")
        .cloned()
        .ok_or_else(|| MutationError::InvalidOperation {
            reason: "params.name is required".into(),
        })?;
    let arguments = require_arguments_object(params)?.clone();

    let mut keys: Vec<String> = arguments.keys().cloned().collect();
    keys.reverse();

    let mut reordered_args = Map::new();
    for key in keys {
        if let Some(value) = arguments.get(&key) {
            reordered_args.insert(key, value.clone());
        }
    }

    let mut reordered_params = Map::new();
    reordered_params.insert("name".to_owned(), name);
    reordered_params.insert("arguments".to_owned(), Value::Object(reordered_args));
    operation.params = Value::Object(reordered_params);
    Ok(())
}

fn mutate_unmapped_field(
    operation: &mut McpOperation,
    detail: Option<&str>,
) -> Result<(), MutationError> {
    let params = require_params_object(operation)?;
    let arguments = require_arguments_object(params)?;
    let note = detail.unwrap_or("synthetic-unmapped-note");
    if arguments.contains_key("internal_notes") {
        return Err(MutationError::InvalidOperation {
            reason: "internal_notes already present".into(),
        });
    }
    arguments.insert("internal_notes".to_owned(), json!(note));
    Ok(())
}

fn require_params_object(
    operation: &mut McpOperation,
) -> Result<&mut Map<String, Value>, MutationError> {
    operation
        .params
        .as_object_mut()
        .ok_or_else(|| MutationError::InvalidOperation {
            reason: "params must be a JSON object".into(),
        })
}

fn require_arguments_object(
    params: &mut Map<String, Value>,
) -> Result<&mut Map<String, Value>, MutationError> {
    params
        .get_mut("arguments")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| MutationError::InvalidOperation {
            reason: "params.arguments must be a JSON object".into(),
        })
}

fn require_tool_name(params: &mut Map<String, Value>) -> Result<String, MutationError> {
    params
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| MutationError::InvalidOperation {
            reason: "params.name must be a string".into(),
        })
}

fn parse_arrow_target(detail: &str) -> Option<String> {
    detail
        .split("->")
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Returns the set of top-level param keys changed by a mutation class.
pub fn changed_operation_fields(kind: MutationKind) -> &'static [&'static str] {
    match kind {
        MutationKind::None => &[],
        MutationKind::ToolName => &["params.name"],
        MutationKind::MappedArgument => &["params.arguments.daily_rate"],
        MutationKind::Method => &["method"],
        MutationKind::MappedTrustedContext => &[],
        MutationKind::JsonReorderOnly => &["params.key_order", "params.arguments.key_order"],
        MutationKind::UnmappedField => &["params.arguments.internal_notes"],
    }
}

/// Returns trusted-context fields changed by a mutation class.
pub fn changed_trusted_fields(kind: MutationKind) -> &'static [&'static str] {
    match kind {
        MutationKind::MappedTrustedContext => &["trusted.agent_id"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::sample_vector_definition;

    fn baseline_operation() -> McpOperation {
        sample_vector_definition().initial_operation
    }

    fn baseline_trusted() -> TrustedAuthorizationContext {
        sample_vector_definition().trusted_context
    }

    #[test]
    fn none_mutation_is_identity() {
        let op = baseline_operation();
        let trusted = baseline_trusted();
        let result = apply_mutation(
            &op,
            &trusted,
            &IntegrityMutation {
                kind: MutationKind::None,
                detail: None,
            },
        )
        .expect("none");
        assert_eq!(result.operation, op);
        assert_eq!(result.trusted, trusted);
    }

    #[test]
    fn mapped_argument_changes_only_daily_rate() {
        let before = baseline_operation();
        let result = apply_mutation(
            &before,
            &baseline_trusted(),
            &IntegrityMutation {
                kind: MutationKind::MappedArgument,
                detail: Some("daily_rate 50 -> 5000".to_owned()),
            },
        )
        .expect("mapped argument");
        assert_ne!(
            result.operation.params["arguments"]["daily_rate"],
            before.params["arguments"]["daily_rate"]
        );
        assert_eq!(result.operation.params["name"], before.params["name"]);
        assert_eq!(result.operation.method, before.method);
        assert_eq!(result.trusted, baseline_trusted());
    }
}
