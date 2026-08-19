//! Deterministic fixture PDP for Cycle 003 authorization decisions.
//!
//! The PDP evaluates sanitized AuthZEN-shaped projections locally without network
//! access and binds every permit/deny outcome to the supplied authorization binding.

use std::fmt;

use serde_json::Value;

use crate::binding::bindings_equal;
use crate::result::{
    AuthorizationBinding, AuthorizationDecision, AuthorizationProjection, Decision,
};

#[path = "pdp_rental.rs"]
mod pdp_rental;

pub use pdp_rental::SyntheticRentalPolicyV1;

/// PDP decision bound to the evaluated authorization binding digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDecision {
    pub decision_id: String,
    pub decision: Decision,
    pub binding: AuthorizationBinding,
}

impl BoundDecision {
    /// Returns the binding digest this decision was evaluated against.
    pub fn binding_digest(&self) -> &str {
        &self.binding.digest
    }

    /// Returns whether this decision is bound to the supplied binding.
    pub fn is_bound_to(&self, binding: &AuthorizationBinding) -> bool {
        bindings_equal(&self.binding, binding)
    }

    /// Converts to the portable result artifact shape.
    pub fn into_authorization_decision(self) -> AuthorizationDecision {
        AuthorizationDecision {
            decision_id: self.decision_id,
            decision: self.decision,
            bound_to: self.binding,
        }
    }
}

impl From<BoundDecision> for AuthorizationDecision {
    fn from(value: BoundDecision) -> Self {
        value.into_authorization_decision()
    }
}

/// Errors raised while evaluating fixture policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    UnknownFixture { id: String },
    MissingResourceId,
    MissingDailyRate,
    MissingSubjectId,
    InvalidDailyRate,
    BindingMismatch,
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFixture { id } => write!(f, "unknown PDP fixture id {id}"),
            Self::MissingResourceId => f.write_str("missing authzen resource id"),
            Self::MissingDailyRate => f.write_str("missing mapped daily_rate"),
            Self::MissingSubjectId => f.write_str("missing trusted subject id"),
            Self::InvalidDailyRate => f.write_str("daily_rate must be an integer"),
            Self::BindingMismatch => {
                f.write_str("supplied binding does not match evaluated authorization context")
            }
        }
    }
}

impl std::error::Error for DecisionError {}

/// Project-owned deterministic PDP boundary.
pub trait DecisionProvider: Send + Sync {
    /// Stable PDP fixture identifier used by vector definitions.
    fn fixture_id(&self) -> &'static str;

    /// Evaluates fixture policy for the projection and binds the outcome to `binding`.
    fn evaluate(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> Result<BoundDecision, DecisionError>;
}

/// Resolves a reference PDP implementation from a vector fixture id.
pub fn pdp_for_fixture(id: &str) -> Result<Box<dyn DecisionProvider>, DecisionError> {
    match id {
        SyntheticRentalPolicyV1::FIXTURE_ID => Ok(Box::new(SyntheticRentalPolicyV1)),
        _ => Err(DecisionError::UnknownFixture { id: id.to_owned() }),
    }
}

/// Builds a stable fixture/run decision id from fixture policy, outcome, and binding digest.
pub fn stable_decision_id(
    fixture_id: &str,
    decision: Decision,
    binding: &AuthorizationBinding,
) -> String {
    let outcome = match decision {
        Decision::Permit => "permit",
        Decision::Deny => "deny",
    };
    format!("{fixture_id}:{outcome}:{}", binding.digest)
}

/// Binds a policy outcome to the evaluated authorization binding.
pub fn bind_decision(
    fixture_id: &str,
    decision: Decision,
    binding: AuthorizationBinding,
) -> BoundDecision {
    BoundDecision {
        decision_id: stable_decision_id(fixture_id, decision, &binding),
        decision,
        binding,
    }
}

pub(crate) fn resource_id(projection: &AuthorizationProjection) -> Result<&str, DecisionError> {
    projection
        .authzen_request
        .get("resource")
        .and_then(Value::as_object)
        .and_then(|resource| resource.get("id"))
        .and_then(Value::as_str)
        .ok_or(DecisionError::MissingResourceId)
}

pub(crate) fn subject_id(projection: &AuthorizationProjection) -> Result<&str, DecisionError> {
    projection
        .trusted_inputs
        .get("subject_id")
        .and_then(Value::as_str)
        .ok_or(DecisionError::MissingSubjectId)
}

pub(crate) fn daily_rate(projection: &AuthorizationProjection) -> Result<i64, DecisionError> {
    let value = projection
        .mapped_inputs
        .get("daily_rate")
        .ok_or(DecisionError::MissingDailyRate)?;

    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|rate| i64::try_from(rate).ok()))
        .ok_or(DecisionError::InvalidDailyRate)
}

pub(crate) fn is_standard_synthetic_subject(subject_id: &str) -> bool {
    subject_id.starts_with("subject-synthetic-")
}
