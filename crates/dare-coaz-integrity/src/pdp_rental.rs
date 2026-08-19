//! Synthetic rental fixture policy for deterministic permit/deny evaluation.
//!
//! Policy rules (fixture-only, no network):
//! ```text
//! rental.quote daily_rate <= 1000  -> PERMIT
//! rental.quote daily_rate > 1000   -> DENY
//! rental.quote_internal            -> DENY for standard synthetic subject
//! ```

use crate::pdp::{
    bind_decision, daily_rate, is_standard_synthetic_subject, resource_id, subject_id,
    BoundDecision, DecisionError, DecisionProvider,
};
use crate::result::{AuthorizationBinding, AuthorizationProjection, Decision};

/// Local deterministic PDP backed by the Cycle 003 synthetic rental policy fixture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyntheticRentalPolicyV1;

impl SyntheticRentalPolicyV1 {
    pub const FIXTURE_ID: &'static str = "synthetic-rental-policy-v1";
    const DAILY_RATE_LIMIT: i64 = 1000;

    fn evaluate_policy(projection: &AuthorizationProjection) -> Result<Decision, DecisionError> {
        let tool = resource_id(projection)?;
        match tool {
            "rental.quote" => {
                let rate = daily_rate(projection)?;
                Ok(if rate <= Self::DAILY_RATE_LIMIT {
                    Decision::Permit
                } else {
                    Decision::Deny
                })
            }
            "rental.quote_internal" => {
                let subject = subject_id(projection)?;
                Ok(if is_standard_synthetic_subject(subject) {
                    Decision::Deny
                } else {
                    Decision::Permit
                })
            }
            _ => Ok(Decision::Deny),
        }
    }
}

impl DecisionProvider for SyntheticRentalPolicyV1 {
    fn fixture_id(&self) -> &'static str {
        Self::FIXTURE_ID
    }

    fn evaluate(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> Result<BoundDecision, DecisionError> {
        let decision = Self::evaluate_policy(projection)?;
        Ok(bind_decision(Self::FIXTURE_ID, decision, binding.clone()))
    }
}
