//! Operator-safe discovery observation used as evidence-bridge input.

use time::OffsetDateTime;

use crate::enumerate::EnumerationOutcome;
use crate::inventory::{DiscoveryInventory, DiscoveryTarget};
use crate::policy::PolicyProfile;

/// Deterministic observation of one discovery/baseline run.
///
/// String fields may still contain operator-supplied noise; the bridge sanitizes
/// them before they appear in `SecurityEvidence`.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryObservation {
    /// Operator-supplied target identity. Sanitized before emission.
    pub target: DiscoveryTarget,
    /// Inventory snapshot when enumeration produced one.
    pub inventory: Option<DiscoveryInventory>,
    /// Wire methods actually invoked, in order. Never includes arguments.
    pub invoked_methods: Vec<String>,
    /// Passive policy profile that governed the run.
    pub policy_profile: PolicyProfile,
    /// Sanitizable evaluation/infrastructure error, when the run failed.
    pub evaluation_error: Option<String>,
    /// When discovery started.
    pub started_at: OffsetDateTime,
    /// When the observation was obtained.
    pub observed_at: OffsetDateTime,
    /// When evidence is recorded. Must be >= `observed_at`.
    pub recorded_at: OffsetDateTime,
}

impl DiscoveryObservation {
    /// Build an observation from a successful enumeration outcome.
    pub fn from_enumeration_outcome(
        outcome: &EnumerationOutcome,
        policy_profile: PolicyProfile,
        started_at: OffsetDateTime,
        recorded_at: OffsetDateTime,
    ) -> Self {
        Self {
            target: outcome.inventory.target.clone(),
            observed_at: outcome.inventory.generated_at,
            inventory: Some(outcome.inventory.clone()),
            invoked_methods: outcome.invoked_methods.clone(),
            policy_profile,
            evaluation_error: None,
            started_at,
            recorded_at,
        }
    }
}
