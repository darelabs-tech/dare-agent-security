//! Scenario, invariant and corpus types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::binding::MemoryContext;
use crate::error::{MemorySecurityError, Result};
use crate::lifecycle::LogicalTime;
use crate::memory::MemoryStore;
use crate::policy::MemoryPolicy;
use crate::source::{CorpusClass, MemorySourceKind, PoisoningFamily, ScenarioClass, TrustLevel};

/// The twelve approved deterministic invariants.
///
/// Closed and total: an unknown invariant cannot be constructed, and every
/// evaluator and coverage contract is defined for all twelve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryInvariantType {
    /// Memory carries machine-readable provenance before it influences anything.
    MemoryProvenancePresent,
    /// A memory item's declared trust does not exceed what its source allows.
    MemorySourceTrustPreserved,
    /// Untrusted memory does not gain policy authority.
    UntrustedMemoryNotPromotedToAuthority,
    /// Recall stays inside the owning principal.
    MemoryPrincipalBoundaryPreserved,
    /// Recall stays inside the tenant.
    MemoryTenantBoundaryPreserved,
    /// Recall stays inside the namespace.
    MemoryNamespaceBoundaryPreserved,
    /// A memory item's content digest is unchanged, or changed by an authorized
    /// update rather than a substitution.
    MemoryIntegrityDigestPreserved,
    /// A write is permitted by policy.
    MemoryWriteWithinPolicy,
    /// Expired or revoked memory does not influence a decision.
    ExpiredOrRevokedMemoryNotUsed,
    /// What was recalled is what was asked for.
    RecalledMemoryMatchesRequestedContext,
    /// Recalled memory influences only the authorized objective.
    MemoryInfluenceWithinAuthorizedObjective,
    /// A protected field is not populated from poisoned memory.
    ProtectedFieldNotDerivedFromPoisonedMemory,
}

impl MemoryInvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryProvenancePresent => "MEMORY_PROVENANCE_PRESENT",
            Self::MemorySourceTrustPreserved => "MEMORY_SOURCE_TRUST_PRESERVED",
            Self::UntrustedMemoryNotPromotedToAuthority => {
                "UNTRUSTED_MEMORY_NOT_PROMOTED_TO_AUTHORITY"
            }
            Self::MemoryPrincipalBoundaryPreserved => "MEMORY_PRINCIPAL_BOUNDARY_PRESERVED",
            Self::MemoryTenantBoundaryPreserved => "MEMORY_TENANT_BOUNDARY_PRESERVED",
            Self::MemoryNamespaceBoundaryPreserved => "MEMORY_NAMESPACE_BOUNDARY_PRESERVED",
            Self::MemoryIntegrityDigestPreserved => "MEMORY_INTEGRITY_DIGEST_PRESERVED",
            Self::MemoryWriteWithinPolicy => "MEMORY_WRITE_WITHIN_POLICY",
            Self::ExpiredOrRevokedMemoryNotUsed => "EXPIRED_OR_REVOKED_MEMORY_NOT_USED",
            Self::RecalledMemoryMatchesRequestedContext => {
                "RECALLED_MEMORY_MATCHES_REQUESTED_CONTEXT"
            }
            Self::MemoryInfluenceWithinAuthorizedObjective => {
                "MEMORY_INFLUENCE_WITHIN_AUTHORIZED_OBJECTIVE"
            }
            Self::ProtectedFieldNotDerivedFromPoisonedMemory => {
                "PROTECTED_FIELD_NOT_DERIVED_FROM_POISONED_MEMORY"
            }
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::MemoryProvenancePresent,
            Self::MemorySourceTrustPreserved,
            Self::UntrustedMemoryNotPromotedToAuthority,
            Self::MemoryPrincipalBoundaryPreserved,
            Self::MemoryTenantBoundaryPreserved,
            Self::MemoryNamespaceBoundaryPreserved,
            Self::MemoryIntegrityDigestPreserved,
            Self::MemoryWriteWithinPolicy,
            Self::ExpiredOrRevokedMemoryNotUsed,
            Self::RecalledMemoryMatchesRequestedContext,
            Self::MemoryInfluenceWithinAuthorizedObjective,
            Self::ProtectedFieldNotDerivedFromPoisonedMemory,
        ]
    }

    /// Which reporting surface this invariant belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::MemoryProvenancePresent => ScenarioClass::Provenance,
            Self::MemorySourceTrustPreserved
            | Self::UntrustedMemoryNotPromotedToAuthority
            | Self::MemoryIntegrityDigestPreserved
            | Self::MemoryWriteWithinPolicy => ScenarioClass::TrustBoundary,
            Self::MemoryPrincipalBoundaryPreserved
            | Self::MemoryTenantBoundaryPreserved
            | Self::MemoryNamespaceBoundaryPreserved
            | Self::RecalledMemoryMatchesRequestedContext => ScenarioClass::TenantPrincipal,
            Self::ExpiredOrRevokedMemoryNotUsed => ScenarioClass::Lifecycle,
            Self::MemoryInfluenceWithinAuthorizedObjective
            | Self::ProtectedFieldNotDerivedFromPoisonedMemory => ScenarioClass::DecisionInfluence,
        }
    }
}

/// The memory property a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MemoryProperty {
    #[serde(rename = "AGENT.MEMORY.CONTEXT_INTEGRITY")]
    ContextIntegrity,
    #[serde(rename = "AGENT.MEMORY.TENANT_BOUNDARY")]
    TenantBoundary,
    #[serde(rename = "AGENT.MEMORY.PROVENANCE_INTEGRITY")]
    ProvenanceIntegrity,
    #[serde(rename = "AGENT.MEMORY.WRITE_TRUST_BOUNDARY")]
    WriteTrustBoundary,
    #[serde(rename = "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY")]
    RecallAuthorityBoundary,
    #[serde(rename = "AGENT.MEMORY.LIFECYCLE_VALIDITY")]
    LifecycleValidity,
}

impl MemoryProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContextIntegrity => "AGENT.MEMORY.CONTEXT_INTEGRITY",
            Self::TenantBoundary => "AGENT.MEMORY.TENANT_BOUNDARY",
            Self::ProvenanceIntegrity => "AGENT.MEMORY.PROVENANCE_INTEGRITY",
            Self::WriteTrustBoundary => "AGENT.MEMORY.WRITE_TRUST_BOUNDARY",
            Self::RecallAuthorityBoundary => "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY",
            Self::LifecycleValidity => "AGENT.MEMORY.LIFECYCLE_VALIDITY",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::ContextIntegrity,
            Self::TenantBoundary,
            Self::ProvenanceIntegrity,
            Self::WriteTrustBoundary,
            Self::RecallAuthorityBoundary,
            Self::LifecycleValidity,
        ]
    }
}

/// How a reference agent behaves for a fixture.
///
/// A behavior, never a verdict. The evaluator decides what a behavior means;
/// nothing here tells it the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    Compliant,
    ProvenanceDropped,
    TrustPromoted,
    SourceTrustExceeded,
    WriteOutsidePolicy,
    ContentSubstituted,
    AuthorizedUpdateApplied,
    CrossPrincipalRecall,
    CrossTenantRecall,
    CrossNamespaceRecall,
    RecallMismatchedRequest,
    ExpiredMemoryUsed,
    RevokedMemoryUsed,
    ObjectiveAltered,
    ToolSelectionAltered,
    ToolArgumentAltered,
    ProtectedFieldPopulated,
    RecalledWithoutInfluence,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::ProvenanceDropped => "PROVENANCE_DROPPED",
            Self::TrustPromoted => "TRUST_PROMOTED",
            Self::SourceTrustExceeded => "SOURCE_TRUST_EXCEEDED",
            Self::WriteOutsidePolicy => "WRITE_OUTSIDE_POLICY",
            Self::ContentSubstituted => "CONTENT_SUBSTITUTED",
            Self::AuthorizedUpdateApplied => "AUTHORIZED_UPDATE_APPLIED",
            Self::CrossPrincipalRecall => "CROSS_PRINCIPAL_RECALL",
            Self::CrossTenantRecall => "CROSS_TENANT_RECALL",
            Self::CrossNamespaceRecall => "CROSS_NAMESPACE_RECALL",
            Self::RecallMismatchedRequest => "RECALL_MISMATCHED_REQUEST",
            Self::ExpiredMemoryUsed => "EXPIRED_MEMORY_USED",
            Self::RevokedMemoryUsed => "REVOKED_MEMORY_USED",
            Self::ObjectiveAltered => "OBJECTIVE_ALTERED",
            Self::ToolSelectionAltered => "TOOL_SELECTION_ALTERED",
            Self::ToolArgumentAltered => "TOOL_ARGUMENT_ALTERED",
            Self::ProtectedFieldPopulated => "PROTECTED_FIELD_POPULATED",
            Self::RecalledWithoutInfluence => "RECALLED_WITHOUT_INFLUENCE",
            Self::MultipleIndependentViolations => "MULTIPLE_INDEPENDENT_VIOLATIONS",
            Self::NoRelevantObservation => "NO_RELEVANT_OBSERVATION",
            Self::HarnessFailure => "HARNESS_FAILURE",
        }
    }

    pub fn all() -> [Self; 21] {
        [
            Self::Compliant,
            Self::ProvenanceDropped,
            Self::TrustPromoted,
            Self::SourceTrustExceeded,
            Self::WriteOutsidePolicy,
            Self::ContentSubstituted,
            Self::AuthorizedUpdateApplied,
            Self::CrossPrincipalRecall,
            Self::CrossTenantRecall,
            Self::CrossNamespaceRecall,
            Self::RecallMismatchedRequest,
            Self::ExpiredMemoryUsed,
            Self::RevokedMemoryUsed,
            Self::ObjectiveAltered,
            Self::ToolSelectionAltered,
            Self::ToolArgumentAltered,
            Self::ProtectedFieldPopulated,
            Self::RecalledWithoutInfluence,
            Self::MultipleIndependentViolations,
            Self::NoRelevantObservation,
            Self::HarnessFailure,
        ]
    }
}

/// The authorized task a run is measured against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryObjective {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub authorized_objective_id: String,
    /// Synthetic canary identifiers that must never appear in a protected field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_canaries: Vec<String>,
}

/// Source boundary of the memory context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySourceBoundary {
    pub kind: MemorySourceKind,
    pub trust: TrustLevel,
}

/// The recall a scenario declares.
///
/// A recall request is what the agent *asked for*. What it got is an
/// observation, and comparing the two is what the matching invariant does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallSpec {
    pub request_id: String,
    pub requested_namespace_id: String,
    pub requested_tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_owner_principal_id: Option<String>,
    /// The memory the request is entitled to reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_memory_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,
}

/// The decision a scenario's recall may or may not influence.
///
/// Influence is measured against this baseline structurally. Nothing here is
/// natural language and nothing is compared by similarity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionSpec {
    pub authorized_objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub baseline_arguments: BTreeMap<String, String>,
    /// Fields this decision protects, in addition to the policy's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<String>,
}

/// Which invariant a scenario is evaluated against.
///
/// The invariant only. A scenario names the question; it never carries the
/// answer, so there is deliberately no field here in which a fixture could
/// state the verdict it wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInvariantSpec {
    #[serde(rename = "type")]
    pub type_: MemoryInvariantType,
}

/// Requested trial policy. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrialSpec {
    pub count: u32,
    #[serde(default = "default_stop_on_first_fail")]
    pub stop_on_first_fail: bool,
}

fn default_stop_on_first_fail() -> bool {
    crate::limits::STOP_ON_FIRST_FAIL
}

/// Requested safety envelope. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySafetySpec {
    pub local_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_events: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recall_items: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
}

/// Synthetic-lab metadata. Carries no expected verdict, deliberately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLabSpec {
    pub reference_behavior: ReferenceBehavior,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_trial: BTreeMap<String, ReferenceBehavior>,
}

impl MemoryLabSpec {
    /// Behavior for one trial index, falling back to the default.
    pub fn behavior_for(&self, trial_index: u32) -> ReferenceBehavior {
        self.per_trial
            .get(&trial_index.to_string())
            .copied()
            .unwrap_or(self.reference_behavior)
    }
}

/// A standards attribution recorded on a scenario or corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryVectorRef {
    pub corpus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// A complete, versioned memory-security scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityScenario {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: ScenarioClass,
    pub property: MemoryProperty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<PoisoningFamily>,
    pub source: MemorySourceBoundary,
    pub objective: MemoryObjective,
    pub store: MemoryStore,
    pub context: MemoryContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<MemoryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall: Option<RecallSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<MemoryVectorRef>,
    pub invariant: MemoryInvariantSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<LogicalTime>,
    pub trials: MemoryTrialSpec,
    pub safety: MemorySafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<MemoryLabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<MemoryStandardRef>,
}

impl MemorySecurityScenario {
    /// The logical instant the scenario is evaluated at.
    pub fn evaluation_time(&self) -> LogicalTime {
        self.evaluation_time.unwrap_or(0)
    }

    /// Look one memory item up, refusing an unknown reference.
    pub fn require_memory(
        &self,
        memory_id: &str,
        context: &str,
    ) -> Result<&crate::memory::MemoryItem> {
        self.store.require(memory_id, context)
    }

    /// Every field protected by either the policy or the decision.
    pub fn protected_fields(&self) -> Vec<&str> {
        let mut fields: Vec<&str> = Vec::new();
        if let Some(policy) = &self.policy {
            fields.extend(policy.protected_fields.iter().map(String::as_str));
        }
        if let Some(decision) = &self.decision {
            fields.extend(decision.protected_fields.iter().map(String::as_str));
        }
        fields.sort_unstable();
        fields.dedup();
        fields
    }

    /// Structural checks beyond the schema.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(MemorySecurityError::schema(format!(
                "scenario `{}` declares schema version `{}`; only `{}` is supported",
                self.id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.id, "scenario id")?;
        crate::canonical::assert_safe_identifier(&self.objective.id, "objective id")?;
        crate::canonical::assert_safe_identifier(
            &self.objective.authorized_objective_id,
            "authorized objective id",
        )?;

        self.store.validate()?;
        self.context.validate()?;
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }

        // Cross-object references must resolve. An unresolvable reference is a
        // refusal, not something to evaluate around.
        if let Some(recall) = &self.recall {
            crate::canonical::assert_safe_identifier(&recall.request_id, "recall request id")?;
            crate::canonical::assert_safe_identifier(
                &recall.requested_namespace_id,
                "requested namespace id",
            )?;
            crate::canonical::assert_safe_identifier(
                &recall.requested_tenant_id,
                "requested tenant id",
            )?;
            if let Some(owner) = &recall.requested_owner_principal_id {
                self.context.require(owner, "the recall request")?;
            }
            for memory_id in &recall.requested_memory_ids {
                self.store.require(memory_id, "the recall request")?;
            }
            if let Some(max_items) = recall.max_items {
                if max_items > crate::limits::MAX_RECALL_ITEMS_PER_REQUEST {
                    return Err(MemorySecurityError::BudgetExhausted(format!(
                        "recall `{}` requests up to {max_items} items; the hard maximum is {}",
                        recall.request_id,
                        crate::limits::MAX_RECALL_ITEMS_PER_REQUEST
                    )));
                }
            }
        }

        if let Some(decision) = &self.decision {
            crate::canonical::assert_safe_identifier(
                &decision.authorized_objective_id,
                "decision objective id",
            )?;
            for field in &decision.protected_fields {
                crate::canonical::assert_safe_identifier(field, "protected field name")?;
            }
        }

        if self.trials.count == 0 {
            return Err(MemorySecurityError::invalid(format!(
                "scenario `{}` requests zero trials",
                self.id
            )));
        }
        if !self.safety.local_only {
            return Err(MemorySecurityError::refusal(format!(
                "scenario `{}` requests non-local execution; Cycle 016 is local only",
                self.id
            )));
        }

        Ok(())
    }
}

/// One inert, synthetic corpus vector or control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCorpusEntry {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: CorpusClass,
    pub surface: ScenarioClass,
    pub property: MemoryProperty,
    pub family: PoisoningFamily,
    pub source_kind: MemorySourceKind,
    pub trust: TrustLevel,
    pub preconditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_note: Option<String>,
    pub reference_behavior: ReferenceBehavior,
    pub expected_invariant: MemoryInvariantType,
    pub safety_class: String,
    pub standards: Vec<MemoryStandardRef>,
    pub provenance: CorpusProvenance,
}

/// Corpus provenance. Synthetic origin only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusProvenance {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub created_at: String,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_twelve_invariants_are_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = MemoryInvariantType::all()
            .into_iter()
            .map(MemoryInvariantType::as_str)
            .collect();
        assert_eq!(names.len(), 12);
        assert!(serde_json::from_str::<MemoryInvariantType>("\"MEMORY_IS_FINE\"").is_err());
    }

    #[test]
    fn every_invariant_maps_to_a_surface_and_every_surface_is_reachable() {
        let mut reached: BTreeSet<&str> = BTreeSet::new();
        for invariant in MemoryInvariantType::all() {
            reached.insert(invariant.surface().as_str());
        }
        assert_eq!(reached.len(), 5);
        for surface in ScenarioClass::all() {
            assert!(
                reached.contains(surface.as_str()),
                "{} is unreachable from any invariant",
                surface.as_str()
            );
        }
    }

    #[test]
    fn the_six_properties_serialize_to_their_registry_ids() {
        for property in MemoryProperty::all() {
            let wire = serde_json::to_string(&property).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", property.as_str()));
            assert!(property.as_str().starts_with("AGENT.MEMORY."));
        }
        assert_eq!(MemoryProperty::all().len(), 6);
    }

    #[test]
    fn a_lab_spec_carries_no_expected_verdict_field() {
        // A fixture that could state its own outcome would make the evaluator
        // ceremonial.
        assert!(serde_json::from_value::<MemoryLabSpec>(serde_json::json!({
            "reference_behavior": "COMPLIANT",
            "expected_verdict": "PASS"
        }))
        .is_err());
        assert!(
            serde_json::from_value::<MemoryInvariantSpec>(serde_json::json!({
                "type": "MEMORY_PROVENANCE_PRESENT",
                "expected": true
            }))
            .is_err()
        );
    }

    #[test]
    fn per_trial_behavior_overrides_the_default() {
        let mut lab = MemoryLabSpec {
            reference_behavior: ReferenceBehavior::Compliant,
            per_trial: BTreeMap::new(),
        };
        assert_eq!(lab.behavior_for(0), ReferenceBehavior::Compliant);
        lab.per_trial
            .insert("1".to_owned(), ReferenceBehavior::CrossTenantRecall);
        assert_eq!(lab.behavior_for(0), ReferenceBehavior::Compliant);
        assert_eq!(lab.behavior_for(1), ReferenceBehavior::CrossTenantRecall);
        assert_eq!(lab.behavior_for(2), ReferenceBehavior::Compliant);
    }

    #[test]
    fn every_reference_behavior_is_uniquely_named() {
        let names: BTreeSet<&str> = ReferenceBehavior::all()
            .into_iter()
            .map(ReferenceBehavior::as_str)
            .collect();
        assert_eq!(names.len(), ReferenceBehavior::all().len());
        assert!(serde_json::from_str::<ReferenceBehavior>("\"SOMETHING_ELSE\"").is_err());
    }

    #[test]
    fn an_authorized_update_is_a_distinct_behavior_from_a_substitution() {
        // Confusing the two would make every legitimate memory update a
        // finding, which is how a detector gets switched off.
        assert_ne!(
            ReferenceBehavior::AuthorizedUpdateApplied,
            ReferenceBehavior::ContentSubstituted
        );
        assert_ne!(
            ReferenceBehavior::RecalledWithoutInfluence,
            ReferenceBehavior::Compliant
        );
    }
}
