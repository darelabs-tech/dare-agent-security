//! Scenario, invariant and corpus types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::authority::{Authority, LogicalTime};
use crate::authorization::AuthorizationPolicy;
use crate::delegation::DelegationChain;
use crate::error::{IdentitySecurityError, Result};
use crate::principal::PrincipalSet;
use crate::resource::ResourceContext;
use crate::source::{CorpusClass, IdentitySourceKind, ScenarioClass, TrustLevel};

/// The twelve approved deterministic invariants.
///
/// Closed and total: an unknown invariant cannot be constructed, and every
/// evaluator and coverage contract is defined for all twelve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityInvariantType {
    /// The principal who started the request is the one it runs under.
    InitiatingPrincipalPreserved,
    /// The agent's own authority is not used in place of the user's.
    AgentAuthorityNotSubstitutedForUser,
    /// A delegation carries its subject forward unchanged.
    DelegatedSubjectPreserved,
    /// Exercised authority stays inside what the delegation granted.
    DelegationScopeNotExceeded,
    /// No edge in the chain widens authority.
    DelegationChainNoPrivilegeAmplification,
    /// Effective authority stays inside the source ceiling.
    EffectiveAuthorityWithinSourceCeiling,
    /// The operation stays inside the tenant the principal holds authority over.
    TenantBoundaryPreserved,
    /// The operation stays inside the resource-owner boundary.
    ResourceOwnerBoundaryPreserved,
    /// An authorization decision still covers the operation finally performed.
    AuthorizationBoundToFinalOperation,
    /// An operation a policy denied is not performed anyway.
    DenyNotBypassed,
    /// A runtime credential does not silently expand effective authority.
    CredentialContextNotExpandAuthority,
    /// A delegation is valid at the moment it is used.
    DelegationValidAtUse,
}

impl IdentityInvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitiatingPrincipalPreserved => "INITIATING_PRINCIPAL_PRESERVED",
            Self::AgentAuthorityNotSubstitutedForUser => "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER",
            Self::DelegatedSubjectPreserved => "DELEGATED_SUBJECT_PRESERVED",
            Self::DelegationScopeNotExceeded => "DELEGATION_SCOPE_NOT_EXCEEDED",
            Self::DelegationChainNoPrivilegeAmplification => {
                "DELEGATION_CHAIN_NO_PRIVILEGE_AMPLIFICATION"
            }
            Self::EffectiveAuthorityWithinSourceCeiling => {
                "EFFECTIVE_AUTHORITY_WITHIN_SOURCE_CEILING"
            }
            Self::TenantBoundaryPreserved => "TENANT_BOUNDARY_PRESERVED",
            Self::ResourceOwnerBoundaryPreserved => "RESOURCE_OWNER_BOUNDARY_PRESERVED",
            Self::AuthorizationBoundToFinalOperation => "AUTHORIZATION_BOUND_TO_FINAL_OPERATION",
            Self::DenyNotBypassed => "DENY_NOT_BYPASSED",
            Self::CredentialContextNotExpandAuthority => "CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY",
            Self::DelegationValidAtUse => "DELEGATION_VALID_AT_USE",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::InitiatingPrincipalPreserved,
            Self::AgentAuthorityNotSubstitutedForUser,
            Self::DelegatedSubjectPreserved,
            Self::DelegationScopeNotExceeded,
            Self::DelegationChainNoPrivilegeAmplification,
            Self::EffectiveAuthorityWithinSourceCeiling,
            Self::TenantBoundaryPreserved,
            Self::ResourceOwnerBoundaryPreserved,
            Self::AuthorizationBoundToFinalOperation,
            Self::DenyNotBypassed,
            Self::CredentialContextNotExpandAuthority,
            Self::DelegationValidAtUse,
        ]
    }

    /// Which reporting surface this invariant belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::InitiatingPrincipalPreserved | Self::AgentAuthorityNotSubstitutedForUser => {
                ScenarioClass::PrincipalBinding
            }
            Self::DelegatedSubjectPreserved
            | Self::DelegationScopeNotExceeded
            | Self::DelegationChainNoPrivilegeAmplification
            | Self::DelegationValidAtUse => ScenarioClass::Delegation,
            Self::EffectiveAuthorityWithinSourceCeiling
            | Self::CredentialContextNotExpandAuthority => ScenarioClass::Privilege,
            Self::TenantBoundaryPreserved | Self::ResourceOwnerBoundaryPreserved => {
                ScenarioClass::TenantResource
            }
            Self::AuthorizationBoundToFinalOperation | Self::DenyNotBypassed => {
                ScenarioClass::AuthorizationBinding
            }
        }
    }
}

/// The identity property a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityProperty {
    #[serde(rename = "AGENT.IDENTITY.DELEGATION_INTEGRITY")]
    DelegationIntegrity,
    #[serde(rename = "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION")]
    PrivilegeAmplification,
    #[serde(rename = "AGENT.IDENTITY.PRINCIPAL_BINDING")]
    PrincipalBinding,
    #[serde(rename = "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY")]
    DelegationScopeBoundary,
    #[serde(rename = "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY")]
    TenantResourceBoundary,
    #[serde(rename = "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING")]
    AuthorizationExecutionBinding,
}

impl IdentityProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DelegationIntegrity => "AGENT.IDENTITY.DELEGATION_INTEGRITY",
            Self::PrivilegeAmplification => "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION",
            Self::PrincipalBinding => "AGENT.IDENTITY.PRINCIPAL_BINDING",
            Self::DelegationScopeBoundary => "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY",
            Self::TenantResourceBoundary => "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY",
            Self::AuthorizationExecutionBinding => "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::DelegationIntegrity,
            Self::PrivilegeAmplification,
            Self::PrincipalBinding,
            Self::DelegationScopeBoundary,
            Self::TenantResourceBoundary,
            Self::AuthorizationExecutionBinding,
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
    InitiatingPrincipalSubstituted,
    AgentAuthoritySubstitutedForUser,
    DelegatedSubjectMismatched,
    DelegationScopeExceeded,
    DelegationChainAmplifiedPrivilege,
    EffectiveAuthorityAboveCeiling,
    TenantBoundaryCrossed,
    ResourceOwnerMismatched,
    OperationMutatedAfterPermit,
    StalePermitReused,
    DenyBypassed,
    CredentialContextExpandedAuthority,
    DelegationExpiredAtUse,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::InitiatingPrincipalSubstituted => "INITIATING_PRINCIPAL_SUBSTITUTED",
            Self::AgentAuthoritySubstitutedForUser => "AGENT_AUTHORITY_SUBSTITUTED_FOR_USER",
            Self::DelegatedSubjectMismatched => "DELEGATED_SUBJECT_MISMATCHED",
            Self::DelegationScopeExceeded => "DELEGATION_SCOPE_EXCEEDED",
            Self::DelegationChainAmplifiedPrivilege => "DELEGATION_CHAIN_AMPLIFIED_PRIVILEGE",
            Self::EffectiveAuthorityAboveCeiling => "EFFECTIVE_AUTHORITY_ABOVE_CEILING",
            Self::TenantBoundaryCrossed => "TENANT_BOUNDARY_CROSSED",
            Self::ResourceOwnerMismatched => "RESOURCE_OWNER_MISMATCHED",
            Self::OperationMutatedAfterPermit => "OPERATION_MUTATED_AFTER_PERMIT",
            Self::StalePermitReused => "STALE_PERMIT_REUSED",
            Self::DenyBypassed => "DENY_BYPASSED",
            Self::CredentialContextExpandedAuthority => "CREDENTIAL_CONTEXT_EXPANDED_AUTHORITY",
            Self::DelegationExpiredAtUse => "DELEGATION_EXPIRED_AT_USE",
            Self::MultipleIndependentViolations => "MULTIPLE_INDEPENDENT_VIOLATIONS",
            Self::NoRelevantObservation => "NO_RELEVANT_OBSERVATION",
            Self::HarnessFailure => "HARNESS_FAILURE",
        }
    }

    pub fn all() -> [Self; 17] {
        [
            Self::Compliant,
            Self::InitiatingPrincipalSubstituted,
            Self::AgentAuthoritySubstitutedForUser,
            Self::DelegatedSubjectMismatched,
            Self::DelegationScopeExceeded,
            Self::DelegationChainAmplifiedPrivilege,
            Self::EffectiveAuthorityAboveCeiling,
            Self::TenantBoundaryCrossed,
            Self::ResourceOwnerMismatched,
            Self::OperationMutatedAfterPermit,
            Self::StalePermitReused,
            Self::DenyBypassed,
            Self::CredentialContextExpandedAuthority,
            Self::DelegationExpiredAtUse,
            Self::MultipleIndependentViolations,
            Self::NoRelevantObservation,
            Self::HarnessFailure,
        ]
    }
}

/// The authorized task a run is measured against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityObjective {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub authorized_purpose_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_canaries: Vec<String>,
}

/// Source boundary of the identity context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySourceBoundary {
    pub kind: IdentitySourceKind,
    pub trust: TrustLevel,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityVectorRef {
    pub corpus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// Which invariant a scenario is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInvariantSpec {
    #[serde(rename = "type")]
    pub type_: IdentityInvariantType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<bool>,
}

/// Requested trial policy. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityTrialSpec {
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
pub struct IdentitySafetySpec {
    pub local_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operations_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_operations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_authorization_decisions_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
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
pub struct IdentityLabSpec {
    pub reference_behavior: ReferenceBehavior,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_trial: BTreeMap<String, ReferenceBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_filler_bytes: Option<usize>,
}

impl IdentityLabSpec {
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
pub struct IdentityStandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// Synthetic credential metadata declared by a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContextSpec {
    pub credential_context_id: String,
    pub owner_principal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tenant_labels: Vec<String>,
    /// The authority this credential would confer *if it had been delegated*.
    ///
    /// Recorded so amplification is measurable, never so it is granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_authority_id: Option<String>,
}

/// A complete, versioned identity-security scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityScenario {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: ScenarioClass,
    pub property: IdentityProperty,
    pub source: IdentitySourceBoundary,
    pub objective: IdentityObjective,
    pub principals: PrincipalSet,
    pub authorities: Vec<Authority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AuthorizationPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_contexts: Vec<CredentialContextSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<IdentityVectorRef>,
    pub invariant: IdentityInvariantSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<LogicalTime>,
    pub trials: IdentityTrialSpec,
    pub safety: IdentitySafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<IdentityLabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<IdentityStandardRef>,
}

impl IdentitySecurityScenario {
    /// Authorities indexed by id.
    pub fn authority_map(&self) -> BTreeMap<String, Authority> {
        self.authorities
            .iter()
            .map(|authority| (authority.id.clone(), authority.clone()))
            .collect()
    }

    /// Look one authority up, refusing an unknown reference.
    pub fn require_authority(&self, id: &str, context: &str) -> Result<&Authority> {
        self.authorities
            .iter()
            .find(|authority| authority.id == id)
            .ok_or_else(|| {
                IdentitySecurityError::unknown_reference(format!(
                    "{context} references authority `{id}`, which the scenario does not declare"
                ))
            })
    }

    /// The logical tick the scenario is evaluated at.
    pub fn evaluation_time(&self) -> LogicalTime {
        self.evaluation_time.unwrap_or(0)
    }

    /// Cross-object structural validation, before anything is evaluated.
    pub fn validate(&self) -> Result<()> {
        self.principals.validate()?;

        let mut seen = std::collections::BTreeSet::new();
        for authority in &self.authorities {
            if !seen.insert(authority.id.as_str()) {
                return Err(IdentitySecurityError::invalid(format!(
                    "duplicate authority id `{}`",
                    authority.id
                )));
            }
        }

        // Every authority a principal claims must exist.
        for principal in &self.principals.principals {
            if let Some(ceiling) = &principal.authority_ceiling_id {
                self.require_authority(ceiling, &format!("principal `{}`", principal.id))?;
            }
        }

        if let Some(chain) = &self.delegation {
            chain.validate_structure(&self.principals)?;
            for edge in &chain.edges {
                self.require_authority(
                    &edge.authority_ceiling_id,
                    &format!("delegation edge `{}`", edge.edge_id),
                )?;
            }
        }

        if let Some(resource) = &self.resource {
            resource.validate(&self.principals)?;
        }

        if let Some(policy) = &self.policy {
            policy.validate()?;
        }

        for credential in &self.credential_contexts {
            self.principals.require(
                &credential.owner_principal_id,
                &format!("credential context `{}`", credential.credential_context_id),
            )?;
            if let Some(authority) = &credential.capability_authority_id {
                self.require_authority(
                    authority,
                    &format!("credential context `{}`", credential.credential_context_id),
                )?;
            }
        }

        Ok(())
    }
}

/// One identity-security corpus vector or benign control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCorpusEntry {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: CorpusClass,
    pub surface: ScenarioClass,
    pub property: IdentityProperty,
    pub source_kind: IdentitySourceKind,
    pub trust: TrustLevel,
    pub preconditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_note: Option<String>,
    pub reference_behavior: ReferenceBehavior,
    pub expected_invariant: IdentityInvariantType,
    pub safety_class: String,
    pub standards: Vec<IdentityStandardRef>,
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
pub(crate) mod tests {
    use super::*;
    use dare_security_evidence::Verdict;
    use std::collections::BTreeSet;

    #[test]
    fn the_twelve_invariants_are_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = IdentityInvariantType::all()
            .into_iter()
            .map(IdentityInvariantType::as_str)
            .collect();
        assert_eq!(names.len(), 12);
        assert!(serde_json::from_str::<IdentityInvariantType>("\"ALWAYS_ALLOW\"").is_err());
        assert!(
            serde_json::from_str::<IdentityInvariantType>("\"deny_not_bypassed\"").is_err(),
            "case matters; a miscased token must not decode"
        );
    }

    #[test]
    fn every_invariant_belongs_to_exactly_one_reporting_surface() {
        // Reports separate the five surfaces, so each invariant must land on
        // exactly one of them.
        let mut by_surface: BTreeMap<ScenarioClass, Vec<&str>> = BTreeMap::new();
        for invariant in IdentityInvariantType::all() {
            by_surface
                .entry(invariant.surface())
                .or_default()
                .push(invariant.as_str());
        }
        assert_eq!(by_surface.len(), 5, "every surface must have invariants");
        let total: usize = by_surface.values().map(Vec::len).sum();
        assert_eq!(total, 12);
    }

    #[test]
    fn a_reference_behavior_is_a_behavior_and_never_a_verdict() {
        // If a behavior token decoded as a verdict, a fixture could name the
        // answer instead of describing what the agent did.
        for behavior in ReferenceBehavior::all() {
            let token = behavior.as_str();
            assert!(
                serde_json::from_str::<Verdict>(&format!("\"{token}\"")).is_err(),
                "{token} decodes as a Verdict"
            );
            // Whole-token comparison: HARNESS_FAILURE contains "FAIL" as a
            // substring, and a substring check here would be wrong.
            for verdict in ["PASS", "FAIL", "INCONCLUSIVE", "ERROR"] {
                assert_ne!(token, verdict);
            }
        }
    }

    #[test]
    fn the_six_properties_serialize_as_their_registry_ids() {
        for property in IdentityProperty::all() {
            assert_eq!(
                serde_json::to_value(property).expect("serializes"),
                serde_json::json!(property.as_str())
            );
            assert!(property.as_str().starts_with("AGENT.IDENTITY."));
        }
    }

    #[test]
    fn stop_on_first_fail_defaults_to_the_approved_value() {
        let trials: IdentityTrialSpec =
            serde_json::from_value(serde_json::json!({"count": 3})).expect("decodes");
        assert_eq!(trials.stop_on_first_fail, crate::limits::STOP_ON_FIRST_FAIL);
        assert!(trials.stop_on_first_fail);
    }

    #[test]
    fn a_lab_spec_can_vary_behavior_per_trial() {
        let lab: IdentityLabSpec = serde_json::from_value(serde_json::json!({
            "reference_behavior": "COMPLIANT",
            "per_trial": {"2": "TENANT_BOUNDARY_CROSSED"}
        }))
        .expect("decodes");
        assert_eq!(lab.behavior_for(0), ReferenceBehavior::Compliant);
        assert_eq!(lab.behavior_for(1), ReferenceBehavior::Compliant);
        assert_eq!(
            lab.behavior_for(2),
            ReferenceBehavior::TenantBoundaryCrossed
        );
    }

    #[test]
    fn a_lab_spec_carries_no_expected_verdict_field() {
        let hostile = serde_json::json!({
            "reference_behavior": "COMPLIANT",
            "expected_verdict": "PASS"
        });
        assert!(serde_json::from_value::<IdentityLabSpec>(hostile).is_err());
    }

    #[test]
    fn an_unknown_reference_behavior_fails_closed() {
        assert!(serde_json::from_str::<ReferenceBehavior>("\"PROBABLY_FINE\"").is_err());
    }
}
