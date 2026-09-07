//! The scenario, the invariants and the corpus entry.
//!
//! A scenario declares what was **approved**: which requests, which resource,
//! which authorization server, which token, which scopes. Everything an adapter
//! later observes is compared against this. The distinction is the one Cycle
//! 017 learned the hard way — an observation is evidence, never the authority
//! that says what was allowed.
//!
//! A scenario also has nowhere to state its own verdict. There is no
//! `expected_verdict` field, no `should_fail`, no `is_vulnerable`. A fixture
//! that could declare its own outcome would reduce the evaluator to agreeing
//! with whoever wrote the fixture.

use serde::{Deserialize, Serialize};

use crate::authorization::AuthorizationContext;
use crate::credential::CredentialContext;
use crate::error::{McpAuthSecurityError, Result};
use crate::identity::IdentityContext;
use crate::metadata::ResourceContext;
use crate::pkce::PkceContext;
use crate::protocol::{RequestEnvelope, SyntheticUri};
use crate::redirect::RedirectContext;
use crate::registration::RegistrationContext;
use crate::scope::ScopeContext;
use crate::source::{CorpusClass, ScenarioClass};
use crate::token::TokenContext;

/// The fifteen deterministic invariants.
///
/// It was fourteen until the post-merge review. The self-reported metadata
/// boundary was being *evaluated* — correctly — but reported under
/// `INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY`, an invariant about
/// forwarding a caller's credential upstream. Promoting `clientInfo` to a
/// principal is not that. It is not adjacent to it.
///
/// Keeping the count at fourteen would have meant keeping a finding filed under
/// a name that does not describe it, in a registry whose whole purpose is that
/// a verdict names what it is about. The count moved instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum McpAuthInvariantType {
    McpProtocolRevisionPreserved,
    McpMethodHeaderBodyBindingPreserved,
    McpNameHeaderBodyBindingPreserved,
    ProtectedResourceMetadataBoundToResource,
    AuthorizationServerIssuerBoundaryPreserved,
    AuthorizationResponseIssuerPreserved,
    TokenResourceAudienceBoundaryPreserved,
    TokenValidityEvidencePresent,
    PkceBindingPreserved,
    RedirectStateBindingPreserved,
    ScopeStepUpDoesNotDropRequiredScope,
    ClientRegistrationMetadataTrustPreserved,
    InboundCredentialNotReusedAsUpstreamAuthority,
    /// Self-reported protocol metadata must stay metadata.
    ///
    /// `clientInfo` and `serverInfo` are what a peer calls itself. A principal
    /// established from one is not authenticated, whatever the name says.
    SelfReportedMetadataNotAuthority,
    FinalOperationAuthorizationBindingPreserved,
}

impl McpAuthInvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::McpProtocolRevisionPreserved => "MCP_PROTOCOL_REVISION_PRESERVED",
            Self::McpMethodHeaderBodyBindingPreserved => "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED",
            Self::McpNameHeaderBodyBindingPreserved => "MCP_NAME_HEADER_BODY_BINDING_PRESERVED",
            Self::ProtectedResourceMetadataBoundToResource => {
                "PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE"
            }
            Self::AuthorizationServerIssuerBoundaryPreserved => {
                "AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED"
            }
            Self::AuthorizationResponseIssuerPreserved => "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED",
            Self::TokenResourceAudienceBoundaryPreserved => {
                "TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED"
            }
            Self::TokenValidityEvidencePresent => "TOKEN_VALIDITY_EVIDENCE_PRESENT",
            Self::PkceBindingPreserved => "PKCE_BINDING_PRESERVED",
            Self::RedirectStateBindingPreserved => "REDIRECT_STATE_BINDING_PRESERVED",
            Self::ScopeStepUpDoesNotDropRequiredScope => {
                "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE"
            }
            Self::ClientRegistrationMetadataTrustPreserved => {
                "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED"
            }
            Self::InboundCredentialNotReusedAsUpstreamAuthority => {
                "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY"
            }
            Self::SelfReportedMetadataNotAuthority => "SELF_REPORTED_METADATA_NOT_AUTHORITY",
            Self::FinalOperationAuthorizationBindingPreserved => {
                "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED"
            }
        }
    }

    pub fn all() -> [Self; 15] {
        [
            Self::McpProtocolRevisionPreserved,
            Self::McpMethodHeaderBodyBindingPreserved,
            Self::McpNameHeaderBodyBindingPreserved,
            Self::ProtectedResourceMetadataBoundToResource,
            Self::AuthorizationServerIssuerBoundaryPreserved,
            Self::AuthorizationResponseIssuerPreserved,
            Self::TokenResourceAudienceBoundaryPreserved,
            Self::TokenValidityEvidencePresent,
            Self::PkceBindingPreserved,
            Self::RedirectStateBindingPreserved,
            Self::ScopeStepUpDoesNotDropRequiredScope,
            Self::ClientRegistrationMetadataTrustPreserved,
            Self::InboundCredentialNotReusedAsUpstreamAuthority,
            Self::SelfReportedMetadataNotAuthority,
            Self::FinalOperationAuthorizationBindingPreserved,
        ]
    }

    /// Which reporting surface this invariant belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::McpProtocolRevisionPreserved
            | Self::McpMethodHeaderBodyBindingPreserved
            | Self::McpNameHeaderBodyBindingPreserved => ScenarioClass::ProtocolBinding,
            Self::ProtectedResourceMetadataBoundToResource
            | Self::AuthorizationServerIssuerBoundaryPreserved
            | Self::AuthorizationResponseIssuerPreserved => ScenarioClass::ResourceAuthorization,
            Self::TokenResourceAudienceBoundaryPreserved | Self::TokenValidityEvidencePresent => {
                ScenarioClass::TokenBinding
            }
            Self::PkceBindingPreserved | Self::RedirectStateBindingPreserved => {
                ScenarioClass::FlowIntegrity
            }
            Self::ScopeStepUpDoesNotDropRequiredScope
            | Self::ClientRegistrationMetadataTrustPreserved => ScenarioClass::ScopeAndRegistration,
            Self::InboundCredentialNotReusedAsUpstreamAuthority
            | Self::SelfReportedMetadataNotAuthority
            | Self::FinalOperationAuthorizationBindingPreserved => {
                ScenarioClass::CredentialAndIdentity
            }
        }
    }

    /// The registry property this invariant reports under.
    pub fn property(self) -> McpAuthProperty {
        match self {
            Self::McpProtocolRevisionPreserved
            | Self::McpMethodHeaderBodyBindingPreserved
            | Self::McpNameHeaderBodyBindingPreserved => McpAuthProperty::ProtocolBinding,
            Self::ProtectedResourceMetadataBoundToResource => {
                McpAuthProperty::ProtectedResourceMetadata
            }
            Self::AuthorizationServerIssuerBoundaryPreserved
            | Self::AuthorizationResponseIssuerPreserved => {
                McpAuthProperty::AuthorizationServerBinding
            }
            Self::TokenResourceAudienceBoundaryPreserved | Self::TokenValidityEvidencePresent => {
                McpAuthProperty::TokenAudienceResourceBinding
            }
            Self::PkceBindingPreserved | Self::RedirectStateBindingPreserved => {
                McpAuthProperty::PkceRedirectStateIntegrity
            }
            Self::ScopeStepUpDoesNotDropRequiredScope => McpAuthProperty::ScopeStepUpIntegrity,
            Self::ClientRegistrationMetadataTrustPreserved => {
                McpAuthProperty::ClientRegistrationTrust
            }
            Self::InboundCredentialNotReusedAsUpstreamAuthority => {
                McpAuthProperty::CredentialSeparation
            }
            Self::SelfReportedMetadataNotAuthority => McpAuthProperty::SelfReportedMetadataBoundary,
            Self::FinalOperationAuthorizationBindingPreserved => {
                McpAuthProperty::FinalOperationBinding
            }
        }
    }
}

/// The ten registry properties, as wire identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum McpAuthProperty {
    #[serde(rename = "MCP.AUTH.PROTOCOL_BINDING")]
    ProtocolBinding,
    #[serde(rename = "MCP.AUTH.PROTECTED_RESOURCE_METADATA")]
    ProtectedResourceMetadata,
    #[serde(rename = "MCP.AUTH.AUTHORIZATION_SERVER_BINDING")]
    AuthorizationServerBinding,
    #[serde(rename = "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING")]
    TokenAudienceResourceBinding,
    #[serde(rename = "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY")]
    PkceRedirectStateIntegrity,
    #[serde(rename = "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY")]
    ScopeStepUpIntegrity,
    #[serde(rename = "MCP.AUTH.CLIENT_REGISTRATION_TRUST")]
    ClientRegistrationTrust,
    #[serde(rename = "MCP.AUTH.CREDENTIAL_SEPARATION")]
    CredentialSeparation,
    #[serde(rename = "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY")]
    SelfReportedMetadataBoundary,
    #[serde(rename = "MCP.AUTH.FINAL_OPERATION_BINDING")]
    FinalOperationBinding,
}

impl McpAuthProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolBinding => "MCP.AUTH.PROTOCOL_BINDING",
            Self::ProtectedResourceMetadata => "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
            Self::AuthorizationServerBinding => "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
            Self::TokenAudienceResourceBinding => "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
            Self::PkceRedirectStateIntegrity => "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
            Self::ScopeStepUpIntegrity => "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
            Self::ClientRegistrationTrust => "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
            Self::CredentialSeparation => "MCP.AUTH.CREDENTIAL_SEPARATION",
            Self::SelfReportedMetadataBoundary => "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY",
            Self::FinalOperationBinding => "MCP.AUTH.FINAL_OPERATION_BINDING",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::ProtocolBinding,
            Self::ProtectedResourceMetadata,
            Self::AuthorizationServerBinding,
            Self::TokenAudienceResourceBinding,
            Self::PkceRedirectStateIntegrity,
            Self::ScopeStepUpIntegrity,
            Self::ClientRegistrationTrust,
            Self::CredentialSeparation,
            Self::SelfReportedMetadataBoundary,
            Self::FinalOperationBinding,
        ]
    }
}

/// How a reference implementation behaves for a fixture.
///
/// A behaviour, never a verdict. The evaluator decides what a behaviour means;
/// nothing here tells it the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    Compliant,
    UnsupportedProtocolRevision,
    MethodHeaderBodyMismatch,
    NameHeaderBodyMismatch,
    ResourceMetadataMismatch,
    AuthorizationServerNotAdvertised,
    AuthorizationResponseIssuerMixUp,
    TokenAudienceMismatch,
    TokenValidityEvidenceMissing,
    PkceDowngraded,
    RedirectOrStateSubstituted,
    ScopeStepUpDroppedScope,
    UntrustedRegistrationRelied,
    InboundCredentialForwarded,
    SelfReportedMetadataPromoted,
    FinalOperationMutatedAfterPermit,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    /// Whether this behaviour is legitimate activity rather than a crossing.
    ///
    /// Controls matter as much as attacks. A surface with only attack fixtures
    /// lets an over-strict engine look perfect while failing every legitimate
    /// flow on that surface.
    pub fn is_legitimate(self) -> bool {
        matches!(self, Self::Compliant)
    }
}

/// What was authorized, and what was finally performed.
///
/// The comparison itself belongs to Cycle 003. This records the two ends of it
/// so the composition has something to compare.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalOperationContext {
    /// The operation the authorization was granted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_operation: Option<crate::protocol::JsonRpcOperation>,
    /// The operation actually performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed_operation: Option<crate::protocol::JsonRpcOperation>,
    /// The resource the authorization covered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_resource: Option<SyntheticUri>,
    /// The resource the performed operation touched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed_resource: Option<SyntheticUri>,

    /// The mapped arguments the authorization decision covered.
    ///
    /// Recorded as a structured value rather than a string so Cycle 003's
    /// canonicalizer decides what "the same arguments" means. A permit for
    /// `amount=100` does not stretch to cover `amount=10000`, and nothing about
    /// the method, the name or the resource would show that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_arguments: Option<serde_json::Value>,
    /// The mapped arguments the performed operation actually carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed_arguments: Option<serde_json::Value>,

    /// The principal the authorization was granted to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_principal: Option<String>,
    /// The principal the operation ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed_principal: Option<String>,

    /// The tenant the authorization was scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_tenant: Option<String>,
    /// The tenant the operation ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed_tenant: Option<String>,

    /// The scopes the authorization decision was made with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_scopes: Vec<String>,
    /// The scopes in force when the operation ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub performed_scopes: Vec<String>,

    /// Whether the deployment re-evaluated authorization after the change.
    ///
    /// A mutation followed by re-evaluation is correct behaviour. A mutation
    /// that silently reuses the earlier permit is the finding.
    #[serde(default)]
    pub reevaluated_after_change: bool,
    /// Whether the deployment refused the mutated operation outright.
    #[serde(default)]
    pub refused_after_change: bool,
}

impl FinalOperationContext {
    pub fn validate(&self) -> Result<()> {
        for operation in [&self.authorized_operation, &self.performed_operation]
            .into_iter()
            .flatten()
        {
            operation.validate()?;
        }
        for principal in [&self.authorized_principal, &self.performed_principal]
            .into_iter()
            .flatten()
        {
            crate::canonical::assert_safe_identifier(principal, "final-operation principal")?;
        }
        for tenant in [&self.authorized_tenant, &self.performed_tenant]
            .into_iter()
            .flatten()
        {
            crate::canonical::assert_safe_identifier(tenant, "final-operation tenant")?;
        }
        for scope in self.authorized_scopes.iter().chain(&self.performed_scopes) {
            crate::canonical::assert_safe_identifier(scope, "final-operation scope")?;
        }
        if self.authorized_scopes.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT
            || self.performed_scopes.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT
        {
            return Err(McpAuthSecurityError::BudgetExhausted(
                "final-operation context carries too many scopes".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The PKCE and redirect evidence, grouped as one flow.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce: Option<PkceContext>,
    #[serde(default)]
    pub redirect: RedirectContext,
}

impl FlowContext {
    pub fn validate(&self) -> Result<()> {
        if let Some(pkce) = &self.pkce {
            pkce.validate()?;
        }
        self.redirect.validate()
    }
}

/// The invariant a scenario is judged against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthInvariantSpec {
    #[serde(rename = "type")]
    pub type_: McpAuthInvariantType,
}

/// The lab behaviour a scenario stages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthLabSpec {
    pub reference_behavior: ReferenceBehavior,
}

/// Trials a scenario asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthTrialSpec {
    pub count: u32,
    #[serde(default)]
    pub stop_on_first_fail: bool,
}

/// Safety declarations a scenario carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthSafetySpec {
    /// Always true. A scenario that declared otherwise is refused.
    pub local_only: bool,
    #[serde(default)]
    pub max_requests_per_trial: Option<u32>,
}

/// A standards attribution a scenario records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthStandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// What the scenario is trying to protect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthObjective {
    pub id: String,
    pub description: String,
    /// Canary values that must never reach a persisted artifact.
    #[serde(default)]
    pub protected_canaries: Vec<String>,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthVectorRef {
    pub corpus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// A complete, versioned MCP auth-security scenario.
///
/// There is deliberately no field in which this could state its own verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthScenario {
    pub schema_version: String,
    pub id: String,
    pub title: String,
    pub class: ScenarioClass,
    pub property: McpAuthProperty,
    pub objective: McpAuthObjective,

    /// The requests the scenario approved.
    pub requests: Vec<RequestEnvelope>,
    pub protected_resource: ResourceContext,
    #[serde(default)]
    pub authorization_flow: AuthorizationContext,
    #[serde(default)]
    pub tokens: TokenContext,
    #[serde(default)]
    pub flow: FlowContext,
    #[serde(default)]
    pub scope: ScopeContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationContext>,
    #[serde(default)]
    pub credential_flow: CredentialContext,
    #[serde(default)]
    pub identity_metadata: IdentityContext,
    #[serde(default)]
    pub final_operation: FinalOperationContext,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<McpAuthVectorRef>,
    pub invariant: McpAuthInvariantSpec,
    pub trials: McpAuthTrialSpec,
    pub safety: McpAuthSafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<McpAuthLabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<McpAuthStandardRef>,
}

impl McpAuthScenario {
    /// Structural checks a schema cannot express.
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.id, "scenario id")?;
        crate::canonical::assert_safe_identifier(&self.objective.id, "objective id")?;

        if !self.safety.local_only {
            return Err(McpAuthSecurityError::refusal(
                "scenario declares itself non-local; Cycle 018 has no non-local execution path",
            ));
        }
        if self.requests.is_empty() {
            return Err(McpAuthSecurityError::invalid(format!(
                "scenario `{}` declares no request",
                self.id
            )));
        }
        if self.requests.len() as u32 > crate::limits::HARD_MAX_REQUESTS_PER_TRIAL {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scenario `{}` declares {} requests; the hard maximum is {}",
                self.id,
                self.requests.len(),
                crate::limits::HARD_MAX_REQUESTS_PER_TRIAL
            )));
        }
        if self.trials.count == 0 || self.trials.count > crate::limits::HARD_MAX_TRIALS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scenario `{}` asks for {} trials; the approved range is 1..={}",
                self.id,
                self.trials.count,
                crate::limits::HARD_MAX_TRIALS
            )));
        }

        let mut seen = std::collections::BTreeSet::new();
        for request in &self.requests {
            request.validate()?;
            if !seen.insert(request.request_id.as_str()) {
                return Err(McpAuthSecurityError::invalid(format!(
                    "scenario `{}` declares a duplicate request id",
                    self.id
                )));
            }
        }

        self.protected_resource.validate()?;
        self.authorization_flow.validate()?;
        self.tokens.validate()?;
        self.flow.validate()?;
        self.scope.validate()?;
        if let Some(registration) = &self.registration {
            registration.validate()?;
        }
        self.credential_flow.validate()?;
        self.identity_metadata.validate()?;
        self.final_operation.validate()?;

        // No exemption here any more. The scenario declaring
        // `MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY` used to be waved past
        // this check, because the invariant it named reported under a different
        // property and the two could not agree. Now they can, so the check is
        // total again.
        if self.invariant.type_.property() != self.property {
            return Err(McpAuthSecurityError::invalid(format!(
                "scenario `{}` declares property `{}` but an invariant that reports under `{}`",
                self.id,
                self.property.as_str(),
                self.invariant.type_.property().as_str()
            )));
        }
        if self.invariant.type_.surface() != self.class {
            return Err(McpAuthSecurityError::invalid(format!(
                "scenario `{}` declares surface `{}` but an invariant on `{}`",
                self.id,
                self.class.as_str(),
                self.invariant.type_.surface().as_str()
            )));
        }
        Ok(())
    }

    /// The approved request with this id, if the scenario declares one.
    pub fn request(&self, request_id: &str) -> Option<&RequestEnvelope> {
        self.requests
            .iter()
            .find(|request| request.request_id == request_id)
    }
}

/// A corpus entry describing one vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthCorpusEntry {
    pub schema_version: String,
    pub id: String,
    pub title: String,
    pub class: CorpusClass,
    pub surface: ScenarioClass,
    pub property: McpAuthProperty,
    pub expected_invariant: McpAuthInvariantType,
    pub reference_behavior: ReferenceBehavior,
    pub preconditions: Vec<String>,
    pub surface_note: String,
    pub safety_class: String,
    pub standards: Vec<McpAuthStandardRef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_fifteen_invariants_are_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = McpAuthInvariantType::all()
            .iter()
            .map(|invariant| invariant.as_str())
            .collect();
        assert_eq!(names.len(), 15);
    }

    #[test]
    fn the_approved_invariant_names_are_exactly_these() {
        let names: Vec<&str> = McpAuthInvariantType::all()
            .iter()
            .map(|invariant| invariant.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "MCP_PROTOCOL_REVISION_PRESERVED",
                "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED",
                "MCP_NAME_HEADER_BODY_BINDING_PRESERVED",
                "PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE",
                "AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED",
                "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED",
                "TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED",
                "TOKEN_VALIDITY_EVIDENCE_PRESENT",
                "PKCE_BINDING_PRESERVED",
                "REDIRECT_STATE_BINDING_PRESERVED",
                "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE",
                "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED",
                "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY",
                "SELF_REPORTED_METADATA_NOT_AUTHORITY",
                "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED",
            ]
        );
    }

    #[test]
    fn the_property_wire_names_match_the_registry_exactly() {
        // A property whose wire name drifted from the registry would file
        // findings under an id no report knows about.
        let registry = dare_coverage::builtin_registry().expect("v1 registry");
        for property in McpAuthProperty::all() {
            assert!(
                registry.get(property.as_str()).is_some(),
                "{} is not in the v1 registry",
                property.as_str()
            );
        }
    }

    #[test]
    fn every_surface_and_property_is_reachable_from_some_invariant() {
        // A surface nothing maps to would render "not tested" forever while
        // looking like a covered dimension.
        let surfaces: BTreeSet<ScenarioClass> = McpAuthInvariantType::all()
            .iter()
            .map(|invariant| invariant.surface())
            .collect();
        assert_eq!(surfaces.len(), 6);

        let properties: BTreeSet<McpAuthProperty> = McpAuthInvariantType::all()
            .iter()
            .map(|invariant| invariant.property())
            .collect();
        // All ten are now reachable from an invariant.
        //
        // This assertion used to read "nine of the ten", with the tenth —
        // MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY — excluded on the
        // grounds that it was "a property of the identity evidence rather than
        // of a request". That was a description of the defect: the property was
        // in the registry, was marked REQUIRED in the profile, and no invariant
        // filed anything under it, so its findings arrived labelled
        // INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY instead.
        //
        // A property no invariant can report under is a property that will read
        // as covered and never be answered.
        assert_eq!(properties.len(), 10);
        assert!(properties.contains(&McpAuthProperty::SelfReportedMetadataBoundary));
        assert_eq!(
            McpAuthInvariantType::SelfReportedMetadataNotAuthority.property(),
            McpAuthProperty::SelfReportedMetadataBoundary
        );
    }

    #[test]
    fn the_self_reported_boundary_no_longer_borrows_the_credential_invariants_name() {
        // The taxonomy fix, stated as the thing it prevents. Promoting
        // `clientInfo` to a principal is not "reusing an inbound credential as
        // upstream authority"; the two are different findings with different
        // fixes, and filing one under the other sends an operator to the wrong
        // place.
        assert_ne!(
            McpAuthInvariantType::SelfReportedMetadataNotAuthority,
            McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority
        );
        assert_ne!(
            McpAuthInvariantType::SelfReportedMetadataNotAuthority.property(),
            McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority.property()
        );
        assert_eq!(
            McpAuthInvariantType::SelfReportedMetadataNotAuthority.as_str(),
            "SELF_REPORTED_METADATA_NOT_AUTHORITY"
        );
    }

    #[test]
    fn a_scenario_type_has_no_field_for_an_expected_verdict() {
        // A fixture that could state its own outcome would reduce the evaluator
        // to agreeing with whoever wrote the fixture.
        let rendered = serde_json::to_string(&McpAuthInvariantSpec {
            type_: McpAuthInvariantType::PkceBindingPreserved,
        })
        .expect("serializes");
        assert_eq!(rendered, "{\"type\":\"PKCE_BINDING_PRESERVED\"}");
        for banned in ["verdict", "expected", "should_", "is_vulnerable"] {
            assert!(!rendered.contains(banned));
        }
    }

    #[test]
    fn the_reference_behaviour_set_is_closed() {
        assert!(serde_json::from_str::<ReferenceBehavior>("\"SOMETHING_ELSE\"").is_err());
        assert!(ReferenceBehavior::Compliant.is_legitimate());
        assert!(!ReferenceBehavior::TokenAudienceMismatch.is_legitimate());
    }

    #[test]
    fn an_unknown_invariant_fails_closed() {
        assert!(serde_json::from_str::<McpAuthInvariantType>("\"SOMETHING_NEW\"").is_err());
    }
}
