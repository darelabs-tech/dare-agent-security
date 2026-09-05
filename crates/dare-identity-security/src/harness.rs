//! Harness contract and the deterministic normalizer.
//!
//! Adapters are dumb transports: they surface what was observed and decide
//! nothing. Every security-relevant classification happens in the evaluator,
//! over the typed events [`normalize`] produces.
//!
//! Cycle 015 has three approved modes, all local and offline. There is no
//! identity provider, OAuth server, PDP, AuthZEN endpoint or MCP client, and
//! [`HarnessMode`] has no variant that could name one.
//!
//! Two properties are structural rather than documented:
//!
//! - a normalized operation always carries `dispatched: false`, because nothing
//!   in this crate can perform an operation;
//! - a missing channel stays missing. The normalizer never invents a principal,
//!   a decision or an operation to fill a gap, so the coverage contract can say
//!   `INCONCLUSIVE` rather than being handed a fabricated `PASS`.

use serde::{Deserialize, Serialize};

use crate::authority::Authority;
use crate::authorization::DecisionEffect;
use crate::error::{IdentitySecurityError, Result};
use crate::model::IdentitySecurityScenario;
use crate::observation::{
    validate_events, AuthorizationDecisionObserved, CredentialContextObserved, DelegationAssertion,
    DelegationEdgeObserved, EffectiveAuthorityObserved, EvidenceText, HarnessErrorEvent,
    HarnessErrorKind, IdentityObservationEvent, OperationObserved, PolicyDecisionObserved,
    PrincipalContext,
};
use crate::operation::Operation;
use crate::resource::ResourceContext;
use crate::source::{DelegationKind, PrincipalKind, PrincipalRole};

/// Approved execution modes. All are local and offline.
///
/// There is deliberately no `LiveIdp`, `RemotePdp`, `AuthzenEndpoint` or
/// `OauthServer` variant: remote identity and authorization execution is out of
/// scope for Cycle 015 and cannot be selected, not merely discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessMode {
    /// Evaluate a sanitized local trace. Contacts no provider.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// The same staging, gated by the Cycle 009 controls.
    LocalSynthetic,
}

impl HarnessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "REPLAY",
            Self::Simulated => "SIMULATED",
            Self::LocalSynthetic => "LOCAL_SYNTHETIC",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Replay, Self::Simulated, Self::LocalSynthetic]
    }

    /// True when observations were staged rather than recorded from a real
    /// agent. Reports must not present these as production evidence.
    pub fn is_synthetic(self) -> bool {
        matches!(self, Self::Simulated | Self::LocalSynthetic)
    }

    /// Parse an operator-supplied mode, failing closed on anything else.
    pub fn parse(token: &str) -> Result<Self> {
        Self::all()
            .into_iter()
            .find(|mode| mode.as_str() == token)
            .ok_or_else(|| {
                IdentitySecurityError::refusal(format!(
                    "unknown or unapproved harness mode `{token}`; Cycle 015 supports only \
                     REPLAY, SIMULATED and LOCAL_SYNTHETIC"
                ))
            })
    }
}

/// A principal as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPrincipalContext {
    pub role: PrincipalRole,
    pub principal_id: String,
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Effective authority as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEffectiveAuthority {
    pub principal_id: String,
    /// The declared authority this observation exercised, by reference.
    pub authority_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ceiling_id: Option<String>,
}

/// A delegation edge as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDelegationEdge {
    pub edge_id: String,
    pub kind: DelegationKind,
    pub delegator_principal_id: String,
    pub delegatee_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    pub authority_ceiling_id: String,
}

/// A delegation assertion as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDelegationAssertion {
    pub asserted_by_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_id: Option<String>,
    pub backed_by_declared_chain: bool,
}

/// A credential context as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCredentialContext {
    pub credential_context_id: String,
    pub owner_principal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tenant_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_authority_id: Option<String>,
}

/// An authorization decision as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAuthorizationDecision {
    pub decision_id: String,
    pub effect: DecisionEffect,
    pub subject_id: String,
    pub policy_digest: String,
    /// The operation this decision was made about, by reference into the
    /// trial's operations.
    pub bound_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
}

/// A policy decision as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyDecision {
    pub operation_key: String,
    pub effect: DecisionEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

/// An adapter-level failure. Produces `ERROR`, never `FAIL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessError {
    pub kind: HarnessErrorKind,
    pub detail: String,
}

/// What an adapter observed in one trial, before normalization.
///
/// Raw transport data. Nothing here is a security conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrialOutput {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<RawPrincipalContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_authorities: Vec<RawEffectiveAuthority>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_edges: Vec<RawDelegationEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_assertions: Vec<RawDelegationAssertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_contexts: Vec<RawCredentialContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_decisions: Vec<RawAuthorizationDecision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_requests: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub final_operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<RawPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// One trial's inputs.
#[derive(Debug, Clone, Copy)]
pub struct TrialRequest<'a> {
    pub trial_index: u32,
    pub scenario: &'a IdentitySecurityScenario,
}

/// A bounded, local source of identity observations.
pub trait HarnessAdapter {
    fn mode(&self) -> HarnessMode;

    /// Observe one trial.
    ///
    /// Implementations must not perform network I/O, spawn a process, contact
    /// an identity provider or authorization server, or perform any operation
    /// the agent requested.
    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput>;
}

/// Convert raw adapter output into normalized, typed observation events.
///
/// Authority and operation references are resolved against the scenario, which
/// is what keeps an adapter from inventing an authority nobody declared. An
/// unresolvable reference is refused rather than dropped: silently omitting it
/// would shorten the evidence the coverage contract then judges.
pub fn normalize(
    raw: &RawTrialOutput,
    scenario: &IdentitySecurityScenario,
) -> Result<Vec<IdentityObservationEvent>> {
    let mut events = Vec::new();

    if let Some(error) = &raw.harness_error {
        events.push(IdentityObservationEvent::HarnessError(HarnessErrorEvent {
            kind: error.kind,
            detail: EvidenceText::from_raw(&error.detail),
        }));
        // A failed trial supports no behavioral claim whatsoever.
        return Ok(events);
    }

    for principal in &raw.principals {
        events.push(IdentityObservationEvent::PrincipalContext(
            PrincipalContext {
                role: principal.role,
                principal_id: principal.principal_id.clone(),
                kind: principal.kind,
                tenant_id: principal.tenant_id.clone(),
            },
        ));
    }

    for observed in &raw.effective_authorities {
        let authority = scenario
            .require_authority(&observed.authority_id, "an effective-authority observation")?
            .clone();
        events.push(IdentityObservationEvent::EffectiveAuthority(
            EffectiveAuthorityObserved {
                principal_id: observed.principal_id.clone(),
                authority,
                source_ceiling_id: observed.source_ceiling_id.clone(),
            },
        ));
    }

    for edge in &raw.delegation_edges {
        events.push(IdentityObservationEvent::DelegationEdge(
            DelegationEdgeObserved {
                edge_id: edge.edge_id.clone(),
                kind: edge.kind,
                delegator_principal_id: edge.delegator_principal_id.clone(),
                delegatee_principal_id: edge.delegatee_principal_id.clone(),
                delegated_subject_id: edge.delegated_subject_id.clone(),
                authority_ceiling_id: edge.authority_ceiling_id.clone(),
            },
        ));
    }

    for assertion in &raw.delegation_assertions {
        events.push(IdentityObservationEvent::DelegationAssertion(
            DelegationAssertion {
                asserted_by_principal_id: assertion.asserted_by_principal_id.clone(),
                delegated_subject_id: assertion.delegated_subject_id.clone(),
                purpose_id: assertion.purpose_id.clone(),
                backed_by_declared_chain: assertion.backed_by_declared_chain,
            },
        ));
    }

    for resource in &raw.resources {
        events.push(IdentityObservationEvent::ResourceContext(resource.clone()));
    }

    for credential in &raw.credential_contexts {
        let capability_authority = match &credential.capability_authority_id {
            Some(id) => Some(
                scenario
                    .require_authority(id, "a credential-context observation")?
                    .clone(),
            ),
            None => None,
        };
        events.push(IdentityObservationEvent::CredentialContext(
            CredentialContextObserved {
                credential_context_id: credential.credential_context_id.clone(),
                owner_principal_id: credential.owner_principal_id.clone(),
                capability_labels: credential.capability_labels.clone(),
                tenant_labels: credential.tenant_labels.clone(),
                capability_authority,
            },
        ));
    }

    // A decision names the operation it decided about; the digest is computed
    // here from that operation, never taken on the adapter's word.
    let operations_by_id: std::collections::BTreeMap<&str, &Operation> = raw
        .operation_requests
        .iter()
        .chain(raw.final_operations.iter())
        .map(|operation| (operation.operation_id.as_str(), operation))
        .collect();

    for decision in &raw.authorization_decisions {
        let operation = operations_by_id
            .get(decision.bound_operation_id.as_str())
            .ok_or_else(|| {
                IdentitySecurityError::unknown_reference(format!(
                    "authorization decision `{}` binds operation `{}`, which the trial did not \
                     observe",
                    decision.decision_id, decision.bound_operation_id
                ))
            })?;
        events.push(IdentityObservationEvent::AuthorizationDecision(
            AuthorizationDecisionObserved {
                decision_id: decision.decision_id.clone(),
                effect: decision.effect,
                subject_id: decision.subject_id.clone(),
                policy_digest: decision.policy_digest.clone(),
                bound_operation_digest: operation.projection_digest()?,
                issued_at: decision.issued_at,
            },
        ));
    }

    for operation in &raw.operation_requests {
        events.push(IdentityObservationEvent::OperationRequest(
            observe_operation(operation)?,
        ));
    }
    for operation in &raw.final_operations {
        events.push(IdentityObservationEvent::FinalOperation(observe_operation(
            operation,
        )?));
    }

    for decision in &raw.policy_decisions {
        events.push(IdentityObservationEvent::PolicyDecision(
            PolicyDecisionObserved {
                operation_key: decision.operation_key.clone(),
                effect: decision.effect,
                policy_id: decision.policy_id.clone(),
            },
        ));
    }

    Ok(events)
}

fn observe_operation(operation: &Operation) -> Result<OperationObserved> {
    Ok(OperationObserved {
        operation: operation.clone(),
        projection_digest: operation.projection_digest()?,
        // Structurally false: Cycle 015 observes operations and never performs
        // one, so no adapter can claim otherwise.
        dispatched: false,
    })
}

/// Normalize and reject any event that is structurally unsafe.
pub fn normalize_checked(
    raw: &RawTrialOutput,
    scenario: &IdentitySecurityScenario,
) -> Result<Vec<IdentityObservationEvent>> {
    let events = normalize(raw, scenario)?;
    validate_events(&events)?;
    Ok(events)
}

/// Total retained bytes for a normalized trial.
pub fn retained_bytes(events: &[IdentityObservationEvent]) -> usize {
    events
        .iter()
        .map(IdentityObservationEvent::retained_bytes)
        .sum()
}

/// How many operations a normalized trial observed.
pub fn observed_operations(events: &[IdentityObservationEvent]) -> u32 {
    events
        .iter()
        .filter(|event| {
            matches!(
                event,
                IdentityObservationEvent::OperationRequest(_)
                    | IdentityObservationEvent::FinalOperation(_)
            )
        })
        .count() as u32
}

/// How many authorization decisions a normalized trial observed.
pub fn observed_decisions(events: &[IdentityObservationEvent]) -> u32 {
    events
        .iter()
        .filter(|event| matches!(event, IdentityObservationEvent::AuthorizationDecision(_)))
        .count() as u32
}

/// The authority a scenario declares for one principal, if any.
pub fn declared_ceiling<'a>(
    scenario: &'a IdentitySecurityScenario,
    principal_id: &str,
) -> Option<&'a Authority> {
    scenario
        .principals
        .get(principal_id)
        .and_then(|principal| principal.authority_ceiling_id.as_ref())
        .and_then(|id| {
            scenario
                .authorities
                .iter()
                .find(|authority| &authority.id == id)
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::observation::CoverageChannel;
    use crate::schema::validate_scenario_document;

    pub(crate) fn scenario() -> IdentitySecurityScenario {
        let raw = include_str!("../tests/fixtures/scenario.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        validate_scenario_document(&value).expect("fixture validates");
        serde_json::from_value(value).expect("fixture decodes")
    }

    fn operation(id: &str, action: &str, resource: &str) -> Operation {
        serde_json::from_value(serde_json::json!({
            "operation_id": id,
            "subject_id": "user-7",
            "action": action,
            "resource_id": resource,
            "resource_type": "document",
            "tenant_id": "tenant-a",
            "objective_id": "objective-summarize-ticket"
        }))
        .expect("operation decodes")
    }

    #[test]
    fn only_three_offline_modes_exist() {
        assert_eq!(HarnessMode::all().len(), 3);
        assert_eq!(
            HarnessMode::all().map(HarnessMode::as_str),
            ["REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"]
        );
        assert!(!HarnessMode::Replay.is_synthetic());
        assert!(HarnessMode::Simulated.is_synthetic());
        assert!(HarnessMode::LocalSynthetic.is_synthetic());
    }

    #[test]
    fn no_remote_identity_mode_can_be_selected() {
        for token in [
            "LIVE_IDP",
            "OAUTH",
            "OIDC",
            "REMOTE_PDP",
            "AUTHZEN",
            "PRODUCTION",
            "LIVE_MCP",
            "replay",
            "",
        ] {
            let err = HarnessMode::parse(token).expect_err("must be refused");
            assert!(err.is_refusal(), "{token}");
        }
        for mode in HarnessMode::all() {
            assert_eq!(HarnessMode::parse(mode.as_str()).expect("known"), mode);
        }
    }

    #[test]
    fn a_normalized_operation_is_never_dispatched() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            final_operations: vec![operation("op-1", "read", "document-123")],
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let IdentityObservationEvent::FinalOperation(observed) = &events[0] else {
            panic!("expected a final operation");
        };
        assert!(!observed.dispatched);
    }

    #[test]
    fn a_harness_error_suppresses_every_behavioral_claim() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::AdapterFailure,
                detail: "adapter stopped".to_owned(),
            }),
            principals: vec![RawPrincipalContext {
                role: PrincipalRole::Effective,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: None,
            }],
            final_operations: vec![operation("op-1", "read", "document-123")],
            ..RawTrialOutput::default()
        };
        let events = normalize(&raw, &scenario).expect("normalizes");
        assert_eq!(events.len(), 1);
        assert!(events[0].is_harness_error());
    }

    #[test]
    fn a_missing_channel_is_never_invented() {
        // Absence of evidence must stay absent; the coverage contract, not the
        // normalizer, decides what a missing channel means.
        let scenario = scenario();
        assert!(normalize(&RawTrialOutput::default(), &scenario)
            .expect("normalizes")
            .is_empty());

        let raw = RawTrialOutput {
            principals: vec![RawPrincipalContext {
                role: PrincipalRole::Initiating,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: None,
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize(&raw, &scenario).expect("normalizes");
        let channels: Vec<CoverageChannel> = events
            .iter()
            .filter_map(IdentityObservationEvent::coverage_channel)
            .collect();
        assert_eq!(channels, vec![CoverageChannel::PrincipalContext]);
        assert!(!channels.contains(&CoverageChannel::FinalOperation));
    }

    #[test]
    fn a_decision_digest_is_computed_never_taken_on_the_adapters_word() {
        // If an adapter could supply the digest, a trace could claim a permit
        // covered an operation it never covered.
        let scenario = scenario();
        let authorized = operation("op-1", "read", "document-123");
        let expected = authorized.projection_digest().expect("digest");

        let raw = RawTrialOutput {
            final_operations: vec![authorized],
            authorization_decisions: vec![RawAuthorizationDecision {
                decision_id: "decision-1".to_owned(),
                effect: DecisionEffect::Permit,
                subject_id: "user-7".to_owned(),
                policy_digest: format!("sha256:{}", "a".repeat(64)),
                bound_operation_id: "op-1".to_owned(),
                issued_at: Some(150),
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let decision = events
            .iter()
            .find_map(|event| match event {
                IdentityObservationEvent::AuthorizationDecision(decision) => Some(decision),
                _ => None,
            })
            .expect("decision present");
        assert_eq!(decision.bound_operation_digest, expected);
    }

    #[test]
    fn a_decision_binding_an_unobserved_operation_is_refused() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            authorization_decisions: vec![RawAuthorizationDecision {
                decision_id: "decision-1".to_owned(),
                effect: DecisionEffect::Permit,
                subject_id: "user-7".to_owned(),
                policy_digest: format!("sha256:{}", "a".repeat(64)),
                bound_operation_id: "op-nowhere".to_owned(),
                issued_at: None,
            }],
            ..RawTrialOutput::default()
        };
        let err = normalize(&raw, &scenario).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("op-nowhere"));
    }

    #[test]
    fn an_authority_reference_the_scenario_never_declared_is_refused() {
        // Dropping it silently would shorten the evidence the coverage contract
        // then judges, turning a gap into an apparent absence of a problem.
        let scenario = scenario();
        let raw = RawTrialOutput {
            effective_authorities: vec![RawEffectiveAuthority {
                principal_id: "user-7".to_owned(),
                authority_id: "authority-invented".to_owned(),
                source_ceiling_id: None,
            }],
            ..RawTrialOutput::default()
        };
        let err = normalize(&raw, &scenario).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("authority-invented"));
    }

    #[test]
    fn normalization_is_deterministic_and_order_preserving() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            principals: vec![RawPrincipalContext {
                role: PrincipalRole::Initiating,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: Some("tenant-a".to_owned()),
            }],
            resources: vec![crate::resource::tests::same_tenant_resource()],
            final_operations: vec![operation("op-1", "read", "document-123")],
            ..RawTrialOutput::default()
        };
        let first = normalize_checked(&raw, &scenario).expect("normalizes");
        let second = normalize_checked(&raw, &scenario).expect("normalizes");
        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(IdentityObservationEvent::kind)
                .collect::<Vec<_>>(),
            ["PRINCIPAL_CONTEXT", "RESOURCE_CONTEXT", "FINAL_OPERATION"]
        );
        assert_eq!(observed_operations(&first), 1);
        assert_eq!(observed_decisions(&first), 0);
        assert!(retained_bytes(&first) > 0);
    }

    #[test]
    fn raw_transport_types_reject_unknown_and_credential_fields() {
        assert!(
            serde_json::from_value::<RawPrincipalContext>(serde_json::json!({
                "role": "EFFECTIVE", "principal_id": "user-7", "kind": "HUMAN",
                "access_token": "eyJhbGciOi"
            }))
            .is_err()
        );

        assert!(serde_json::from_value::<RawTrialOutput>(serde_json::json!({
            "issuer": "https://example.invalid"
        }))
        .is_err());
    }

    #[test]
    fn the_declared_ceiling_helper_resolves_through_the_scenario() {
        let scenario = scenario();
        let ceiling = declared_ceiling(&scenario, "user-7").expect("user has a ceiling");
        assert_eq!(ceiling.id, "authority-user-read");
        assert!(declared_ceiling(&scenario, "nobody").is_none());
    }
}
