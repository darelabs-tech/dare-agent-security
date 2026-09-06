//! The adapter contract and normalization.
//!
//! An adapter produces raw trial output. Normalization turns that into the
//! closed observation model — and, crucially, does so **against the approved
//! scenario**.
//!
//! This is where the Cycle 017 lesson lives. A recorded observation is
//! evidence about what happened; it is not the authority that says what was
//! allowed. Every authorization-relevant field an adapter reports is checked
//! against the scenario before an evaluator sees it, so a trace cannot restate
//! the resource, the issuer, the audience, the scopes or the operation with
//! wider semantics and have the widened version judged as approved.
//!
//! Prose is deliberately exempt. A differing title or description does not
//! widen authority, and refusing one would be refusing documentation.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::model::McpAuthScenario;
use crate::observation::{EvidenceText, McpAuthObservation};
use crate::protocol::{ProtocolContext, RequestEnvelope};
use crate::source::{HarnessErrorKind, ProtocolRevisionClass};

/// The three approved modes. There is no fourth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessMode {
    Replay,
    Simulated,
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

    /// Whether observations were staged rather than recorded.
    pub fn is_synthetic(self) -> bool {
        matches!(self, Self::Simulated | Self::LocalSynthetic)
    }
}

/// A harness error an adapter reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessError {
    pub kind: HarnessErrorKind,
    pub detail: String,
}

/// What an adapter produced for one trial.
///
/// Deliberately thin. Everything an adapter can say is either a request it
/// observed or a failure it hit; the rest of the evidence comes from the
/// approved scenario, because the adapter has no authority to restate it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrialOutput {
    #[serde(default)]
    pub observed_requests: Vec<RequestEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// What an adapter is asked to observe.
#[derive(Debug, Clone, Copy)]
pub struct TrialRequest<'a> {
    pub trial_index: u32,
    pub scenario: &'a McpAuthScenario,
}

/// The adapter contract.
///
/// Note what is absent: there is no method returning a verdict, a violation or
/// a finding. An adapter reports observations and nothing else.
pub trait HarnessAdapter {
    fn mode(&self) -> HarnessMode;

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput>;

    /// How many trials a bounded source can supply.
    fn trial_capacity(&self) -> u32 {
        crate::limits::HARD_MAX_TRIALS
    }

    /// Whether the observations describe a reference implementation rather than
    /// a production one.
    ///
    /// A replayed observation is still synthetic: the trace declares itself so,
    /// and a report must not present it as production evidence.
    fn observations_are_synthetic(&self) -> bool {
        true
    }
}

/// Normalize raw output into observations, without checking scenario binding.
///
/// Used where the caller has already bound the output. Prefer
/// [`normalize_checked`].
pub fn normalize(raw: &RawTrialOutput, scenario: &McpAuthScenario) -> Vec<McpAuthObservation> {
    if let Some(error) = &raw.harness_error {
        // A harness failure suppresses everything else. Mixing a failure with
        // partial observations would let a run that could not complete
        // contribute coverage toward a PASS.
        return vec![McpAuthObservation::HarnessError {
            kind: error.kind,
            detail: EvidenceText::from_raw(&error.detail),
        }];
    }

    let mut observations = Vec::new();

    for request in &raw.observed_requests {
        observations.push(McpAuthObservation::ProtocolContext {
            request_id: request.request_id.clone(),
            declared_revision: request.protocol.declared_revision.clone(),
            revision_class: request.protocol.revision_class(),
            http_transport: request.protocol.http_transport,
        });
        if request.headers.method.is_some() || request.headers.name.is_some() {
            observations.push(McpAuthObservation::HeaderContext {
                request_id: request.request_id.clone(),
                routed_method: request.headers.method.clone(),
                routed_name: request.headers.name.clone(),
            });
        }
        observations.push(McpAuthObservation::OperationContext {
            request_id: request.request_id.clone(),
            method: request.operation.method.clone(),
            name: request.operation.name.clone(),
        });
    }

    // Everything below comes from the approved scenario rather than from the
    // adapter. This is the structural half of the Cycle 017 lesson: an adapter
    // that cannot restate the resource, issuer, token or scope cannot widen
    // them, whatever it reports.
    if scenario.protected_resource.metadata.is_some() {
        observations.push(McpAuthObservation::ProtectedResourceMetadata {
            resource: scenario.protected_resource.clone(),
        });
    }
    if !scenario.protected_resource.authorization_servers.is_empty() {
        observations.push(McpAuthObservation::AuthorizationServerMetadata {
            resource: scenario.protected_resource.clone(),
        });
    }
    if let Some(request) = &scenario.authorization.request {
        observations.push(McpAuthObservation::AuthorizationRequest {
            request: request.clone(),
        });
    }
    if let Some(response) = &scenario.authorization.response {
        observations.push(McpAuthObservation::AuthorizationResponse {
            response: response.clone(),
        });
    }
    if scenario.tokens.presented.is_some() {
        observations.push(McpAuthObservation::TokenClaims {
            token: scenario.tokens.clone(),
        });
        if scenario.tokens.target_resource.is_some() {
            observations.push(McpAuthObservation::ResourceAudience {
                token: scenario.tokens.clone(),
            });
        }
    }
    if let Some(pkce) = &scenario.flow.pkce {
        observations.push(McpAuthObservation::Pkce { pkce: pkce.clone() });
    }
    if scenario.flow.redirect != crate::redirect::RedirectContext::default() {
        observations.push(McpAuthObservation::RedirectState {
            redirect: scenario.flow.redirect.clone(),
            state_correlated: scenario.authorization.state_correlation_holds(),
        });
    }
    if scenario.scope.challenge_observed {
        observations.push(McpAuthObservation::ScopeChallenge {
            scope: scenario.scope.clone(),
        });
    }
    if let Some(registration) = &scenario.registration {
        observations.push(McpAuthObservation::ClientRegistration {
            registration: registration.clone(),
        });
    }
    if scenario.credentials.inbound.is_some() || scenario.credentials.upstream.is_some() {
        observations.push(McpAuthObservation::CredentialFlow {
            credentials: scenario.credentials.clone(),
        });
    }
    if scenario.identity_metadata.client_info.is_some()
        || scenario.identity_metadata.server_info.is_some()
    {
        observations.push(McpAuthObservation::IdentityMetadata {
            identity: scenario.identity_metadata.clone(),
        });
    }
    if scenario.final_operation != crate::model::FinalOperationContext::default() {
        observations.push(McpAuthObservation::FinalOperationBinding {
            binding: scenario.final_operation.clone(),
        });
    }

    observations
}

/// Normalize after checking that every observation is bound to the scenario.
///
/// The check is the point. Without it an adapter could report a request the
/// scenario never approved, running under a revision it never declared, and the
/// evaluator would judge the adapter's version as though it had been approved.
pub fn normalize_checked(
    raw: &RawTrialOutput,
    scenario: &McpAuthScenario,
) -> Result<Vec<McpAuthObservation>> {
    assert_requests_bound(raw, scenario)?;
    Ok(normalize(raw, scenario))
}

/// Compare only authorization-relevant request semantics.
///
/// A human-readable label is deliberately excluded: changing prose does not
/// widen authority. The protocol revision, the routed method and name, and the
/// body operation do.
pub fn assert_requests_bound(raw: &RawTrialOutput, scenario: &McpAuthScenario) -> Result<()> {
    for observed in &raw.observed_requests {
        let approved = scenario.request(&observed.request_id).ok_or_else(|| {
            McpAuthSecurityError::DigestMismatch(
                "an observation names a request the approved scenario does not declare".to_owned(),
            )
        })?;

        if observed.protocol != approved.protocol {
            return Err(McpAuthSecurityError::DigestMismatch(format!(
                "an observation changes the protocol context of request `{}`",
                observed.request_id
            )));
        }
        if observed.operation != approved.operation {
            return Err(McpAuthSecurityError::DigestMismatch(format!(
                "an observation changes the operation semantics of request `{}`",
                observed.request_id
            )));
        }
        // Routing metadata is the one field a run legitimately varies: staging
        // a header/body mismatch is exactly how the binding invariants are
        // exercised. It stays free, and it is precisely what the evaluator
        // judges — the scenario's own headers are the approved side.
    }
    Ok(())
}

/// Whether a revision is one the modern auth surface applies to.
pub fn carries_modern_auth_surface(protocol: &ProtocolContext) -> bool {
    matches!(protocol.revision_class(), ProtocolRevisionClass::Current)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authorization::tests::authorization_context;
    use crate::credential::tests::credential_context;
    use crate::identity::tests::identity_context;
    use crate::metadata::tests::{resource_context, uri};
    use crate::model::{
        FinalOperationContext, FlowContext, McpAuthInvariantSpec, McpAuthInvariantType,
        McpAuthLabSpec, McpAuthObjective, McpAuthProperty, McpAuthSafetySpec, McpAuthScenario,
        McpAuthTrialSpec, ReferenceBehavior,
    };
    use crate::pkce::tests::pkce_context;
    use crate::protocol::tests::envelope;
    use crate::redirect::tests::redirect_context;
    use crate::registration::tests::registration_context;
    use crate::scope::tests::scope_context;
    use crate::source::ScenarioClass;
    use crate::token::tests::token_context;

    pub(crate) fn scenario() -> McpAuthScenario {
        McpAuthScenario {
            schema_version: "1".to_owned(),
            id: "MCP-AUTH-LAB-001".to_owned(),
            title: "a compliant modern MCP authorization flow".to_owned(),
            class: ScenarioClass::ProtocolBinding,
            property: McpAuthProperty::ProtocolBinding,
            objective: McpAuthObjective {
                id: "objective-invoice".to_owned(),
                description: "Create an invoice through an authorized MCP tool call.".to_owned(),
                protected_canaries: vec!["DARE-SYNTHETIC-CANARY-MCPAUTH01".to_owned()],
            },
            requests: vec![envelope()],
            protected_resource: resource_context(),
            authorization: authorization_context(),
            tokens: token_context(),
            flow: FlowContext {
                pkce: Some(pkce_context()),
                redirect: redirect_context(),
            },
            scope: scope_context(),
            registration: Some(registration_context()),
            credentials: credential_context(),
            identity_metadata: identity_context(),
            final_operation: FinalOperationContext {
                authorized_operation: Some(envelope().operation),
                performed_operation: Some(envelope().operation),
                authorized_resource: Some(uri("mcp-invoices")),
                performed_resource: Some(uri("mcp-invoices")),
                reevaluated_after_change: false,
                refused_after_change: false,
            },
            vector: None,
            invariant: McpAuthInvariantSpec {
                type_: McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            },
            trials: McpAuthTrialSpec {
                count: 3,
                stop_on_first_fail: true,
            },
            safety: McpAuthSafetySpec {
                local_only: true,
                max_requests_per_trial: None,
            },
            lab: Some(McpAuthLabSpec {
                reference_behavior: ReferenceBehavior::Compliant,
            }),
            standards: vec![],
        }
    }

    fn raw() -> RawTrialOutput {
        RawTrialOutput {
            observed_requests: vec![envelope()],
            harness_error: None,
        }
    }

    #[test]
    fn the_fixture_scenario_validates() {
        scenario().validate().expect("valid");
    }

    #[test]
    fn there_is_no_remote_or_live_mode() {
        // A remote mode would have to be added to this enum to exist at all,
        // which is why the enum is the check rather than a runtime guard.
        for absent in ["LIVE", "REMOTE", "PROVIDER", "HTTP", "PRODUCTION", "OAUTH"] {
            assert!(
                serde_json::from_str::<HarnessMode>(&format!("\"{absent}\"")).is_err(),
                "`{absent}` deserialized into a mode"
            );
        }
    }

    #[test]
    fn normalization_produces_the_channels_the_scenario_supports() {
        let observations = normalize_checked(&raw(), &scenario()).expect("normalizes");
        let channels: std::collections::BTreeSet<_> =
            observations.iter().filter_map(|o| o.channel()).collect();
        assert!(channels.contains(&crate::observation::CoverageChannel::ProtocolContext));
        assert!(channels.contains(&crate::observation::CoverageChannel::HeaderContext));
        assert!(channels.contains(&crate::observation::CoverageChannel::OperationContext));
        assert!(channels.contains(&crate::observation::CoverageChannel::TokenClaims));
    }

    #[test]
    fn an_observation_naming_an_undeclared_request_is_refused() {
        // The Cycle 017 lesson in its simplest form.
        let mut output = raw();
        output.observed_requests[0].request_id = "req-shadow".to_owned();
        let err = normalize_checked(&output, &scenario()).expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn an_observation_cannot_change_the_protocol_revision() {
        // Otherwise a trace could claim a legacy request was current and have
        // the modern authorization invariants applied to it.
        let mut output = raw();
        output.observed_requests[0].protocol.declared_revision =
            crate::LEGACY_WIRE_REVISION.to_owned();
        let err = normalize_checked(&output, &scenario()).expect_err("must be refused");
        assert!(err.to_string().contains("protocol context"));
    }

    #[test]
    fn an_observation_cannot_change_the_body_operation() {
        // The body is what was approved. A trace that rewrote it could make an
        // unapproved operation look authorized.
        let mut output = raw();
        output.observed_requests[0].operation.name = Some("delete-invoice".to_owned());
        let err = normalize_checked(&output, &scenario()).expect_err("must be refused");
        assert!(err.to_string().contains("operation semantics"));
    }

    #[test]
    fn routing_metadata_stays_free_because_it_is_what_is_judged() {
        // Staging a header/body mismatch is how the binding invariants are
        // exercised. Binding the headers too would make the invariant
        // untestable.
        let mut output = raw();
        output.observed_requests[0].headers.method = Some("resources/read".to_owned());
        let observations = normalize_checked(&output, &scenario()).expect("normalizes");
        assert!(observations.iter().any(|o| matches!(
            o,
            McpAuthObservation::HeaderContext { routed_method: Some(m), .. } if m == "resources/read"
        )));
    }

    #[test]
    fn a_harness_error_suppresses_every_other_observation() {
        // Mixing a failure with partial observations would let a run that could
        // not complete contribute coverage toward a PASS.
        let output = RawTrialOutput {
            observed_requests: vec![envelope()],
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::AdapterFailure,
                detail: "adapter stopped".to_owned(),
            }),
        };
        let observations = normalize_checked(&output, &scenario()).expect("normalizes");
        assert_eq!(observations.len(), 1);
        assert!(observations[0].channel().is_none());
    }

    #[test]
    fn a_replayed_observation_still_reports_as_synthetic_by_default() {
        struct Fake;
        impl HarnessAdapter for Fake {
            fn mode(&self) -> HarnessMode {
                HarnessMode::Replay
            }
            fn observe(&self, _: &TrialRequest<'_>) -> Result<RawTrialOutput> {
                Ok(RawTrialOutput::default())
            }
        }
        assert!(!Fake.mode().is_synthetic());
        assert!(Fake.observations_are_synthetic());
    }

    #[test]
    fn the_adapter_trait_offers_no_way_to_state_a_verdict() {
        // Compile-time: `HarnessAdapter` has `observe`, `mode`,
        // `trial_capacity` and `observations_are_synthetic`. There is no method
        // returning a Verdict, and adding one would be a visible API change.
        fn assert_object_safe(_: &dyn HarnessAdapter) {}
        struct Fake;
        impl HarnessAdapter for Fake {
            fn mode(&self) -> HarnessMode {
                HarnessMode::Simulated
            }
            fn observe(&self, _: &TrialRequest<'_>) -> Result<RawTrialOutput> {
                Ok(RawTrialOutput::default())
            }
        }
        assert_object_safe(&Fake);
    }
}
