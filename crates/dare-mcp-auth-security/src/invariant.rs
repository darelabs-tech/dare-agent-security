//! The deterministic invariant registry.
//!
//! Fourteen evaluators, each a comparison of typed fields. No model, no
//! heuristic, no prose inference and no fixture-declared verdict appears
//! anywhere in this file.
//!
//! The order inside [`evaluate`] matters:
//!
//! 1. a harness failure means the run could not observe, so no security
//!    conclusion is available in either direction — `ERROR`;
//! 2. violations are collected next, and **all** of them are collected. One
//!    flow can mix up the issuer, present a token for the wrong resource and
//!    forward a credential upstream, and reporting the first would understate
//!    what was seen;
//! 3. only if nothing was violated does coverage decide between `PASS` and
//!    `INCONCLUSIVE`. Checking coverage first would let a run with a real
//!    violation report `INCONCLUSIVE` because some unrelated channel was
//!    missing — hiding a finding behind a gap.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::coverage::assess_coverage;
use crate::model::{McpAuthInvariantType, McpAuthScenario};
use crate::observation::McpAuthObservation;
use crate::source::ProtocolRevisionClass;

/// One independently observed violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthViolation {
    pub invariant: McpAuthInvariantType,
    pub reason: String,
    /// Digests of the observations that decided this violation.
    ///
    /// A finding with no deciding evidence is an assertion rather than a
    /// finding: an operator has to be able to get from the verdict back to
    /// what was observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The outcome of evaluating one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthInvariantOutcome {
    pub invariant: McpAuthInvariantType,
    pub verdict: Verdict,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<McpAuthViolation>,
    pub coverage_satisfied: bool,
}

impl McpAuthInvariantOutcome {
    fn pass(invariant: McpAuthInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Pass,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: true,
        }
    }

    fn fail(invariant: McpAuthInvariantType, violations: Vec<McpAuthViolation>) -> Self {
        let reason = match violations.len() {
            1 => violations[0].reason.clone(),
            n => format!(
                "{n} independent violations of {} were observed",
                invariant.as_str()
            ),
        };
        Self {
            invariant,
            verdict: Verdict::Fail,
            reason,
            violations,
            // A violation was observed, so the boundary was demonstrably
            // exercised, whatever else the run did or did not record.
            coverage_satisfied: true,
        }
    }

    fn inconclusive(invariant: McpAuthInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Inconclusive,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }

    fn error(invariant: McpAuthInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Error,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }
}

/// Every invariant this engine implements.
pub fn supported_invariants() -> [McpAuthInvariantType; 14] {
    McpAuthInvariantType::all()
}

/// Evaluate one invariant against one trial's observations.
pub fn evaluate(
    invariant: McpAuthInvariantType,
    scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> McpAuthInvariantOutcome {
    use McpAuthInvariantType as I;

    // 1. Could the run observe at all?
    if let Some(McpAuthObservation::HarnessError { kind, detail }) = observations
        .iter()
        .find(|o| matches!(o, McpAuthObservation::HarnessError { .. }))
    {
        return McpAuthInvariantOutcome::error(
            invariant,
            format!(
                "the harness could not observe ({}): {}",
                kind.as_str(),
                detail.text
            ),
        );
    }

    // 2. Every independently observed violation.
    let violations = match invariant {
        I::McpProtocolRevisionPreserved => protocol_revision(observations),
        I::McpMethodHeaderBodyBindingPreserved => method_binding(scenario, observations),
        I::McpNameHeaderBodyBindingPreserved => name_binding(scenario, observations),
        I::ProtectedResourceMetadataBoundToResource => resource_metadata(observations),
        I::AuthorizationServerIssuerBoundaryPreserved => issuer_boundary(observations),
        I::AuthorizationResponseIssuerPreserved => response_issuer(scenario, observations),
        I::TokenResourceAudienceBoundaryPreserved => token_audience(scenario, observations),
        I::TokenValidityEvidencePresent => token_validity(scenario, observations),
        I::PkceBindingPreserved => pkce_binding(scenario, observations),
        I::RedirectStateBindingPreserved => redirect_state(scenario, observations),
        I::ScopeStepUpDoesNotDropRequiredScope => scope_step_up(scenario, observations),
        I::ClientRegistrationMetadataTrustPreserved => registration_trust(scenario, observations),
        I::InboundCredentialNotReusedAsUpstreamAuthority => {
            credential_separation(scenario, observations)
        }
        I::FinalOperationAuthorizationBindingPreserved => final_operation(scenario, observations),
    };

    if !violations.is_empty() {
        return McpAuthInvariantOutcome::fail(invariant, violations);
    }

    // 3. Nothing violated. Whether that means the boundary held or that nobody
    //    looked is decided by the coverage contract.
    let coverage = assess_coverage(invariant, observations);
    if !coverage.satisfied {
        return McpAuthInvariantOutcome::inconclusive(invariant, coverage.reason);
    }

    McpAuthInvariantOutcome::pass(
        invariant,
        format!(
            "invariant {} held for every observation in this trial",
            invariant.as_str()
        ),
    )
}

// --- helpers -----------------------------------------------------------------

fn digest_of(observation: &McpAuthObservation) -> Vec<String> {
    observation.digest().ok().into_iter().collect()
}

fn digests_for<F>(observations: &[McpAuthObservation], predicate: F) -> Vec<String>
where
    F: Fn(&McpAuthObservation) -> bool,
{
    observations
        .iter()
        .filter(|o| predicate(o))
        .flat_map(digest_of)
        .collect()
}

fn violation(
    invariant: McpAuthInvariantType,
    reason: String,
    digests: Vec<String>,
) -> McpAuthViolation {
    McpAuthViolation {
        invariant,
        reason,
        deciding_event_digests: digests,
        request_id: None,
        subject: None,
        detail: None,
    }
}

// --- evaluators --------------------------------------------------------------

/// A request running under a revision the engine does not support.
fn protocol_revision(observations: &[McpAuthObservation]) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::ProtocolContext {
            request_id,
            revision_class,
            ..
        } = observation
        else {
            continue;
        };
        if *revision_class == ProtocolRevisionClass::Unsupported {
            violations.push(McpAuthViolation {
                request_id: Some(request_id.clone()),
                detail: Some(
                    "an unsupported revision fails closed rather than being evaluated against \
                     the current authorization surface"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::McpProtocolRevisionPreserved,
                    format!("request `{request_id}` declares an unsupported protocol revision"),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// Routing metadata that names a different method from the body.
fn method_binding(
    scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for (request_id, routed) in routed_methods(observations) {
        let Some(body) = body_method(observations, request_id) else {
            continue;
        };
        if !crate::protocol::routing_values_agree(routed, body) {
            violations.push(McpAuthViolation {
                request_id: Some(request_id.to_owned()),
                detail: Some(format!(
                    "scenario `{}` approved the body operation; the routed method disagrees",
                    scenario.id
                )),
                ..violation(
                    McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
                    format!(
                        "request `{request_id}` was routed on a method the body did not request"
                    ),
                    digests_for(observations, |o| {
                        matches!(
                            o,
                            McpAuthObservation::HeaderContext { request_id: id, .. }
                                | McpAuthObservation::OperationContext { request_id: id, .. }
                            if id == request_id
                        )
                    }),
                )
            });
        }
    }
    violations
}

/// Routing metadata that names a different operation from the body.
fn name_binding(
    scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for (request_id, routed) in routed_names(observations) {
        let body = body_name(observations, request_id);
        let agrees = match body {
            Some(body) => crate::protocol::routing_values_agree(routed, body),
            // The transport routed on a name the body never asked for.
            None => false,
        };
        if !agrees {
            violations.push(McpAuthViolation {
                request_id: Some(request_id.to_owned()),
                detail: Some(format!(
                    "scenario `{}` approved the body operation; the routed name disagrees",
                    scenario.id
                )),
                ..violation(
                    McpAuthInvariantType::McpNameHeaderBodyBindingPreserved,
                    format!(
                        "request `{request_id}` was routed on an operation name the body did not \
                         request"
                    ),
                    digests_for(observations, |o| {
                        matches!(
                            o,
                            McpAuthObservation::HeaderContext { request_id: id, .. }
                                | McpAuthObservation::OperationContext { request_id: id, .. }
                            if id == request_id
                        )
                    }),
                )
            });
        }
    }
    violations
}

fn routed_methods(observations: &[McpAuthObservation]) -> Vec<(&str, &str)> {
    observations
        .iter()
        .filter_map(|o| match o {
            McpAuthObservation::HeaderContext {
                request_id,
                routed_method: Some(method),
                ..
            } => Some((request_id.as_str(), method.as_str())),
            _ => None,
        })
        .collect()
}

fn routed_names(observations: &[McpAuthObservation]) -> Vec<(&str, &str)> {
    observations
        .iter()
        .filter_map(|o| match o {
            McpAuthObservation::HeaderContext {
                request_id,
                routed_name: Some(name),
                ..
            } => Some((request_id.as_str(), name.as_str())),
            _ => None,
        })
        .collect()
}

fn body_method<'a>(observations: &'a [McpAuthObservation], request_id: &str) -> Option<&'a str> {
    observations.iter().find_map(|o| match o {
        McpAuthObservation::OperationContext {
            request_id: id,
            method,
            ..
        } if id == request_id => Some(method.as_str()),
        _ => None,
    })
}

fn body_name<'a>(observations: &'a [McpAuthObservation], request_id: &str) -> Option<&'a str> {
    observations.iter().find_map(|o| match o {
        McpAuthObservation::OperationContext {
            request_id: id,
            name,
            ..
        } if id == request_id => name.as_deref(),
        _ => None,
    })
}

/// Metadata describing a resource other than the one under test.
fn resource_metadata(observations: &[McpAuthObservation]) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::ProtectedResourceMetadata { resource } = observation else {
            continue;
        };
        let Some(metadata) = &resource.metadata else {
            continue;
        };
        if metadata.resource != resource.expected_resource {
            violations.push(McpAuthViolation {
                subject: Some(metadata.resource.to_string()),
                detail: Some(
                    "metadata is evidence about a resource, and evidence about a different \
                     resource says nothing about this one"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::ProtectedResourceMetadataBoundToResource,
                    format!(
                        "protected resource metadata describes `{}` but the request was for `{}`",
                        metadata.resource, resource.expected_resource
                    ),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// An authorization server the resource does not advertise.
fn issuer_boundary(observations: &[McpAuthObservation]) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::AuthorizationServerMetadata { resource } = observation else {
            continue;
        };
        let Some(selected) = &resource.selected_authorization_server else {
            continue;
        };

        if let Some(metadata) = &resource.metadata {
            if !metadata.advertises(selected) {
                violations.push(McpAuthViolation {
                    subject: Some(selected.to_string()),
                    detail: Some(
                        "the resource's own metadata lists which authorization servers may issue \
                         for it; this one is not among them"
                            .to_owned(),
                    ),
                    ..violation(
                        McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved,
                        format!(
                            "authorization server `{selected}` is not advertised by the protected \
                             resource"
                        ),
                        digest_of(observation),
                    )
                });
            }
        }

        // The selected server's own metadata must exist and agree about its
        // issuer. A selection nobody recorded metadata for cannot be checked
        // against anything.
        match resource.selected_metadata() {
            Some(server) if &server.issuer != selected => {
                violations.push(McpAuthViolation {
                    subject: Some(selected.to_string()),
                    ..violation(
                        McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved,
                        format!(
                            "the metadata resolved for `{selected}` declares issuer `{}`",
                            server.issuer
                        ),
                        digest_of(observation),
                    )
                });
            }
            None => {
                violations.push(McpAuthViolation {
                    subject: Some(selected.to_string()),
                    detail: Some(
                        "a server selected without recorded metadata cannot be checked against \
                         anything, and accepting it would mean trusting the selection itself"
                            .to_owned(),
                    ),
                    ..violation(
                        McpAuthInvariantType::AuthorizationServerIssuerBoundaryPreserved,
                        format!("authorization server `{selected}` has no recorded metadata"),
                        digest_of(observation),
                    )
                });
            }
            _ => {}
        }
    }
    violations
}

/// A response from an issuer other than the one selected.
fn response_issuer(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    let request = observations.iter().find_map(|o| match o {
        McpAuthObservation::AuthorizationRequest { request } => Some(request),
        _ => None,
    });
    let response = observations.iter().find_map(|o| match o {
        McpAuthObservation::AuthorizationResponse { response } => Some(response),
        _ => None,
    });

    let (Some(request), Some(response)) = (request, response) else {
        return violations;
    };
    let Some(issuer) = &response.response_issuer else {
        return violations;
    };

    if issuer != &request.selected_issuer {
        violations.push(McpAuthViolation {
            request_id: Some(response.request_id.clone()),
            subject: Some(issuer.to_string()),
            detail: Some(if response.accepted_by_client {
                "the client accepted it".to_owned()
            } else {
                "the client rejected it, which is the correct behaviour; the mix-up is still \
                 recorded because it was attempted"
                    .to_owned()
            }),
            ..violation(
                McpAuthInvariantType::AuthorizationResponseIssuerPreserved,
                format!(
                    "the authorization response came from `{issuer}` but `{}` was selected",
                    request.selected_issuer
                ),
                digests_for(observations, |o| {
                    matches!(
                        o,
                        McpAuthObservation::AuthorizationRequest { .. }
                            | McpAuthObservation::AuthorizationResponse { .. }
                    )
                }),
            )
        });
    }
    violations
}

/// A token that does not name the resource under test.
fn token_audience(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::ResourceAudience { token } = observation else {
            continue;
        };
        if token.resource_binding_holds() == Some(false) {
            let claims = token.presented.as_ref().expect("binding implies a token");
            let target = token
                .target_resource
                .as_ref()
                .expect("binding implies a target");
            violations.push(McpAuthViolation {
                subject: Some(claims.token_id.clone()),
                detail: Some(
                    "a token minted for another resource is not weaker authorization for this \
                     one; it is none"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::TokenResourceAudienceBoundaryPreserved,
                    format!(
                        "token `{}` names no audience or resource matching `{target}`",
                        claims.token_id
                    ),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// A token the deployment relied on without recording any verification.
fn token_validity(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::TokenClaims { token } = observation else {
            continue;
        };
        let Some(claims) = &token.presented else {
            continue;
        };
        // Missing verification evidence is INCONCLUSIVE, not FAIL — unless the
        // deployment went ahead and accepted the token anyway, which is a
        // decision it made on no evidence and is a finding in itself.
        if !claims.has_validity_evidence() && token.accepted_by_resource {
            violations.push(McpAuthViolation {
                subject: Some(claims.token_id.clone()),
                detail: Some(
                    "accepting a token with no recorded verification is a decision made on no \
                     evidence"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::TokenValidityEvidencePresent,
                    format!(
                        "token `{}` was accepted with no verification evidence",
                        claims.token_id
                    ),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// PKCE absent, downgraded, or not bound to its verifier.
fn pkce_binding(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::Pkce { pkce } = observation else {
            continue;
        };
        if pkce.method_requirement_holds() == Some(false) {
            violations.push(McpAuthViolation {
                detail: Some(
                    "plain is not a weaker binding than S256; the verifier travels with the \
                     challenge and binds nothing against interception"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::PkceBindingPreserved,
                    format!("the flow requires S256 but used `{}`", pkce.method.as_str()),
                    digest_of(observation),
                )
            });
        }
        if pkce.binding_holds() == Some(false) {
            violations.push(violation(
                McpAuthInvariantType::PkceBindingPreserved,
                "the PKCE verifier does not correspond to the challenge that started the flow"
                    .to_owned(),
                digest_of(observation),
            ));
        }
    }
    violations
}

/// A redirect or state value that did not survive the round trip.
fn redirect_state(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::RedirectState {
            redirect,
            state_correlated,
        } = observation
        else {
            continue;
        };
        if redirect.delivery_matches_request() == Some(false) {
            violations.push(violation(
                McpAuthInvariantType::RedirectStateBindingPreserved,
                "the authorization response was delivered to a redirect URI the request did not \
                 name"
                    .to_owned(),
                digest_of(observation),
            ));
        }
        if redirect.requested_is_registered() == Some(false) {
            violations.push(violation(
                McpAuthInvariantType::RedirectStateBindingPreserved,
                "the authorization request named a redirect URI the client had not registered"
                    .to_owned(),
                digest_of(observation),
            ));
        }
        if *state_correlated == Some(false) {
            violations.push(violation(
                McpAuthInvariantType::RedirectStateBindingPreserved,
                "the state value did not survive the round trip, so the response cannot be \
                 correlated to the request that started it"
                    .to_owned(),
                digest_of(observation),
            ));
        }
    }
    violations
}

/// A step-up that dropped a scope the request already required.
fn scope_step_up(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::ScopeChallenge { scope } = observation else {
            continue;
        };
        if let Some(dropped) = scope.dropped_scopes() {
            if !dropped.is_empty() {
                let names: Vec<&str> = dropped.into_iter().collect();
                violations.push(McpAuthViolation {
                    detail: Some(
                        "a step-up may widen privilege; it may not silently discard what was \
                         already required"
                            .to_owned(),
                    ),
                    ..violation(
                        McpAuthInvariantType::ScopeStepUpDoesNotDropRequiredScope,
                        format!(
                            "the step-up retry dropped previously required scope(s): {}",
                            names.join(", ")
                        ),
                        digest_of(observation),
                    )
                });
            }
        }
        if !scope.retries_within_bound() {
            violations.push(violation(
                McpAuthInvariantType::ScopeStepUpDoesNotDropRequiredScope,
                format!(
                    "the flow retried {} times; the approved ceiling is {}",
                    scope.retry_count,
                    crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES
                ),
                digest_of(observation),
            ));
        }
    }
    violations
}

/// Registration metadata relied upon beyond what its provenance supports.
fn registration_trust(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::ClientRegistration { registration } = observation else {
            continue;
        };
        if registration.trust_holds() == Some(false) {
            violations.push(McpAuthViolation {
                subject: Some(registration.client_id.clone()),
                detail: Some(
                    "a redirect URI or client identifier is not established because an untrusted \
                     document asserts it"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::ClientRegistrationMetadataTrustPreserved,
                    format!(
                        "client `{}` was accepted on registration metadata of class `{}`",
                        registration.client_id,
                        registration.trust_class.as_str()
                    ),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// An inbound credential reused as upstream authority.
fn credential_separation(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::CredentialFlow { credentials } = observation else {
            continue;
        };
        if credentials.separation_holds() == Some(false) {
            violations.push(McpAuthViolation {
                detail: Some(
                    "the upstream service sees a valid credential and has no way to know it was \
                     minted for another audience"
                        .to_owned(),
                ),
                ..violation(
                    McpAuthInvariantType::InboundCredentialNotReusedAsUpstreamAuthority,
                    "the inbound MCP credential was reused as upstream authority".to_owned(),
                    digest_of(observation),
                )
            });
        }
    }
    violations
}

/// Authorization that no longer covers the operation performed.
///
/// The comparison of *what changed* is Cycle 003's; this evaluator asks the
/// narrower Cycle 018 question — whether a change happened without the
/// deployment re-evaluating or refusing.
fn final_operation(
    _scenario: &McpAuthScenario,
    observations: &[McpAuthObservation],
) -> Vec<McpAuthViolation> {
    let mut violations = Vec::new();
    for observation in observations {
        let McpAuthObservation::FinalOperationBinding { binding } = observation else {
            continue;
        };
        let changed = crate::compat::authorization_relevant_change(binding);
        if changed.is_empty() {
            continue;
        }
        if binding.reevaluated_after_change || binding.refused_after_change {
            // Re-evaluating or refusing is correct behaviour, not a finding.
            continue;
        }
        violations.push(McpAuthViolation {
            detail: Some(
                "a permit covers the operation it was granted for; reusing it after an \
                 authorization-relevant change is a stale permit"
                    .to_owned(),
            ),
            ..violation(
                McpAuthInvariantType::FinalOperationAuthorizationBindingPreserved,
                format!(
                    "the performed operation changed in {} without re-evaluation or refusal",
                    changed.join(", ")
                ),
                digest_of(observation),
            )
        });
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::observation::EvidenceText;
    use crate::source::HarnessErrorKind;

    fn observations() -> Vec<McpAuthObservation> {
        let raw = crate::harness::RawTrialOutput {
            observed_requests: scenario().requests.clone(),
            harness_error: None,
        };
        crate::harness::normalize(&raw, &scenario())
    }

    #[test]
    fn the_registry_is_closed_at_fourteen() {
        assert_eq!(supported_invariants().len(), 14);
    }

    #[test]
    fn a_harness_failure_is_an_error_for_every_invariant() {
        // Not a FAIL and not a PASS: the run could not observe, so no security
        // conclusion is available in either direction.
        let failed = vec![McpAuthObservation::HarnessError {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("stopped"),
        }];
        for invariant in supported_invariants() {
            let outcome = evaluate(invariant, &scenario(), &failed);
            assert_eq!(outcome.verdict, Verdict::Error, "{invariant:?}");
            assert!(outcome.violations.is_empty());
        }
    }

    #[test]
    fn an_empty_observation_set_is_inconclusive_for_every_invariant() {
        // Never PASS. This is the absence-only pass the whole coverage contract
        // exists to prevent.
        for invariant in supported_invariants() {
            let outcome = evaluate(invariant, &scenario(), &[]);
            assert_eq!(outcome.verdict, Verdict::Inconclusive, "{invariant:?}");
            assert!(!outcome.coverage_satisfied);
        }
    }

    #[test]
    fn a_compliant_flow_passes_the_invariant_it_is_staged_for() {
        let outcome = evaluate(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &scenario(),
            &observations(),
        );
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);
    }

    #[test]
    fn every_violation_names_the_evidence_that_decided_it() {
        // A finding with no deciding evidence is an assertion, not a finding.
        let mut broken = scenario();
        broken.requests[0].headers.method = Some("resources/read".to_owned());
        let raw = crate::harness::RawTrialOutput {
            observed_requests: broken.requests.clone(),
            harness_error: None,
        };
        let observed = crate::harness::normalize(&raw, &broken);
        let outcome = evaluate(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &broken,
            &observed,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        for violation in &outcome.violations {
            assert!(!violation.deciding_event_digests.is_empty());
            assert!(!violation.reason.trim().is_empty());
        }
    }

    #[test]
    fn a_violation_is_reported_even_when_another_channel_is_missing() {
        // Coverage is checked *after* violations. Checking it first would let a
        // run with a real finding report INCONCLUSIVE because something
        // unrelated was not observed, which hides the finding behind a gap.
        let mut broken = scenario();
        broken.requests[0].headers.method = Some("resources/read".to_owned());
        let raw = crate::harness::RawTrialOutput {
            observed_requests: broken.requests.clone(),
            harness_error: None,
        };
        let mut observed = crate::harness::normalize(&raw, &broken);
        // Drop everything except the two channels the finding needs.
        observed.retain(|o| {
            matches!(
                o,
                McpAuthObservation::HeaderContext { .. }
                    | McpAuthObservation::OperationContext { .. }
            )
        });
        let outcome = evaluate(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &broken,
            &observed,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn no_evaluator_reads_a_score_or_a_fixture_verdict() {
        // Structural: the observation model has no verdict variant and no
        // numeric confidence, so there is nothing an evaluator could read.
        let rendered = serde_json::to_string(&observations()).expect("serializes");
        for banned in ["\"verdict\"", "\"expected\"", "\"confidence\"", "\"score\""] {
            assert!(!rendered.contains(banned), "observations carry {banned}");
        }
    }
}
