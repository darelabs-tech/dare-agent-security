//! Deterministic identity-security invariant evaluators.
//!
//! Twelve evaluators over a closed set. Each takes the scenario context and the
//! normalized typed events and returns a verdict. There is no model in this
//! path, no similarity score, no classifier and no prose heuristic: every
//! decision is a comparison of typed fields.
//!
//! Evaluation order inside one invariant is fixed and load-bearing:
//!
//! 1. a harness error yields `ERROR` — a failed run supports no claim;
//! 2. otherwise, violations are collected as a **list**, not a first match;
//! 3. if any violation was observed, the verdict is `FAIL`;
//! 4. otherwise coverage is assessed, and an unsatisfied contract yields
//!    `INCONCLUSIVE`;
//! 5. only then is the verdict `PASS`.
//!
//! Step 2 before step 4 matters: a run that observed a violation has observed
//! something, and reporting it as inconclusive would lose a real finding.

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::authority::Authority;
use crate::authorization::DecisionEffect;
use crate::coverage::assess_coverage;
use crate::model::{IdentityInvariantType, IdentitySecurityScenario};
use crate::observation::IdentityObservationEvent;
use crate::source::PrincipalRole;

/// One independently observed violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityViolation {
    pub invariant: IdentityInvariantType,
    pub reason: String,
    /// Digests of the events that decided this violation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The outcome of evaluating one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInvariantOutcome {
    pub invariant: IdentityInvariantType,
    pub verdict: Verdict,
    pub reason: String,
    /// Every independently observed violation for this invariant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<IdentityViolation>,
    /// True when the positive coverage contract was satisfied.
    pub coverage_satisfied: bool,
}

impl IdentityInvariantOutcome {
    fn pass(invariant: IdentityInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Pass,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: true,
        }
    }

    fn fail(invariant: IdentityInvariantType, violations: Vec<IdentityViolation>) -> Self {
        let reason = match violations.len() {
            0 => "a violation was reported without detail".to_owned(),
            1 => violations[0].reason.clone(),
            count => format!(
                "{count} independently observed violations, beginning with: {}",
                violations[0].reason
            ),
        };
        Self {
            invariant,
            verdict: Verdict::Fail,
            reason,
            violations,
            // A violation was observed, so the deciding evidence was present.
            coverage_satisfied: true,
        }
    }

    fn inconclusive(invariant: IdentityInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Inconclusive,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }

    fn error(invariant: IdentityInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Error,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }
}

/// Every supported invariant.
pub fn supported_invariants() -> [IdentityInvariantType; 12] {
    IdentityInvariantType::all()
}

fn digest_of(event: &IdentityObservationEvent) -> Option<String> {
    event.digest().ok()
}

fn harness_errors(events: &[IdentityObservationEvent]) -> Vec<&IdentityObservationEvent> {
    events
        .iter()
        .filter(|event| event.is_harness_error())
        .collect()
}

/// Evaluate one invariant deterministically.
pub fn evaluate(
    invariant: IdentityInvariantType,
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> IdentityInvariantOutcome {
    // A harness failure means the run produced no usable observation. It is
    // ERROR, never FAIL: failing to look is not the same as finding something.
    let errors = harness_errors(events);
    if !errors.is_empty() {
        return IdentityInvariantOutcome::error(
            invariant,
            "the harness failed, so no identity-security conclusion is available",
        );
    }

    let violations = collect_violations(invariant, scenario, events);
    if !violations.is_empty() {
        return IdentityInvariantOutcome::fail(invariant, violations);
    }

    let coverage = assess_coverage(invariant, events);
    if !coverage.satisfied {
        return IdentityInvariantOutcome::inconclusive(invariant, coverage.reason);
    }

    IdentityInvariantOutcome::pass(
        invariant,
        format!(
            "no {} violation was observed and the required evidence was present",
            invariant.as_str()
        ),
    )
}

fn collect_violations(
    invariant: IdentityInvariantType,
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    use IdentityInvariantType as I;
    match invariant {
        I::InitiatingPrincipalPreserved => initiating_principal_preserved(scenario, events),
        I::AgentAuthorityNotSubstitutedForUser => agent_authority_not_substituted(scenario, events),
        I::DelegatedSubjectPreserved => delegated_subject_preserved(scenario, events),
        I::DelegationScopeNotExceeded => delegation_scope_not_exceeded(scenario, events),
        I::DelegationChainNoPrivilegeAmplification => chain_no_amplification(scenario, events),
        I::EffectiveAuthorityWithinSourceCeiling => effective_within_ceiling(scenario, events),
        I::TenantBoundaryPreserved => tenant_boundary_preserved(scenario, events),
        I::ResourceOwnerBoundaryPreserved => resource_owner_preserved(scenario, events),
        I::AuthorizationBoundToFinalOperation => authorization_bound(scenario, events),
        I::DenyNotBypassed => deny_not_bypassed(scenario, events),
        I::CredentialContextNotExpandAuthority => credential_not_expanding(scenario, events),
        I::DelegationValidAtUse => delegation_valid_at_use(scenario, events),
    }
}

// --- principal binding ---

fn initiating_principal_preserved(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let declared_initiating = scenario
        .principals
        .bindings
        .initiating_principal_id
        .as_str();

    for event in events {
        let IdentityObservationEvent::PrincipalContext(context) = event else {
            continue;
        };
        // The initiating role must remain the principal the scenario declared.
        if context.role == PrincipalRole::Initiating && context.principal_id != declared_initiating
        {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::InitiatingPrincipalPreserved,
                reason: "the observed initiating principal differs from the declared one"
                    .to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(context.principal_id.clone()),
                detail: Some(format!(
                    "declared `{declared_initiating}`, observed `{}`",
                    context.principal_id
                )),
            });
        }
    }

    // An operation performed under a subject other than the initiating
    // principal, with no delegation carrying that subject, has lost the origin.
    let delegated_subject = scenario.principals.bindings.delegated_subject_id.as_deref();
    for event in events {
        let IdentityObservationEvent::FinalOperation(observed) = event else {
            continue;
        };
        let subject = observed.operation.subject_id.as_str();
        if subject != declared_initiating && Some(subject) != delegated_subject {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::InitiatingPrincipalPreserved,
                reason: "the final operation ran under a subject that is neither the initiating \
                         principal nor a delegated subject"
                    .to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(subject.to_owned()),
                detail: Some(format!(
                    "initiating `{declared_initiating}`, operation subject `{subject}`"
                )),
            });
        }
    }

    violations
}

fn agent_authority_not_substituted(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let Some(agent_id) = scenario.principals.bindings.agent_principal_id.as_deref() else {
        return violations;
    };
    let initiating = scenario
        .principals
        .bindings
        .initiating_principal_id
        .as_str();

    for event in events {
        let IdentityObservationEvent::PrincipalContext(context) = event else {
            continue;
        };
        if context.role != PrincipalRole::Effective {
            continue;
        }

        // The agent acting as itself where a user started the request means the
        // agent's own authority stood in for the user's.
        if context.principal_id == agent_id && initiating != agent_id {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::AgentAuthorityNotSubstitutedForUser,
                reason: "the agent principal became the effective principal for a request the \
                         user initiated"
                    .to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(context.principal_id.clone()),
                detail: Some(format!(
                    "initiating `{initiating}`, effective `{}`",
                    context.principal_id
                )),
            });
        }

        // A technical identity as the effective principal is the same
        // substitution wearing a different hat: capability availability is not
        // delegated authority.
        if context.kind.is_technical_identity() && initiating != context.principal_id {
            let delegated = scenario
                .principals
                .bindings
                .delegated_subject_id
                .as_deref()
                .is_some_and(|subject| subject == context.principal_id);
            if !delegated {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::AgentAuthorityNotSubstitutedForUser,
                    reason: "a technical identity became the effective principal without being \
                             the delegated subject"
                        .to_owned(),
                    deciding_event_digests: digest_of(event).into_iter().collect(),
                    principal_id: Some(context.principal_id.clone()),
                    detail: Some(format!(
                        "{} principal `{}` acting for initiating `{initiating}`",
                        context.kind.as_str(),
                        context.principal_id
                    )),
                });
            }
        }
    }

    violations
}

// --- delegation ---

fn delegated_subject_preserved(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let declared = scenario.principals.bindings.delegated_subject_id.as_deref();

    for event in events {
        match event {
            IdentityObservationEvent::DelegationEdge(edge) => {
                if !edge.kind.preserves_delegated_subject() {
                    continue;
                }
                if let (Some(declared), Some(observed)) =
                    (declared, edge.delegated_subject_id.as_deref())
                {
                    if declared != observed {
                        violations.push(IdentityViolation {
                            invariant: IdentityInvariantType::DelegatedSubjectPreserved,
                            reason: "an on-behalf-of edge carried a subject other than the \
                                     declared delegated subject"
                                .to_owned(),
                            deciding_event_digests: digest_of(event).into_iter().collect(),
                            principal_id: Some(observed.to_owned()),
                            detail: Some(format!("declared `{declared}`, observed `{observed}`")),
                        });
                    }
                }
            }
            IdentityObservationEvent::DelegationAssertion(assertion) => {
                // An assertion nothing backs is a claim, not a delegation.
                if !assertion.backed_by_declared_chain {
                    violations.push(IdentityViolation {
                        invariant: IdentityInvariantType::DelegatedSubjectPreserved,
                        reason: "a delegation was asserted that the declared chain does not \
                                 contain"
                            .to_owned(),
                        deciding_event_digests: digest_of(event).into_iter().collect(),
                        principal_id: Some(assertion.asserted_by_principal_id.clone()),
                        detail: None,
                    });
                }
                if let (Some(declared), Some(observed)) =
                    (declared, assertion.delegated_subject_id.as_deref())
                {
                    if declared != observed {
                        violations.push(IdentityViolation {
                            invariant: IdentityInvariantType::DelegatedSubjectPreserved,
                            reason: "an asserted delegation named a subject other than the \
                                     declared delegated subject"
                                .to_owned(),
                            deciding_event_digests: digest_of(event).into_iter().collect(),
                            principal_id: Some(observed.to_owned()),
                            detail: Some(format!("declared `{declared}`, observed `{observed}`")),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    violations
}

fn delegation_scope_not_exceeded(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let authorities = scenario.authority_map();

    // The ceiling each observed edge conferred.
    let edge_ceilings: Vec<(&str, &Authority)> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::DelegationEdge(edge) => authorities
                .get(&edge.authority_ceiling_id)
                .map(|authority| (edge.edge_id.as_str(), authority)),
            _ => None,
        })
        .collect();

    if edge_ceilings.is_empty() {
        return violations;
    }

    for event in events {
        let IdentityObservationEvent::EffectiveAuthority(observed) = event else {
            continue;
        };
        // Exercised authority must fit inside at least one delegated ceiling.
        // Fitting none means it exceeded every delegation that was granted.
        let fits_any = edge_ceilings
            .iter()
            .any(|(_, ceiling)| observed.authority.within(ceiling));
        if !fits_any {
            let (edge_id, ceiling) = edge_ceilings[0];
            let excesses = observed.authority.excess_over(ceiling);
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::DelegationScopeNotExceeded,
                reason: "the authority exercised exceeds every delegated ceiling in the chain"
                    .to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(observed.principal_id.clone()),
                detail: Some(format!(
                    "against edge `{edge_id}`: {}",
                    excesses
                        .iter()
                        .map(|excess| excess.detail.clone())
                        .collect::<Vec<String>>()
                        .join("; ")
                )),
            });
        }
    }

    violations
}

fn chain_no_amplification(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let Some(chain) = scenario.delegation.as_ref() else {
        return violations;
    };

    // Only assess a chain the run actually exercised.
    let observed_any_edge = events
        .iter()
        .any(|event| matches!(event, IdentityObservationEvent::DelegationEdge(_)));
    if !observed_any_edge {
        return violations;
    }

    for defect in chain.defects(&scenario.authority_map(), scenario.evaluation_time()) {
        if let crate::delegation::ChainDefect::AuthorityExpanded { edge_id, excesses } = &defect {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::DelegationChainNoPrivilegeAmplification,
                reason: "a delegation edge widened authority instead of preserving or narrowing it"
                    .to_owned(),
                deciding_event_digests: Vec::new(),
                principal_id: None,
                detail: Some(format!(
                    "edge `{edge_id}`: {}",
                    excesses
                        .iter()
                        .map(|excess| excess.detail.clone())
                        .collect::<Vec<String>>()
                        .join("; ")
                )),
            });
        }
    }

    violations
}

fn delegation_valid_at_use(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let Some(chain) = scenario.delegation.as_ref() else {
        return violations;
    };

    let used_edges: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::DelegationEdge(edge) => Some(edge.edge_id.as_str()),
            _ => None,
        })
        .collect();
    if used_edges.is_empty() {
        return violations;
    }

    for defect in chain.defects(&scenario.authority_map(), scenario.evaluation_time()) {
        if let crate::delegation::ChainDefect::NotValidAtUse { edge_id, detail } = &defect {
            // Only edges the run actually used can be "used while invalid".
            if used_edges.contains(&edge_id.as_str()) {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::DelegationValidAtUse,
                    reason: "a delegation edge was used outside its validity window".to_owned(),
                    deciding_event_digests: Vec::new(),
                    principal_id: None,
                    detail: Some(format!("edge `{edge_id}`: {detail}")),
                });
            }
        }
    }

    violations
}

// --- privilege ---

fn effective_within_ceiling(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let authorities = scenario.authority_map();

    for event in events {
        let IdentityObservationEvent::EffectiveAuthority(observed) = event else {
            continue;
        };

        // The ceiling is whichever the observation names, else the one the
        // principal declares. Absent both, there is nothing to compare against,
        // and the coverage contract already prevents a PASS on silence.
        let ceiling_id = observed.source_ceiling_id.clone().or_else(|| {
            scenario
                .principals
                .get(&observed.principal_id)
                .and_then(|principal| principal.authority_ceiling_id.clone())
        });
        let Some(ceiling_id) = ceiling_id else {
            continue;
        };
        let Some(ceiling) = authorities.get(&ceiling_id) else {
            continue;
        };

        let excesses = observed.authority.excess_over(ceiling);
        if !excesses.is_empty() {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::EffectiveAuthorityWithinSourceCeiling,
                reason: "the authority exercised exceeds the source ceiling".to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(observed.principal_id.clone()),
                detail: Some(format!(
                    "ceiling `{ceiling_id}`: {}",
                    excesses
                        .iter()
                        .map(|excess| excess.detail.clone())
                        .collect::<Vec<String>>()
                        .join("; ")
                )),
            });
        }
    }

    violations
}

fn credential_not_expanding(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let authorities = scenario.authority_map();

    // What each declared credential could confer if it had been delegated.
    let credential_authorities: Vec<(&str, &Authority)> = scenario
        .credential_contexts
        .iter()
        .filter_map(|credential| {
            credential
                .capability_authority_id
                .as_ref()
                .and_then(|id| authorities.get(id))
                .map(|authority| (credential.credential_context_id.as_str(), authority))
        })
        .collect();

    // The ceiling the initiating principal actually holds.
    let initiating_ceiling = scenario
        .principals
        .principal_for(PrincipalRole::Initiating)
        .and_then(|principal| principal.authority_ceiling_id.as_ref())
        .and_then(|id| authorities.get(id));

    let observed_credentials: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::CredentialContext(credential) => {
                Some(credential.credential_context_id.as_str())
            }
            _ => None,
        })
        .collect();

    if observed_credentials.is_empty() {
        return violations;
    }

    for event in events {
        let IdentityObservationEvent::EffectiveAuthority(observed) = event else {
            continue;
        };
        let Some(user_ceiling) = initiating_ceiling else {
            continue;
        };

        // The exercised authority exceeds what the user holds...
        let excess_over_user = observed.authority.excess_over(user_ceiling);
        if excess_over_user.is_empty() {
            continue;
        }

        // ...and the excess is explained by a credential that was present. That
        // is capability availability being treated as delegated authority.
        for (credential_id, capability) in &credential_authorities {
            if !observed_credentials.contains(credential_id) {
                continue;
            }
            if observed.authority.within(capability) {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::CredentialContextNotExpandAuthority,
                    reason: "authority beyond the user's ceiling was exercised within the \
                             capability of an available credential; credential availability is \
                             not delegated authority"
                        .to_owned(),
                    deciding_event_digests: digest_of(event).into_iter().collect(),
                    principal_id: Some(observed.principal_id.clone()),
                    detail: Some(format!(
                        "credential `{credential_id}` explains {} excess axis/axes over the \
                         user ceiling",
                        excess_over_user.len()
                    )),
                });
            }
        }
    }

    violations
}

// --- tenant and resource ---

fn tenant_boundary_preserved(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let authorities = scenario.authority_map();

    let resources: Vec<&crate::resource::ResourceContext> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::ResourceContext(resource) => Some(resource),
            _ => None,
        })
        .collect();
    if resources.is_empty() {
        return violations;
    }

    // The tenants the effective principal actually holds authority over.
    let effective_id = scenario.principals.bindings.effective_principal_id.as_str();
    let permitted_tenants = scenario
        .principals
        .get(effective_id)
        .and_then(|principal| principal.authority_ceiling_id.as_ref())
        .and_then(|id| authorities.get(id))
        .map(|authority| authority.tenant_ids.clone());

    for resource in &resources {
        if let Some(permitted) = &permitted_tenants {
            if !permitted.permits(&resource.tenant_id) {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::TenantBoundaryPreserved,
                    reason: "the resource belongs to a tenant the effective principal holds no \
                             authority over"
                        .to_owned(),
                    deciding_event_digests: Vec::new(),
                    principal_id: Some(effective_id.to_owned()),
                    detail: Some(format!(
                        "resource `{}` in tenant `{}`",
                        resource.resource_id, resource.tenant_id
                    )),
                });
            }
        }
    }

    // An operation naming a tenant other than the resource's own is a crossing
    // regardless of what any ceiling says.
    for event in events {
        let (IdentityObservationEvent::OperationRequest(observed)
        | IdentityObservationEvent::FinalOperation(observed)) = event
        else {
            continue;
        };
        for resource in &resources {
            if resource.resource_id == observed.operation.resource_id
                && resource.tenant_id != observed.operation.tenant_id
            {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::TenantBoundaryPreserved,
                    reason: "the operation named a tenant different from the resource's own \
                             tenant"
                        .to_owned(),
                    deciding_event_digests: digest_of(event).into_iter().collect(),
                    principal_id: Some(observed.operation.subject_id.clone()),
                    detail: Some(format!(
                        "resource tenant `{}`, operation tenant `{}`",
                        resource.tenant_id, observed.operation.tenant_id
                    )),
                });
            }
        }
    }

    violations
}

fn resource_owner_preserved(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    let declared_owner = scenario.principals.bindings.resource_owner_id.as_deref();

    for event in events {
        let IdentityObservationEvent::ResourceContext(resource) = event else {
            continue;
        };
        if let Some(declared) = declared_owner {
            if resource.owner_principal_id != declared {
                violations.push(IdentityViolation {
                    invariant: IdentityInvariantType::ResourceOwnerBoundaryPreserved,
                    reason: "the resource is owned by a principal other than the declared \
                             resource owner"
                        .to_owned(),
                    deciding_event_digests: digest_of(event).into_iter().collect(),
                    principal_id: Some(resource.owner_principal_id.clone()),
                    detail: Some(format!(
                        "declared owner `{declared}`, resource owner `{}`",
                        resource.owner_principal_id
                    )),
                });
            }
        }
    }

    violations
}

// --- authorization binding (Cycle 003 semantics) ---

fn authorization_bound(
    _scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();

    let permits: Vec<&crate::observation::AuthorizationDecisionObserved> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::AuthorizationDecision(decision)
                if decision.effect == DecisionEffect::Permit =>
            {
                Some(decision)
            }
            _ => None,
        })
        .collect();

    for event in events {
        let IdentityObservationEvent::FinalOperation(observed) = event else {
            continue;
        };
        if permits.is_empty() {
            continue;
        }

        // Semantic comparison, not byte equality: the projection excludes
        // incidental arguments, so a changed trace id keeps the permit while a
        // changed resource, action, tenant or subject does not.
        let covered = permits
            .iter()
            .any(|permit| permit.bound_operation_digest == observed.projection_digest);
        if !covered {
            let permit = permits[0];
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::AuthorizationBoundToFinalOperation,
                reason: "the operation finally performed is not the one any permit covered; the \
                         earlier decision does not apply without re-evaluation"
                    .to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(observed.operation.subject_id.clone()),
                detail: Some(format!(
                    "permit `{}` bound a different authorization-relevant projection",
                    permit.decision_id
                )),
            });
        }
    }

    violations
}

fn deny_not_bypassed(
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();

    // Operation keys denied by an observed policy decision.
    let denied_now: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            IdentityObservationEvent::PolicyDecision(decision)
                if decision.effect == DecisionEffect::Deny =>
            {
                Some(decision.operation_key.as_str())
            }
            _ => None,
        })
        .collect();

    // Operation keys the policy itself declares denied.
    let declared_denied: Vec<&str> = scenario
        .policy
        .as_ref()
        .map(|policy| {
            policy
                .denied_operation_keys
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();

    for event in events {
        let (IdentityObservationEvent::OperationRequest(observed)
        | IdentityObservationEvent::FinalOperation(observed)) = event
        else {
            continue;
        };
        let key = observed.operation.key();

        // Whole-key equality. A prefix of a denied key is not itself denied.
        if denied_now.contains(&key.as_str()) || declared_denied.contains(&key.as_str()) {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::DenyNotBypassed,
                reason: "an operation the policy denied was requested anyway".to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: Some(observed.operation.subject_id.clone()),
                detail: Some(format!("denied operation key `{key}`")),
            });
        }
    }

    // A decision that permits something the policy declares denied is a bypass
    // at the decision layer, before any operation is attempted.
    for event in events {
        let IdentityObservationEvent::PolicyDecision(decision) = event else {
            continue;
        };
        if decision.effect == DecisionEffect::Permit
            && declared_denied.contains(&decision.operation_key.as_str())
        {
            violations.push(IdentityViolation {
                invariant: IdentityInvariantType::DenyNotBypassed,
                reason: "an operation the policy declares denied was permitted".to_owned(),
                deciding_event_digests: digest_of(event).into_iter().collect(),
                principal_id: None,
                detail: Some(format!("operation key `{}`", decision.operation_key)),
            });
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::CoverageChannel as _Channel;

    #[test]
    fn the_evaluator_registry_is_total_over_the_closed_set() {
        assert_eq!(supported_invariants().len(), 12);
    }

    #[test]
    fn channels_and_invariants_stay_in_their_own_vocabularies() {
        // A sanity check that the two closed sets did not drift into each
        // other; an invariant name is never a channel name.
        let channels: Vec<&str> = _Channel::all().into_iter().map(_Channel::as_str).collect();
        for invariant in supported_invariants() {
            assert!(!channels.contains(&invariant.as_str()));
        }
    }
}
