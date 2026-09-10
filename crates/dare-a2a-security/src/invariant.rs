//! The deterministic invariant registry.
//!
//! Fourteen evaluators, each a comparison of typed fields. No model, no
//! heuristic, no prose inference and no fixture-declared verdict appears
//! anywhere in this file.
//!
//! # The order inside [`evaluate`]
//!
//! 1. a harness failure means the run could not observe, so no security
//!    conclusion is available in either direction — `ERROR`;
//! 2. violations are collected next, and **all** of them are collected. One
//!    exchange can substitute a task, widen a tenant and amplify a delegation
//!    at once, and reporting the first would understate what was seen;
//! 3. only if nothing was violated does coverage decide between `PASS` and
//!    `INCONCLUSIVE`. Checking coverage first would let an exchange with a real
//!    substitution report `INCONCLUSIVE` because some unrelated channel was
//!    missing — hiding a finding behind a gap.
//!
//! # Three answers, not two
//!
//! Every evaluator distinguishes *compared and differed* from *nothing to
//! compare*. The first is a finding; the second is a gap. An operator acts on
//! them differently: a substitution needs investigating, a gap needs evidence
//! collecting.
//!
//! # Applicable is not the same as decided
//!
//! An invariant with no subject in the evidence — replay safety in a run with
//! no repeats — is neither passed nor undecided. The question does not arise,
//! and counting it as a gap would make a clean result unreachable for any
//! deployment that does not exercise every surface at once.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::coverage::assess_coverage;
use crate::model::A2aInvariant;
use crate::observation::{A2aObservation, ObservationChannel, ObservationSet};
use crate::source::VerificationStatus;

/// One independently observed violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aViolation {
    pub invariant: A2aInvariant,
    pub reason: String,
    /// Digests of the observations that decided this violation.
    ///
    /// A finding with no deciding evidence is an assertion rather than a
    /// finding: an operator has to be able to get from the verdict back to what
    /// was observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_observation_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

impl A2aViolation {
    fn new(
        invariant: A2aInvariant,
        reason: impl Into<String>,
        deciding: &[&A2aObservation],
    ) -> Self {
        Self {
            invariant,
            reason: reason.into(),
            deciding_observation_digests: deciding
                .iter()
                .filter_map(|observation| observation.digest().ok())
                .collect(),
            peer_id: None,
            message_id: None,
        }
    }

    fn for_peer(mut self, peer_id: &str) -> Self {
        self.peer_id = Some(peer_id.to_owned());
        self
    }

    fn for_message(mut self, message_id: &str) -> Self {
        self.message_id = Some(message_id.to_owned());
        self
    }
}

/// The outcome of evaluating one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aInvariantOutcome {
    pub invariant: A2aInvariant,
    pub verdict: Verdict,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<A2aViolation>,
    pub coverage_satisfied: bool,
    /// Whether this invariant has a subject in this evidence at all.
    ///
    /// Distinct from `coverage_satisfied`, which asks whether an invariant that
    /// *does* apply could be decided. A run with a repeated transfer and no
    /// idempotency evidence is applicable and undecided; a run with no repeats
    /// is neither.
    pub applicable: bool,
}

impl A2aInvariantOutcome {
    fn pass(invariant: A2aInvariant, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Pass,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: true,
            applicable: true,
        }
    }

    fn fail(invariant: A2aInvariant, violations: Vec<A2aViolation>) -> Self {
        let reason = match violations.len() {
            1 => violations[0].reason.clone(),
            count => format!(
                "{count} independent violations of {} were observed",
                invariant.as_str()
            ),
        };
        Self {
            invariant,
            verdict: Verdict::Fail,
            reason,
            violations,
            // A failing invariant was decided by what was observed. Coverage
            // gates PASS, never FAIL: a violation seen through partial evidence
            // is still a violation, and an attacker who could hide one by
            // removing an unrelated document would have the inverse of a
            // coverage contract.
            coverage_satisfied: true,
            applicable: true,
        }
    }

    fn inconclusive(invariant: A2aInvariant, reason: impl Into<String>, applicable: bool) -> Self {
        Self {
            invariant,
            verdict: Verdict::Inconclusive,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
            applicable,
        }
    }

    fn error(invariant: A2aInvariant, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Error,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
            applicable: true,
        }
    }
}

/// Every invariant this engine implements.
pub fn supported_invariants() -> [A2aInvariant; 14] {
    A2aInvariant::all()
}

/// Evaluate one invariant against one run's observations.
pub fn evaluate(invariant: A2aInvariant, observations: &ObservationSet) -> A2aInvariantOutcome {
    use A2aInvariant as I;

    if let Some(A2aObservation::HarnessError(context)) = observations
        .observations
        .iter()
        .find(|observation| matches!(observation, A2aObservation::HarnessError(_)))
    {
        return A2aInvariantOutcome::error(
            invariant,
            format!(
                "the harness could not observe ({}): {}",
                context.kind.as_str(),
                context.reason
            ),
        );
    }

    let violations = match invariant {
        I::DiscoveryBindingPreserved => discovery_binding(observations),
        I::PeerIdentityBound => peer_identity(observations),
        I::MessageAuthenticityEstablished => message_authenticity(observations),
        I::SecurityRequirementSatisfied => security_requirement(observations),
        I::SkillAuthorized => skill_authorization(observations),
        I::MessageAuthorityBoundaryPreserved => message_authority(observations),
        I::TaskContextBindingPreserved => task_context_binding(observations),
        I::AuthorityPropagationBounded => authority_propagation(observations),
        I::TenantBoundaryPreserved => tenant_boundary(observations),
        I::DataScopeBoundaryPreserved => data_scope_boundary(observations),
        I::ReplayBoundaryPreserved => replay_boundary(observations),
        I::ProtocolNegotiationIntegrityPreserved => protocol_negotiation(observations),
        I::ExtensionTrustBoundaryPreserved => extension_trust(observations),
        I::PushNotificationBoundaryPreserved => push_notification(observations),
    };

    if !violations.is_empty() {
        return A2aInvariantOutcome::fail(invariant, violations);
    }

    let coverage = assess_coverage(invariant, observations);
    if coverage.satisfied {
        return A2aInvariantOutcome::pass(
            invariant,
            format!(
                "{} held, and the evidence needed to decide it was present",
                invariant.as_str()
            ),
        );
    }

    if !applies_to(invariant, observations) {
        return A2aInvariantOutcome::inconclusive(
            invariant,
            format!(
                "{} has no subject in this evidence, so the question does not arise",
                invariant.as_str()
            ),
            false,
        );
    }

    A2aInvariantOutcome::inconclusive(invariant, coverage.reason, true)
}

/// Whether an invariant has a subject in this evidence at all.
///
/// The distinction between *undecided* and *does not arise*. A run with no
/// repeated exchange has no replay safety to establish; reporting that as
/// undecided would make every run that happened not to retry permanently
/// inconclusive about replay, and an operator reading a wall of INCONCLUSIVE
/// learns nothing from the one that matters.
fn applies_to(invariant: A2aInvariant, observations: &ObservationSet) -> bool {
    use A2aInvariant as I;
    use ObservationChannel as C;

    match invariant {
        I::DiscoveryBindingPreserved => observations.has_channel(C::AgentCardContext),
        I::PeerIdentityBound => observations.has_channel(C::PeerIdentityContext),
        I::MessageAuthenticityEstablished
        | I::SecurityRequirementSatisfied
        | I::SkillAuthorized
        | I::TaskContextBindingPreserved
        | I::ProtocolNegotiationIntegrityPreserved => observations.has_channel(C::MessageContext),
        I::MessageAuthorityBoundaryPreserved => {
            observations.has_channel(C::MessageAuthorityContext)
        }
        I::AuthorityPropagationBounded => observations.has_channel(C::DelegationContext),
        I::TenantBoundaryPreserved => observations.has_channel(C::TenantContext),
        I::DataScopeBoundaryPreserved => observations.has_channel(C::DataScopeContext),
        I::ReplayBoundaryPreserved => observations.has_channel(C::ReplayContext),
        I::ExtensionTrustBoundaryPreserved => observations.has_channel(C::ExtensionContext),
        I::PushNotificationBoundaryPreserved => {
            observations.has_channel(C::PushNotificationContext)
        }
    }
}

/// Evaluate every invariant against one run's observations.
///
/// The scenario-selected invariant is a coverage selector, never a filter. A
/// real violation on another applicable boundary must not disappear because the
/// fixture author was looking somewhere else.
pub fn evaluate_all(observations: &ObservationSet) -> Vec<A2aInvariantOutcome> {
    supported_invariants()
        .iter()
        .map(|invariant| evaluate(*invariant, observations))
        .collect()
}

/// Every concrete violation the retained observations prove, across all
/// fourteen.
pub fn collect_observed_violations(observations: &ObservationSet) -> Vec<A2aViolation> {
    evaluate_all(observations)
        .into_iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .flat_map(|outcome| outcome.violations)
        .collect()
}

/// Combine one run's invariant outcomes into a single verdict.
///
/// `FAIL` outranks everything, because an observed violation is retained
/// evidence and a gap elsewhere does not unsee it. Then `ERROR` (the run broke)
/// outranks `INCONCLUSIVE` (the run was fine and the evidence was thin), which
/// outranks `PASS`.
///
/// Invariants with no subject in the evidence are left out entirely. A run of
/// read-only exchanges must not be reported as undecided because replay safety
/// went unanswered — that question was never raised.
pub fn aggregate(outcomes: &[A2aInvariantOutcome]) -> Verdict {
    let applicable: Vec<&A2aInvariantOutcome> = outcomes
        .iter()
        .filter(|outcome| outcome.applicable)
        .collect();

    if applicable.is_empty() {
        // Including the empty run. Nothing applied because nothing was seen,
        // and "nothing to disagree with" is not a secure exchange.
        return Verdict::Inconclusive;
    }
    for verdict in [Verdict::Fail, Verdict::Error, Verdict::Inconclusive] {
        if applicable.iter().any(|outcome| outcome.verdict == verdict) {
            return verdict;
        }
    }
    Verdict::Pass
}

// --- evaluators ------------------------------------------------------------

/// I01. The card in hand is the card policy approved.
fn discovery_binding(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::AgentCardContext(context) = observation else {
            continue;
        };

        if context.digest_matches_policy == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the Agent Card observed for `{}` is not the one the policy pinned; the \
                         card digests do not match",
                        context.peer_id
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
        if context.provider_matches_policy == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the card for `{}` names a provider the policy did not approve",
                        context.peer_id
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
        if let Some(disagreement) = &context.provider_disagreement {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the card for `{}` names provider `{}` while the observed exchange names \
                         `{}`; a discovered description is not an authenticated identity",
                        context.peer_id, disagreement.card_provider, disagreement.observed_provider
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
        // A signature that was checked and failed is a finding. One nobody
        // checked is a gap, which coverage reports.
        if context.signature_status.is_concrete_failure() {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the card signature for `{}` was verified and found invalid",
                        context.peer_id
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
        if context.signer_approved == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the card for `{}` was signed by a key the policy does not approve; a \
                         signed card is not an authorized provider",
                        context.peer_id
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
        if !context.unapproved_interfaces.is_empty() {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::DiscoveryBindingPreserved,
                    format!(
                        "the card for `{}` advertises interfaces the policy did not approve: {}",
                        context.peer_id,
                        context.unapproved_interfaces.join(", ")
                    ),
                    &[observation],
                )
                .for_peer(&context.peer_id),
            );
        }
    }
    violations
}

/// I02. The authenticated party is the intended agent, audience and tenant.
fn peer_identity(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        match observation {
            A2aObservation::PeerIdentityContext(context) => {
                if context.audience_binding.is_concrete_failure() {
                    violations.push(
                        A2aViolation::new(
                            A2aInvariant::PeerIdentityBound,
                            format!(
                                "the credential presented for `{}` was issued for another \
                                 audience; a valid credential is not one issued for this \
                                 recipient",
                                context.peer_id
                            ),
                            &[observation],
                        )
                        .for_peer(&context.peer_id),
                    );
                }
                if context.provider_binding.is_concrete_failure() {
                    violations.push(
                        A2aViolation::new(
                            A2aInvariant::PeerIdentityBound,
                            format!(
                                "the observed provider for `{}` is not the one the policy \
                                 expected",
                                context.peer_id
                            ),
                            &[observation],
                        )
                        .for_peer(&context.peer_id),
                    );
                }
                // The identity question this invariant exists for: a peer
                // naming its own logical agent is a claim, and a claim that
                // differs from what policy approved is a substitution.
                if context.logical_agent_binding.is_concrete_failure() {
                    violations.push(
                        A2aViolation::new(
                            A2aInvariant::PeerIdentityBound,
                            format!(
                                "`{}` presented itself as logical agent `{}`, which is not \
                                 the agent local policy approved for that role",
                                context.peer_id, context.logical_agent_id
                            ),
                            &[observation],
                        )
                        .for_peer(&context.peer_id),
                    );
                }
                // Service identity standing in for delegated identity. Only
                // reported where policy said this peer must act for somebody:
                // legitimate service-to-service authentication carries no
                // delegated subject and is not a finding.
                if context.delegated_identity_substituted() {
                    violations.push(
                        A2aViolation::new(
                            A2aInvariant::PeerIdentityBound,
                            format!(
                                "authentication for `{}` established the service principal \
                                 `{}` where policy requires a delegated subject; a service \
                                 account that authenticated is not the user it acts for",
                                context.peer_id,
                                context.authorization_subject.as_deref().unwrap_or("(none)")
                            ),
                            &[observation],
                        )
                        .for_peer(&context.peer_id),
                    );
                }
            }
            // A guard rather than a nested `if`: an authentication that was not
            // *checked and found invalid* produces no violation here, and
            // falling through to the wildcard says so in one place.
            A2aObservation::PeerAuthenticationContext(context)
                if context.status.is_concrete_failure() =>
            {
                violations.push(
                    A2aViolation::new(
                        A2aInvariant::PeerIdentityBound,
                        format!(
                            "authentication for `{}` was verified and found invalid",
                            context.peer_id
                        ),
                        &[observation],
                    )
                    .for_peer(&context.peer_id),
                );
            }
            _ => {}
        }
    }
    violations
}

/// I03. Authentication evidence binds the exact message received.
fn message_authenticity(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::MessageAuthenticationContext(context) = observation else {
            continue;
        };

        if context.status.is_concrete_failure() {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::MessageAuthenticityEstablished,
                    format!(
                        "the signature over message `{}` was verified and found invalid",
                        context.message_id
                    ),
                    &[observation],
                )
                .for_message(&context.message_id),
            );
        }
        // A signature over a *different* envelope is the substitution this
        // invariant exists for: valid, and covering something else.
        if context.covers_observed_envelope == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::MessageAuthenticityEstablished,
                    format!(
                        "the signature presented for message `{}` covers a different envelope \
                         than the one observed; a signature over a message is not a signature \
                         over this message",
                        context.message_id
                    ),
                    &[observation],
                )
                .for_message(&context.message_id),
            );
        }
    }
    violations
}

/// I04. The mechanism used satisfies an approved requirement.
fn security_requirement(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::SecurityRequirementContext(context) = observation else {
            continue;
        };

        if context.satisfies_card_requirement == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::SecurityRequirementSatisfied,
                    format!(
                        "message `{}` used scheme `{}`, which is not one the card requires for \
                         the skill it invoked",
                        context.message_id,
                        context.scheme_used.as_deref().unwrap_or("(none)")
                    ),
                    &[observation],
                )
                .for_message(&context.message_id),
            );
        }
        if context.kind_approved_by_policy == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::SecurityRequirementSatisfied,
                    format!(
                        "message `{}` authenticated with a scheme kind the policy does not \
                         approve for `{}`",
                        context.message_id, context.peer_id
                    ),
                    &[observation],
                )
                .for_message(&context.message_id),
            );
        }
    }
    violations
}

/// I05. The effective subject may invoke the skill that was invoked.
fn skill_authorization(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::SkillAuthorizationContext(assessment) = observation else {
            continue;
        };

        if assessment.allowed == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::SkillAuthorized,
                    format!(
                        "`{}` invoked skill `{}` on `{}`, which local policy does not grant it; \
                         authenticating is not being authorized",
                        assessment.subject.as_deref().unwrap_or("(no subject)"),
                        assessment.skill_id.as_deref().unwrap_or("(no skill)"),
                        assessment.peer_id
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
        // Invoking something the peer never advertised is a different fact from
        // invoking something it has and the subject may not use.
        if assessment.skill_advertised == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::SkillAuthorized,
                    format!(
                        "message `{}` invoked skill `{}`, which the peer's card never advertises",
                        assessment.message_id,
                        assessment.skill_id.as_deref().unwrap_or("(no skill)")
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
    }
    violations
}

/// I06. Peer-controlled content stayed data.
fn message_authority(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::MessageAuthorityContext(context) = observation else {
            continue;
        };
        if !context.content_became_instruction {
            continue;
        }
        violations.push(
            A2aViolation::new(
                A2aInvariant::MessageAuthorityBoundaryPreserved,
                format!(
                    "peer-controlled content from `{}` in message `{}` reached a position where \
                     it could direct behaviour (parts: {}); an authentic message is not an \
                     authorized instruction",
                    context.peer_id,
                    context.message_id,
                    context.crossing_part_ids.join(", ")
                ),
                &[observation],
            )
            .for_message(&context.message_id),
        );
    }
    violations
}

/// I07. Task, context and initiating principal stayed the same.
fn task_context_binding(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::TaskContextBindingContext(context) = observation else {
            continue;
        };

        if context.context_ids.len() > 1 {
            violations.push(A2aViolation::new(
                A2aInvariant::TaskContextBindingPreserved,
                format!(
                    "task `{}` carries {} different context ids ({}); a matching task id is not \
                     a matching context",
                    context.task_id,
                    context.context_ids.len(),
                    context
                        .context_ids
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &[observation],
            ));
        }
        if context.initiating_principals.len() > 1 {
            violations.push(A2aViolation::new(
                A2aInvariant::TaskContextBindingPreserved,
                format!(
                    "task `{}` was initiated by {} different principals ({}); a matching task id \
                     is not a matching principal",
                    context.task_id,
                    context.initiating_principals.len(),
                    context
                        .initiating_principals
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// I08. Authority held or narrowed across every hop.
fn authority_propagation(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::DelegationContext(context) = observation else {
            continue;
        };

        for amplification in &context.amplifications {
            violations.push(A2aViolation::new(
                A2aInvariant::AuthorityPropagationBounded,
                format!(
                    "delegation chain `{}` widened the {} at hop `{}` relative to `{}`; \
                     delegation may hold or narrow and never widen",
                    context.chain_id,
                    amplification.kind.as_str(),
                    amplification.hop_id,
                    amplification.upstream_hop_id
                ),
                &[observation],
            ));
        }
        if !context.is_connected {
            violations.push(A2aViolation::new(
                A2aInvariant::AuthorityPropagationBounded,
                format!(
                    "delegation chain `{}` has a hop whose grantor is not the previous hop's \
                     grantee; authority does not flow through a break",
                    context.chain_id
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// I09. The exchange stayed inside the approved tenant.
fn tenant_boundary(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::TenantContext(assessment) = observation else {
            continue;
        };

        if assessment.claim_matches_policy == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::TenantBoundaryPreserved,
                    format!(
                        "message `{}` claims tenant `{}` while policy places the subject in \
                         `{}`; a routing value is not proof of tenant authorization",
                        assessment.message_id,
                        assessment.claimed_tenant.as_deref().unwrap_or("(none)"),
                        assessment.policy_tenant.as_deref().unwrap_or("(none)")
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
        if assessment.tenant_may_reach_peer == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::TenantBoundaryPreserved,
                    format!(
                        "tenant `{}` is not permitted to reach peer `{}`",
                        assessment.policy_tenant.as_deref().unwrap_or("(none)"),
                        assessment.peer_id
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
    }
    violations
}

/// I10. Disclosure stayed inside what policy allowed.
fn data_scope_boundary(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::DataScopeContext(assessment) = observation else {
            continue;
        };
        if assessment.within_ceiling != Some(false) {
            continue;
        }
        violations.push(
            A2aViolation::new(
                A2aInvariant::DataScopeBoundaryPreserved,
                format!(
                    "message `{}` carries {:?} data to `{}`, whose ceiling is {:?}",
                    assessment.message_id,
                    assessment.peak_sensitivity,
                    assessment.peer_id,
                    assessment.peer_ceiling
                ),
                &[observation],
            )
            .for_message(&assessment.message_id),
        );
    }
    violations
}

/// I11. A repeated action was proven safe to repeat.
fn replay_boundary(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::ReplayContext(assessment) = observation else {
            continue;
        };
        if assessment.replay_is_safe != Some(false) {
            continue;
        }
        violations.push(
            A2aViolation::new(
                A2aInvariant::ReplayBoundaryPreserved,
                format!(
                    "message `{}` repeats a {} operation with no idempotency key and no policy \
                     declaring it safe to repeat; a retry is not a safe replay",
                    assessment.message_id,
                    assessment.operation_effect.as_str()
                ),
                &[observation],
            )
            .for_message(&assessment.message_id),
        );
    }
    violations
}

/// I12. The version and interface used were ones policy permits.
fn protocol_negotiation(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::ProtocolContext(assessment) = observation else {
            continue;
        };

        if assessment.version_approved == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::ProtocolNegotiationIntegrityPreserved,
                    format!(
                        "message `{}` used protocol version `{}`, which policy does not approve",
                        assessment.message_id, assessment.used_version
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        } else if assessment.below_minimum == Some(true) {
            // Reported separately from approval, because a downgrade *within*
            // the approved set is still a downgrade and an operator wants to
            // know which of the two happened.
            violations.push(
                A2aViolation::new(
                    A2aInvariant::ProtocolNegotiationIntegrityPreserved,
                    format!(
                        "message `{}` used protocol version `{}`, below the policy floor; \
                         compatibility with a version is not permission to use it",
                        assessment.message_id, assessment.used_version
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
        if assessment.transport_approved == Some(false) {
            violations.push(
                A2aViolation::new(
                    A2aInvariant::ProtocolNegotiationIntegrityPreserved,
                    format!(
                        "message `{}` used transport {}, which policy does not approve",
                        assessment.message_id,
                        assessment.used_transport.as_str()
                    ),
                    &[observation],
                )
                .for_message(&assessment.message_id),
            );
        }
    }
    violations
}

/// I13. Extensions in use were declared, approved and non-authoritative.
fn extension_trust(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::ExtensionContext(assessment) = observation else {
            continue;
        };
        if assessment.is_safe_to_interpret() {
            continue;
        }

        let reason = if !assessment.declared {
            format!(
                "extension `{}` was used but the card never declares it",
                assessment.extension_id
            )
        } else if !assessment.approved {
            format!(
                "extension `{}` is declared and local policy does not approve it{}",
                assessment.extension_id,
                if assessment.required {
                    "; a required extension nobody approved cannot be interpreted safely"
                } else {
                    ""
                }
            )
        } else {
            format!(
                "extension `{}` claims to affect authorization and policy approved it to run but \
                 not to decide; a declaration is not authority",
                assessment.extension_id
            )
        };

        violations.push(A2aViolation::new(
            A2aInvariant::ExtensionTrustBoundaryPreserved,
            reason,
            &[observation],
        ));
    }
    violations
}

/// I14. A callback configuration discloses no further than approved.
fn push_notification(observations: &ObservationSet) -> Vec<A2aViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let A2aObservation::PushNotificationContext(assessment) = observation else {
            continue;
        };

        if assessment.destination_approved == Some(false) {
            violations.push(A2aViolation::new(
                A2aInvariant::PushNotificationBoundaryPreserved,
                format!(
                    "push configuration `{}` names a destination policy did not approve; the \
                     destination was compared as a string and nothing was contacted",
                    assessment.config_id
                ),
                &[observation],
            ));
        }
        if assessment.within_sensitivity_ceiling == Some(false) {
            violations.push(A2aViolation::new(
                A2aInvariant::PushNotificationBoundaryPreserved,
                format!(
                    "push configuration `{}` would send data more sensitive than policy allows \
                     for a callback",
                    assessment.config_id
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Whether a status may satisfy a positive PASS condition.
///
/// Re-exported for the CLI and the corpus, so nothing outside this crate has to
/// re-derive it — and so no caller can accidentally accept `INDETERMINATE`.
pub fn status_may_pass(status: VerificationStatus) -> bool {
    status.may_satisfy_positive_evidence()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::tests::evidence;
    use crate::observation::{project, HarnessErrorContext};
    use crate::source::{DataSensitivity, HarnessErrorKind, OperationEffect};
    use std::collections::BTreeSet;

    fn observe(evidence: &crate::normalize::A2aEvidence) -> ObservationSet {
        project(evidence)
    }

    #[test]
    fn a_compliant_bundle_passes_the_invariants_its_evidence_can_decide() {
        let observations = observe(&evidence());
        let outcomes = evaluate_all(&observations);
        let failed: Vec<&str> = outcomes
            .iter()
            .filter(|outcome| outcome.verdict == Verdict::Fail)
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert!(failed.is_empty(), "a compliant bundle failed {failed:?}");

        for invariant in [
            A2aInvariant::DiscoveryBindingPreserved,
            A2aInvariant::PeerIdentityBound,
            A2aInvariant::MessageAuthenticityEstablished,
            A2aInvariant::SkillAuthorized,
            A2aInvariant::TenantBoundaryPreserved,
            A2aInvariant::TaskContextBindingPreserved,
        ] {
            let outcome = evaluate(invariant, &observations);
            assert_eq!(
                outcome.verdict,
                Verdict::Pass,
                "{}: {}",
                invariant.as_str(),
                outcome.reason
            );
        }
        assert_eq!(aggregate(&outcomes), Verdict::Pass);
    }

    #[test]
    fn an_empty_run_is_inconclusive_and_never_passes() {
        // The cheapest false PASS available: hand the engine an empty trace and
        // let every invariant find nothing to disagree with.
        let outcomes = evaluate_all(&ObservationSet::default());
        for outcome in &outcomes {
            assert_eq!(
                outcome.verdict,
                Verdict::Inconclusive,
                "{} passed on an empty run",
                outcome.invariant.as_str()
            );
        }
        assert_eq!(aggregate(&outcomes), Verdict::Inconclusive);
    }

    #[test]
    fn a_harness_error_is_an_error_and_not_a_finding() {
        let set = ObservationSet::new(vec![A2aObservation::HarnessError(HarnessErrorContext {
            kind: HarnessErrorKind::DocumentRefused,
            reason: "a document exceeded the byte budget".to_owned(),
        })]);
        for outcome in evaluate_all(&set) {
            assert_eq!(outcome.verdict, Verdict::Error);
            assert!(outcome.violations.is_empty());
        }
    }

    #[test]
    fn an_invariant_with_no_subject_is_inapplicable_rather_than_undecided() {
        // A run of read-only exchanges raises no replay question. Marking it
        // undecided would make every run that happened not to retry permanently
        // inconclusive about replay.
        let outcomes = evaluate_all(&observe(&evidence()));
        let inapplicable: BTreeSet<&str> = outcomes
            .iter()
            .filter(|outcome| !outcome.applicable)
            .map(|outcome| outcome.invariant.as_str())
            .collect();

        assert!(inapplicable.contains("REPLAY_BOUNDARY_PRESERVED"));
        assert!(inapplicable.contains("PUSH_NOTIFICATION_BOUNDARY_PRESERVED"));
        for outcome in &outcomes {
            if inapplicable.contains(outcome.invariant.as_str()) {
                assert!(
                    outcome.reason.contains("does not arise"),
                    "{} says nothing about why it was skipped",
                    outcome.invariant.as_str()
                );
            }
        }
    }

    #[test]
    fn a_substituted_card_fails_discovery_and_cites_its_evidence() {
        let mut substituted = evidence();
        substituted.cards[0].provider = Some("attacker".to_owned());
        let outcome = evaluate(
            A2aInvariant::DiscoveryBindingPreserved,
            &observe(&substituted),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(!outcome.violations[0]
            .deciding_observation_digests
            .is_empty());
    }

    #[test]
    fn an_invalid_card_signature_fails_and_an_unrecorded_one_does_not() {
        // A signature that was checked and failed is a finding. One nobody
        // checked is a gap, and reporting it as a finding would make every
        // unsigned card look like an attack.
        let mut invalid = evidence();
        invalid.cards[0].signature.as_mut().unwrap().status = VerificationStatus::Invalid;
        assert_eq!(
            evaluate(A2aInvariant::DiscoveryBindingPreserved, &observe(&invalid)).verdict,
            Verdict::Fail
        );

        let mut unrecorded = evidence();
        unrecorded.cards[0].signature = None;
        let outcome = evaluate(
            A2aInvariant::DiscoveryBindingPreserved,
            &observe(&unrecorded),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn a_signature_over_a_different_envelope_fails_message_authenticity() {
        // Valid, and covering something else. The substitution this invariant
        // exists for.
        let mut substituted = evidence();
        substituted.message_authentication[0].covered_envelope_digest =
            Some(crate::canonical::digest_bytes(b"another-envelope"));
        let outcome = evaluate(
            A2aInvariant::MessageAuthenticityEstablished,
            &observe(&substituted),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0]
            .reason
            .contains("not a signature over this message"));
    }

    #[test]
    fn an_unauthorized_skill_fails_and_names_the_subject() {
        let mut unauthorized = evidence();
        unauthorized.peers.peers[0].delegated_subject = Some("user-mallory".to_owned());
        let outcome = evaluate(A2aInvariant::SkillAuthorized, &observe(&unauthorized));
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("user-mallory"));
    }

    #[test]
    fn peer_content_reaching_authority_fails_and_names_the_parts() {
        // "The message crossed a boundary" is not actionable. "Part part-1 from
        // planner directed behaviour" is.
        let mut crossed = evidence();
        crossed.exchanges.exchanges[0].parts[0].treated_as_instruction = true;
        let outcome = evaluate(
            A2aInvariant::MessageAuthorityBoundaryPreserved,
            &observe(&crossed),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("part-1"));
    }

    #[test]
    fn a_task_carrying_two_contexts_fails_context_binding() {
        let mut substituted = evidence();
        let mut second = substituted.exchanges.exchanges[0].clone();
        second.message_id = "msg-2".to_owned();
        second.context_id = Some("context-2".to_owned());
        substituted.exchanges.exchanges.push(second);

        let outcome = evaluate(
            A2aInvariant::TaskContextBindingPreserved,
            &observe(&substituted),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0]
            .reason
            .contains("not a matching context"));
    }

    #[test]
    fn a_widened_delegation_fails_and_names_the_hop_and_dimension() {
        let mut widened = evidence();
        widened.delegation_chains[0].hops[1]
            .allowed_skills
            .insert("transfer-funds".to_owned());
        let outcome = evaluate(
            A2aInvariant::AuthorityPropagationBounded,
            &observe(&widened),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("SKILLS"));
        assert!(outcome.violations[0].reason.contains("hop-2"));
    }

    #[test]
    fn a_cross_tenant_claim_fails_and_names_both_tenants() {
        let mut crossing = evidence();
        crossing.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());
        let outcome = evaluate(A2aInvariant::TenantBoundaryPreserved, &observe(&crossing));
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("tenant-b"));
        assert!(outcome.violations[0].reason.contains("tenant-a"));
    }

    #[test]
    fn a_widened_data_scope_fails() {
        let mut widened = evidence();
        widened.exchanges.exchanges[0].parts[0].data_labels =
            BTreeSet::from([DataSensitivity::Restricted]);
        assert_eq!(
            evaluate(A2aInvariant::DataScopeBoundaryPreserved, &observe(&widened)).verdict,
            Verdict::Fail
        );
    }

    #[test]
    fn a_repeat_with_no_replay_evidence_fails_and_a_read_repeat_does_not() {
        let mut unproven = evidence();
        unproven.exchanges.exchanges[0].is_repeat = true;
        unproven.exchanges.exchanges[0].operation_effect =
            OperationEffect::NonIdempotentStateChange;
        unproven.exchanges.exchanges[0].requested_skill = Some("transfer-funds".to_owned());
        assert_eq!(
            evaluate(A2aInvariant::ReplayBoundaryPreserved, &observe(&unproven)).verdict,
            Verdict::Fail
        );

        let mut read_repeat = evidence();
        read_repeat.exchanges.exchanges[0].is_repeat = true;
        read_repeat.exchanges.exchanges[0].operation_effect = OperationEffect::ReadOnly;
        let outcome = evaluate(
            A2aInvariant::ReplayBoundaryPreserved,
            &observe(&read_repeat),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn a_downgraded_protocol_version_fails() {
        let mut downgraded = evidence();
        downgraded.exchanges.exchanges[0].protocol_version = "0.9.0".to_owned();
        let outcome = evaluate(
            A2aInvariant::ProtocolNegotiationIntegrityPreserved,
            &observe(&downgraded),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn a_required_unapproved_extension_fails() {
        let mut hostile = evidence();
        hostile.cards[0].extensions = vec![crate::agent_card::CardExtension {
            extension_id: "ext-unknown".to_owned(),
            required: true,
            claims_authority: false,
        }];
        let outcome = evaluate(
            A2aInvariant::ExtensionTrustBoundaryPreserved,
            &observe(&hostile),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0]
            .reason
            .contains("cannot be interpreted safely"));
    }

    #[test]
    fn an_unapproved_push_destination_fails_without_contacting_anything() {
        let mut hostile = evidence();
        hostile.push_configs = vec![crate::push_notification::tests::config(
            "https://attacker.example/collect",
        )];
        let outcome = evaluate(
            A2aInvariant::PushNotificationBoundaryPreserved,
            &observe(&hostile),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0]
            .reason
            .contains("nothing was contacted"));
    }

    #[test]
    fn every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets() {
        // A corpus built around one question must still notice the answer to a
        // second, or a fixture author's focus becomes the engine's field of
        // view.
        let mut multi = evidence();
        multi.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());
        multi.exchanges.exchanges[0].parts[0].treated_as_instruction = true;
        multi.delegation_chains[0].hops[1]
            .allowed_skills
            .insert("transfer-funds".to_owned());

        let invariants: BTreeSet<&str> = collect_observed_violations(&observe(&multi))
            .iter()
            .map(|violation| violation.invariant.as_str())
            .collect();

        assert!(invariants.contains("TENANT_BOUNDARY_PRESERVED"));
        assert!(invariants.contains("MESSAGE_AUTHORITY_BOUNDARY_PRESERVED"));
        assert!(invariants.contains("AUTHORITY_PROPAGATION_BOUNDED"));
        assert!(invariants.len() >= 3, "{invariants:?}");
    }

    #[test]
    fn a_secondary_gap_does_not_erase_a_primary_failure() {
        let mut failing = evidence();
        failing.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());
        let outcomes = evaluate_all(&observe(&failing));

        assert!(outcomes
            .iter()
            .any(|outcome| outcome.verdict == Verdict::Inconclusive));
        assert_eq!(aggregate(&outcomes), Verdict::Fail);
    }

    #[test]
    fn a_failure_outranks_a_later_harness_error() {
        // An observed violation is retained evidence, and a run that broke
        // afterwards does not unsee it.
        let outcomes = vec![
            A2aInvariantOutcome::fail(
                A2aInvariant::TenantBoundaryPreserved,
                vec![A2aViolation {
                    invariant: A2aInvariant::TenantBoundaryPreserved,
                    reason: "a tenant claim differed".to_owned(),
                    deciding_observation_digests: vec!["sha256:x".to_owned()],
                    peer_id: None,
                    message_id: None,
                }],
            ),
            A2aInvariantOutcome::error(
                A2aInvariant::ReplayBoundaryPreserved,
                "the harness could not observe",
            ),
        ];
        assert_eq!(aggregate(&outcomes), Verdict::Fail);
    }

    #[test]
    fn coverage_gates_pass_and_never_gates_fail() {
        // A violation seen through partial evidence is still a violation. If
        // coverage gated FAIL, an attacker could hide a finding by removing an
        // unrelated document.
        let mut failing = evidence();
        failing.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());
        failing.cards.clear();
        let outcome = evaluate(A2aInvariant::TenantBoundaryPreserved, &observe(&failing));
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.coverage_satisfied);
    }

    #[test]
    fn no_violation_reads_as_prose_inference() {
        // Every reason names a peer, a message, an id or a concrete difference.
        // A reason that could have been written without looking at the evidence
        // is the shape a model-generated verdict takes.
        let mut failing = evidence();
        failing.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());
        failing.exchanges.exchanges[0].parts[0].treated_as_instruction = true;
        for violation in collect_observed_violations(&observe(&failing)) {
            assert!(
                violation.reason.contains('`'),
                "a violation names nothing concrete: {}",
                violation.reason
            );
            assert!(!violation.deciding_observation_digests.is_empty());
        }
    }

    #[test]
    fn the_fourteen_evaluators_are_all_reachable() {
        // A registry entry with no evaluator behind it would report PASS or
        // INCONCLUSIVE forever and look like a covered risk.
        assert_eq!(supported_invariants().len(), 14);
        let evaluated: BTreeSet<&str> = evaluate_all(&observe(&evidence()))
            .iter()
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert_eq!(evaluated.len(), 14);
    }

    #[test]
    fn an_indeterminate_status_never_satisfies_positive_evidence() {
        // A verifier saying it could not tell is not this engine's confidence.
        assert!(status_may_pass(VerificationStatus::Valid));
        assert!(!status_may_pass(VerificationStatus::Indeterminate));
        assert!(!status_may_pass(VerificationStatus::Unrecorded));
        assert!(!status_may_pass(VerificationStatus::Invalid));
    }
}
