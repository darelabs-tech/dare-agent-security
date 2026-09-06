//! Cycle 015 deterministic invariant evaluators, exercised end to end.
//!
//! Each of the twelve invariants is driven through the three outcomes that
//! matter: it PASSes when the boundary held and the evidence was present, it
//! FAILs on a typed observed fact, and it reports INCONCLUSIVE when the
//! evidence its contract requires was never observed.
//!
//! Nothing here reads prose. Every verdict below is decided by comparing typed
//! fields, which is the property that makes the engine reproducible.

use dare_identity_security::authority::{Authority, AuthorityDimension};
use dare_identity_security::authorization::DecisionEffect;
use dare_identity_security::invariant::evaluate;
use dare_identity_security::model::{IdentityInvariantType, IdentitySecurityScenario};
use dare_identity_security::observation::{
    AuthorizationDecisionObserved, CredentialContextObserved, DelegationAssertion,
    DelegationEdgeObserved, EffectiveAuthorityObserved, EvidenceText, HarnessErrorEvent,
    HarnessErrorKind, IdentityObservationEvent, OperationObserved, PolicyDecisionObserved,
    PrincipalContext,
};
use dare_identity_security::operation::Operation;
use dare_identity_security::resource::ResourceContext;
use dare_identity_security::schema::validate_scenario_document;
use dare_identity_security::source::{DelegationKind, PrincipalKind, PrincipalRole};
use dare_identity_security::Verdict;

// --- fixture helpers ---

fn scenario() -> IdentitySecurityScenario {
    let raw = include_str!("fixtures/scenario.json");
    let value: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
    validate_scenario_document(&value).expect("fixture validates against the schema");
    let scenario: IdentitySecurityScenario =
        serde_json::from_value(value).expect("fixture decodes");
    scenario.validate().expect("fixture is structurally valid");
    scenario
}

fn authority(scenario: &IdentitySecurityScenario, id: &str) -> Authority {
    scenario
        .require_authority(id, "test")
        .expect("authority present")
        .clone()
}

fn principal_event(role: PrincipalRole, id: &str, kind: PrincipalKind) -> IdentityObservationEvent {
    IdentityObservationEvent::PrincipalContext(PrincipalContext {
        role,
        principal_id: id.to_owned(),
        kind,
        tenant_id: Some("tenant-a".to_owned()),
    })
}

fn operation(subject: &str, action: &str, resource: &str, tenant: &str) -> Operation {
    serde_json::from_value(serde_json::json!({
        "operation_id": "op-1",
        "subject_id": subject,
        "action": action,
        "resource_id": resource,
        "resource_type": "document",
        "tenant_id": tenant,
        "objective_id": "objective-summarize-ticket",
        "authorization_relevant_arguments": {"field_set": "summary"},
        "incidental_arguments": {"trace_id": "trace-001"}
    }))
    .expect("operation decodes")
}

fn observed(operation: Operation, is_final: bool) -> IdentityObservationEvent {
    let projection_digest = operation.projection_digest().expect("digest");
    let record = OperationObserved {
        operation,
        projection_digest,
        dispatched: false,
    };
    if is_final {
        IdentityObservationEvent::FinalOperation(record)
    } else {
        IdentityObservationEvent::OperationRequest(record)
    }
}

fn effective_authority(
    principal: &str,
    authority: Authority,
    ceiling: &str,
) -> IdentityObservationEvent {
    IdentityObservationEvent::EffectiveAuthority(EffectiveAuthorityObserved {
        principal_id: principal.to_owned(),
        authority,
        source_ceiling_id: Some(ceiling.to_owned()),
    })
}

fn edge_event(ceiling: &str, subject: Option<&str>) -> IdentityObservationEvent {
    IdentityObservationEvent::DelegationEdge(DelegationEdgeObserved {
        edge_id: "edge-user-to-agent".to_owned(),
        kind: DelegationKind::OnBehalfOf,
        delegator_principal_id: "user-7".to_owned(),
        delegatee_principal_id: "agent-1".to_owned(),
        delegated_subject_id: subject.map(str::to_owned),
        authority_ceiling_id: ceiling.to_owned(),
    })
}

fn permit(digest: &str) -> IdentityObservationEvent {
    IdentityObservationEvent::AuthorizationDecision(AuthorizationDecisionObserved {
        decision_id: "decision-1".to_owned(),
        effect: DecisionEffect::Permit,
        subject_id: "user-7".to_owned(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
        bound_operation_digest: digest.to_owned(),
        issued_at: Some(150),
    })
}

fn verdict(
    invariant: IdentityInvariantType,
    scenario: &IdentitySecurityScenario,
    events: &[IdentityObservationEvent],
) -> Verdict {
    evaluate(invariant, scenario, events).verdict
}

// --- the rule that governs the whole cycle ---

#[test]
fn silence_is_inconclusive_for_every_invariant_never_pass() {
    let scenario = scenario();
    for invariant in dare_identity_security::supported_invariants() {
        let outcome = evaluate(invariant, &scenario, &[]);
        assert_eq!(
            outcome.verdict,
            Verdict::Inconclusive,
            "{} must be inconclusive on an empty stream",
            invariant.as_str()
        );
        assert!(!outcome.coverage_satisfied);
        assert!(outcome.violations.is_empty());
    }
}

#[test]
fn a_harness_failure_is_error_for_every_invariant_never_fail() {
    // Failing to look is not the same as finding something.
    let scenario = scenario();
    let events = vec![IdentityObservationEvent::HarnessError(HarnessErrorEvent {
        kind: HarnessErrorKind::AdapterFailure,
        detail: EvidenceText::from_raw("adapter stopped"),
    })];
    for invariant in dare_identity_security::supported_invariants() {
        let outcome = evaluate(invariant, &scenario, &events);
        assert_eq!(
            outcome.verdict,
            Verdict::Error,
            "{} must be ERROR when the harness failed",
            invariant.as_str()
        );
        assert!(outcome.violations.is_empty());
    }
}

// --- principal binding ---

#[test]
fn the_initiating_principal_is_preserved_when_the_user_stays_the_subject() {
    let scenario = scenario();
    let events = vec![
        principal_event(PrincipalRole::Initiating, "user-7", PrincipalKind::Human),
        principal_event(PrincipalRole::Effective, "user-7", PrincipalKind::Human),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::InitiatingPrincipalPreserved,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn a_substituted_initiating_principal_fails() {
    let scenario = scenario();
    let events = vec![
        principal_event(
            PrincipalRole::Initiating,
            "svc-index",
            PrincipalKind::Service,
        ),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::InitiatingPrincipalPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(
        outcome.violations[0].principal_id.as_deref(),
        Some("svc-index")
    );
}

#[test]
fn an_operation_under_an_unrelated_subject_fails() {
    // Neither the initiating principal nor a delegated subject.
    let scenario = scenario();
    let events = vec![
        principal_event(PrincipalRole::Initiating, "user-7", PrincipalKind::Human),
        observed(
            operation("svc-index", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::InitiatingPrincipalPreserved,
            &scenario,
            &events
        ),
        Verdict::Fail
    );
}

#[test]
fn naming_a_principal_without_exercising_authority_is_inconclusive() {
    // Seeing who someone is does not show what they did.
    let scenario = scenario();
    let events = vec![principal_event(
        PrincipalRole::Initiating,
        "user-7",
        PrincipalKind::Human,
    )];
    let outcome = evaluate(
        IdentityInvariantType::InitiatingPrincipalPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Inconclusive);
    assert!(outcome.reason.contains("exercised"));
}

#[test]
fn the_agent_acting_as_itself_for_a_user_request_fails() {
    let scenario = scenario();
    let events = vec![
        principal_event(PrincipalRole::Effective, "agent-1", PrincipalKind::Agent),
        observed(
            operation("agent-1", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::AgentAuthorityNotSubstitutedForUser,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .reason
        .contains("agent principal became"));
}

#[test]
fn a_service_identity_acting_as_the_effective_principal_fails() {
    // Credential availability is not delegated authority, stated as a verdict.
    let scenario = scenario();
    let events = vec![
        principal_event(
            PrincipalRole::Effective,
            "svc-index",
            PrincipalKind::Service,
        ),
        observed(
            operation("svc-index", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::AgentAuthorityNotSubstitutedForUser,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0].reason.contains("technical identity"));
}

// --- delegation ---

#[test]
fn a_delegation_carrying_its_subject_passes() {
    let scenario = scenario();
    let events = vec![edge_event("authority-agent-read", Some("user-7"))];
    assert_eq!(
        verdict(
            IdentityInvariantType::DelegatedSubjectPreserved,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn an_on_behalf_of_edge_that_changes_its_subject_fails() {
    let scenario = scenario();
    let events = vec![edge_event("authority-agent-read", Some("svc-index"))];
    let outcome = evaluate(
        IdentityInvariantType::DelegatedSubjectPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert_eq!(
        outcome.violations[0].principal_id.as_deref(),
        Some("svc-index")
    );
}

#[test]
fn a_delegation_asserted_but_not_declared_fails() {
    // An assertion nothing backs is a claim, not a delegation.
    let scenario = scenario();
    let events = vec![IdentityObservationEvent::DelegationAssertion(
        DelegationAssertion {
            asserted_by_principal_id: "agent-1".to_owned(),
            delegated_subject_id: Some("user-7".to_owned()),
            purpose_id: None,
            backed_by_declared_chain: false,
        },
    )];
    let outcome = evaluate(
        IdentityInvariantType::DelegatedSubjectPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0].reason.contains("does not contain"));
}

#[test]
fn authority_within_the_delegated_ceiling_passes() {
    let scenario = scenario();
    let mut exercised = authority(&scenario, "authority-agent-read");
    exercised.id = "authority-exercised".to_owned();

    let events = vec![
        edge_event("authority-agent-read", Some("user-7")),
        effective_authority("agent-1", exercised, "authority-agent-read"),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::DelegationScopeNotExceeded,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn authority_beyond_every_delegated_ceiling_fails() {
    let scenario = scenario();
    let mut exercised = authority(&scenario, "authority-agent-read");
    exercised.id = "authority-exercised".to_owned();
    exercised.actions = AuthorityDimension::only(["read", "delete"]);

    let events = vec![
        edge_event("authority-agent-read", Some("user-7")),
        effective_authority("agent-1", exercised, "authority-agent-read"),
    ];
    let outcome = evaluate(
        IdentityInvariantType::DelegationScopeNotExceeded,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .detail
        .as_ref()
        .expect("detail")
        .contains("ACTIONS"));
}

#[test]
fn a_chain_that_narrows_shows_no_amplification() {
    let scenario = scenario();
    let events = vec![edge_event("authority-agent-read", Some("user-7"))];
    assert_eq!(
        verdict(
            IdentityInvariantType::DelegationChainNoPrivilegeAmplification,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn a_delegation_used_inside_its_window_passes_and_outside_it_fails() {
    let mut scenario = scenario();
    let events = vec![edge_event("authority-agent-read", Some("user-7"))];

    // The fixture evaluates at tick 150, inside the 100..200 window.
    assert_eq!(
        verdict(
            IdentityInvariantType::DelegationValidAtUse,
            &scenario,
            &events
        ),
        Verdict::Pass
    );

    scenario.evaluation_time = Some(250);
    let outcome = evaluate(
        IdentityInvariantType::DelegationValidAtUse,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .detail
        .as_ref()
        .expect("detail")
        .contains("expired"));
}

#[test]
fn a_not_yet_valid_delegation_also_fails() {
    let mut scenario = scenario();
    scenario.evaluation_time = Some(50);
    let events = vec![edge_event("authority-agent-read", Some("user-7"))];
    let outcome = evaluate(
        IdentityInvariantType::DelegationValidAtUse,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .detail
        .as_ref()
        .expect("detail")
        .contains("not yet valid"));
}

// --- privilege ---

#[test]
fn effective_authority_within_the_source_ceiling_passes() {
    let scenario = scenario();
    let mut exercised = authority(&scenario, "authority-user-read");
    exercised.id = "authority-exercised".to_owned();
    exercised.actions = AuthorityDimension::only(["read"]);

    let events = vec![effective_authority(
        "user-7",
        exercised,
        "authority-user-read",
    )];
    assert_eq!(
        verdict(
            IdentityInvariantType::EffectiveAuthorityWithinSourceCeiling,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn a_read_only_user_exercising_admin_authority_fails() {
    // IDENTITY-LAB-006 in miniature: the runtime has admin capability, the user
    // does not, and the user's operation must not inherit it.
    let scenario = scenario();
    let mut exercised = authority(&scenario, "authority-service-admin");
    exercised.id = "authority-exercised".to_owned();

    let events = vec![effective_authority(
        "user-7",
        exercised,
        "authority-user-read",
    )];
    let outcome = evaluate(
        IdentityInvariantType::EffectiveAuthorityWithinSourceCeiling,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .reason
        .contains("exceeds the source ceiling"));
}

#[test]
fn an_available_credential_does_not_expand_authority() {
    let scenario = scenario();
    let mut exercised = authority(&scenario, "authority-user-read");
    exercised.id = "authority-exercised".to_owned();

    let credential = IdentityObservationEvent::CredentialContext(CredentialContextObserved {
        credential_context_id: "cred-index-admin".to_owned(),
        owner_principal_id: "svc-index".to_owned(),
        capability_labels: vec!["index.admin".to_owned()],
        tenant_labels: vec!["tenant-a".to_owned(), "tenant-b".to_owned()],
        capability_authority: None,
    });

    // Staying inside the user's ceiling while the credential is present: the
    // credential existing is not itself a violation.
    let events = vec![
        credential.clone(),
        effective_authority("user-7", exercised, "authority-user-read"),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::CredentialContextNotExpandAuthority,
            &scenario,
            &events
        ),
        Verdict::Pass
    );

    // Exercising the credential's capability beyond the user's ceiling is.
    let mut amplified = authority(&scenario, "authority-service-admin");
    amplified.id = "authority-exercised".to_owned();
    let events = vec![
        credential,
        effective_authority("user-7", amplified, "authority-user-read"),
    ];
    let outcome = evaluate(
        IdentityInvariantType::CredentialContextNotExpandAuthority,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .reason
        .contains("credential availability is not delegated authority"));
}

// --- tenant and resource owner ---

#[test]
fn a_same_tenant_resource_passes() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-123".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_principal_id: "user-7".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::TenantBoundaryPreserved,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn a_cross_tenant_resource_fails() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-999".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-b".to_owned(),
            owner_principal_id: "user-7".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-999", "tenant-b"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::TenantBoundaryPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0].reason.contains("holds no"));
}

#[test]
fn an_operation_naming_a_different_tenant_than_its_resource_fails() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-123".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_principal_id: "user-7".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-b"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::TenantBoundaryPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
}

#[test]
fn the_correct_resource_owner_passes_and_the_wrong_one_fails() {
    let scenario = scenario();
    let owned = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-123".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_principal_id: "user-7".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    assert_eq!(
        verdict(
            IdentityInvariantType::ResourceOwnerBoundaryPreserved,
            &scenario,
            &owned
        ),
        Verdict::Pass
    );

    let other = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-123".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            owner_principal_id: "svc-index".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::ResourceOwnerBoundaryPreserved,
        &scenario,
        &other,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
}

// --- authorization binding (Cycle 003 semantics) ---

#[test]
fn an_unchanged_operation_stays_bound_to_its_permit() {
    let scenario = scenario();
    let authorized = operation("user-7", "read", "document-123", "tenant-a");
    let digest = authorized.projection_digest().expect("digest");

    let events = vec![permit(&digest), observed(authorized, true)];
    assert_eq!(
        verdict(
            IdentityInvariantType::AuthorizationBoundToFinalOperation,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn an_incidental_change_does_not_break_the_binding() {
    // A changed trace id must not invalidate a permit, or the check fires on
    // everything and gets switched off.
    let scenario = scenario();
    let authorized = operation("user-7", "read", "document-123", "tenant-a");
    let digest = authorized.projection_digest().expect("digest");

    let mut later = authorized;
    later
        .incidental_arguments
        .insert("trace_id".to_owned(), "trace-999".to_owned());

    let events = vec![permit(&digest), observed(later, true)];
    assert_eq!(
        verdict(
            IdentityInvariantType::AuthorizationBoundToFinalOperation,
            &scenario,
            &events
        ),
        Verdict::Pass
    );
}

#[test]
fn a_post_permit_resource_mutation_breaks_the_binding() {
    // The approval's own example: resource-123 authorized, document-999 done.
    let scenario = scenario();
    let authorized = operation("user-7", "read", "document-123", "tenant-a");
    let digest = authorized.projection_digest().expect("digest");
    let mutated = operation("user-7", "read", "document-999", "tenant-a");

    let events = vec![permit(&digest), observed(mutated, true)];
    let outcome = evaluate(
        IdentityInvariantType::AuthorizationBoundToFinalOperation,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.violations[0]
        .reason
        .contains("not the one any permit covered"));
}

#[test]
fn a_post_permit_action_mutation_breaks_the_binding() {
    let scenario = scenario();
    let authorized = operation("user-7", "read", "document-123", "tenant-a");
    let digest = authorized.projection_digest().expect("digest");
    let mutated = operation("user-7", "delete", "document-123", "tenant-a");

    let events = vec![permit(&digest), observed(mutated, true)];
    assert_eq!(
        verdict(
            IdentityInvariantType::AuthorizationBoundToFinalOperation,
            &scenario,
            &events
        ),
        Verdict::Fail
    );
}

#[test]
fn a_permit_without_a_final_operation_is_inconclusive() {
    let scenario = scenario();
    let authorized = operation("user-7", "read", "document-123", "tenant-a");
    let digest = authorized.projection_digest().expect("digest");

    let outcome = evaluate(
        IdentityInvariantType::AuthorizationBoundToFinalOperation,
        &scenario,
        &[permit(&digest)],
    );
    assert_eq!(outcome.verdict, Verdict::Inconclusive);
}

#[test]
fn a_denied_operation_requested_anyway_fails_without_dispatch() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::PolicyDecision(PolicyDecisionObserved {
            operation_key: "document.delete".to_owned(),
            effect: DecisionEffect::Deny,
            policy_id: Some("policy-support-desk".to_owned()),
        }),
        observed(
            operation("user-7", "delete", "document-123", "tenant-a"),
            false,
        ),
    ];
    let outcome = evaluate(IdentityInvariantType::DenyNotBypassed, &scenario, &events);
    assert_eq!(outcome.verdict, Verdict::Fail);

    // And the operation was observed, never performed.
    for event in &events {
        if let IdentityObservationEvent::OperationRequest(record) = event {
            assert!(!record.dispatched);
        }
    }
}

#[test]
fn a_permitted_operation_does_not_read_as_a_bypass() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::PolicyDecision(PolicyDecisionObserved {
            operation_key: "document.read".to_owned(),
            effect: DecisionEffect::Permit,
            policy_id: Some("policy-support-desk".to_owned()),
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            false,
        ),
    ];
    assert_eq!(
        verdict(IdentityInvariantType::DenyNotBypassed, &scenario, &events),
        Verdict::Pass
    );
}

#[test]
fn a_denied_key_is_matched_whole_never_by_prefix() {
    // `document.read` must not be treated as denied because `document.delete`
    // is. Loose matching here would fail every honest run.
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::PolicyDecision(PolicyDecisionObserved {
            operation_key: "document.delete".to_owned(),
            effect: DecisionEffect::Deny,
            policy_id: None,
        }),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            false,
        ),
    ];
    assert_eq!(
        verdict(IdentityInvariantType::DenyNotBypassed, &scenario, &events),
        Verdict::Pass
    );
}

// --- independence and determinism ---

#[test]
fn independent_violations_are_all_captured_across_invariants() {
    // IDENTITY-LAB-020: principal substitution, tenant crossing and privilege
    // amplification true at once. Each invariant reports its own, and none
    // masks another.
    let scenario = scenario();
    let mut amplified = authority(&scenario, "authority-service-admin");
    amplified.id = "authority-exercised".to_owned();

    let events = vec![
        principal_event(
            PrincipalRole::Effective,
            "svc-index",
            PrincipalKind::Service,
        ),
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-999".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-b".to_owned(),
            owner_principal_id: "svc-index".to_owned(),
            classification: None,
        }),
        effective_authority("user-7", amplified, "authority-user-read"),
        observed(
            operation("svc-index", "read", "document-999", "tenant-b"),
            true,
        ),
    ];

    let failing: Vec<&str> = dare_identity_security::supported_invariants()
        .into_iter()
        .filter(|invariant| evaluate(*invariant, &scenario, &events).verdict == Verdict::Fail)
        .map(IdentityInvariantType::as_str)
        .collect();

    assert!(
        failing.len() >= 4,
        "several independent boundaries were crossed; got {failing:?}"
    );
    assert!(failing.contains(&"AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER"));
    assert!(failing.contains(&"TENANT_BOUNDARY_PRESERVED"));
    assert!(failing.contains(&"RESOURCE_OWNER_BOUNDARY_PRESERVED"));
    assert!(failing.contains(&"EFFECTIVE_AUTHORITY_WITHIN_SOURCE_CEILING"));
}

#[test]
fn several_violations_of_one_invariant_are_all_listed() {
    let scenario = scenario();
    let events = vec![
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-999".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-b".to_owned(),
            owner_principal_id: "svc-index".to_owned(),
            classification: None,
        }),
        IdentityObservationEvent::ResourceContext(ResourceContext {
            resource_id: "document-888".to_owned(),
            resource_type: "document".to_owned(),
            tenant_id: "tenant-c".to_owned(),
            owner_principal_id: "agent-1".to_owned(),
            classification: None,
        }),
        observed(
            operation("user-7", "read", "document-999", "tenant-b"),
            true,
        ),
    ];
    let outcome = evaluate(
        IdentityInvariantType::ResourceOwnerBoundaryPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert_eq!(
        outcome.violations.len(),
        2,
        "a first-match evaluator would have reported one and lost the other"
    );
}

#[test]
fn evaluation_is_deterministic_across_repeated_runs() {
    let scenario = scenario();
    let events = vec![
        principal_event(PrincipalRole::Effective, "user-7", PrincipalKind::Human),
        observed(
            operation("user-7", "read", "document-123", "tenant-a"),
            true,
        ),
    ];
    for invariant in dare_identity_security::supported_invariants() {
        assert_eq!(
            evaluate(invariant, &scenario, &events),
            evaluate(invariant, &scenario, &events),
            "{} is not deterministic",
            invariant.as_str()
        );
    }
}

#[test]
fn a_violation_outranks_missing_coverage() {
    // A run that observed a violation has observed something. Reporting it as
    // inconclusive would lose a real finding.
    let scenario = scenario();
    let events = vec![principal_event(
        PrincipalRole::Initiating,
        "svc-index",
        PrincipalKind::Service,
    )];
    let outcome = evaluate(
        IdentityInvariantType::InitiatingPrincipalPreserved,
        &scenario,
        &events,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(
        outcome.coverage_satisfied,
        "the deciding evidence was present"
    );
}

#[test]
fn no_observed_operation_is_ever_marked_dispatched() {
    let scenario = scenario();
    let events = vec![observed(
        operation("user-7", "delete", "document-123", "tenant-a"),
        true,
    )];
    let _ = evaluate(IdentityInvariantType::DenyNotBypassed, &scenario, &events);
    for event in &events {
        if let IdentityObservationEvent::FinalOperation(record) = event {
            assert!(!record.dispatched);
        }
    }
}
