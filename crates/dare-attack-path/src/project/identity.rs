//! Identity projector (Cycle 015, BLUEPRINT §6.2).
use std::collections::BTreeMap;

use dare_attack_graph::{
    v2::{EntryClass, GuardVerdict, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_identity_security::{
    model::IdentitySecurityScenario, observation::IdentityObservationEvent,
    resource::ResourceClassification, result::IdentitySecurityResult, source::PrincipalKind,
};

use super::{edge, plain, tenant, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactEdge, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

pub fn principal_type(kind: PrincipalKind) -> NodeType {
    match kind {
        PrincipalKind::Human => NodeType::Human,
        PrincipalKind::Agent => NodeType::Agent,
        PrincipalKind::Workload | PrincipalKind::Service => NodeType::Identity,
    }
}

pub fn project(
    bundle: &LoadedBundle,
    result: &IdentitySecurityResult,
    scenario: &IdentitySecurityScenario,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let static_ev = || statically_proven(bundle.engine, &[&result.scenario_digest]);
    // Principals: the type of each is fixed by its declared kind.
    let mut principals: BTreeMap<&str, NodeRef> = BTreeMap::new();
    for (index, principal) in scenario.principals.principals.iter().enumerate() {
        let security = principal.tenant_id.as_deref().map_or_else(plain, tenant);
        let node = sink.node(
            NodeRef::new(principal_type(principal.kind), &principal.id),
            principal.display_label.as_deref().unwrap_or(&principal.id),
            security,
            "Principal",
            format!("input:scenario#/principals/principals/{index}"),
        );
        principals.insert(principal.id.as_str(), node);
    }
    let lookup = |id: &str| principals.get(id).cloned();
    let bindings = &scenario.principals.bindings;
    if let Some(initiating) = lookup(&bindings.initiating_principal_id) {
        if initiating.node_type == NodeType::Human {
            sink.designate(
                &initiating,
                Designation::Entry(EntryClass::LowPrivilegePrincipal),
            );
        }
    }

    // Violations name principals; a FAIL narrows to their edges.
    for trial in &result.trials {
        for violation in &trial.violations {
            if let Some(node) = violation.principal_id.as_deref().and_then(lookup) {
                verdicts.violation(&result.property_id, node);
            }
        }
    }

    // Delegation chain, declared; observed use upgrades the evidence.
    let mut observed_edges: BTreeMap<&str, usize> = BTreeMap::new();
    for (trial_index, trial) in result.trials.iter().enumerate() {
        for event in &trial.events {
            if let IdentityObservationEvent::DelegationEdge(seen) = event {
                observed_edges
                    .entry(seen.edge_id.as_str())
                    .or_insert(trial_index);
            }
        }
    }
    if let Some(chain) = &scenario.delegation {
        for (index, link) in chain.edges.iter().enumerate() {
            let (Some(from), Some(to)) = (
                lookup(&link.delegator_principal_id),
                lookup(&link.delegatee_principal_id),
            ) else {
                sink.unprojected("DelegationEdge::unknown_principal");
                continue;
            };
            let subject = link
                .delegated_subject_id
                .as_deref()
                .and_then(lookup)
                .unwrap_or_else(|| from.clone());
            let mut scopes: Vec<String> = [link.purpose_id.clone(), link.audience.clone()]
                .into_iter()
                .flatten()
                .collect();
            scopes.sort();
            let authority = FactAuthority {
                principal: Some(subject),
                delegated: true,
                scopes,
                ..FactAuthority::default()
            };
            let evidence = match observed_edges.get(link.edge_id.as_str()) {
                Some(&trial) => observed(trial_ids(bundle, &result.evidence_ids, trial)),
                None => static_ev(),
            };
            edge(
                sink,
                verdicts,
                Some(Role::IdentityDelegates),
                EdgeType::DelegatesTo,
                &from,
                &to,
                authority,
                evidence,
                "DelegationEdge",
                format!("input:scenario#/delegation/edges/{index}"),
            );
        }
    }

    // Credentials: owned (declared), used (observed).
    let mut credentials: BTreeMap<&str, (NodeRef, Vec<String>)> = BTreeMap::new();
    for (index, spec) in scenario.credential_contexts.iter().enumerate() {
        let owner = lookup(&spec.owner_principal_id);
        let privileged = owner
            .as_ref()
            .is_some_and(|o| o.node_type == NodeType::Identity);
        let credential = sink.node(
            NodeRef::new(NodeType::Credential, &spec.credential_context_id),
            &spec.credential_context_id,
            NodeSecurity {
                privileged,
                ..NodeSecurity::default()
            },
            "CredentialContextSpec",
            format!("input:scenario#/credential_contexts/{index}"),
        );
        if privileged {
            sink.designate(
                &credential,
                Designation::Target(TargetClass::PrivilegedCredential),
            );
        }
        if let Some(owner) = owner {
            edge(
                sink,
                verdicts,
                None,
                EdgeType::AuthenticatesAs,
                &owner,
                &credential,
                FactAuthority {
                    principal: Some(owner.clone()),
                    ..FactAuthority::default()
                },
                static_ev(),
                "CredentialContextSpec",
                format!("input:scenario#/credential_contexts/{index}"),
            );
        }
        credentials.insert(
            spec.credential_context_id.as_str(),
            (credential, spec.tenant_labels.clone()),
        );
    }

    // The resource and its tenant.
    let resource = scenario.resource.as_ref().map(|context| {
        let sensitive = context.classification == Some(ResourceClassification::SyntheticRestricted);
        let node = sink.node(
            NodeRef::new(NodeType::Resource, &context.resource_id),
            &context.resource_id,
            NodeSecurity {
                tenant: Some(context.tenant_id.clone()),
                sensitive,
                ..NodeSecurity::default()
            },
            "ResourceContext",
            "input:scenario#/resource",
        );
        let tenant_node = sink.node(
            NodeRef::new(NodeType::Tenant, &context.tenant_id),
            &context.tenant_id,
            plain(),
            "ResourceContext.tenant_id",
            "input:scenario#/resource",
        );
        edge(
            sink,
            verdicts,
            None,
            EdgeType::BelongsToTenant,
            &node,
            &tenant_node,
            FactAuthority::default(),
            static_ev(),
            "ResourceContext",
            "input:scenario#/resource",
        );
        if sensitive {
            sink.designate(&node, Designation::Target(TargetClass::SensitiveResource));
        }
        (node, context.tenant_id.clone())
    });
    if let Some((resource_node, resource_tenant)) = &resource {
        for (credential, labels) in credentials.values() {
            if labels.iter().any(|l| l == resource_tenant) {
                edge(
                    sink,
                    verdicts,
                    Some(Role::IdentityCredentialReaches),
                    EdgeType::CanReach,
                    credential,
                    resource_node,
                    FactAuthority {
                        tenant: Some(resource_tenant.clone()),
                        credential: Some(credential.clone()),
                        ..FactAuthority::default()
                    },
                    static_ev(),
                    "CredentialContextSpec.tenant_labels",
                    "input:scenario#/credential_contexts",
                );
            }
        }
    }

    let mutation = matches!(
        verdicts.verdict("AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING"),
        Some(GuardVerdict::Fail)
    ) || matches!(
        verdicts.verdict("AGENT.IDENTITY.PRINCIPAL_BINDING"),
        Some(GuardVerdict::Fail)
    );
    let effective = lookup(&bindings.effective_principal_id);
    for (trial_index, trial) in result.trials.iter().enumerate() {
        let ids = trial_ids(bundle, &result.evidence_ids, trial_index);
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            match event {
                IdentityObservationEvent::CredentialContext(seen) => {
                    if let (Some(user), Some((credential, _))) = (
                        &effective,
                        credentials.get(seen.credential_context_id.as_str()),
                    ) {
                        edge(
                            sink,
                            verdicts,
                            Some(Role::IdentityUsesCredential),
                            EdgeType::UsesCredential,
                            user,
                            credential,
                            FactAuthority {
                                principal: Some(user.clone()),
                                credential: Some(credential.clone()),
                                ..FactAuthority::default()
                            },
                            observed(ids.clone()),
                            "CredentialContextObserved",
                            &locator,
                        );
                    }
                }
                IdentityObservationEvent::FinalOperation(operation) => {
                    let op = &operation.operation;
                    let Some(subject) = lookup(&op.subject_id) else {
                        sink.unprojected("FinalOperation::unknown_subject");
                        continue;
                    };
                    let authority = FactAuthority {
                        principal: Some(subject.clone()),
                        tenant: Some(op.tenant_id.clone()),
                        ..FactAuthority::default()
                    };
                    if let Some(tool_id) = &op.tool_id {
                        let tool = sink.node(
                            NodeRef::new(NodeType::Tool, tool_id),
                            tool_id,
                            plain(),
                            "Operation.tool_id",
                            &locator,
                        );
                        edge(
                            sink,
                            verdicts,
                            Some(Role::IdentityCalls),
                            EdgeType::Calls,
                            &subject,
                            &tool,
                            authority.clone(),
                            observed(ids.clone()),
                            "FinalOperation (request, not execution)",
                            &locator,
                        );
                    }
                    let target = match &resource {
                        Some((node, _)) if node.local_id == op.resource_id => node.clone(),
                        _ => sink.node(
                            NodeRef::new(NodeType::Resource, &op.resource_id),
                            &op.resource_id,
                            tenant(&op.tenant_id),
                            "Operation.resource_id",
                            &locator,
                        ),
                    };
                    let guards = verdicts.guards(Role::IdentitySubjectReaches, &subject, &target);
                    sink.edge(FactEdge {
                        edge_type: EdgeType::CanReach,
                        source: subject.clone(),
                        target,
                        authority,
                        evidence: observed(ids.clone()),
                        guards,
                        authority_mutation: mutation,
                        original_kind: "FinalOperation (request, not execution)".to_owned(),
                        locator: locator.clone(),
                    });
                }
                // Used above to upgrade the declared delegation to OBSERVED.
                IdentityObservationEvent::DelegationEdge(_) => {}
                other => sink.unprojected(format!("IdentityObservationEvent::{}", other.kind())),
            }
        }
    }
}
