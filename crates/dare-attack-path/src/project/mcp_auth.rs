//! MCP Auth projector (Cycle 018, BLUEPRINT §6.5).
//!
//! Topology comes from the bound scenario. When a trial observed the
//! credential flow or the final-operation binding, the same edges are also
//! emitted with that trial's evidence; `merge` keeps the stronger status.
//! Every 018 guard is RUN scope: its violations name no graph entity.
use dare_attack_graph::{v2::TargetClass, EdgeEvidence, EdgeType, NodeSecurity, NodeType};
use dare_mcp_auth_security::{
    model::McpAuthScenario, observation::McpAuthObservation, result::McpAuthSecurityResult,
};

use super::{edge, identity::principal_type, plain, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactEdge, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

pub fn project(
    bundle: &LoadedBundle,
    result: &McpAuthSecurityResult,
    scenario: Option<&McpAuthScenario>,
    verdicts: &RunVerdicts,
    sink: &mut FactSink,
) {
    let Some(scenario) = scenario else {
        // A remote MCP-auth run whose scenario was not supplied: its guards
        // exist, but there is no topology to attach them to.
        sink.unprojected("McpAuthScenario::not_supplied");
        return;
    };
    let mut evidence_sets: Vec<(EdgeEvidence, String)> = vec![(
        statically_proven(bundle.engine, &[&result.scenario_digest]),
        "input:scenario".to_owned(),
    )];
    let mut credential_observed = Vec::new();
    let mut operation_observed = Vec::new();
    for (trial_index, trial) in result.trials.iter().enumerate() {
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            match event {
                McpAuthObservation::CredentialFlow { .. } => credential_observed.push((
                    observed(trial_ids(bundle, &result.evidence_ids, trial_index)),
                    locator,
                )),
                McpAuthObservation::FinalOperationBinding { .. } => operation_observed.push((
                    observed(trial_ids(bundle, &result.evidence_ids, trial_index)),
                    locator,
                )),
                other => {
                    sink.unprojected(format!("McpAuthObservation::{}", super::event_kind(other)))
                }
            }
        }
    }

    let server_uri = scenario.protected_resource.expected_resource.as_str();
    let server = sink.node(
        NodeRef::new(NodeType::McpServer, server_uri),
        server_uri,
        plain(),
        "ResourceContext.expected_resource",
        "input:scenario#/protected_resource",
    );
    let principal = scenario
        .identity_metadata
        .acting_principal
        .as_ref()
        .map(|p| {
            let security = p.tenant_id.as_deref().map_or_else(plain, super::tenant);
            sink.node(
                NodeRef::new(principal_type(p.kind), &p.principal_id),
                &p.principal_id,
                security,
                "AuthoritativePrincipal",
                "input:scenario#/identity_metadata/acting_principal",
            )
        });
    let credentials = &scenario.credential_flow;
    let inbound = credentials.inbound.as_ref().map(|c| {
        sink.node(
            NodeRef::new(NodeType::Credential, &c.credential_id),
            &c.credential_id,
            plain(),
            "CredentialRef (inbound)",
            "input:scenario#/credential_flow/inbound",
        )
    });
    let upstream = credentials.upstream.as_ref().map(|c| {
        let node = sink.node(
            NodeRef::new(NodeType::Credential, &c.credential_id),
            &c.credential_id,
            NodeSecurity {
                privileged: true,
                ..NodeSecurity::default()
            },
            "CredentialRef (upstream)",
            "input:scenario#/credential_flow/upstream",
        );
        sink.designate(
            &node,
            Designation::Target(TargetClass::PrivilegedCredential),
        );
        node
    });
    let final_op = &scenario.final_operation;
    let performed_resource = final_op.performed_resource.as_ref().map(|uri| {
        sink.node(
            NodeRef::new(NodeType::Resource, uri.as_str()),
            uri.as_str(),
            plain(),
            "FinalOperationContext.performed_resource",
            "input:scenario#/final_operation",
        )
    });
    let issuer = scenario
        .protected_resource
        .selected_authorization_server
        .as_ref()
        .map(|uri| {
            sink.node(
                NodeRef::new(NodeType::PolicyDecisionPoint, uri.as_str()),
                uri.as_str(),
                plain(),
                "AuthorizationServerMetadata",
                "input:scenario#/protected_resource",
            )
        });

    evidence_sets.extend(credential_observed.iter().cloned());
    for (evidence, locator) in &evidence_sets {
        let is_static = evidence.status == dare_attack_graph::EdgeEvidenceStatus::StaticallyProven;
        let observes_credentials =
            is_static || credential_observed.iter().any(|(_, l)| l == locator);
        if observes_credentials {
            if let (Some(principal), Some(inbound)) = (&principal, &inbound) {
                edge(
                    sink,
                    verdicts,
                    Some(Role::McpUsesInbound),
                    EdgeType::UsesCredential,
                    principal,
                    inbound,
                    FactAuthority {
                        principal: Some(principal.clone()),
                        credential: Some(inbound.clone()),
                        ..FactAuthority::default()
                    },
                    evidence.clone(),
                    "CredentialContext.inbound",
                    locator,
                );
            }
            if let Some(inbound) = &inbound {
                edge(
                    sink,
                    verdicts,
                    Some(Role::McpInboundReaches),
                    EdgeType::CanReach,
                    inbound,
                    &server,
                    FactAuthority {
                        credential: Some(inbound.clone()),
                        ..FactAuthority::default()
                    },
                    evidence.clone(),
                    "CredentialContext.inbound",
                    locator,
                );
            }
            if let Some(upstream) = &upstream {
                edge(
                    sink,
                    verdicts,
                    Some(Role::McpUpstream),
                    EdgeType::UsesCredential,
                    &server,
                    upstream,
                    FactAuthority {
                        service_identity: Some(server_uri.to_owned()),
                        credential: Some(upstream.clone()),
                        ..FactAuthority::default()
                    },
                    evidence.clone(),
                    "CredentialContext.upstream",
                    locator,
                );
                if let Some(resource) = &performed_resource {
                    edge(
                        sink,
                        verdicts,
                        Some(Role::McpUpstream),
                        EdgeType::CanReach,
                        upstream,
                        resource,
                        FactAuthority {
                            credential: Some(upstream.clone()),
                            ..FactAuthority::default()
                        },
                        evidence.clone(),
                        "CredentialContext.upstream",
                        locator,
                    );
                }
            }
        }
    }
    if let Some(issuer) = &issuer {
        edge(
            sink,
            verdicts,
            Some(Role::McpAuthorizedBy),
            EdgeType::AuthorizedBy,
            &server,
            issuer,
            FactAuthority::default(),
            evidence_sets[0].0.clone(),
            "ResourceContext.selected_authorization_server",
            "input:scenario#/protected_resource",
        );
    }

    // The final operation: who acted on what, and whether that differs
    // from what was authorized.
    let mutation = final_op.authorized_principal != final_op.performed_principal
        || final_op.authorized_tenant != final_op.performed_tenant
        || final_op.authorized_resource != final_op.performed_resource;
    let actor = match (&final_op.performed_principal, &principal) {
        (Some(id), Some(p)) if &p.local_id == id => Some(p.clone()),
        (Some(id), _) => Some(sink.node(
            NodeRef::new(NodeType::Identity, id),
            id,
            plain(),
            "FinalOperationContext.performed_principal",
            "input:scenario#/final_operation",
        )),
        (None, p) => p.clone(),
    };
    if let (Some(actor), Some(resource)) = (actor, performed_resource) {
        let authority = FactAuthority {
            principal: Some(actor.clone()),
            tenant: final_op.performed_tenant.clone(),
            ..FactAuthority::default()
        };
        let mut sets = vec![evidence_sets[0].clone()];
        sets.extend(operation_observed);
        for (evidence, locator) in sets {
            let guards = verdicts.guards(Role::McpFinalOperation, &actor, &resource);
            sink.edge(FactEdge {
                edge_type: EdgeType::CanReach,
                source: actor.clone(),
                target: resource.clone(),
                authority: authority.clone(),
                evidence,
                guards,
                authority_mutation: mutation,
                original_kind: "FinalOperationContext".to_owned(),
                locator,
            });
        }
    }
}
