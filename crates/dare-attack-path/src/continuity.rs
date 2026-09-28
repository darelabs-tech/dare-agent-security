//! Authority continuity (BLUEPRINT §7.3, task-032).
//!
//! A path is feasible when each step is explained by the authority carried
//! so far. State: `P`, the acting principal (a node, or unset), and `A`, the
//! actors currently acting under `P`. The first edge no rule explains makes
//! the path DISCONTINUOUS.
use std::collections::BTreeSet;

use dare_attack_graph::{
    v2::{EdgeV2, GuardVerdict, NodeV2},
    EdgeType, NodeType,
};

/// Properties whose FAIL explains an unexplained authority change (C4).
pub const MUTATION_PROPERTIES: [&str; 3] = [
    "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING",
    "AGENT.IDENTITY.PRINCIPAL_BINDING",
    "MCP.AUTH.FINAL_OPERATION_BINDING",
];

fn principal_like(node_type: NodeType) -> bool {
    matches!(
        node_type,
        NodeType::Human | NodeType::Agent | NodeType::Identity | NodeType::Credential
    )
}

fn actor_like(node_type: NodeType) -> bool {
    matches!(
        node_type,
        NodeType::Human | NodeType::Agent | NodeType::Identity
    )
}

/// `None` when the path is feasible, otherwise the index of the first edge
/// no rule explains. `node_type` resolves a node id to its type.
pub fn discontinuity<'a>(
    entry: &NodeV2,
    edges: &[&EdgeV2],
    node_type: impl Fn(&str) -> Option<NodeType> + 'a,
) -> Option<u32> {
    let mut principal: Option<String> = None;
    let mut actors: BTreeSet<String> = BTreeSet::new();
    if principal_like(entry.node_type) {
        principal = Some(entry.id.clone());
        actors.insert(entry.id.clone());
    }
    for (index, edge) in edges.iter().enumerate() {
        let x = &edge.source;
        let y = &edge.target;
        let source_acts = principal.is_none() || actors.contains(x);
        // Only a principal that is a graph node can be checked; an `ext:`
        // subject is opaque and never contradicts the path (REGRESSION R-12).
        let named = edge
            .authority
            .principal
            .as_deref()
            .filter(|p| !p.starts_with("ext:"));
        match edge.edge_type {
            // C1
            EdgeType::DelegatesTo | EdgeType::AuthenticatesAs => {
                if !source_acts {
                    return Some(index as u32);
                }
                principal = Some(y.clone());
                actors = BTreeSet::from([y.clone()]);
            }
            // C2
            EdgeType::UsesCredential => {
                if !(source_acts || named.is_some_and(|p| Some(p) == principal.as_deref())) {
                    return Some(index as u32);
                }
                principal = Some(y.clone());
                actors.insert(y.clone());
            }
            // C3, then C4
            EdgeType::Calls
            | EdgeType::CanInvoke
            | EdgeType::CanReach
            | EdgeType::Reads
            | EdgeType::Writes
            | EdgeType::Deletes
            | EdgeType::AuthorizedBy => {
                let principal_ok =
                    named.is_none_or(|p| actors.contains(p) || principal.as_deref() == Some(p));
                if source_acts && principal_ok {
                    actors.insert(y.clone());
                } else if edge.authority_mutation
                    && edge.guards.iter().any(|g| {
                        g.verdict == GuardVerdict::Fail
                            && MUTATION_PROPERTIES.contains(&g.property.as_str())
                    })
                {
                    let acting = named.map(str::to_owned).unwrap_or_else(|| x.clone());
                    principal = Some(acting.clone());
                    actors = BTreeSet::from([acting, y.clone()]);
                } else {
                    return Some(index as u32);
                }
            }
            // C5
            EdgeType::TransfersTo => {
                if node_type(y).is_some_and(actor_like) {
                    principal = Some(y.clone());
                    actors = BTreeSet::from([y.clone()]);
                }
            }
            // C6
            EdgeType::BelongsToTenant | EdgeType::EnforcedBy | EdgeType::CrossesTrustBoundary => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use dare_attack_graph::{
        v2::{Guard, GuardScope},
        AuthorityContext, EdgeEvidence, EdgeEvidenceStatus, NodeSecurity,
    };

    fn node(id: &str, node_type: NodeType) -> NodeV2 {
        NodeV2 {
            id: id.into(),
            node_type,
            display_name: id.into(),
            security: NodeSecurity::default(),
            provenance: vec![],
        }
    }

    fn edge(source: &str, edge_type: EdgeType, target: &str, principal: Option<&str>) -> EdgeV2 {
        EdgeV2 {
            id: format!("{source}-{target}"),
            edge_type,
            source: source.into(),
            target: target.into(),
            authority: AuthorityContext {
                principal: principal.map(str::to_owned),
                ..AuthorityContext::default()
            },
            evidence: EdgeEvidence {
                status: EdgeEvidenceStatus::Observed,
                evidence_ids: vec!["e".into()],
                rationale: None,
                source_facts: vec![],
                reason: None,
            },
            guards: vec![],
            authority_mutation: false,
            crosses_trust_boundary: vec![],
            provenance: vec![],
        }
    }

    fn types(id: &str) -> Option<NodeType> {
        Some(match id.split(':').nth(1)? {
            "human" => NodeType::Human,
            "agent" => NodeType::Agent,
            "identity" => NodeType::Identity,
            "credential" => NodeType::Credential,
            "tool" => NodeType::Tool,
            "resource" => NodeType::Resource,
            "data" => NodeType::Data,
            "tenant" => NodeType::Tenant,
            _ => return None,
        })
    }

    fn run(entry: (&str, NodeType), edges: &[EdgeV2]) -> Option<u32> {
        let refs: Vec<&EdgeV2> = edges.iter().collect();
        discontinuity(&node(entry.0, entry.1), &refs, types)
    }

    const USER: &str = "node:human:u";
    const AGENT: &str = "node:agent:a";
    const OTHER: &str = "node:agent:b";
    const TOOL: &str = "node:tool:t";
    const CRED: &str = "node:credential:c";
    const RES: &str = "node:resource:r";
    const DOC: &str = "node:data:d";

    #[test]
    fn c1_delegation_hands_authority_to_the_delegatee() {
        let ok = [
            edge(USER, EdgeType::DelegatesTo, AGENT, Some(USER)),
            edge(AGENT, EdgeType::Calls, TOOL, Some(AGENT)),
        ];
        assert_eq!(run((USER, NodeType::Human), &ok), None);
        // The delegator no longer acts after handing off.
        let bad = [
            edge(USER, EdgeType::DelegatesTo, AGENT, None),
            edge(USER, EdgeType::Calls, TOOL, None),
        ];
        assert_eq!(run((USER, NodeType::Human), &bad), Some(1));
        // A delegation from someone not acting is discontinuous.
        let foreign = [edge(OTHER, EdgeType::DelegatesTo, AGENT, None)];
        assert_eq!(run((USER, NodeType::Human), &foreign), Some(0));
    }

    #[test]
    fn c2_a_credential_is_used_by_an_actor_or_for_the_principal() {
        let ok = [
            edge(AGENT, EdgeType::UsesCredential, CRED, None),
            edge(CRED, EdgeType::CanReach, RES, None),
        ];
        assert_eq!(run((AGENT, NodeType::Agent), &ok), None);
        let for_principal = [edge(TOOL, EdgeType::UsesCredential, CRED, Some(AGENT))];
        assert_eq!(run((AGENT, NodeType::Agent), &for_principal), None);
        let stranger = [edge(TOOL, EdgeType::UsesCredential, CRED, Some(OTHER))];
        assert_eq!(run((AGENT, NodeType::Agent), &stranger), Some(0));
    }

    #[test]
    fn c3_an_access_needs_an_acting_source_and_a_known_principal() {
        let ok = [
            edge(AGENT, EdgeType::Calls, TOOL, None),
            edge(TOOL, EdgeType::Reads, RES, Some(AGENT)),
        ];
        assert_eq!(run((AGENT, NodeType::Agent), &ok), None);
        let other_principal = [edge(AGENT, EdgeType::Calls, TOOL, Some(OTHER))];
        assert_eq!(run((AGENT, NodeType::Agent), &other_principal), Some(0));
        let ext = [edge(AGENT, EdgeType::Calls, TOOL, Some("ext:user-alice"))];
        assert_eq!(
            run((AGENT, NodeType::Agent), &ext),
            None,
            "R-12: ext subjects are opaque"
        );
    }

    #[test]
    fn c4_a_failed_binding_explains_the_change() {
        let mut jump = edge(OTHER, EdgeType::CanReach, RES, Some(OTHER));
        assert_eq!(
            run((AGENT, NodeType::Agent), std::slice::from_ref(&jump)),
            Some(0)
        );
        jump.authority_mutation = true;
        assert_eq!(
            run((AGENT, NodeType::Agent), std::slice::from_ref(&jump)),
            Some(0),
            "mutation alone is not enough"
        );
        jump.guards.push(Guard {
            property: "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING".into(),
            verdict: GuardVerdict::Fail,
            evidence_ids: vec!["e".into()],
            scope: GuardScope::Run,
            artifact_index: 0,
        });
        assert_eq!(
            run((AGENT, NodeType::Agent), std::slice::from_ref(&jump)),
            None
        );
        jump.guards[0].property = "AGENT.TOOL.CHAIN_BOUNDARY".into();
        assert_eq!(
            run((AGENT, NodeType::Agent), &[jump]),
            Some(0),
            "only the named properties explain it"
        );
    }

    #[test]
    fn c5_content_reaching_an_agent_makes_it_the_actor() {
        let path = [
            edge(DOC, EdgeType::TransfersTo, AGENT, None),
            edge(AGENT, EdgeType::Calls, TOOL, None),
        ];
        assert_eq!(run((DOC, NodeType::Data), &path), None);
        // Content reaching a non-actor does not make it act: a later access
        // made in the name of an agent that never entered the path is
        // unexplained (C3).
        let not_actor = [
            edge(DOC, EdgeType::TransfersTo, TOOL, None),
            edge(TOOL, EdgeType::Reads, RES, Some(AGENT)),
        ];
        assert_eq!(run((DOC, NodeType::Data), &not_actor), Some(1));
        // With no named principal the access is not contradicted.
        let unnamed = [
            edge(DOC, EdgeType::TransfersTo, TOOL, None),
            edge(TOOL, EdgeType::Reads, RES, None),
        ];
        assert_eq!(run((DOC, NodeType::Data), &unnamed), None);
        let then_foreign = [
            edge(DOC, EdgeType::TransfersTo, AGENT, None),
            edge(OTHER, EdgeType::Calls, TOOL, None),
        ];
        assert_eq!(run((DOC, NodeType::Data), &then_foreign), Some(1));
    }

    #[test]
    fn c6_structural_edges_never_break_a_path() {
        let path = [
            edge(AGENT, EdgeType::CanReach, RES, None),
            edge(RES, EdgeType::BelongsToTenant, "node:tenant:t", Some(OTHER)),
        ];
        assert_eq!(run((AGENT, NodeType::Agent), &path), None);
    }
}
