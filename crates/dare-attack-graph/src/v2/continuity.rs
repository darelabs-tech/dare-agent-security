//! Authority continuity (Cycle 023 BLUEPRINT §7.3; moved here by Cycle 024
//! AD-02 so that path feasibility and blast-radius reach share one rule).
//!
//! State: `P`, the acting principal (a node, or unset), and `A`, the actors
//! currently acting under `P`. [`Authority::step`] applies rules C1–C6 to one
//! edge. [`discontinuity`] walks a path and returns the first edge no rule
//! explains.
use std::collections::BTreeSet;

use crate::{edge::EdgeType, node::NodeType};

use super::model::{EdgeV2, GuardVerdict, NodeV2};

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

/// The authority a walk carries: `P` and `A`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority {
    pub principal: Option<String>,
    pub actors: BTreeSet<String>,
}

impl Authority {
    /// The initial state of a path from `entry` (§7.3): a principal-like entry
    /// acts as itself; anything else starts with no principal.
    pub fn for_entry(entry: &NodeV2) -> Self {
        if principal_like(entry.node_type) {
            Self::acting(&entry.id)
        } else {
            Self::unset()
        }
    }

    /// `P = node`, `A = {node}`.
    pub fn acting(node: &str) -> Self {
        Self {
            principal: Some(node.to_owned()),
            actors: BTreeSet::from([node.to_owned()]),
        }
    }

    /// `P` unset, `A = {}`.
    pub fn unset() -> Self {
        Self {
            principal: None,
            actors: BTreeSet::new(),
        }
    }

    /// `P` unset, `A = {node}`: a component that acts under whatever
    /// authority its edges carry.
    pub fn component(node: &str) -> Self {
        Self {
            principal: None,
            actors: BTreeSet::from([node.to_owned()]),
        }
    }

    /// Applies C1–C6 to `edge`. Returns false, leaving the state unchanged,
    /// when no rule explains the step.
    pub fn step(&mut self, edge: &EdgeV2, node_type: impl Fn(&str) -> Option<NodeType>) -> bool {
        let x = &edge.source;
        let y = &edge.target;
        let source_acts = self.principal.is_none() || self.actors.contains(x);
        // Only a principal that is a graph node can be checked; an `ext:`
        // subject is opaque and never contradicts the path (Cycle 023 R-12).
        let named = edge
            .authority
            .principal
            .as_deref()
            .filter(|p| !p.starts_with("ext:"));
        match edge.edge_type {
            // C1
            EdgeType::DelegatesTo | EdgeType::AuthenticatesAs => {
                if !source_acts {
                    return false;
                }
                self.principal = Some(y.clone());
                self.actors = BTreeSet::from([y.clone()]);
            }
            // C2
            EdgeType::UsesCredential => {
                if !(source_acts || named.is_some_and(|p| Some(p) == self.principal.as_deref())) {
                    return false;
                }
                self.principal = Some(y.clone());
                self.actors.insert(y.clone());
            }
            // C3, then C4
            EdgeType::Calls
            | EdgeType::CanInvoke
            | EdgeType::CanReach
            | EdgeType::Reads
            | EdgeType::Writes
            | EdgeType::Deletes
            | EdgeType::AuthorizedBy => {
                let principal_ok = named.is_none_or(|p| {
                    self.actors.contains(p) || self.principal.as_deref() == Some(p)
                });
                if source_acts && principal_ok {
                    self.actors.insert(y.clone());
                } else if edge.authority_mutation
                    && edge.guards.iter().any(|g| {
                        g.verdict == GuardVerdict::Fail
                            && MUTATION_PROPERTIES.contains(&g.property.as_str())
                    })
                {
                    let acting = named.map(str::to_owned).unwrap_or_else(|| x.clone());
                    self.principal = Some(acting.clone());
                    self.actors = BTreeSet::from([acting, y.clone()]);
                } else {
                    return false;
                }
            }
            // C5
            EdgeType::TransfersTo => {
                if node_type(y).is_some_and(actor_like) {
                    self.principal = Some(y.clone());
                    self.actors = BTreeSet::from([y.clone()]);
                }
            }
            // C6
            EdgeType::BelongsToTenant | EdgeType::EnforcedBy | EdgeType::CrossesTrustBoundary => {}
        }
        true
    }
}

/// `None` when the path is feasible, otherwise the index of the first edge
/// no rule explains. `node_type` resolves a node id to its type.
pub fn discontinuity<'a>(
    entry: &NodeV2,
    edges: &[&EdgeV2],
    node_type: impl Fn(&str) -> Option<NodeType> + 'a,
) -> Option<u32> {
    let mut state = Authority::for_entry(entry);
    for (index, edge) in edges.iter().enumerate() {
        if !state.step(edge, &node_type) {
            return Some(index as u32);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::AuthorityContext,
        evidence::{EdgeEvidence, EdgeEvidenceStatus},
        model::NodeSecurity,
        v2::model::{Guard, GuardScope},
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

    fn acting_step(state: &mut Authority, e: &EdgeV2) -> bool {
        state.step(e, types)
    }

    #[test]
    fn step_c1_hands_authority_to_the_delegatee() {
        let mut s = Authority::acting(USER);
        assert!(acting_step(
            &mut s,
            &edge(USER, EdgeType::DelegatesTo, AGENT, None)
        ));
        assert_eq!(s.principal.as_deref(), Some(AGENT));
        assert_eq!(s.actors, BTreeSet::from([AGENT.to_owned()]));
        let before = s.clone();
        assert!(!acting_step(
            &mut s,
            &edge(USER, EdgeType::Calls, TOOL, None)
        ));
        assert_eq!(s, before, "a refused step leaves the state unchanged");
    }

    #[test]
    fn step_c2_adds_the_credential_as_principal_and_actor() {
        let mut s = Authority::acting(AGENT);
        assert!(acting_step(
            &mut s,
            &edge(AGENT, EdgeType::UsesCredential, CRED, None)
        ));
        assert_eq!(s.principal.as_deref(), Some(CRED));
        assert_eq!(
            s.actors,
            BTreeSet::from([AGENT.to_owned(), CRED.to_owned()])
        );
        let mut s = Authority::acting(AGENT);
        assert!(!acting_step(
            &mut s,
            &edge(TOOL, EdgeType::UsesCredential, CRED, Some(OTHER))
        ));
    }

    #[test]
    fn step_c3_adds_the_target_to_the_actors() {
        let mut s = Authority::acting(AGENT);
        assert!(acting_step(
            &mut s,
            &edge(AGENT, EdgeType::Calls, TOOL, None)
        ));
        assert!(s.actors.contains(TOOL));
        assert_eq!(s.principal.as_deref(), Some(AGENT));
        assert!(!acting_step(
            &mut s,
            &edge(TOOL, EdgeType::Reads, RES, Some(OTHER))
        ));
    }

    #[test]
    fn step_c4_switches_the_principal_on_an_explained_mutation() {
        let mut jump = edge(OTHER, EdgeType::CanReach, RES, Some(OTHER));
        jump.authority_mutation = true;
        jump.guards.push(Guard {
            property: "MCP.AUTH.FINAL_OPERATION_BINDING".into(),
            verdict: GuardVerdict::Fail,
            evidence_ids: vec!["e".into()],
            scope: GuardScope::Run,
            artifact_index: 0,
        });
        let mut s = Authority::acting(AGENT);
        assert!(acting_step(&mut s, &jump));
        assert_eq!(s.principal.as_deref(), Some(OTHER));
        assert_eq!(s.actors, BTreeSet::from([OTHER.to_owned(), RES.to_owned()]));
    }

    #[test]
    fn step_c5_and_c6() {
        let mut s = Authority::unset();
        assert!(acting_step(
            &mut s,
            &edge(DOC, EdgeType::TransfersTo, AGENT, None)
        ));
        assert_eq!(s, Authority::acting(AGENT));
        let mut s = Authority::acting(AGENT);
        assert!(acting_step(
            &mut s,
            &edge(AGENT, EdgeType::TransfersTo, TOOL, None)
        ));
        assert_eq!(
            s,
            Authority::acting(AGENT),
            "a non-actor target changes nothing"
        );
        assert!(acting_step(
            &mut s,
            &edge(RES, EdgeType::BelongsToTenant, "node:tenant:t", None)
        ));
        assert_eq!(s, Authority::acting(AGENT));
    }

    #[test]
    fn initial_states() {
        let human = node(USER, NodeType::Human);
        assert_eq!(Authority::for_entry(&human), Authority::acting(USER));
        let doc = node(DOC, NodeType::Data);
        assert_eq!(Authority::for_entry(&doc), Authority::unset());
        let c = Authority::component(TOOL);
        assert_eq!(c.principal, None);
        assert_eq!(c.actors, BTreeSet::from([TOOL.to_owned()]));
        // With no principal, any source acts (C1-C3 "P unset").
        let mut c = Authority::component(TOOL);
        assert!(acting_step(
            &mut c,
            &edge(OTHER, EdgeType::Calls, RES, None)
        ));
    }
}
