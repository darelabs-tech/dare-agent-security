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
///
/// Generic over the node key so that a search may carry interned ids while
/// the rule itself exists once, in [`Authority::step_by`]. Every caller that
/// works on node-id strings uses the default `String` form and
/// [`Authority::step`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority<T = String> {
    pub principal: Option<T>,
    pub actors: BTreeSet<T>,
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
        Self::acting_as(node.to_owned())
    }

    /// `P` unset, `A = {}`.
    pub fn unset() -> Self {
        Self::empty()
    }

    /// `P` unset, `A = {node}`: a component that acts under whatever
    /// authority its edges carry.
    pub fn component(node: &str) -> Self {
        Self::component_of(node.to_owned())
    }

    /// Applies C1–C6 to `edge`. Returns false, leaving the state unchanged,
    /// when no rule explains the step.
    pub fn step(&mut self, edge: &EdgeV2, node_type: impl Fn(&str) -> Option<NodeType>) -> bool {
        self.step_by(edge, str::to_owned, node_type)
    }
}

impl<T: Ord + Clone> Authority<T> {
    /// `P = node`, `A = {node}`.
    pub fn acting_as(node: T) -> Self {
        Self {
            principal: Some(node.clone()),
            actors: BTreeSet::from([node]),
        }
    }

    /// `P` unset, `A = {}`.
    pub fn empty() -> Self {
        Self {
            principal: None,
            actors: BTreeSet::new(),
        }
    }

    /// `P` unset, `A = {node}`.
    pub fn component_of(node: T) -> Self {
        Self {
            principal: None,
            actors: BTreeSet::from([node]),
        }
    }

    /// Applies C1–C6 to `edge`, with `key` mapping each node id the edge
    /// names to `T`. `key` must be injective over the ids it is given.
    /// Returns false, leaving the state unchanged, when no rule explains the
    /// step.
    pub fn step_by(
        &mut self,
        edge: &EdgeV2,
        key: impl Fn(&str) -> T,
        node_type: impl Fn(&str) -> Option<NodeType>,
    ) -> bool {
        let source_acts = self.principal.is_none() || self.actors.contains(&key(&edge.source));
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
                let y = key(&edge.target);
                self.principal = Some(y.clone());
                self.actors = BTreeSet::from([y]);
            }
            // C2
            EdgeType::UsesCredential => {
                if !(source_acts || named.is_some_and(|p| self.principal.as_ref() == Some(&key(p))))
                {
                    return false;
                }
                let y = key(&edge.target);
                self.principal = Some(y.clone());
                self.actors.insert(y);
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
                    let p = key(p);
                    self.actors.contains(&p) || self.principal.as_ref() == Some(&p)
                });
                if source_acts && principal_ok {
                    self.actors.insert(key(&edge.target));
                } else if edge.authority_mutation
                    && edge.guards.iter().any(|g| {
                        g.verdict == GuardVerdict::Fail
                            && MUTATION_PROPERTIES.contains(&g.property.as_str())
                    })
                {
                    let acting = named.map_or_else(|| key(&edge.source), &key);
                    self.principal = Some(acting.clone());
                    self.actors = BTreeSet::from([acting, key(&edge.target)]);
                } else {
                    return false;
                }
            }
            // C5
            EdgeType::TransfersTo => {
                if node_type(&edge.target).is_some_and(actor_like) {
                    let y = key(&edge.target);
                    self.principal = Some(y.clone());
                    self.actors = BTreeSet::from([y]);
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

    /// The interned form used by the blast-radius search applies the same
    /// rule: over random edge sequences, `step_by` with `u32` keys and `step`
    /// on strings accept and refuse the same edges and end in the same state.
    #[test]
    fn interned_and_string_authorities_take_the_same_steps() {
        let ids = [
            "node:human:h",
            "node:agent:a",
            "node:agent:b",
            "node:identity:i",
            "node:credential:c",
            "node:tool:t",
            "node:resource:r",
            "node:data:d",
        ];
        let kinds = [
            EdgeType::AuthenticatesAs,
            EdgeType::DelegatesTo,
            EdgeType::CanInvoke,
            EdgeType::Calls,
            EdgeType::UsesCredential,
            EdgeType::AuthorizedBy,
            EdgeType::EnforcedBy,
            EdgeType::Reads,
            EdgeType::Writes,
            EdgeType::Deletes,
            EdgeType::TransfersTo,
            EdgeType::BelongsToTenant,
            EdgeType::CrossesTrustBoundary,
            EdgeType::CanReach,
        ];
        let key = |id: &str| -> u32 {
            ids.iter()
                .position(|n| *n == id)
                .map_or(100 + id.len() as u32, |i| i as u32)
        };
        let expand = |a: &Authority<u32>| Authority {
            principal: a.principal.map(|k| ids[k as usize].to_owned()),
            actors: a
                .actors
                .iter()
                .map(|k| ids[*k as usize].to_owned())
                .collect(),
        };
        let mut seed = 0x0025_u64;
        let mut next = |n: usize| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((seed >> 33) % n as u64) as usize
        };
        let (mut taken, mut refused) = (0, 0);
        for _ in 0..2_000 {
            let start = ids[next(ids.len())];
            let (mut text, mut compact) = match next(3) {
                0 => (Authority::acting(start), Authority::acting_as(key(start))),
                1 => (Authority::unset(), Authority::<u32>::empty()),
                _ => (
                    Authority::component(start),
                    Authority::component_of(key(start)),
                ),
            };
            for _ in 0..8 {
                let principal = match next(4) {
                    0 => Some(ids[next(ids.len())]),
                    1 => Some("ext:issuer:sub"),
                    _ => None,
                };
                let mut e = edge(
                    ids[next(ids.len())],
                    kinds[next(kinds.len())],
                    ids[next(ids.len())],
                    principal,
                );
                if next(4) == 0 {
                    e.authority_mutation = true;
                    e.guards.push(Guard {
                        property: MUTATION_PROPERTIES[next(3)].into(),
                        verdict: GuardVerdict::Fail,
                        evidence_ids: vec!["e".into()],
                        scope: GuardScope::Run,
                        artifact_index: 0,
                    });
                }
                let a = text.step(&e, types);
                let b = compact.step_by(&e, key, types);
                assert_eq!(a, b, "{e:?}");
                assert_eq!(text, expand(&compact), "{e:?}");
                if a {
                    taken += 1;
                } else {
                    refused += 1;
                }
            }
        }
        // Both outcomes were exercised, many times.
        assert!(taken > 1_000 && refused > 1_000, "{taken} {refused}");
    }
}
