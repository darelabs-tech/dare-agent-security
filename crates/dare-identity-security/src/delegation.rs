//! Delegation chains: edges, graph integrity and bounded authority propagation.
//!
//! An edge is declarative. It names a delegator, a delegatee, optionally a
//! delegated subject, and the authority ceiling being handed on. It stores no
//! delegation token, no assertion signature and nothing a secret could hide in;
//! Cycle 015 models what a delegation *says*, and Cycle 018 will deal with what
//! a token *proves*.
//!
//! The graph rules are all fail-closed:
//!
//! - every edge must reference principals the scenario declared;
//! - the chain must be acyclic, and a repeated edge id is refused;
//! - depth is bounded, and the bound is a refusal rather than a truncation;
//! - an edge may narrow authority and may never widen it;
//! - an `ON_BEHALF_OF` edge must carry its delegated subject forward unchanged;
//! - an expired or not-yet-valid edge cannot authorize anything.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::authority::{Authority, AuthorityExcess, LogicalTime, ValidityWindow};
use crate::error::{IdentitySecurityError, Result};
use crate::principal::PrincipalSet;
use crate::source::DelegationKind;

/// One delegation edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEdge {
    pub edge_id: String,
    pub kind: DelegationKind,
    pub delegator_principal_id: String,
    pub delegatee_principal_id: String,
    /// The subject this delegation is *for*, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    /// The authority ceiling handed on by this edge, by reference.
    pub authority_ceiling_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<ValidityWindow>,
}

/// A bounded delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationChain {
    pub schema_version: String,
    pub chain_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub edges: Vec<DelegationEdge>,
}

/// Why a delegation chain was refused or found defective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainDefect {
    /// An edge widened authority instead of preserving or narrowing it.
    AuthorityExpanded {
        edge_id: String,
        excesses: Vec<AuthorityExcess>,
    },
    /// An `ON_BEHALF_OF` edge changed the subject it was carrying.
    SubjectNotPreserved {
        edge_id: String,
        expected: String,
        found: String,
    },
    /// An edge was used outside its validity window.
    NotValidAtUse { edge_id: String, detail: String },
    /// The purpose narrowed to something the previous edge never allowed.
    PurposeNotCompatible {
        edge_id: String,
        expected: String,
        found: String,
    },
    /// The audience changed to one the previous edge never allowed.
    AudienceNotCompatible {
        edge_id: String,
        expected: String,
        found: String,
    },
}

impl ChainDefect {
    pub fn edge_id(&self) -> &str {
        match self {
            Self::AuthorityExpanded { edge_id, .. }
            | Self::SubjectNotPreserved { edge_id, .. }
            | Self::NotValidAtUse { edge_id, .. }
            | Self::PurposeNotCompatible { edge_id, .. }
            | Self::AudienceNotCompatible { edge_id, .. } => edge_id,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthorityExpanded { .. } => "AUTHORITY_EXPANDED",
            Self::SubjectNotPreserved { .. } => "SUBJECT_NOT_PRESERVED",
            Self::NotValidAtUse { .. } => "NOT_VALID_AT_USE",
            Self::PurposeNotCompatible { .. } => "PURPOSE_NOT_COMPATIBLE",
            Self::AudienceNotCompatible { .. } => "AUDIENCE_NOT_COMPATIBLE",
        }
    }
}

impl DelegationChain {
    /// Structural validation: bounds, uniqueness, references and acyclicity.
    ///
    /// Runs before any authority comparison, because a malformed graph cannot
    /// be meaningfully compared — and refusing is honest where guessing is not.
    pub fn validate_structure(&self, principals: &PrincipalSet) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(IdentitySecurityError::refusal(format!(
                "delegation chain declares unsupported schema_version `{}`",
                self.schema_version
            )));
        }

        if self.edges.len() as u32 > crate::limits::HARD_MAX_DELEGATION_EDGES {
            return Err(IdentitySecurityError::refusal(format!(
                "delegation chain declares {} edges, above the hard maximum {}",
                self.edges.len(),
                crate::limits::HARD_MAX_DELEGATION_EDGES
            )));
        }

        let mut seen_edges = BTreeSet::new();
        for edge in &self.edges {
            if !seen_edges.insert(edge.edge_id.as_str()) {
                // A duplicate edge id makes the chain ambiguous: two different
                // delegations would answer to the same name in evidence.
                return Err(IdentitySecurityError::invalid(format!(
                    "duplicate delegation edge id `{}`",
                    edge.edge_id
                )));
            }

            principals.require(
                &edge.delegator_principal_id,
                &format!("delegation edge `{}` delegator", edge.edge_id),
            )?;
            principals.require(
                &edge.delegatee_principal_id,
                &format!("delegation edge `{}` delegatee", edge.edge_id),
            )?;
            if let Some(subject) = &edge.delegated_subject_id {
                principals.require(
                    subject,
                    &format!("delegation edge `{}` delegated subject", edge.edge_id),
                )?;
            }

            if edge.delegator_principal_id == edge.delegatee_principal_id {
                return Err(IdentitySecurityError::invalid(format!(
                    "delegation edge `{}` delegates from `{}` to itself",
                    edge.edge_id, edge.delegator_principal_id
                )));
            }
        }

        self.assert_acyclic()?;
        self.assert_within_depth_bound()?;
        Ok(())
    }

    /// Refuse a cycle in the delegation graph.
    ///
    /// A cycle would let authority travel around a loop and arrive looking
    /// larger than it left, which is the amplification this cycle exists to
    /// prevent — so it is refused rather than measured.
    fn assert_acyclic(&self) -> Result<()> {
        let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &self.edges {
            adjacency
                .entry(edge.delegator_principal_id.as_str())
                .or_default()
                .push(edge.delegatee_principal_id.as_str());
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Visiting,
            Done,
        }

        fn visit<'a>(
            node: &'a str,
            adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
            marks: &mut BTreeMap<&'a str, Mark>,
        ) -> Result<()> {
            match marks.get(node) {
                Some(Mark::Done) => return Ok(()),
                Some(Mark::Visiting) => {
                    return Err(IdentitySecurityError::refusal(format!(
                        "delegation chain contains a cycle through principal `{node}`"
                    )));
                }
                None => {}
            }
            marks.insert(node, Mark::Visiting);
            for next in adjacency.get(node).into_iter().flatten() {
                visit(next, adjacency, marks)?;
            }
            marks.insert(node, Mark::Done);
            Ok(())
        }

        let mut marks = BTreeMap::new();
        let nodes: Vec<&str> = adjacency.keys().copied().collect();
        for node in nodes {
            visit(node, &adjacency, &mut marks)?;
        }
        Ok(())
    }

    /// The longest path through the chain, measured in edges.
    pub fn depth(&self) -> u32 {
        let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut has_incoming: BTreeSet<&str> = BTreeSet::new();
        for edge in &self.edges {
            adjacency
                .entry(edge.delegator_principal_id.as_str())
                .or_default()
                .push(edge.delegatee_principal_id.as_str());
            has_incoming.insert(edge.delegatee_principal_id.as_str());
        }

        fn longest<'a>(
            node: &'a str,
            adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
            depth: u32,
            budget: u32,
        ) -> u32 {
            // The budget stops a runaway walk on a graph that slipped past the
            // acyclicity check; it never lets a longer path be under-reported
            // as short enough, because exceeding it still exceeds the bound.
            if budget == 0 {
                return depth;
            }
            adjacency
                .get(node)
                .into_iter()
                .flatten()
                .map(|next| longest(next, adjacency, depth + 1, budget - 1))
                .max()
                .unwrap_or(depth)
        }

        let budget = crate::limits::HARD_MAX_DELEGATION_EDGES + 1;
        adjacency
            .keys()
            .filter(|node| !has_incoming.contains(*node))
            .map(|root| longest(root, &adjacency, 0, budget))
            .max()
            .unwrap_or(0)
    }

    fn assert_within_depth_bound(&self) -> Result<()> {
        let depth = self.depth();
        if depth > crate::limits::HARD_MAX_DELEGATION_DEPTH {
            return Err(IdentitySecurityError::refusal(format!(
                "delegation chain depth {depth} exceeds the hard maximum {}",
                crate::limits::HARD_MAX_DELEGATION_DEPTH
            )));
        }
        Ok(())
    }

    /// Edges in delegation order, following delegator -> delegatee.
    ///
    /// Returns the edges as a path when the chain is linear. A chain that is
    /// not a simple path is returned in declaration order, which is still
    /// deterministic and still checked pairwise.
    pub fn ordered_edges(&self) -> Vec<&DelegationEdge> {
        let mut by_delegator: BTreeMap<&str, &DelegationEdge> = BTreeMap::new();
        let mut has_incoming: BTreeSet<&str> = BTreeSet::new();
        for edge in &self.edges {
            by_delegator.insert(edge.delegator_principal_id.as_str(), edge);
            has_incoming.insert(edge.delegatee_principal_id.as_str());
        }

        let root = self
            .edges
            .iter()
            .map(|edge| edge.delegator_principal_id.as_str())
            .find(|delegator| !has_incoming.contains(delegator));

        let Some(root) = root else {
            return self.edges.iter().collect();
        };

        let mut ordered = Vec::new();
        let mut current = root;
        let mut guard = self.edges.len();
        while let Some(edge) = by_delegator.get(current) {
            ordered.push(*edge);
            current = edge.delegatee_principal_id.as_str();
            guard = match guard.checked_sub(1) {
                Some(remaining) => remaining,
                None => break,
            };
        }

        if ordered.len() == self.edges.len() {
            ordered
        } else {
            self.edges.iter().collect()
        }
    }

    /// Every way the chain propagates authority defectively.
    ///
    /// A list rather than a first match: a chain can expand authority on one
    /// edge, lose its subject on another and be expired on a third, and a
    /// report that mentioned only the first would understate the problem.
    pub fn defects(
        &self,
        authorities: &BTreeMap<String, Authority>,
        at: LogicalTime,
    ) -> Vec<ChainDefect> {
        let mut defects = Vec::new();
        let ordered = self.ordered_edges();

        let mut previous: Option<&DelegationEdge> = None;
        for edge in ordered {
            // Validity is checked per edge: an expired edge cannot authorize
            // anything regardless of what it says about authority.
            if let Some(window) = &edge.validity {
                if let Some(detail) = window.describe_exclusion(at) {
                    defects.push(ChainDefect::NotValidAtUse {
                        edge_id: edge.edge_id.clone(),
                        detail,
                    });
                }
            }

            if let Some(previous) = previous {
                // Authority may narrow, never widen.
                if let (Some(mine), Some(theirs)) = (
                    authorities.get(&edge.authority_ceiling_id),
                    authorities.get(&previous.authority_ceiling_id),
                ) {
                    let excesses = mine.excess_over(theirs);
                    if !excesses.is_empty() {
                        defects.push(ChainDefect::AuthorityExpanded {
                            edge_id: edge.edge_id.clone(),
                            excesses,
                        });
                    }
                }

                // An ON_BEHALF_OF edge exists to carry a subject. Changing it
                // discards the only thing that edge was for.
                if edge.kind.preserves_delegated_subject() {
                    if let (Some(expected), Some(found)) = (
                        previous.delegated_subject_id.as_ref(),
                        edge.delegated_subject_id.as_ref(),
                    ) {
                        if expected != found {
                            defects.push(ChainDefect::SubjectNotPreserved {
                                edge_id: edge.edge_id.clone(),
                                expected: expected.clone(),
                                found: found.clone(),
                            });
                        }
                    }
                }

                if let (Some(expected), Some(found)) =
                    (previous.purpose_id.as_ref(), edge.purpose_id.as_ref())
                {
                    if expected != found {
                        defects.push(ChainDefect::PurposeNotCompatible {
                            edge_id: edge.edge_id.clone(),
                            expected: expected.clone(),
                            found: found.clone(),
                        });
                    }
                }

                if let (Some(expected), Some(found)) =
                    (previous.audience.as_ref(), edge.audience.as_ref())
                {
                    if expected != found {
                        defects.push(ChainDefect::AudienceNotCompatible {
                            edge_id: edge.edge_id.clone(),
                            expected: expected.clone(),
                            found: found.clone(),
                        });
                    }
                }
            }

            previous = Some(edge);
        }

        defects
    }

    /// The authority ceiling the chain ultimately confers, if any.
    pub fn terminal_ceiling_id(&self) -> Option<&str> {
        self.ordered_edges()
            .last()
            .map(|edge| edge.authority_ceiling_id.as_str())
    }

    /// The subject the chain ultimately carries, if any.
    pub fn terminal_subject_id(&self) -> Option<&str> {
        self.ordered_edges()
            .last()
            .and_then(|edge| edge.delegated_subject_id.as_deref())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authority::AuthorityDimension;
    use crate::principal::tests::valid_principal_set;
    use serde_json::json;

    fn authorities() -> BTreeMap<String, Authority> {
        let mut map = BTreeMap::new();
        let broad = Authority {
            id: "authority-user-read".to_owned(),
            title: None,
            actions: AuthorityDimension::only(["read", "list"]),
            resource_ids: AuthorityDimension::Any,
            resource_types: AuthorityDimension::only(["document"]),
            tenant_ids: AuthorityDimension::only(["tenant-a"]),
            scopes: AuthorityDimension::only(["support.read"]),
            purposes: AuthorityDimension::only(["purpose-summarize"]),
            audiences: AuthorityDimension::only(["api://support"]),
            validity: None,
        };
        let narrowed = Authority {
            id: "authority-agent-read".to_owned(),
            actions: AuthorityDimension::only(["read"]),
            ..broad.clone()
        };
        let widened = Authority {
            id: "authority-agent-admin".to_owned(),
            actions: AuthorityDimension::only(["read", "delete"]),
            ..broad.clone()
        };
        map.insert(broad.id.clone(), broad);
        map.insert(narrowed.id.clone(), narrowed);
        map.insert(widened.id.clone(), widened);
        map
    }

    pub(crate) fn valid_chain_value() -> serde_json::Value {
        json!({
            "schema_version": "1",
            "chain_id": "chain-support-obo",
            "title": "user delegates read to the agent, which hands off to a service",
            "edges": [
                {
                    "edge_id": "edge-user-to-agent",
                    "kind": "ON_BEHALF_OF",
                    "delegator_principal_id": "user-7",
                    "delegatee_principal_id": "agent-1",
                    "delegated_subject_id": "user-7",
                    "authority_ceiling_id": "authority-user-read",
                    "purpose_id": "purpose-summarize",
                    "audience": "api://support"
                },
                {
                    "edge_id": "edge-agent-to-service",
                    "kind": "SERVICE_DELEGATION",
                    "delegator_principal_id": "agent-1",
                    "delegatee_principal_id": "svc-index",
                    "delegated_subject_id": "user-7",
                    "authority_ceiling_id": "authority-agent-read",
                    "purpose_id": "purpose-summarize",
                    "audience": "api://support"
                }
            ]
        })
    }

    pub(crate) fn valid_chain() -> DelegationChain {
        serde_json::from_value(valid_chain_value()).expect("chain decodes")
    }

    #[test]
    fn a_representative_chain_validates_and_narrows() {
        let chain = valid_chain();
        chain
            .validate_structure(&valid_principal_set())
            .expect("structurally valid");
        assert!(chain.defects(&authorities(), 0).is_empty());
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.terminal_ceiling_id(), Some("authority-agent-read"));
        assert_eq!(chain.terminal_subject_id(), Some("user-7"));
    }

    #[test]
    fn an_edge_that_widens_authority_is_a_defect() {
        let mut chain = valid_chain();
        chain.edges[1].authority_ceiling_id = "authority-agent-admin".to_owned();

        let defects = chain.defects(&authorities(), 0);
        assert_eq!(defects.len(), 1);
        assert_eq!(defects[0].kind(), "AUTHORITY_EXPANDED");
        assert_eq!(defects[0].edge_id(), "edge-agent-to-service");
    }

    #[test]
    fn an_edge_that_narrows_authority_is_not_a_defect() {
        // Narrowing is the whole point of delegation, so it must stay silent.
        let mut chain = valid_chain();
        chain.edges[0].authority_ceiling_id = "authority-user-read".to_owned();
        chain.edges[1].authority_ceiling_id = "authority-agent-read".to_owned();
        assert!(chain.defects(&authorities(), 0).is_empty());
    }

    #[test]
    fn an_on_behalf_of_edge_must_carry_its_subject_forward() {
        let mut chain = valid_chain();
        chain.edges[1].kind = DelegationKind::OnBehalfOf;
        chain.edges[1].delegated_subject_id = Some("agent-1".to_owned());

        let defects = chain.defects(&authorities(), 0);
        let subject: Vec<&ChainDefect> = defects
            .iter()
            .filter(|defect| defect.kind() == "SUBJECT_NOT_PRESERVED")
            .collect();
        assert_eq!(subject.len(), 1);
    }

    #[test]
    fn an_expired_edge_is_a_defect_at_the_time_of_use() {
        let mut chain = valid_chain();
        chain.edges[1].validity = Some(ValidityWindow::new(10, 20).expect("window"));

        assert!(
            chain.defects(&authorities(), 15).is_empty(),
            "inside the window"
        );

        let defects = chain.defects(&authorities(), 25);
        assert_eq!(defects.len(), 1);
        assert_eq!(defects[0].kind(), "NOT_VALID_AT_USE");
        match &defects[0] {
            ChainDefect::NotValidAtUse { detail, .. } => assert!(detail.contains("expired")),
            other => panic!("unexpected defect {other:?}"),
        }
    }

    #[test]
    fn a_not_yet_valid_edge_is_also_a_defect() {
        let mut chain = valid_chain();
        chain.edges[1].validity = Some(ValidityWindow::new(100, 200).expect("window"));
        let defects = chain.defects(&authorities(), 50);
        match &defects[0] {
            ChainDefect::NotValidAtUse { detail, .. } => assert!(detail.contains("not yet valid")),
            other => panic!("unexpected defect {other:?}"),
        }
    }

    #[test]
    fn several_defects_in_one_chain_are_all_reported() {
        // One classification never masks another.
        let mut chain = valid_chain();
        chain.edges[1].authority_ceiling_id = "authority-agent-admin".to_owned();
        chain.edges[1].kind = DelegationKind::OnBehalfOf;
        chain.edges[1].delegated_subject_id = Some("agent-1".to_owned());
        chain.edges[1].validity = Some(ValidityWindow::new(10, 20).expect("window"));
        chain.edges[1].audience = Some("api://other".to_owned());

        let defects = chain.defects(&authorities(), 99);
        let kinds: BTreeSet<&str> = defects.iter().map(ChainDefect::kind).collect();
        assert!(kinds.contains("AUTHORITY_EXPANDED"));
        assert!(kinds.contains("SUBJECT_NOT_PRESERVED"));
        assert!(kinds.contains("NOT_VALID_AT_USE"));
        assert!(kinds.contains("AUDIENCE_NOT_COMPATIBLE"));
        assert!(defects.len() >= 4);
    }

    #[test]
    fn a_cycle_is_refused_rather_than_measured() {
        let mut chain = valid_chain();
        chain.edges.push(DelegationEdge {
            edge_id: "edge-service-back-to-user".to_owned(),
            kind: DelegationKind::AgentHandoff,
            delegator_principal_id: "svc-index".to_owned(),
            delegatee_principal_id: "user-7".to_owned(),
            delegated_subject_id: None,
            authority_ceiling_id: "authority-user-read".to_owned(),
            purpose_id: None,
            audience: None,
            validity: None,
        });

        let err = chain
            .validate_structure(&valid_principal_set())
            .expect_err("a cycle must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn a_self_delegation_is_refused() {
        let mut chain = valid_chain();
        chain.edges[0].delegatee_principal_id = "user-7".to_owned();
        assert!(chain.validate_structure(&valid_principal_set()).is_err());
    }

    #[test]
    fn an_unknown_principal_reference_is_refused() {
        let mut chain = valid_chain();
        chain.edges[0].delegatee_principal_id = "ghost".to_owned();
        let err = chain
            .validate_structure(&valid_principal_set())
            .expect_err("unknown reference");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn a_duplicate_edge_id_is_refused() {
        let mut chain = valid_chain();
        let mut duplicate = chain.edges[1].clone();
        duplicate.delegatee_principal_id = "user-7".to_owned();
        duplicate.delegator_principal_id = "svc-index".to_owned();
        chain.edges.push(duplicate);
        let err = chain
            .validate_structure(&valid_principal_set())
            .expect_err("duplicate edge id");
        assert!(err.to_string().contains("duplicate delegation edge id"));
    }

    #[test]
    fn the_edge_count_bound_is_a_refusal_not_a_truncation() {
        let mut chain = valid_chain();
        let template = chain.edges[0].clone();
        for index in 0..20 {
            let mut edge = template.clone();
            edge.edge_id = format!("filler-{index}");
            chain.edges.push(edge);
        }
        let err = chain
            .validate_structure(&valid_principal_set())
            .expect_err("over-limit chain");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("above the hard maximum 12"));
    }

    #[test]
    fn the_depth_bound_is_enforced() {
        // A linear chain of five edges is depth 5, one past the maximum.
        let mut set = valid_principal_set();
        for index in 0..4 {
            let mut principal = set.principals[1].clone();
            principal.id = format!("agent-{}", index + 2);
            set.principals.push(principal);
        }

        let mut chain = valid_chain();
        chain.edges.clear();
        let path = [
            "user-7", "agent-1", "agent-2", "agent-3", "agent-4", "agent-5",
        ];
        for (index, window) in path.windows(2).enumerate() {
            chain.edges.push(DelegationEdge {
                edge_id: format!("edge-{index}"),
                kind: DelegationKind::AgentHandoff,
                delegator_principal_id: window[0].to_owned(),
                delegatee_principal_id: window[1].to_owned(),
                delegated_subject_id: None,
                authority_ceiling_id: "authority-user-read".to_owned(),
                purpose_id: None,
                audience: None,
                validity: None,
            });
        }
        assert_eq!(chain.depth(), 5);

        let err = chain
            .validate_structure(&set)
            .expect_err("depth 5 exceeds the maximum of 4");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("depth 5"));
    }

    #[test]
    fn exactly_the_maximum_depth_is_allowed() {
        let mut set = valid_principal_set();
        for index in 0..3 {
            let mut principal = set.principals[1].clone();
            principal.id = format!("agent-{}", index + 2);
            set.principals.push(principal);
        }

        let mut chain = valid_chain();
        chain.edges.clear();
        let path = ["user-7", "agent-1", "agent-2", "agent-3", "agent-4"];
        for (index, window) in path.windows(2).enumerate() {
            chain.edges.push(DelegationEdge {
                edge_id: format!("edge-{index}"),
                kind: DelegationKind::AgentHandoff,
                delegator_principal_id: window[0].to_owned(),
                delegatee_principal_id: window[1].to_owned(),
                delegated_subject_id: None,
                authority_ceiling_id: "authority-user-read".to_owned(),
                purpose_id: None,
                audience: None,
                validity: None,
            });
        }
        assert_eq!(chain.depth(), 4);
        chain
            .validate_structure(&set)
            .expect("the boundary is allowed");
    }

    #[test]
    fn an_empty_chain_is_structurally_valid_and_confers_nothing() {
        // No delegation is not a defective delegation. It simply grants
        // nothing, and the authority evaluators decide what that means.
        let mut chain = valid_chain();
        chain.edges.clear();
        chain
            .validate_structure(&valid_principal_set())
            .expect("valid");
        assert_eq!(chain.depth(), 0);
        assert_eq!(chain.terminal_ceiling_id(), None);
        assert!(chain.defects(&authorities(), 0).is_empty());
    }

    #[test]
    fn an_edge_cannot_carry_token_material() {
        for hostile in [
            json!({"edge_id": "e", "kind": "ON_BEHALF_OF", "delegator_principal_id": "a",
                   "delegatee_principal_id": "b", "authority_ceiling_id": "c",
                   "assertion_jwt": "eyJhbGciOi"}),
            json!({"edge_id": "e", "kind": "ON_BEHALF_OF", "delegator_principal_id": "a",
                   "delegatee_principal_id": "b", "authority_ceiling_id": "c",
                   "access_token": "abc"}),
            json!({"edge_id": "e", "kind": "ON_BEHALF_OF", "delegator_principal_id": "a",
                   "delegatee_principal_id": "b", "authority_ceiling_id": "c",
                   "signature": "sig"}),
        ] {
            assert!(
                serde_json::from_value::<DelegationEdge>(hostile.clone()).is_err(),
                "must refuse: {hostile}"
            );
        }
    }

    #[test]
    fn ordering_is_deterministic_for_a_linear_chain() {
        let chain = valid_chain();
        let first: Vec<&str> = chain
            .ordered_edges()
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect();
        let second: Vec<&str> = chain
            .ordered_edges()
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect();
        assert_eq!(first, second);
        assert_eq!(first, ["edge-user-to-agent", "edge-agent-to-service"]);
    }

    #[test]
    fn defects_are_deterministic_across_repeated_evaluation() {
        let mut chain = valid_chain();
        chain.edges[1].authority_ceiling_id = "authority-agent-admin".to_owned();
        let authorities = authorities();
        assert_eq!(
            chain.defects(&authorities, 0),
            chain.defects(&authorities, 0)
        );
    }
}
