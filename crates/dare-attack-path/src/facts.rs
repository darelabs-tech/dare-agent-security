//! Run facts: what every projector emits (BLUEPRINT §4.6).
//!
//! Facts use engine-local identifiers. `merge` turns them into node ids,
//! applying the system model's aliases, and never earlier: a projector
//! cannot merge identities.
use std::collections::BTreeMap;

use dare_attack_graph::{
    v2::{EntryClass, GuardScope, GuardVerdict, TargetClass},
    EdgeEvidence, EdgeEvidenceStatus, EdgeType, NodeSecurity, NodeType,
};

use crate::{bundle::LoadedBundle, ids::EngineSlug, ids::RunTag};

/// A node named by its type and engine-local id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeRef {
    pub node_type: NodeType,
    pub local_id: String,
}

impl NodeRef {
    pub fn new(node_type: NodeType, local_id: impl Into<String>) -> Self {
        Self {
            node_type,
            local_id: local_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactNode {
    pub node: NodeRef,
    pub raw_label: String,
    pub security: NodeSecurity,
    pub original_kind: String,
    pub locator: String,
}

/// `AuthorityContext` before resolution: `principal` and `credential` name
/// local nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactAuthority {
    pub principal: Option<NodeRef>,
    pub agent_identity: Option<String>,
    pub service_identity: Option<String>,
    pub delegated: bool,
    pub tenant: Option<String>,
    pub credential: Option<NodeRef>,
    pub authorization_decision: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactGuard {
    pub property: String,
    pub verdict: GuardVerdict,
    pub evidence_ids: Vec<String>,
    pub scope: GuardScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactEdge {
    pub edge_type: EdgeType,
    pub source: NodeRef,
    pub target: NodeRef,
    pub authority: FactAuthority,
    pub evidence: EdgeEvidence,
    pub guards: Vec<FactGuard>,
    pub authority_mutation: bool,
    pub original_kind: String,
    pub locator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Designation {
    Entry(EntryClass),
    Target(TargetClass),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FactDesignation {
    pub node: NodeRef,
    pub designation: Designation,
}

/// Everything one artifact contributes.
#[derive(Debug, Clone)]
pub struct RunFacts {
    pub artifact_index: u32,
    pub engine: EngineSlug,
    pub run: RunTag,
    pub mode: String,
    pub synthetic: bool,
    pub dynamic_authorized: bool,
    pub result_digest: String,
    pub evidence_digest: String,
    pub input_digests: Vec<String>,
    pub verified_inputs: Vec<String>,
    pub nodes: Vec<FactNode>,
    pub edges: Vec<FactEdge>,
    pub designations: Vec<FactDesignation>,
    pub unprojected: BTreeMap<String, u32>,
}

/// Evidence for an edge observed in a trial or outcome.
pub fn observed(evidence_ids: Vec<String>) -> EdgeEvidence {
    let mut ids = evidence_ids;
    ids.sort();
    ids.dedup();
    EdgeEvidence {
        status: EdgeEvidenceStatus::Observed,
        evidence_ids: ids,
        rationale: None,
        source_facts: vec![],
        reason: None,
    }
}

/// `input:<engine>:<hex>` for a relationship read from a pinned input (AD-09).
pub fn input_evidence_id(engine: EngineSlug, digest: &str) -> String {
    format!(
        "input:{}:{}",
        engine.as_str(),
        digest.strip_prefix("sha256:").unwrap_or(digest)
    )
}

/// Evidence for a relationship read from a pinned input document.
pub fn statically_proven(engine: EngineSlug, digests: &[&str]) -> EdgeEvidence {
    let mut ids: Vec<String> = digests
        .iter()
        .map(|d| input_evidence_id(engine, d))
        .collect();
    ids.sort();
    ids.dedup();
    EdgeEvidence {
        status: EdgeEvidenceStatus::StaticallyProven,
        evidence_ids: ids,
        rationale: None,
        source_facts: vec![],
        reason: None,
    }
}

/// Accumulates facts for one run. Nodes are keyed by `NodeRef`; a second
/// sighting ORs the security flags and keeps the first label and locator.
#[derive(Debug)]
pub struct FactSink {
    facts: RunFacts,
    index: BTreeMap<NodeRef, usize>,
}

impl FactSink {
    pub fn new(bundle: &LoadedBundle) -> Self {
        Self {
            facts: RunFacts {
                artifact_index: bundle.index as u32,
                engine: bundle.engine,
                run: bundle.run.clone(),
                mode: bundle.mode.clone(),
                synthetic: bundle.synthetic,
                dynamic_authorized: bundle.dynamic_authorized,
                result_digest: bundle.result_digest.clone(),
                evidence_digest: bundle.evidence_digest.clone(),
                input_digests: bundle.input_digests.clone(),
                verified_inputs: bundle.verified_inputs.clone(),
                nodes: vec![],
                edges: vec![],
                designations: vec![],
                unprojected: BTreeMap::new(),
            },
            index: BTreeMap::new(),
        }
    }

    pub fn node(
        &mut self,
        node: NodeRef,
        raw_label: &str,
        security: NodeSecurity,
        original_kind: &str,
        locator: impl Into<String>,
    ) -> NodeRef {
        if let Some(&at) = self.index.get(&node) {
            let existing = &mut self.facts.nodes[at].security;
            existing.privileged |= security.privileged;
            existing.sensitive |= security.sensitive;
            existing.destructive |= security.destructive;
            if existing.tenant.is_none() {
                existing.tenant = security.tenant;
            }
            if existing.state_impact.is_none() {
                existing.state_impact = security.state_impact;
            }
            return node;
        }
        self.index.insert(node.clone(), self.facts.nodes.len());
        self.facts.nodes.push(FactNode {
            node: node.clone(),
            raw_label: raw_label.to_owned(),
            security,
            original_kind: original_kind.to_owned(),
            locator: locator.into(),
        });
        node
    }

    pub fn has(&self, node: &NodeRef) -> bool {
        self.index.contains_key(node)
    }

    pub fn edge(&mut self, edge: FactEdge) {
        self.facts.edges.push(edge);
    }

    pub fn designate(&mut self, node: &NodeRef, designation: Designation) {
        let fact = FactDesignation {
            node: node.clone(),
            designation,
        };
        if !self.facts.designations.contains(&fact) {
            self.facts.designations.push(fact);
        }
    }

    pub fn unprojected(&mut self, kind: impl Into<String>) {
        *self.facts.unprojected.entry(kind.into()).or_insert(0) += 1;
    }

    pub fn finish(mut self) -> RunFacts {
        self.facts.designations.sort();
        self.facts
    }
}
