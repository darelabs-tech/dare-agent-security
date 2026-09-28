//! The closed property → guarded-edge table and the guard verdict rule
//! (BLUEPRINT §6.1–§6.9 guards, §6.11).
//!
//! A projector never invents a guard: it names the *role* an edge plays, and
//! this table says which properties guard that role. A guard is attached only
//! for a property the run actually decided (it has evidence records); an
//! edge whose role's properties were all undecided stays unguarded, and so
//! `UNASSESSED`.
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::v2::{GuardScope, GuardVerdict};

use crate::{
    evidence_index::EvidenceIndex,
    facts::{FactGuard, NodeRef},
};

/// The role an edge plays in its engine's model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    ToolCalls,
    ToolCanInvoke,
    ToolOutputToSut,
    IdentityDelegates,
    IdentityUsesCredential,
    IdentityCalls,
    IdentitySubjectReaches,
    IdentityCredentialReaches,
    MemoryWrites,
    MemoryReads,
    MemoryInfluences,
    MemoryCalls,
    RagReads,
    RagInfluences,
    McpInboundReaches,
    McpUpstream,
    McpAuthorizedBy,
    McpFinalOperation,
    McpUsesInbound,
    SupplyDependency,
    SupplyLineage,
    SupplyDatasetLineage,
    SupplyExposesTool,
    A2aDelegates,
    A2aCalls,
    PromptChannel,
    MultiTurnChannel,
    MultiTurnCalls,
}

const TOOL_CALLS: &[&str] = &[
    "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
    "AGENT.TOOL.SELECTION_INTENT_BINDING",
    "AGENT.TOOL.ARGUMENT_INTEGRITY",
    "AGENT.TOOL.CHAIN_BOUNDARY",
];
const SUPPLY_FLOW: &[&str] = &[
    "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
    "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
    "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
    "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
    "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
];
const SUPPLY_LINEAGE: &[&str] = &[
    "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
    "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
    "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
    "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
    "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
    "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
];
const SUPPLY_DATASET_LINEAGE: &[&str] = &[
    "AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS",
    "AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE",
    "AGENT.SUPPLY_CHAIN.SOURCE_TRUST",
    "AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY",
    "AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY",
    "AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING",
    "AGENT.SUPPLY_CHAIN.MODEL_LINEAGE",
    "AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE",
];
const A2A_CALLS: &[&str] = &[
    "AGENT.A2A.MESSAGE_AUTHENTICITY",
    "AGENT.A2A.PEER_IDENTITY_BINDING",
    "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY",
    "AGENT.A2A.SKILL_AUTHORIZATION",
    "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
    "AGENT.A2A.TENANT_BOUNDARY",
    "AGENT.A2A.DATA_SCOPE_BOUNDARY",
    "AGENT.A2A.REPLAY_BOUNDARY",
    "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY",
    "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
    "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
];
const MULTI_TURN_CHANNEL: &[&str] = &[
    "AGENT.GOAL.REFUSAL_PERSISTENCE",
    "AGENT.GOAL.CUMULATIVE_INTENT_BOUNDARY",
    "AGENT.GOAL.DELAYED_INSTRUCTION_BOUNDARY",
    "AGENT.GOAL.OBJECTIVE_STABILITY",
    "AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY",
    "AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY",
    "AGENT.MEMORY.CONVERSATION_ISOLATION",
];

/// The owning properties a 021 `DelegatedFinding` may name. A finding for
/// any other property is counted as unprojected.
pub const MULTI_TURN_DELEGATED: &[&str] = &[
    "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
    "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
];

/// Properties guarding each role.
pub fn properties(role: Role) -> &'static [&'static str] {
    match role {
        Role::ToolCalls => TOOL_CALLS,
        Role::ToolCanInvoke => &["AGENT.TOOL.METADATA_TRUST_BOUNDARY"],
        Role::ToolOutputToSut => &["AGENT.TOOL.OUTPUT_TRUST_BOUNDARY"],
        Role::IdentityDelegates => &[
            "AGENT.IDENTITY.DELEGATION_INTEGRITY",
            "AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY",
            "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION",
        ],
        Role::IdentityUsesCredential => &["AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION"],
        Role::IdentityCalls => &[
            "AGENT.IDENTITY.PRINCIPAL_BINDING",
            "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING",
        ],
        Role::IdentitySubjectReaches => &[
            "AGENT.IDENTITY.PRINCIPAL_BINDING",
            "AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING",
            "AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY",
        ],
        Role::IdentityCredentialReaches => &["AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY"],
        Role::MemoryWrites => &[
            "AGENT.MEMORY.WRITE_TRUST_BOUNDARY",
            "AGENT.MEMORY.PROVENANCE_INTEGRITY",
        ],
        Role::MemoryReads => &[
            "AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY",
            "AGENT.MEMORY.TENANT_BOUNDARY",
            "AGENT.MEMORY.LIFECYCLE_VALIDITY",
        ],
        Role::MemoryInfluences | Role::MemoryCalls => &["AGENT.MEMORY.CONTEXT_INTEGRITY"],
        Role::RagReads => &[
            "AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY",
            "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
            "AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE",
            "AGENT.RAG.RESULT_SET_INTEGRITY",
        ],
        Role::RagInfluences => &[
            "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
            "AGENT.RAG.PROVENANCE_INTEGRITY",
        ],
        Role::McpInboundReaches => &[
            "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
            "MCP.AUTH.PROTOCOL_BINDING",
            "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
            "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
            "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
        ],
        Role::McpUpstream => &["MCP.AUTH.CREDENTIAL_SEPARATION"],
        Role::McpAuthorizedBy => &[
            "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
            "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
        ],
        Role::McpFinalOperation => &["MCP.AUTH.FINAL_OPERATION_BINDING"],
        Role::McpUsesInbound => &["MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY"],
        Role::SupplyDependency => SUPPLY_FLOW,
        Role::SupplyLineage => SUPPLY_LINEAGE,
        Role::SupplyDatasetLineage => SUPPLY_DATASET_LINEAGE,
        Role::SupplyExposesTool => &["AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT"],
        Role::A2aDelegates => &["AGENT.A2A.AUTHORITY_PROPAGATION"],
        Role::A2aCalls => A2A_CALLS,
        Role::PromptChannel => &[
            "AGENT.GOAL.INSTRUCTION_INTEGRITY",
            "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
            "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
        ],
        Role::MultiTurnChannel => MULTI_TURN_CHANNEL,
        Role::MultiTurnCalls => &["AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY"],
    }
}

pub const ALL_ROLES: [Role; 28] = [
    Role::ToolCalls,
    Role::ToolCanInvoke,
    Role::ToolOutputToSut,
    Role::IdentityDelegates,
    Role::IdentityUsesCredential,
    Role::IdentityCalls,
    Role::IdentitySubjectReaches,
    Role::IdentityCredentialReaches,
    Role::MemoryWrites,
    Role::MemoryReads,
    Role::MemoryInfluences,
    Role::MemoryCalls,
    Role::RagReads,
    Role::RagInfluences,
    Role::McpInboundReaches,
    Role::McpUpstream,
    Role::McpAuthorizedBy,
    Role::McpFinalOperation,
    Role::McpUsesInbound,
    Role::SupplyDependency,
    Role::SupplyLineage,
    Role::SupplyDatasetLineage,
    Role::SupplyExposesTool,
    Role::A2aDelegates,
    Role::A2aCalls,
    Role::PromptChannel,
    Role::MultiTurnChannel,
    Role::MultiTurnCalls,
];

/// What one run decided, per property (§6.11).
#[derive(Debug, Clone, Default)]
pub struct RunVerdicts {
    /// Property → (worst verdict over its records, its record ids).
    decided: BTreeMap<String, (GuardVerdict, Vec<String>)>,
    /// Property → entities its violations name (ENTITY-scope narrowing).
    violating: BTreeMap<String, BTreeSet<NodeRef>>,
    /// Extra FAIL guards that are ENTITY-scoped by construction (021
    /// delegated findings): (property, edge endpoint) → evidence ids.
    delegated: BTreeMap<(String, NodeRef), Vec<String>>,
}

impl RunVerdicts {
    /// The worst verdict per property over the run's evidence records.
    pub fn from_evidence(evidence: &EvidenceIndex) -> Self {
        let mut decided: BTreeMap<String, (GuardVerdict, Vec<String>)> = BTreeMap::new();
        for record in evidence.records() {
            let slot = decided
                .entry(record.property.clone())
                .or_insert((record.verdict, vec![]));
            slot.0 = slot.0.worst(record.verdict);
            slot.1.push(record.id.clone());
        }
        for (_, ids) in decided.values_mut() {
            ids.sort();
            ids.dedup();
        }
        Self {
            decided,
            ..Self::default()
        }
    }

    /// Records that a violation of `property` names `entity`.
    pub fn violation(&mut self, property: &str, entity: NodeRef) {
        self.violating
            .entry(property.to_owned())
            .or_default()
            .insert(entity);
    }

    /// Adds an ENTITY-scope FAIL for `property` on the multi-turn channel
    /// edges touching `entity` (a 021 delegated finding).
    pub fn delegated_fail(&mut self, property: &str, entity: NodeRef, evidence_ids: Vec<String>) {
        let slot = self
            .delegated
            .entry((property.to_owned(), entity))
            .or_default();
        slot.extend(evidence_ids);
        slot.sort();
        slot.dedup();
    }

    pub fn verdict(&self, property: &str) -> Option<GuardVerdict> {
        self.decided.get(property).map(|(v, _)| *v)
    }

    /// The guards for an edge playing `role` between `source` and `target`.
    pub fn guards(&self, role: Role, source: &NodeRef, target: &NodeRef) -> Vec<FactGuard> {
        let mut out = Vec::new();
        for property in properties(role) {
            if let Some((verdict, ids)) = self.decided.get(*property) {
                let named = self.violating.get(*property).filter(|set| !set.is_empty());
                let (verdict, scope) = match (verdict, named) {
                    (GuardVerdict::Fail, Some(entities)) => {
                        if entities.contains(source) || entities.contains(target) {
                            (GuardVerdict::Fail, GuardScope::Entity)
                        } else {
                            (GuardVerdict::Inconclusive, GuardScope::Entity)
                        }
                    }
                    (verdict, _) => (*verdict, GuardScope::Run),
                };
                out.push(FactGuard {
                    property: (*property).to_owned(),
                    verdict,
                    evidence_ids: ids.clone(),
                    scope,
                });
            }
        }
        for ((property, entity), ids) in &self.delegated {
            if role == Role::MultiTurnChannel && (entity == source || entity == target) {
                out.push(FactGuard {
                    property: property.clone(),
                    verdict: GuardVerdict::Fail,
                    evidence_ids: ids.clone(),
                    scope: GuardScope::Entity,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dare_attack_graph::NodeType;

    fn registry_ids() -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for raw in [
            dare_coverage::REGISTRY_JSON,
            dare_coverage::AGENTIC_REGISTRY_JSON,
        ] {
            let registry: serde_json::Value = serde_json::from_str(raw).unwrap();
            for property in registry["properties"].as_array().unwrap() {
                ids.insert(property["id"].as_str().unwrap().to_owned());
            }
        }
        ids
    }

    #[test]
    fn every_guard_property_exists_in_the_registries() {
        let ids = registry_ids();
        for role in ALL_ROLES {
            assert!(!properties(role).is_empty(), "{role:?}");
            for property in properties(role) {
                assert!(ids.contains(*property), "{role:?}: {property}");
            }
        }
        for property in MULTI_TURN_DELEGATED {
            assert!(ids.contains(*property), "{property}");
        }
    }

    fn verdicts(pairs: &[(&str, GuardVerdict)]) -> RunVerdicts {
        let mut v = RunVerdicts::default();
        for (property, verdict) in pairs {
            v.decided.insert(
                (*property).to_owned(),
                (*verdict, vec![format!("ev-{property}")]),
            );
        }
        v
    }

    fn node(id: &str) -> NodeRef {
        NodeRef::new(NodeType::Tool, id)
    }

    #[test]
    fn run_scope_applies_the_decided_verdict_and_skips_undecided_properties() {
        let v = verdicts(&[("AGENT.TOOL.AUTHORIZATION_BOUNDARY", GuardVerdict::Pass)]);
        let guards = v.guards(Role::ToolCalls, &node("sut"), &node("export"));
        assert_eq!(guards.len(), 1, "only the decided property guards the edge");
        assert_eq!(guards[0].scope, GuardScope::Run);
        assert_eq!(guards[0].verdict, GuardVerdict::Pass);
        assert!(v
            .guards(Role::ToolCanInvoke, &node("sut"), &node("export"))
            .is_empty());
    }

    #[test]
    fn a_failure_naming_an_entity_fails_only_that_entitys_edges() {
        let mut v = verdicts(&[("AGENT.TOOL.CHAIN_BOUNDARY", GuardVerdict::Fail)]);
        v.violation("AGENT.TOOL.CHAIN_BOUNDARY", node("export"));
        let hit = v.guards(Role::ToolCalls, &node("sut"), &node("export"));
        assert_eq!(hit[0].verdict, GuardVerdict::Fail);
        assert_eq!(hit[0].scope, GuardScope::Entity);
        let other = v.guards(Role::ToolCalls, &node("sut"), &node("search"));
        assert_eq!(other[0].verdict, GuardVerdict::Inconclusive);
        assert_eq!(other[0].scope, GuardScope::Entity);
    }

    #[test]
    fn a_failure_naming_no_entity_stays_run_scoped() {
        let v = verdicts(&[("AGENT.TOOL.CHAIN_BOUNDARY", GuardVerdict::Fail)]);
        let guards = v.guards(Role::ToolCalls, &node("sut"), &node("search"));
        assert_eq!(guards[0].verdict, GuardVerdict::Fail);
        assert_eq!(guards[0].scope, GuardScope::Run);
    }

    #[test]
    fn narrowing_never_improves_a_verdict_beyond_inconclusive() {
        // ENTITY scope only turns FAIL into INCONCLUSIVE on unnamed edges;
        // it never produces PASS from a FAIL.
        let mut v = verdicts(&[("AGENT.TOOL.CHAIN_BOUNDARY", GuardVerdict::Fail)]);
        v.violation("AGENT.TOOL.CHAIN_BOUNDARY", node("export"));
        for target in ["export", "search", "other"] {
            let guards = v.guards(Role::ToolCalls, &node("sut"), &node(target));
            assert!(guards.iter().all(|g| g.verdict != GuardVerdict::Pass));
        }
    }

    #[test]
    fn delegated_failures_attach_only_to_their_entity_and_role() {
        let mut v = verdicts(&[]);
        v.delegated_fail(
            "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
            node("channel.user"),
            vec!["ev".into()],
        );
        assert_eq!(
            v.guards(Role::MultiTurnChannel, &node("channel.user"), &node("sut"))
                .len(),
            1
        );
        assert!(v
            .guards(Role::MultiTurnChannel, &node("channel.tool"), &node("sut"))
            .is_empty());
        assert!(v
            .guards(Role::ToolCalls, &node("channel.user"), &node("sut"))
            .is_empty());
    }
}
