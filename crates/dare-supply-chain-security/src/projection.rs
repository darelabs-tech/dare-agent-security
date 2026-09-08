//! Agentic surfaces as supply-chain components.
//!
//! A tool, a skill plugin and an MCP server arrive in a deployment the same way
//! a package does: somebody published them, somebody pulled them in, and what
//! is running may not be what was approved. That makes them supply-chain
//! components, and this module says so — they are not a separate model with
//! separate rules, they are [`Component`]s that the same identity, digest,
//! provenance and attestation machinery already covers.
//!
//! # What this module is for
//!
//! Two boundaries that are easy to cross by accident, and expensive once
//! crossed:
//!
//! **Cycle 014 owns tool authorization.** Whether a tool may be *invoked*, by
//! whom, with which arguments, under which policy — none of that is here. This
//! cycle asks where the tool came from and whether it is the one that was
//! approved. A tool can be perfectly authorized and be the wrong artifact; a
//! tool can be the right artifact and be invoked by someone who should not.
//! Two questions, two engines, and an answer to one is not an answer to the
//! other.
//!
//! **Cycle 020 owns A2A security.** An external agent appearing in a bill of
//! materials is an *inventory row*. It says a document mentioned another
//! agent. It does not say the two agents are allowed to talk, that a delegation
//! is authorized, or that a trust relationship exists — and
//! `external agent listed != A2A authorization` is a listed rule of this cycle
//! precisely because the inventory row looks so much like the authorization.
//!
//! Both boundaries are enforced structurally: [`AgenticProjection`] has no
//! field in which an authorization decision could be recorded, and the tests
//! assert that adding one fails to decode.

use serde::{Deserialize, Serialize};

use crate::component::Component;
use crate::normalize::SupplyChainEvidence;
use crate::source::ComponentType;

/// Component classes that are agentic surfaces rather than plain dependencies.
///
/// `EXTERNAL_AGENT` is deliberately absent: it is inventoried, but it is not a
/// component this deployment supplies, and treating it as one would invite the
/// engine to assess artifacts nobody here builds or installs.
pub const AGENTIC_SURFACE_CLASSES: [ComponentType; 4] = [
    ComponentType::Tool,
    ComponentType::SkillPlugin,
    ComponentType::McpServer,
    ComponentType::Guardrail,
];

/// Whether a class is an agentic surface this cycle projects.
pub fn is_agentic_surface(component_type: ComponentType) -> bool {
    AGENTIC_SURFACE_CLASSES.contains(&component_type)
}

/// The supply-chain view of one agentic surface.
///
/// Every field answers a supply-chain question. There is no field for whether
/// the surface may be used, invoked, delegated to, or trusted at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgenticProjection {
    pub component_id: String,
    pub component_type: ComponentType,
    /// Whether an immutable artifact digest is recorded.
    pub has_digest: bool,
    /// Whether any origin claim (source, supplier, publisher) exists.
    pub has_origin_claim: bool,
    /// Whether both an approved and an observed capability set exist, so drift
    /// is answerable. The drift answer itself belongs to
    /// [`crate::capability`].
    pub capabilities_comparable: bool,
}

/// Project one component as an agentic surface.
///
/// `None` for classes that are not agentic surfaces — a package is a
/// supply-chain component and is assessed as one, but it is not a surface an
/// agent acts through, and returning a projection for it would make the
/// distinction meaningless.
pub fn project(component: &Component) -> Option<AgenticProjection> {
    if !is_agentic_surface(component.component_type) {
        return None;
    }
    let capabilities_comparable = component.capabilities.as_ref().is_some_and(|projection| {
        !projection.approved.is_empty() && !projection.observed.is_empty()
    });
    Some(AgenticProjection {
        component_id: component.component_id.clone(),
        component_type: component.component_type,
        has_digest: !component.digests.is_empty(),
        has_origin_claim: !component.supplier.is_empty(),
        capabilities_comparable,
    })
}

/// Every agentic surface in the evidence.
pub fn agentic_surfaces(evidence: &SupplyChainEvidence) -> Vec<AgenticProjection> {
    evidence.components.iter().filter_map(project).collect()
}

/// One external agent a document mentioned.
///
/// An inventory row and nothing else. It records that an external agent was
/// named and which local components record an edge to it, so an operator knows
/// the surface exists. It records nothing about whether communication with it
/// is authorized — that is Cycle 020's question, and this type has no field in
/// which to answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAgentEntry {
    pub component_id: String,
    pub name: String,
    /// Local components that record a relationship to this external agent.
    pub referenced_by: Vec<String>,
    /// Whether the inventory row carries an origin claim at all.
    pub has_origin_claim: bool,
}

/// Inventory the external agents named in the evidence.
///
/// The rows are ordered by component id so the inventory is stable across runs
/// and across document orderings.
pub fn external_agents(evidence: &SupplyChainEvidence) -> Vec<ExternalAgentEntry> {
    let mut entries: Vec<ExternalAgentEntry> = evidence
        .components
        .iter()
        .filter(|component| component.component_type == ComponentType::ExternalAgent)
        .map(|component| {
            let mut referenced_by: Vec<String> = evidence
                .graph
                .edges
                .iter()
                .filter(|edge| edge.target_id == component.component_id)
                .map(|edge| edge.source_id.clone())
                .collect();
            referenced_by.sort();
            referenced_by.dedup();
            ExternalAgentEntry {
                component_id: component.component_id.clone(),
                name: component.name.clone(),
                referenced_by,
                has_origin_claim: !component.supplier.is_empty(),
            }
        })
        .collect();
    entries.sort_by(|left, right| left.component_id.cmp(&right.component_id));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::capability::projection as capability_projection;
    use crate::component::tests::component;
    use crate::normalize::EvidenceBuilder;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use crate::source::ObservationKind;

    fn evidence(components: Vec<Component>, graph: RelationshipGraph) -> SupplyChainEvidence {
        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_import(components, graph)
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn the_four_agentic_surface_classes_project_and_others_do_not() {
        // A package is a supply-chain component and is assessed as one, but it
        // is not a surface an agent acts through.
        for class in AGENTIC_SURFACE_CLASSES {
            assert!(project(&component("thing", class)).is_some(), "{class:?}");
        }
        for class in [
            ComponentType::Package,
            ComponentType::Model,
            ComponentType::Dataset,
            ComponentType::ContainerImage,
        ] {
            assert!(project(&component("thing", class)).is_none(), "{class:?}");
        }
    }

    #[test]
    fn an_external_agent_is_not_an_agentic_surface_of_this_deployment() {
        // Inventoried, but not a component this deployment supplies. Assessing
        // it as one would have the engine judging artifacts nobody here builds
        // or installs.
        assert!(!is_agentic_surface(ComponentType::ExternalAgent));
        assert!(project(&component("partner", ComponentType::ExternalAgent)).is_none());
    }

    #[test]
    fn an_mcp_server_carries_the_same_supply_chain_questions_as_a_package() {
        let mut server = component("filesystem-mcp", ComponentType::McpServer);
        server.supplier.supplier_id = Some("acme".to_owned());
        server.capabilities = Some(capability_projection(&["read"], &["read", "write"]));

        let projected = project(&server).expect("projects");
        assert!(projected.has_digest);
        assert!(projected.has_origin_claim);
        assert!(projected.capabilities_comparable);
    }

    #[test]
    fn a_one_sided_capability_set_is_not_comparable() {
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(capability_projection(&[], &["read"]));
        assert!(!project(&tool).expect("projects").capabilities_comparable);
    }

    #[test]
    fn the_projection_cannot_record_a_cycle_014_authorization_decision() {
        // Structural. Whether a tool may be invoked, by whom, with which
        // arguments is Cycle 014's question, and a field here would let this
        // engine answer it from evidence that says nothing about it.
        let rendered = serde_json::to_string(
            &project(&component("file-tool", ComponentType::Tool)).expect("projects"),
        )
        .expect("serializes");
        for absent in ["authorized", "invocation", "permitted", "allowed", "scope"] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "the projection carries a `{absent}` field"
            );
        }
        for hostile in ["tool_authorized", "invocation_allowed", "granted_scopes"] {
            let value = serde_json::json!({
                "component_id": "t", "component_type": "TOOL", "has_digest": true,
                "has_origin_claim": false, "capabilities_comparable": false,
                hostile: true
            });
            assert!(
                serde_json::from_value::<AgenticProjection>(value).is_err(),
                "`{hostile}` decoded"
            );
        }
    }

    #[test]
    fn an_external_agent_is_inventoried_with_who_refers_to_it() {
        let mut partner = component("partner-agent", ComponentType::ExternalAgent);
        partner.supplier.supplier_id = Some("partner-corp".to_owned());
        let local = component("planner", ComponentType::Agent);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner",
                "partner-agent",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let inventory = external_agents(&evidence(vec![partner, local], graph));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].component_id, "partner-agent");
        assert_eq!(inventory[0].referenced_by, vec!["planner"]);
        assert!(inventory[0].has_origin_claim);
    }

    #[test]
    fn an_unreferenced_external_agent_is_still_inventoried() {
        // A named agent nobody records an edge to is exactly the row an
        // operator wants to see. Dropping it would hide the surface on the
        // grounds that the document was incomplete about it.
        let partner = component("partner-agent", ComponentType::ExternalAgent);
        let inventory = external_agents(&evidence(vec![partner], RelationshipGraph::new()));
        assert_eq!(inventory.len(), 1);
        assert!(inventory[0].referenced_by.is_empty());
    }

    #[test]
    fn the_inventory_cannot_record_an_a2a_authorization() {
        // `external agent listed != A2A authorization`. The inventory row looks
        // enough like the authorization that the rule is listed in the crate
        // docs; here it is enforced by there being no field to put one in.
        let partner = component("partner-agent", ComponentType::ExternalAgent);
        let inventory = external_agents(&evidence(vec![partner], RelationshipGraph::new()));
        let rendered = serde_json::to_string(&inventory).expect("serializes");
        for absent in ["authorized", "trusted", "delegation", "allowed", "a2a"] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "the inventory carries a `{absent}` field"
            );
        }
        for hostile in ["a2a_authorized", "delegation_allowed", "trusted"] {
            let value = serde_json::json!({
                "component_id": "p", "name": "p", "referenced_by": [],
                "has_origin_claim": false,
                hostile: true
            });
            assert!(
                serde_json::from_value::<ExternalAgentEntry>(value).is_err(),
                "`{hostile}` decoded"
            );
        }
    }

    #[test]
    fn the_inventory_is_ordered_independently_of_document_order() {
        // Two documents listing the same agents in different orders must
        // produce the same inventory, or a reordering would read as a change.
        let first = component("agent-b", ComponentType::ExternalAgent);
        let second = component("agent-a", ComponentType::ExternalAgent);
        let forward = external_agents(&evidence(
            vec![first.clone(), second.clone()],
            RelationshipGraph::new(),
        ));
        let reverse = external_agents(&evidence(vec![second, first], RelationshipGraph::new()));
        assert_eq!(forward, reverse);
        assert_eq!(forward[0].component_id, "agent-a");
    }

    #[test]
    fn agentic_surfaces_are_gathered_from_the_whole_evidence_bundle() {
        let tool = component("file-tool", ComponentType::Tool);
        let server = component("filesystem-mcp", ComponentType::McpServer);
        let package = component("react", ComponentType::Package);
        let surfaces = agentic_surfaces(&evidence(
            vec![tool, server, package],
            RelationshipGraph::new(),
        ));
        let ids: Vec<&str> = surfaces
            .iter()
            .map(|surface| surface.component_id.as_str())
            .collect();
        assert_eq!(ids, vec!["file-tool", "filesystem-mcp"]);
    }
}
