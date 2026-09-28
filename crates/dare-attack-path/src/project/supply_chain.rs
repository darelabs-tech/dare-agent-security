//! Supply-chain projector (Cycle 019, BLUEPRINT §6.6).
//!
//! Components and relationships come from the evidence the engine itself
//! rebuilt from the pinned inputs (AD-06). Every edge is STATICALLY_PROVEN:
//! it cites the BOM documents when a BOM stated it, and `evidence_digest`,
//! the pin that covers the manifest too (observation O-3).
use std::collections::BTreeMap;

use dare_attack_graph::{v2::EntryClass, EdgeType, NodeType};
use dare_supply_chain_security::{
    normalize::SupplyChainEvidence,
    relationship::RelationType,
    result::SupplyChainSecurityResult,
    source::{ComponentType, ObservationKind},
};

use super::{edge, enum_name, plain};
use crate::{
    bundle::LoadedBundle,
    facts::{statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

pub fn node_type(component: ComponentType) -> NodeType {
    match component {
        ComponentType::Agent | ComponentType::ExternalAgent => NodeType::Agent,
        ComponentType::Tool => NodeType::Tool,
        ComponentType::McpServer => NodeType::McpServer,
        ComponentType::Model | ComponentType::EmbeddingModel | ComponentType::ServiceApi => {
            NodeType::DownstreamService
        }
        ComponentType::Dataset | ComponentType::PromptPolicyAsset => NodeType::Data,
        ComponentType::Framework
        | ComponentType::Package
        | ComponentType::ContainerImage
        | ComponentType::SkillPlugin => NodeType::Capability,
        ComponentType::Guardrail => NodeType::PolicyEnforcementPoint,
    }
}

fn is_entry(component: ComponentType) -> bool {
    matches!(
        component,
        ComponentType::Package
            | ComponentType::ContainerImage
            | ComponentType::Framework
            | ComponentType::SkillPlugin
            | ComponentType::Model
            | ComponentType::EmbeddingModel
            | ComponentType::Dataset
            | ComponentType::ExternalAgent
    )
}

/// How a relationship becomes a graph edge: (edge type, reversed, role).
/// `None` for relations that carry provenance, not reachability.
pub fn edge_for(relation: RelationType, source_is_dataset: bool) -> Option<(EdgeType, bool, Role)> {
    Some(match relation {
        RelationType::DependsOn
        | RelationType::Uses
        | RelationType::Loads
        | RelationType::BuiltFrom
        | RelationType::EmbedsWith => (EdgeType::TransfersTo, true, Role::SupplyDependency),
        RelationType::TrainedFrom | RelationType::FineTunedFrom => (
            EdgeType::TransfersTo,
            true,
            if source_is_dataset {
                Role::SupplyDatasetLineage
            } else {
                Role::SupplyLineage
            },
        ),
        RelationType::Calls => (EdgeType::Calls, false, Role::SupplyDependency),
        RelationType::ExposesTool => (EdgeType::CanInvoke, false, Role::SupplyExposesTool),
        RelationType::ConnectsTo => (EdgeType::CanReach, false, Role::SupplyDependency),
        RelationType::ProvidedBy | RelationType::AttestedBy | RelationType::SignedBy => {
            return None
        }
    })
}

pub fn project(
    bundle: &LoadedBundle,
    result: &SupplyChainSecurityResult,
    evidence: &SupplyChainEvidence,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let bom_digests: Vec<&str> = evidence
        .documents
        .iter()
        .map(|d| d.content_digest.as_str())
        .collect();
    let mut components: BTreeMap<&str, (NodeRef, ComponentType)> = BTreeMap::new();
    for (index, component) in evidence.components.iter().enumerate() {
        let node = sink.node(
            NodeRef::new(node_type(component.component_type), &component.component_id),
            &component.name,
            plain(),
            &format!("ComponentType::{}", enum_name(&component.component_type)),
            format!("evidence#/components/{index}"),
        );
        if is_entry(component.component_type) {
            sink.designate(&node, Designation::Entry(EntryClass::SupplyChainComponent));
        }
        components.insert(
            component.component_id.as_str(),
            (node, component.component_type),
        );
    }
    for outcome in &result.outcomes {
        let property = outcome.invariant.property_id();
        for violation in &outcome.violations {
            if let Some((node, _)) = violation
                .component_id
                .as_deref()
                .and_then(|id| components.get(id))
            {
                verdicts.violation(property, node.clone());
            }
        }
    }
    for (index, relationship) in evidence.graph.edges.iter().enumerate() {
        let (Some((from, _)), Some((to, to_kind))) = (
            components.get(relationship.source_id.as_str()),
            components.get(relationship.target_id.as_str()),
        ) else {
            sink.unprojected("Relationship::unknown_component");
            continue;
        };
        // `A TRAINED_FROM B`: the lineage flows from B, so B is the edge source.
        let lineage_from_dataset = *to_kind == ComponentType::Dataset;
        let Some((edge_type, reversed, role)) =
            edge_for(relationship.relation, lineage_from_dataset)
        else {
            sink.unprojected(format!(
                "RelationType::{}",
                enum_name(&relationship.relation)
            ));
            continue;
        };
        let (source, target) = if reversed { (to, from) } else { (from, to) };
        let mut cited: Vec<&str> = vec![result.evidence_digest.as_str()];
        // A relationship the BOM stated is `Observed` (or `DeclaredAndObserved`
        // once the manifest agrees); only a manifest-only edge is `Declared`.
        if relationship.observation != ObservationKind::Declared {
            cited.extend(bom_digests.iter().copied());
        }
        edge(
            sink,
            verdicts,
            Some(role),
            edge_type,
            source,
            target,
            FactAuthority::default(),
            statically_proven(bundle.engine, &cited),
            &format!("RelationType::{}", enum_name(&relationship.relation)),
            format!("evidence#/graph/edges/{index}"),
        );
    }
}
