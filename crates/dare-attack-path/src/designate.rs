//! Entry points and targets (BLUEPRINT §6.10, task-030).
//!
//! Projectors designate what their engine alone can tell (an untrusted
//! channel, a peer, a destructive tool). This module adds the designations
//! that follow from merged security flags, then applies the system model's
//! additions and exclusions. `CROSS_TENANT_RESOURCE` is not a node flag: it
//! depends on the entry, so enumeration asks for it per entry.
use dare_attack_graph::{
    v2::{DesignationOrigin, EntryDesignation, NodeV2, TargetClass, TargetDesignation},
    NodeType,
};

use crate::{
    error::{ModelRefusal, Result},
    ids::entity_node_id,
    merge::Merged,
    model::AdmittedModel,
};

/// Targets that follow from merged security flags.
pub fn apply_defaults(merged: &mut Merged) {
    for node in merged.nodes.values() {
        let mut add = |class| {
            merged.targets.insert(TargetDesignation {
                node: node.id.clone(),
                class,
                origin: DesignationOrigin::Default,
            });
        };
        if node.security.sensitive {
            add(TargetClass::SensitiveResource);
        }
        if node.node_type == NodeType::Credential && node.security.privileged {
            add(TargetClass::PrivilegedCredential);
        }
        if node.security.destructive {
            add(TargetClass::DestructiveCapability);
        }
    }
}

fn resolve(
    model: &AdmittedModel,
    merged: &Merged,
    entity_id: Option<&str>,
    node_id: Option<&str>,
) -> Option<String> {
    match (entity_id, node_id) {
        (Some(entity), None) => model
            .entity(entity)
            .and_then(|(_, e)| entity_node_id(e.node_type, &e.entity_id)),
        (None, Some(node)) => Some(node.to_owned()),
        _ => None,
    }
    .filter(|id| merged.nodes.contains_key(id))
}

/// §4.5 rule 5: model designations resolve to graph nodes; `exclude`
/// removes a designation of the same class whatever its origin.
pub fn apply_model(merged: &mut Merged, model: &AdmittedModel) -> Result<()> {
    for (index, point) in model.model.entry_points.iter().enumerate() {
        let node = resolve(
            model,
            merged,
            point.entity_id.as_deref(),
            point.node_id.as_deref(),
        )
        .ok_or(ModelRefusal::UnknownDesignationTarget { designation: index })?;
        merged
            .entries
            .retain(|d| !(d.node == node && d.class == point.class));
        if !point.exclude {
            merged.entries.insert(EntryDesignation {
                node,
                class: point.class,
                origin: DesignationOrigin::Model,
            });
        }
    }
    let offset = model.model.entry_points.len();
    for (index, point) in model.model.targets.iter().enumerate() {
        let node = resolve(
            model,
            merged,
            point.entity_id.as_deref(),
            point.node_id.as_deref(),
        )
        .ok_or(ModelRefusal::UnknownDesignationTarget {
            designation: offset + index,
        })?;
        merged
            .targets
            .retain(|d| !(d.node == node && d.class == point.class));
        if !point.exclude {
            merged.targets.insert(TargetDesignation {
                node,
                class: point.class,
                origin: DesignationOrigin::Model,
            });
        }
    }
    Ok(())
}

/// `CROSS_TENANT_RESOURCE` targets for one entry: RESOURCE or DATA nodes whose
/// tenant differs from the entry's own. An entry with no tenant has none
/// (REGRESSION R-9); a path that crosses tenants is still flagged by its
/// `cross_tenant` impact factor.
pub fn cross_tenant_targets<'a>(
    entry: &NodeV2,
    nodes: impl Iterator<Item = &'a NodeV2>,
) -> Vec<String> {
    let Some(tenant) = entry.security.tenant.as_deref() else {
        return vec![];
    };
    nodes
        .filter(|n| matches!(n.node_type, NodeType::Resource | NodeType::Data))
        .filter(|n| n.security.tenant.as_deref().is_some_and(|t| t != tenant))
        .map(|n| n.id.clone())
        .collect()
}
