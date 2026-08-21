use std::collections::{BTreeMap, BTreeSet};

use crate::changeset::ChangeType;

pub const ALL_PROPERTY_IDS: [&str; 10] = [
    "MCP.DISCOVERY.PASSIVE_BOUNDARY",
    "MCP.DISCOVERY.EXPLICIT_TARGET",
    "MCP.AUTHZ.PER_OPERATION",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS",
    "MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT",
    "MCP.EVIDENCE.REDACTION",
    "MCP.IDENTITY.CONFUSED_DEPUTY",
    "MCP.DISCOVERY.STREAMABLE_HTTP",
    "MCP.AUTHZ.DYNAMIC_VALIDATION",
];

#[derive(Debug, Clone)]
pub struct DependencyMap {
    by_change: BTreeMap<ChangeType, BTreeSet<String>>,
}

impl Default for DependencyMap {
    fn default() -> Self {
        use ChangeType::*;
        let authorization = ids(&[
            "MCP.AUTHZ.PER_OPERATION",
            "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
            "MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS",
            "MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT",
            "MCP.IDENTITY.CONFUSED_DEPUTY",
            "MCP.AUTHZ.DYNAMIC_VALIDATION",
        ]);
        let inventory = ids(&[
            "MCP.DISCOVERY.PASSIVE_BOUNDARY",
            "MCP.DISCOVERY.EXPLICIT_TARGET",
            "MCP.AUTHZ.PER_OPERATION",
            "MCP.EVIDENCE.REDACTION",
            "MCP.DISCOVERY.STREAMABLE_HTTP",
        ]);
        let mut by_change = BTreeMap::new();
        for ty in [
            InventoryChanged,
            CapabilityAdded,
            CapabilityRemoved,
            CapabilityChanged,
        ] {
            by_change.insert(ty, inventory.clone());
        }
        for ty in [AuthorizationChanged, CredentialChanged, TenantModelChanged] {
            by_change.insert(ty, authorization.clone());
        }
        by_change.insert(
            SourceCodeChanged,
            authorization.union(&inventory).cloned().collect(),
        );
        by_change.insert(
            DependencyChanged,
            ALL_PROPERTY_IDS.iter().map(|id| (*id).to_owned()).collect(),
        );
        for ty in [ProfileChanged, PropertyRegistryChanged, PolicyChanged] {
            by_change.insert(
                ty,
                ALL_PROPERTY_IDS.iter().map(|id| (*id).to_owned()).collect(),
            );
        }
        by_change.insert(RoeChanged, ids(&["MCP.AUTHZ.DYNAMIC_VALIDATION"]));
        by_change.insert(GraphChanged, BTreeSet::new());
        by_change.insert(
            ValidationChanged,
            ids(&[
                "MCP.AUTHZ.PER_OPERATION",
                "MCP.AUTHZ.DYNAMIC_VALIDATION",
                "MCP.IDENTITY.CONFUSED_DEPUTY",
            ]),
        );
        by_change.insert(
            RuntimeEvidenceChanged,
            ids(&["MCP.EVIDENCE.REDACTION", "MCP.AUTHZ.DYNAMIC_VALIDATION"]),
        );
        Self { by_change }
    }
}

impl DependencyMap {
    pub fn properties_for(&self, change: ChangeType) -> Option<&BTreeSet<String>> {
        self.by_change.get(&change)
    }
}

fn ids(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
