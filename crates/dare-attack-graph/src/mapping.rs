use crate::edge::EdgeType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyGraphMapping {
    pub property_id: &'static str,
    pub edge_effects: &'static [EdgeType],
    pub annotation: Option<&'static str>,
}

pub const BUILTIN_MAPPINGS: &[PropertyGraphMapping] = &[
    PropertyGraphMapping {
        property_id: "MCP.AUTHZ.PER_OPERATION",
        edge_effects: &[EdgeType::CanInvoke, EdgeType::AuthorizedBy],
        annotation: None,
    },
    PropertyGraphMapping {
        property_id: "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
        edge_effects: &[EdgeType::Calls],
        annotation: Some("execution_binding"),
    },
    PropertyGraphMapping {
        property_id: "MCP.IDENTITY.CONFUSED_DEPUTY",
        edge_effects: &[],
        annotation: Some("authority_mismatch"),
    },
    PropertyGraphMapping {
        property_id: "MCP.DISCOVERY.PASSIVE_BOUNDARY",
        edge_effects: &[EdgeType::CanReach],
        annotation: Some("passive_boundary"),
    },
    PropertyGraphMapping {
        property_id: "MCP.EVIDENCE.REDACTION",
        edge_effects: &[],
        annotation: Some("redaction"),
    },
];

pub fn mapping_for(property_id: &str) -> Option<&'static PropertyGraphMapping> {
    BUILTIN_MAPPINGS
        .iter()
        .find(|mapping| mapping.property_id == property_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mappings_only_use_real_registry_ids() {
        let registry: serde_json::Value =
            serde_json::from_str(dare_coverage::REGISTRY_JSON).unwrap();
        let ids: Vec<_> = registry["properties"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["id"].as_str())
            .collect();
        assert!(BUILTIN_MAPPINGS
            .iter()
            .all(|mapping| ids.contains(&mapping.property_id)));
    }
}
