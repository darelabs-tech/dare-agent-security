//! Optional Cycle 005 adapter: scenario id → registry property id.
//! Isolated mapping data. Core coverage math does not depend on lab types.

use std::collections::BTreeMap;

use crate::error::CoverageError;
use crate::property::PropertyRegistry;

pub const SCENARIO_PROPERTY_MAP_JSON: &str =
    include_str!("../../../integrations/cycle-005/scenario-property-map.json");

/// Stable corpus ids. Kept as data so core does not import `dare-mcp-lab`.
pub const LAB_SCENARIO_IDS: [&str; 10] = [
    "MCP-LAB-001",
    "MCP-LAB-002",
    "MCP-LAB-003",
    "MCP-LAB-004",
    "MCP-LAB-005",
    "MCP-LAB-006",
    "MCP-LAB-007",
    "MCP-LAB-008",
    "MCP-LAB-009",
    "MCP-LAB-010",
];

pub fn load_scenario_property_map() -> Result<BTreeMap<String, String>, CoverageError> {
    serde_json::from_str(SCENARIO_PROPERTY_MAP_JSON).map_err(|_| CoverageError::Serialization {
        kind: "cycle005-map",
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioMapping {
    pub scenario_id: String,
    pub property_id: Option<String>,
    pub mapped: bool,
}

pub fn map_corpus(
    registry: &PropertyRegistry,
) -> Result<(Vec<ScenarioMapping>, Vec<String>), CoverageError> {
    let map = load_scenario_property_map()?;
    let mut mappings = Vec::new();
    let mut unmapped = Vec::new();
    for id in LAB_SCENARIO_IDS {
        if let Some(property_id) = map.get(id) {
            registry.require(property_id)?;
            mappings.push(ScenarioMapping {
                scenario_id: id.to_owned(),
                property_id: Some(property_id.clone()),
                mapped: true,
            });
        } else {
            unmapped.push(id.to_owned());
            mappings.push(ScenarioMapping {
                scenario_id: id.to_owned(),
                property_id: None,
                mapped: false,
            });
        }
    }
    Ok((mappings, unmapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::builtin_registry;

    #[test]
    fn mapped_lab_ids_exist_in_core_registry() {
        let registry = builtin_registry().unwrap();
        let (mappings, unmapped) = map_corpus(&registry).unwrap();
        assert!(mappings
            .iter()
            .any(|m| m.scenario_id == "MCP-LAB-001" && m.mapped));
        assert!(unmapped.contains(&"MCP-LAB-007".to_owned()));
        assert!(unmapped.contains(&"MCP-LAB-010".to_owned()));
        assert!(!unmapped.contains(&"MCP-LAB-004".to_owned()));
    }
}
