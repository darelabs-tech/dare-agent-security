//! Corpus discovery — load scenario manifests from `labs/scenarios`.

use std::path::{Path, PathBuf};

use crate::error::LabError;
use crate::scenario::{load_scenario_file, ScenarioManifest};

/// Stable ordered corpus identifiers for Cycle 005.
pub const CORPUS_SCENARIO_IDS: &[&str] = &[
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

pub fn scenarios_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../labs/scenarios")
}

pub fn scenario_path(id: &str) -> PathBuf {
    // Reject traversal in scenario ids before joining.
    assert_valid_scenario_id(id);
    scenarios_root().join(id).join("scenario.json")
}

fn assert_valid_scenario_id(id: &str) {
    assert!(
        !id.contains("..") && !id.contains('/') && !id.contains('\\') && !id.is_empty(),
        "invalid scenario id: {id}"
    );
}

pub fn load_corpus_scenario(id: &str) -> Result<ScenarioManifest, LabError> {
    if id.contains("..") || id.contains('/') || id.contains('\\') || id.is_empty() {
        return Err(LabError::SafetyPolicy {
            reason: format!("refusing unsafe scenario id `{id}`"),
        });
    }
    load_scenario_file(scenario_path(id))
}

pub fn load_full_corpus() -> Result<Vec<ScenarioManifest>, LabError> {
    CORPUS_SCENARIO_IDS
        .iter()
        .map(|id| load_corpus_scenario(id))
        .collect()
}

pub fn assert_corpus_present(root: &Path) -> Result<(), LabError> {
    for id in CORPUS_SCENARIO_IDS {
        let path = root.join(id).join("scenario.json");
        if !path.is_file() {
            return Err(LabError::Io {
                path: path.display().to_string(),
                reason: "missing scenario.json".to_owned(),
            });
        }
    }
    Ok(())
}
