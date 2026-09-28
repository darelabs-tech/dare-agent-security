//! Scenario loaders (BLUEPRINT AD-04, task-013).
//!
//! Every engine CLI's `load_scenario` is private. These loaders repeat the
//! same sequence using only the engines' public items: the engine's size
//! check, JSON, the engine's schema or hostile-field check, a typed decode,
//! and the scenario's own `validate()` where the engine has one. Any engine
//! error becomes a positional refusal; the engine's message is dropped
//! because it may quote the input.
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    admit::AdmittedDir,
    error::{Refusal, Result},
};

pub const SCENARIO_FILE: &str = "inputs/scenario.json";

fn refused(index: usize, reason: &'static str) -> Refusal {
    Refusal::InvalidDocument {
        index,
        file: "scenario",
        reason,
    }
}

fn decode<T: DeserializeOwned>(index: usize, value: Value) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|_| refused(index, "does not match the engine's scenario type").into())
}

/// Reads `inputs/scenario.json` (or `relative`) under the admission rules.
pub fn read_scenario(dir: &AdmittedDir, relative: &str) -> Result<(Vec<u8>, Value)> {
    dir.read_json(relative, "scenario")
}

macro_rules! schema_loader {
    ($name:ident, $engine:ident, $ty:ty, validate: $validate:expr) => {
        pub fn $name(dir: &AdmittedDir, relative: &str) -> Result<$ty> {
            let index = dir.index;
            let (raw, value) = read_scenario(dir, relative)?;
            $engine::schema::enforce_document_size(&raw, "scenario").map_err(|_| {
                Refusal::FileTooLarge {
                    index,
                    file: "scenario",
                }
            })?;
            $engine::schema::validate_scenario_document(&value)
                .map_err(|_| refused(index, "fails the engine's scenario schema"))?;
            let scenario: $ty = decode(index, value)?;
            let validate: fn(&$ty) -> bool = $validate;
            if !validate(&scenario) {
                return Err(refused(index, "fails the engine's scenario validation").into());
            }
            Ok(scenario)
        }
    };
}

schema_loader!(
    load_tool,
    dare_tool_security,
    dare_tool_security::model::ToolSecurityScenario,
    validate: |_| true
);
schema_loader!(
    load_identity,
    dare_identity_security,
    dare_identity_security::model::IdentitySecurityScenario,
    validate: |s| s.validate().is_ok()
);
schema_loader!(
    load_memory,
    dare_memory_security,
    dare_memory_security::model::MemorySecurityScenario,
    validate: |s| s.validate().is_ok()
);
schema_loader!(
    load_rag,
    dare_rag_security,
    dare_rag_security::model::RagSecurityScenario,
    validate: |s| s.validate().is_ok()
);
schema_loader!(
    load_mcp_auth,
    dare_mcp_auth_security,
    dare_mcp_auth_security::model::McpAuthScenario,
    validate: |s| s.validate().is_ok()
);

macro_rules! hostile_loader {
    ($name:ident, $engine:ident, $ty:ty) => {
        pub fn $name(dir: &AdmittedDir, relative: &str) -> Result<$ty> {
            let index = dir.index;
            let (raw, value) = read_scenario(dir, relative)?;
            $engine::schema::enforce_document_size(&raw, "the scenario").map_err(|_| {
                Refusal::FileTooLarge {
                    index,
                    file: "scenario",
                }
            })?;
            $engine::schema::assert_no_hostile_fields(&value, "the scenario")
                .map_err(|_| refused(index, "carries a field the engine refuses"))?;
            let scenario: $ty = decode(index, value)?;
            scenario
                .validate()
                .map_err(|_| refused(index, "fails the engine's scenario validation"))?;
            Ok(scenario)
        }
    };
}

hostile_loader!(
    load_supply_chain,
    dare_supply_chain_security,
    dare_supply_chain_security::model::SupplyChainScenario
);
hostile_loader!(
    load_a2a,
    dare_a2a_security,
    dare_a2a_security::model::A2aScenario
);
