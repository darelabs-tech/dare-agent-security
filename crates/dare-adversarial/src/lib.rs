//! Controlled adversarial validation with offline-first, fail-closed enforcement.

pub mod budget;
pub mod budget_enforce;
pub mod canonical;
pub mod eligibility;
pub mod error;
pub mod evidence_bridge;
pub mod kill_switch;
pub mod model;
pub mod plan;
pub mod policy;
pub mod precondition;
pub mod proof_registry;
pub mod reclassify;
pub mod roe;
pub mod runner;
mod schema;
pub mod vector;

use std::{fs, path::Path};

use serde_json::Value;

pub use dare_attack_graph::{Path as AttackPath, PathStatus};
pub use dare_security_evidence::Verdict;
pub use error::{AdversarialError, Result};
pub use model::*;
pub use runner::ControlledRunner;

pub fn load_bundle(path: &Path) -> Result<ValidationBundle> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    parse_bundle(value)
}

pub fn parse_bundle(value: Value) -> Result<ValidationBundle> {
    let object = value.as_object().ok_or_else(|| {
        AdversarialError::Invalid("fixture bundle must be a JSON object".to_owned())
    })?;
    let plan = plan::parse_plan(
        object
            .get("plan")
            .cloned()
            .ok_or_else(|| AdversarialError::Invalid("bundle has no plan".to_owned()))?,
    )?;
    let vector = vector::parse_vector(
        object
            .get("vector")
            .cloned()
            .ok_or_else(|| AdversarialError::Invalid("bundle has no vector".to_owned()))?,
    )?;
    let budget = budget::parse_budget(
        object
            .get("budget")
            .cloned()
            .ok_or_else(|| AdversarialError::Invalid("bundle has no budget".to_owned()))?,
    )?;
    if let Some(roe) = object.get("roe").filter(|value| !value.is_null()) {
        roe::parse_roe(roe.clone())?;
    }
    let bundle: ValidationBundle = serde_json::from_value(value)?;
    // Ensure schema-parsed values and the final strongly typed object are identical.
    if bundle.plan != plan || bundle.vector != vector || bundle.budget != budget {
        return Err(AdversarialError::Invalid(
            "bundle changed during typed decoding".to_owned(),
        ));
    }
    Ok(bundle)
}
