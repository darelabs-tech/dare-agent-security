use std::{fs, path::Path};

use serde_json::Value;

use crate::{model::ExecutionBudget, schema, Result};

pub const EXECUTION_BUDGET_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/adversarial/v1/execution-budget.schema.json");

pub fn load_budget(path: &Path) -> Result<ExecutionBudget> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    parse_budget(value)
}

pub fn parse_budget(value: Value) -> Result<ExecutionBudget> {
    schema::validate(&value, EXECUTION_BUDGET_SCHEMA_V1_JSON, "execution budget")?;
    serde_json::from_value(value).map_err(Into::into)
}
