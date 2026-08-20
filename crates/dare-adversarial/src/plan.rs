use std::{fs, path::Path};

use serde_json::Value;

use crate::{model::ValidationPlan, schema, Result};

pub const VALIDATION_PLAN_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/adversarial/v1/validation-plan.schema.json");

pub fn load_plan(path: &Path) -> Result<ValidationPlan> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    parse_plan(value)
}

pub fn parse_plan(value: Value) -> Result<ValidationPlan> {
    schema::validate(&value, VALIDATION_PLAN_SCHEMA_V1_JSON, "validation plan")?;
    serde_json::from_value(value).map_err(Into::into)
}
