use std::{fs, path::Path};

use serde_json::Value;

use crate::{model::TestVector, schema, AdversarialError, Result};

pub const TEST_VECTOR_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/adversarial/v1/test-vector.schema.json");
const FORBIDDEN_CODE_KEYS: &[&str] = &["shell", "python", "eval", "callback", "script"];

pub fn load_vector(path: &Path) -> Result<TestVector> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    parse_vector(value)
}

pub fn parse_vector(value: Value) -> Result<TestVector> {
    schema::validate(&value, TEST_VECTOR_SCHEMA_V1_JSON, "test vector")?;
    reject_code_like_fields(&value)?;
    serde_json::from_value(value).map_err(Into::into)
}

pub fn reject_code_like_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if FORBIDDEN_CODE_KEYS
                    .iter()
                    .any(|forbidden| key.eq_ignore_ascii_case(forbidden))
                {
                    return Err(AdversarialError::SafetyRefusal(format!(
                        "vectors are data, not code: field `{key}` is forbidden"
                    )));
                }
                reject_code_like_fields(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_code_like_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
