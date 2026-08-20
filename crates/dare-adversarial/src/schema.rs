use serde_json::Value;

use crate::{AdversarialError, Result};

pub(crate) fn validate(instance: &Value, schema_json: &str, label: &str) -> Result<()> {
    let schema: Value = serde_json::from_str(schema_json)?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| AdversarialError::Schema(format!("{label}: {error}")))?;
    if let Err(error) = validator.validate(instance) {
        return Err(AdversarialError::Schema(format!(
            "{label}: {}",
            error.instance_path()
        )));
    }
    Ok(())
}
