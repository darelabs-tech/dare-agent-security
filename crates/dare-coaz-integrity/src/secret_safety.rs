//! Contract-level secret-safety scanning for vector/result JSON values.

use serde_json::Value;

use crate::error::IntegrityError;
use crate::result::VectorResult;
use crate::vector::VectorDefinition;

const HIGH_RISK_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "authorization",
    "bearer",
    "access_token",
];

/// Scan a vector definition for prohibited credential-bearing keys.
pub fn validate_vector_secret_safety(vector: &VectorDefinition) -> Result<(), IntegrityError> {
    scan_value(
        &serde_json::to_value(vector).map_err(|_| IntegrityError::Serialization {
            kind: "vector-json".to_owned(),
        })?,
        "/",
    )?;
    Ok(())
}

/// Scan a vector result for prohibited credential-bearing keys.
pub fn validate_result_secret_safety(result: &VectorResult) -> Result<(), IntegrityError> {
    scan_value(
        &serde_json::to_value(result).map_err(|_| IntegrityError::Serialization {
            kind: "result-json".to_owned(),
        })?,
        "/",
    )?;
    Ok(())
}

fn scan_value(value: &Value, path: &str) -> Result<(), IntegrityError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}/{key}");
                if is_high_risk_key(key) {
                    return Err(IntegrityError::secret(
                        child_path,
                        "prohibited credential-bearing field name",
                    ));
                }
                scan_value(child, &child_path)?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_value(item, &format!("{path}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_high_risk_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
    HIGH_RISK_KEYS.iter().any(|candidate| {
        let candidate_norm = candidate.replace(['-', '_'], "");
        normalized == candidate_norm || normalized.contains(&candidate_norm)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::sample_vector_definition;

    #[test]
    fn sample_vector_has_no_prohibited_keys() {
        validate_vector_secret_safety(&sample_vector_definition()).expect("sample is safe");
    }

    #[test]
    fn rejects_secret_bearing_object_keys() {
        let mut value = serde_json::to_value(sample_vector_definition()).expect("json");
        value["trusted_context"]["claims"]["access_token"] =
            serde_json::json!("SYNTHETIC.not-real");
        let err = scan_value(&value, "/").expect_err("must reject");
        assert!(matches!(err, IntegrityError::SecretSafety { .. }));
        assert!(!err.to_string().contains("SYNTHETIC"));
    }
}
