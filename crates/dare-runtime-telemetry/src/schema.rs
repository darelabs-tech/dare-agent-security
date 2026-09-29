//! Embedded schemas (`schemas/runtime-telemetry/v1/`).
use serde_json::Value;

use crate::error::{Result, TelemetryError};

pub const OTLP_TRACE_SUBSET_SCHEMA_JSON: &str =
    include_str!("../../../schemas/runtime-telemetry/v1/otlp-trace-subset.schema.json");

/// True when `value` satisfies the embedded schema `schema_json`.
pub fn conforms(schema_json: &str, value: &Value) -> Result<bool> {
    let schema: Value = serde_json::from_str(schema_json)
        .map_err(|_| TelemetryError::Internal("embedded schema"))?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|_| TelemetryError::Internal("embedded schema"))?;
    let valid = validator.iter_errors(value).next().is_none();
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{error::Input, otlp::read_trace_file};

    /// The schema and the reader agree on what an export is.
    #[test]
    fn the_trace_schema_and_the_reader_agree() {
        let good = json!({"resourceSpans": [{"scopeSpans": [{"spans": [{
            "traceId": "5b8efff798038103d269b633813fc60c", "spanId": "eee19b7ec3c1b174",
            "parentSpanId": "", "name": "n", "kind": 1,
            "startTimeUnixNano": "1", "endTimeUnixNano": 2
        }]}]}]});
        assert!(conforms(OTLP_TRACE_SUBSET_SCHEMA_JSON, &good).unwrap());
        assert!(read_trace_file(&good, Input::Trace(0)).is_ok());
        let mut bad_top = good.clone();
        bad_top["resourceLogs"] = json!([]);
        assert!(!conforms(OTLP_TRACE_SUBSET_SCHEMA_JSON, &bad_top).unwrap());
        assert!(read_trace_file(&bad_top, Input::Trace(0)).is_err());
        let mut bad_id = good;
        bad_id["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"] = json!("xyz");
        assert!(!conforms(OTLP_TRACE_SUBSET_SCHEMA_JSON, &bad_id).unwrap());
        assert!(read_trace_file(&bad_id, Input::Trace(0)).is_err());
    }
}
