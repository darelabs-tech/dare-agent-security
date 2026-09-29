//! The four artifacts of a run (RF-14), built in memory before any write.
//!
//! `runtime-telemetry-result.json` is checked against its schema, and every
//! artifact carries keys, ids, rule codes and digests only (AD-07): a key is
//! written through [`safe_key`], a value never.
use dare_security_evidence::SecurityEvidence;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    coverage::{assessment_facts, baseline_report, executions_document},
    error::{Result, TelemetryError},
    evaluate::TraceOutcome,
    evidence_bridge::{bind_evidence, safe_key},
    policy::Policy,
    result::{Run, RESULT_SCHEMA_JSON},
    schema::conforms,
    summary::summary,
};

pub const RESULT_FILE: &str = "runtime-telemetry-result.json";
pub const EVIDENCE_FILE: &str = "runtime-telemetry-evidence.json";
pub const FINDINGS_FILE: &str = "runtime-telemetry-findings.json";
pub const SUMMARY_FILE: &str = "summary.md";

fn pretty<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| TelemetryError::Internal("serialization"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn finding(o: &TraceOutcome) -> Value {
    let violations: Vec<Value> = o
        .violations
        .iter()
        .map(|v| {
            json!({
                "reason_code": v.reason,
                "span_ids": v.span_ids,
                "keys": v.keys.iter().map(|k| safe_key(k)).collect::<Vec<_>>(),
                "fingerprints": v.fingerprints,
            })
        })
        .collect();
    let gaps: Vec<Value> = o
        .gaps
        .iter()
        .map(|g| match g {
            crate::complete::Gap::MissingKey(k) => {
                json!({ "reason": "missing_key", "key": safe_key(k) })
            }
            other => serde_json::to_value(other).unwrap_or(Value::Null),
        })
        .collect();
    json!({
        "rule": o.rule.code(),
        "property_id": o.rule.property_id(),
        "trace_id": o.trace_id,
        "verdict": o.verdict,
        "violations": violations,
        "gaps": gaps,
    })
}

/// Binds the evidence ids into the run, then renders the four artifacts in a
/// fixed order: result, evidence, findings, summary.
pub fn artifacts(run: &mut Run, policy: Option<&Policy>) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let records: Vec<SecurityEvidence> = bind_evidence(run)?;
    let result_value =
        serde_json::to_value(&run.result).map_err(|_| TelemetryError::Internal("serialization"))?;
    if !conforms(RESULT_SCHEMA_JSON, &result_value)? {
        return Err(TelemetryError::Internal("result schema"));
    }
    let executions = executions_document(&run.result)?;
    executions
        .check(&assessment_facts(policy))
        .map_err(|_| TelemetryError::Internal("executions document"))?;
    let evidence = json!({
        "schema_version": "1",
        "engine": run.result.engine,
        "records": records,
        "executions": executions,
        "coverage": baseline_report(&run.result)?,
    });
    let findings = json!({
        "schema_version": "1",
        "engine": run.result.engine,
        "findings": run.findings.iter().map(finding).collect::<Vec<_>>(),
    });
    Ok(vec![
        (RESULT_FILE, pretty(&result_value)?),
        (EVIDENCE_FILE, pretty(&evidence)?),
        (FINDINGS_FILE, pretty(&findings)?),
        (SUMMARY_FILE, summary(run).into_bytes()),
    ])
}
