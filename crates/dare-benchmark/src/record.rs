//! Benchmark Record — one normalized target/run outcome.

use std::path::Path;

use dare_coverage::CoverageStatus;
use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::corpus::SchemaRef;
use crate::error::BenchmarkError;
use crate::run::RunnerMode;

pub const RECORD_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/benchmark/v1/benchmark-record.schema.json";
pub const RECORD_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/benchmark/v1/benchmark-record.schema.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRef {
    pub id: String,
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentMeta {
    pub mode: RunnerMode,
    pub plan_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageCounts {
    pub assessment_coverage: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_coverage: Option<f64>,
    pub not_applicable: u32,
    pub out_of_scope: u32,
    pub not_tested: u32,
    pub blocked: u32,
    pub error: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCounts {
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub error: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyResultRow {
    pub property_id: String,
    pub coverage_status: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::disclosure::DisclosureState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRecord {
    pub schema: SchemaRef,
    pub benchmark_run_id: String,
    pub target: TargetRef,
    pub assessment: AssessmentMeta,
    pub coverage: CoverageCounts,
    pub findings: FindingCounts,
    pub property_results: Vec<PropertyResultRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<PublicationMeta>,
}

pub fn validate_record_instance(instance: &Value) -> Result<(), BenchmarkError> {
    let schema: Value =
        serde_json::from_str(RECORD_SCHEMA_V1_JSON).map_err(|_| BenchmarkError::Serialization {
            kind: "record-schema",
        })?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| BenchmarkError::schema("/", err.to_string()))?;
    if validator.is_valid(instance) {
        return Ok(());
    }
    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(BenchmarkError::schema(
            err.instance_path().to_string(),
            err.to_string(),
        )),
        None => Err(BenchmarkError::schema("/", "record failed schema")),
    }
}

pub fn validate_benchmark_record(record: &BenchmarkRecord) -> Result<(), BenchmarkError> {
    let value = serde_json::to_value(record).map_err(|_| BenchmarkError::Serialization {
        kind: "record-json",
    })?;
    validate_record_instance(&value)?;
    for row in &record.property_results {
        dare_coverage::validate_pair(row.coverage_status, row.verdict, true)
            .map_err(|err| BenchmarkError::InvalidState(format!("{}: {err}", row.property_id)))?;
    }
    Ok(())
}

pub fn load_benchmark_record(raw: &str) -> Result<BenchmarkRecord, BenchmarkError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| BenchmarkError::Serialization {
        kind: "record-parse",
    })?;
    validate_record_instance(&value)?;
    let record: BenchmarkRecord =
        serde_json::from_value(value).map_err(|_| BenchmarkError::Serialization {
            kind: "record-typed",
        })?;
    validate_benchmark_record(&record)?;
    Ok(record)
}

pub fn load_record_file(path: impl AsRef<Path>) -> Result<BenchmarkRecord, BenchmarkError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| BenchmarkError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_benchmark_record(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}
