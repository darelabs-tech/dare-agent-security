//! Benchmark policy (coverage/confidence thresholds).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::canonical::digest_value;
use crate::error::BenchmarkError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkPolicy {
    pub version: String,
    pub min_assessment_coverage_for_prevalence: f64,
    pub max_error_ratio: f64,
    pub min_confidence_for_prevalence: f64,
    pub min_eligible_targets_for_rate: u32,
    pub default_runner_mode: String,
    pub allow_authorized_dynamic: bool,
}

pub const BUILTIN_POLICY_JSON: &str =
    include_str!("../../../benchmark/policies/benchmark-policy.json");

pub fn load_benchmark_policy(raw: &str) -> Result<BenchmarkPolicy, BenchmarkError> {
    serde_json::from_str(raw).map_err(|_| BenchmarkError::Serialization {
        kind: "policy-parse",
    })
}

pub fn builtin_policy() -> Result<BenchmarkPolicy, BenchmarkError> {
    load_benchmark_policy(BUILTIN_POLICY_JSON)
}

pub fn load_policy_file(path: impl AsRef<Path>) -> Result<BenchmarkPolicy, BenchmarkError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| BenchmarkError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_benchmark_policy(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}

pub fn policy_digest(policy: &BenchmarkPolicy) -> Result<String, BenchmarkError> {
    let value = serde_json::to_value(policy).map_err(|_| BenchmarkError::Serialization {
        kind: "policy-digest",
    })?;
    digest_value(&value)
}
