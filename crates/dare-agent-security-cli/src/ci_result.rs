//! Deterministic CI aggregate result contract (Cycle 004 task-002).
//!
//! Reuses Cycle 001 verdict vocabulary. Does not parse prose or invent
//! GitHub-specific security verdicts.

use std::path::{Path, PathBuf};

use dare_security_evidence::{validate, SecurityEvidence, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS};

/// Canonical schema `$id` for CI result v1.
pub const CI_RESULT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/ci/v1/ci-result.schema.json";

/// Embedded schema document. Kept in sync with `schemas/ci/v1/ci-result.schema.json`.
pub const CI_RESULT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/ci/v1/ci-result.schema.json");

/// Default output directory under a GitHub workspace.
pub const DEFAULT_OUTPUT_DIR: &str = ".dare-agent-security";

/// Filename for the aggregate CI result artifact.
pub const CI_RESULT_FILENAME: &str = "ci-result.json";

/// Filename for the job summary artifact.
pub const SUMMARY_FILENAME: &str = "summary.md";

/// GitHub Actions output key-value file (appended to GITHUB_OUTPUT by entrypoint).
pub const GITHUB_OUTPUT_FILENAME: &str = "github-output.env";

/// Supported Action modes (v0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionMode {
    Discover,
    Validate,
}

impl ActionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Validate => "validate",
        }
    }
}

/// Per-verdict evidence counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvidenceCounts {
    #[serde(rename = "PASS")]
    pub pass: u32,
    #[serde(rename = "FAIL")]
    pub fail: u32,
    #[serde(rename = "INCONCLUSIVE")]
    pub inconclusive: u32,
    #[serde(rename = "ERROR")]
    pub error: u32,
}

impl EvidenceCounts {
    pub fn total(&self) -> u32 {
        self.pass + self.fail + self.inconclusive + self.error
    }

    pub fn increment(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Pass => self.pass += 1,
            Verdict::Fail => self.fail += 1,
            Verdict::Inconclusive => self.inconclusive += 1,
            Verdict::Error => self.error += 1,
        }
    }
}

/// GitHub Action output keys mapped from the CI result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubOutputs {
    pub verdict: Verdict,
    #[serde(rename = "evidence-path")]
    pub evidence_path: String,
    #[serde(rename = "summary-path")]
    pub summary_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiTimestamps {
    pub completed_at: String,
}

/// Machine-readable aggregate CI outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiResult {
    pub schema: SchemaRef,
    pub mode: ActionMode,
    pub aggregate_verdict: Verdict,
    pub evidence_counts: EvidenceCounts,
    pub evidence_paths: Vec<String>,
    pub output_dir: String,
    pub process_exit_code: u8,
    pub fail_on_inconclusive: bool,
    pub github_outputs: GitHubOutputs,
    pub timestamps: CiTimestamps,
}

/// Failure while building or validating a CI result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CiResultError {
    #[error("structural validation failed at {path}: {reason}")]
    StructuralValidation { path: String, reason: String },
    #[error("failed to read evidence at {path}: {reason}")]
    EvidenceRead { path: PathBuf, reason: String },
    #[error("serialization error: {kind}")]
    Serialization { kind: &'static str },
}

/// Aggregate precedence: ERROR > FAIL > INCONCLUSIVE > PASS.
pub fn aggregate_verdict(counts: &EvidenceCounts) -> Verdict {
    if counts.error > 0 {
        Verdict::Error
    } else if counts.fail > 0 {
        Verdict::Fail
    } else if counts.inconclusive > 0 {
        Verdict::Inconclusive
    } else if counts.pass > 0 {
        Verdict::Pass
    } else {
        Verdict::Inconclusive
    }
}

/// Map aggregate verdict to process exit code (aligned with EXIT.md).
pub fn process_exit_code(aggregate: Verdict, fail_on_inconclusive: bool) -> u8 {
    match aggregate {
        Verdict::Pass => SUCCESS as u8,
        Verdict::Fail => PARTIAL as u8,
        Verdict::Error => SCANNER_ERROR as u8,
        Verdict::Inconclusive if fail_on_inconclusive => PARTIAL as u8,
        Verdict::Inconclusive => SUCCESS as u8,
    }
}

/// Load verdicts from evidence JSON files. Malformed files yield `ERROR` count.
pub fn collect_evidence_verdicts(paths: &[PathBuf]) -> (EvidenceCounts, Vec<String>, Verdict) {
    let mut counts = EvidenceCounts::default();
    let mut valid_paths = Vec::new();
    let mut saw_malformed = false;

    for path in paths {
        let rel = path.to_string_lossy().into_owned();
        match load_evidence_verdict(path) {
            Ok(verdict) => {
                counts.increment(verdict);
                valid_paths.push(rel);
            }
            Err(_) => {
                saw_malformed = true;
                counts.increment(Verdict::Error);
            }
        }
    }

    let aggregate = if saw_malformed {
        Verdict::Error
    } else {
        aggregate_verdict(&counts)
    };

    (counts, valid_paths, aggregate)
}

fn load_evidence_verdict(path: &Path) -> Result<Verdict, CiResultError> {
    let raw = std::fs::read_to_string(path).map_err(|err| CiResultError::EvidenceRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let evidence: SecurityEvidence =
        serde_json::from_str(&raw).map_err(|err| CiResultError::EvidenceRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    validate(&evidence).map_err(|err| CiResultError::EvidenceRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    Ok(evidence.verdict)
}

/// Build a CI result from evidence paths and configuration.
pub fn build_ci_result(
    mode: ActionMode,
    output_dir: impl AsRef<Path>,
    evidence_paths: &[PathBuf],
    fail_on_inconclusive: bool,
) -> CiResult {
    let output_dir = output_dir.as_ref().to_string_lossy().into_owned();
    let (counts, valid_paths, aggregate) = collect_evidence_verdicts(evidence_paths);
    let exit = process_exit_code(aggregate, fail_on_inconclusive);

    let primary_evidence = valid_paths
        .first()
        .cloned()
        .unwrap_or_else(|| format!("{output_dir}/evidence/.none"));
    let summary_path = format!("{output_dir}/{SUMMARY_FILENAME}");

    CiResult {
        schema: SchemaRef {
            id: CI_RESULT_SCHEMA_V1_ID.to_owned(),
            version: "1.0.0".to_owned(),
        },
        mode,
        aggregate_verdict: aggregate,
        evidence_counts: counts,
        evidence_paths: valid_paths,
        output_dir: output_dir.clone(),
        process_exit_code: exit,
        fail_on_inconclusive,
        github_outputs: GitHubOutputs {
            verdict: aggregate,
            evidence_path: primary_evidence,
            summary_path: summary_path.clone(),
        },
        timestamps: CiTimestamps {
            completed_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        },
    }
}

pub fn ci_result_schema_v1() -> Result<Value, CiResultError> {
    serde_json::from_str(CI_RESULT_SCHEMA_V1_JSON).map_err(|_| CiResultError::Serialization {
        kind: "schema-json",
    })
}

pub fn ci_result_schema_v1_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/ci/v1/ci-result.schema.json")
}

pub fn validate_ci_result_instance(instance: &Value) -> Result<(), CiResultError> {
    let schema = ci_result_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| CiResultError::StructuralValidation {
            path: "/".to_owned(),
            reason: compact_error(&err.to_string()),
        })?;

    if validator.is_valid(instance) {
        return Ok(());
    }

    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(CiResultError::StructuralValidation {
            path: err.instance_path().to_string(),
            reason: compact_error(&err.to_string()),
        }),
        None => Err(CiResultError::StructuralValidation {
            path: "/".to_owned(),
            reason: "instance failed schema validation".to_owned(),
        }),
    }
}

pub fn validate_ci_result(result: &CiResult) -> Result<(), CiResultError> {
    let value = serde_json::to_value(result).map_err(|_| CiResultError::Serialization {
        kind: "ci-result-json",
    })?;
    validate_ci_result_instance(&value)
}

fn compact_error(message: &str) -> String {
    message.chars().take(240).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aggregate_precedence_error_over_fail() {
        let counts = EvidenceCounts {
            pass: 1,
            fail: 1,
            error: 1,
            inconclusive: 0,
        };
        assert_eq!(aggregate_verdict(&counts), Verdict::Error);
    }

    #[test]
    fn aggregate_precedence_fail_over_inconclusive() {
        let counts = EvidenceCounts {
            pass: 2,
            fail: 1,
            inconclusive: 1,
            error: 0,
        };
        assert_eq!(aggregate_verdict(&counts), Verdict::Fail);
    }

    #[test]
    fn aggregate_precedence_inconclusive_over_pass() {
        let counts = EvidenceCounts {
            pass: 3,
            fail: 0,
            inconclusive: 1,
            error: 0,
        };
        assert_eq!(aggregate_verdict(&counts), Verdict::Inconclusive);
    }

    #[test]
    fn no_evidence_is_inconclusive_not_pass() {
        let counts = EvidenceCounts::default();
        assert_eq!(aggregate_verdict(&counts), Verdict::Inconclusive);
        assert_ne!(aggregate_verdict(&counts), Verdict::Pass);
    }

    #[test]
    fn inconclusive_exit_respects_fail_on_inconclusive_flag() {
        assert_eq!(
            process_exit_code(Verdict::Inconclusive, true),
            PARTIAL as u8
        );
        assert_eq!(
            process_exit_code(Verdict::Inconclusive, false),
            SUCCESS as u8
        );
    }

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(ci_result_schema_v1_path()).expect("read schema");
        assert_eq!(disk, CI_RESULT_SCHEMA_V1_JSON);
    }

    #[test]
    fn built_result_validates_against_schema() {
        let result = build_ci_result(ActionMode::Validate, DEFAULT_OUTPUT_DIR, &[], true);
        validate_ci_result(&result).expect("valid ci result");
        assert_eq!(result.aggregate_verdict, Verdict::Inconclusive);
    }

    #[test]
    fn invalid_verdict_in_json_rejected_by_schema() {
        let mut value = json!({
            "schema": { "id": CI_RESULT_SCHEMA_V1_ID, "version": "1.0.0" },
            "mode": "discover",
            "aggregate_verdict": "MAYBE",
            "evidence_counts": { "PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "ERROR": 0 },
            "evidence_paths": [],
            "output_dir": ".dare-agent-security",
            "process_exit_code": 2,
            "fail_on_inconclusive": true,
            "github_outputs": {
                "verdict": "MAYBE",
                "evidence-path": "",
                "summary-path": ".dare-agent-security/summary.md"
            },
            "timestamps": { "completed_at": "2026-01-01T00:00:00Z" }
        });
        assert!(validate_ci_result_instance(&value).is_err());
        value["aggregate_verdict"] = json!("PASS");
        value["github_outputs"]["verdict"] = json!("PASS");
        value["github_outputs"]["evidence-path"] = json!(".dare-agent-security/evidence/.none");
        assert!(validate_ci_result_instance(&value).is_ok());
    }
}
