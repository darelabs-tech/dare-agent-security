use dare_attack_graph::PathStatus;
use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::{canonical::digest, model::ValidationResult, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevisionStatus {
    Observed,
    Rejected,
    ReviewRequired,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRevision {
    pub path_id: String,
    pub previous_digest: String,
    pub previous_status: PathStatus,
    pub validation_result_digest: String,
    pub new_status: RevisionStatus,
    pub rationale: String,
    pub new_digest: String,
}

pub fn reclassify(
    path_id: &str,
    previous_digest: &str,
    previous_status: PathStatus,
    result: &ValidationResult,
) -> Result<PathRevision> {
    let result_digest = digest(result)?;
    let (new_status, rationale) = match (previous_status, result.verdict) {
        (PathStatus::Inferred, Some(Verdict::Fail)) => (
            RevisionStatus::Observed,
            "controlled runtime evidence observed the security failure",
        ),
        (PathStatus::Inferred, Some(Verdict::Pass)) => (
            RevisionStatus::Rejected,
            "controlled runtime evidence disproved the inferred path",
        ),
        (PathStatus::Proven, Some(Verdict::Pass)) => (
            RevisionStatus::ReviewRequired,
            "runtime evidence contradicts static proof",
        ),
        _ => (
            RevisionStatus::Unchanged,
            "evidence is insufficient for path reclassification",
        ),
    };
    let new_digest = digest(&serde_json::json!({
        "parent": previous_digest,
        "result": result_digest,
        "status": new_status,
        "path_id": path_id
    }))?;
    Ok(PathRevision {
        path_id: path_id.to_owned(),
        previous_digest: previous_digest.to_owned(),
        previous_status,
        validation_result_digest: result_digest,
        new_status,
        rationale: rationale.to_owned(),
        new_digest,
    })
}
