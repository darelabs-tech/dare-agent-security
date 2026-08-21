use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseCandidate {
    pub baseline_snapshot_digest: String,
    pub expected_baseline_snapshot_digest: String,
    pub original_evidence_ids: Vec<String>,
    pub baseline_dependencies: BTreeMap<String, Option<String>>,
    pub candidate_dependencies: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseDecision {
    pub allowed: bool,
    pub reason: String,
}

pub fn can_reuse(candidate: &ReuseCandidate) -> ReuseDecision {
    if candidate.baseline_snapshot_digest != candidate.expected_baseline_snapshot_digest {
        return denied("baseline digest mismatch");
    }
    if candidate.original_evidence_ids.is_empty() {
        return denied("original evidence is required");
    }
    if candidate
        .baseline_dependencies
        .keys()
        .ne(candidate.candidate_dependencies.keys())
    {
        return denied("dependency set changed or was omitted");
    }
    for (name, before) in &candidate.baseline_dependencies {
        let after = &candidate.candidate_dependencies[name];
        match (before, after) {
            (Some(left), Some(right)) if left == right => {}
            (None, _) | (_, None) => return denied(&format!("dependency {name} is unknown")),
            _ => return denied(&format!("dependency {name} changed")),
        }
    }
    ReuseDecision {
        allowed: true,
        reason: "all security dependencies and original evidence are stable".to_owned(),
    }
}

fn denied(reason: &str) -> ReuseDecision {
    ReuseDecision {
        allowed: false,
        reason: reason.to_owned(),
    }
}
