use serde::{Deserialize, Serialize};

use crate::error::{GraphError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeEvidenceStatus {
    Observed,
    StaticallyProven,
    Inferred,
    NotTested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeEvidence {
    pub status: EdgeEvidenceStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_facts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub fn validate_edge_evidence(evidence: &EdgeEvidence) -> Result<()> {
    let nonempty = |value: &Option<String>| value.as_ref().is_some_and(|s| !s.trim().is_empty());
    match evidence.status {
        EdgeEvidenceStatus::Observed | EdgeEvidenceStatus::StaticallyProven
            if evidence.evidence_ids.is_empty() =>
        {
            Err(GraphError::Invalid(
                "proven edge requires evidence_ids".into(),
            ))
        }
        EdgeEvidenceStatus::Inferred
            if !nonempty(&evidence.rationale) || evidence.source_facts.is_empty() =>
        {
            Err(GraphError::Invalid(
                "INFERRED edge requires rationale and source_facts".into(),
            ))
        }
        EdgeEvidenceStatus::NotTested if !nonempty(&evidence.reason) => Err(GraphError::Invalid(
            "NOT_TESTED edge requires reason".into(),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants_are_enforced() {
        let missing = EdgeEvidence {
            status: EdgeEvidenceStatus::Observed,
            evidence_ids: vec![],
            rationale: None,
            source_facts: vec![],
            reason: None,
        };
        assert!(validate_edge_evidence(&missing).is_err());
    }
}
