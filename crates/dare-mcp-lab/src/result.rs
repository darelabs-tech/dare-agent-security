//! Scenario execution result — expected vs observed (Cycle 005).

use dare_security_evidence::{SecurityEvidence, Verdict};
use serde::{Deserialize, Serialize};

use crate::framework::VariantKind;

/// Outcome of one scenario variant run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioRunResult {
    pub scenario_id: String,
    pub scenario_revision: String,
    pub variant: VariantKind,
    pub expected_verdict: Verdict,
    pub observed_verdict: Verdict,
    pub assertion_passed: bool,
    pub evidence_id: String,
    pub notes: String,
}

impl ScenarioRunResult {
    pub fn from_evidence(
        scenario_id: impl Into<String>,
        scenario_revision: impl Into<String>,
        variant: VariantKind,
        expected: Verdict,
        evidence: &SecurityEvidence,
        notes: impl Into<String>,
    ) -> Self {
        let observed = evidence.verdict;
        Self {
            scenario_id: scenario_id.into(),
            scenario_revision: scenario_revision.into(),
            variant,
            expected_verdict: expected,
            observed_verdict: observed,
            // Security FAIL can yield scenario PASS when FAIL is expected.
            assertion_passed: expected == observed,
            evidence_id: evidence.id.clone(),
            notes: notes.into(),
        }
    }
}
