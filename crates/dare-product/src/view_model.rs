//! Product result view model (redacted, report-ready).

use serde::{Deserialize, Serialize};

use crate::classification::Classification;
use crate::PRODUCT_SCHEMA_VERSION;

pub const SUMMARY_SCHEMA_ID: &str = "https://darelabs.tech/schemas/product/v1/summary.schema.json";
pub const FINDINGS_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/v1/findings.schema.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateResult {
    Pass,
    Fail,
    Partial,
    Blocked,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SeverityCounts {
    #[serde(default)]
    pub critical: u32,
    #[serde(default)]
    pub high: u32,
    #[serde(default)]
    pub medium: u32,
    #[serde(default)]
    pub low: u32,
    #[serde(default)]
    pub info: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub property: String,
    pub severity: FindingSeverity,
    pub confidence: String,
    pub component: String,
    pub status: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub attack_path_refs: Vec<String>,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub observed: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub retest_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductSummary {
    pub schema_id: String,
    pub schema_version: String,
    pub run_id: String,
    pub project_name: String,
    pub profile: String,
    pub profile_version: String,
    pub gate: GateResult,
    pub overall_coverage: f64,
    pub required_coverage: f64,
    pub severity_counts: SeverityCounts,
    pub top_finding_ids: Vec<String>,
    pub attack_path_summary: String,
    pub validation_status: String,
    pub limitations: Vec<String>,
    pub classification: Classification,
    pub privacy_mode: String,
    pub offline: bool,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductViewModel {
    pub summary: ProductSummary,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub coverage: serde_json::Value,
    #[serde(default)]
    pub attack_graph: serde_json::Value,
    #[serde(default)]
    pub validation: serde_json::Value,
    #[serde(default)]
    pub drift: serde_json::Value,
}

impl ProductViewModel {
    pub fn schema_version() -> &'static str {
        PRODUCT_SCHEMA_VERSION
    }

    pub fn recount_severity(&mut self) {
        let mut counts = SeverityCounts::default();
        for f in &self.findings {
            match f.severity {
                FindingSeverity::Critical => counts.critical += 1,
                FindingSeverity::High => counts.high += 1,
                FindingSeverity::Medium => counts.medium += 1,
                FindingSeverity::Low => counts.low += 1,
                FindingSeverity::Info => counts.info += 1,
            }
        }
        self.summary.severity_counts = counts;
        self.summary.top_finding_ids = self.findings.iter().take(5).map(|f| f.id.clone()).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recount_updates_top_ids() {
        let mut vm = ProductViewModel {
            summary: ProductSummary {
                schema_id: SUMMARY_SCHEMA_ID.to_owned(),
                schema_version: PRODUCT_SCHEMA_VERSION.to_owned(),
                run_id: "run-1".to_owned(),
                project_name: "demo".to_owned(),
                profile: "mcp-security-baseline".to_owned(),
                profile_version: "1.0.0".to_owned(),
                gate: GateResult::Fail,
                overall_coverage: 0.5,
                required_coverage: 0.8,
                severity_counts: SeverityCounts::default(),
                top_finding_ids: vec![],
                attack_path_summary: "none".to_owned(),
                validation_status: "plan-only".to_owned(),
                limitations: vec![],
                classification: Classification::default(),
                privacy_mode: "standard".to_owned(),
                offline: true,
                generated_at: "2026-01-01T00:00:00Z".to_owned(),
            },
            findings: vec![Finding {
                id: "F-1".to_owned(),
                title: "Auth missing".to_owned(),
                property: "MCP.AUTHZ.PER_OPERATION".to_owned(),
                severity: FindingSeverity::High,
                confidence: "HIGH".to_owned(),
                component: "tool:export".to_owned(),
                status: "FAIL".to_owned(),
                evidence_refs: vec!["ev-1".to_owned()],
                attack_path_refs: vec![],
                expected: Some("DENY".to_owned()),
                observed: Some("ALLOW".to_owned()),
                remediation: Some("Require per-operation authz".to_owned()),
                retest_status: Some("PENDING".to_owned()),
            }],
            coverage: serde_json::json!({}),
            attack_graph: serde_json::json!({}),
            validation: serde_json::json!({}),
            drift: serde_json::json!({}),
        };
        vm.recount_severity();
        assert_eq!(vm.summary.severity_counts.high, 1);
        assert_eq!(vm.summary.top_finding_ids, vec!["F-1".to_owned()]);
    }
}
