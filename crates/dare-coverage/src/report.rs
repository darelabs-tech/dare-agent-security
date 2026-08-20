//! Machine-readable coverage report and CI threshold gate.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::correlate::CorrelatedRow;
use crate::error::CoverageError;
use crate::math::{
    coverage_ratio, eligible_count, required_eligible_count, required_tested_count, tested_count,
    CoveragePolicy,
};
use crate::profile::{profile_digest_sha256, AssessmentProfile, RequirementLevel, SchemaRef};
use crate::status::CoverageStatus;
use dare_security_evidence::Verdict;

pub const REPORT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/coverage/v1/coverage-report.schema.json";
pub const REPORT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/coverage/v1/coverage-report.schema.json");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyResult {
    pub property_id: String,
    pub requirement: RequirementLevel,
    pub coverage_status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub evidence_ids: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportCounts {
    #[serde(rename = "APPLICABLE")]
    pub applicable: u32,
    #[serde(rename = "NOT_APPLICABLE")]
    pub not_applicable: u32,
    #[serde(rename = "NOT_TESTED")]
    pub not_tested: u32,
    #[serde(rename = "OUT_OF_SCOPE")]
    pub out_of_scope: u32,
    #[serde(rename = "BLOCKED")]
    pub blocked: u32,
    #[serde(rename = "PASS")]
    pub pass: u32,
    #[serde(rename = "FAIL")]
    pub fail: u32,
    #[serde(rename = "INCONCLUSIVE")]
    pub inconclusive: u32,
    #[serde(rename = "ERROR")]
    pub error: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateResult {
    pub ok: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema: SchemaRef,
    pub profile: ProfileRef,
    pub profile_digest_sha256: String,
    pub overall_coverage: f64,
    pub required_coverage: f64,
    pub eligible: u32,
    pub tested: u32,
    pub required_eligible: u32,
    pub required_tested: u32,
    pub counts: ReportCounts,
    pub properties: Vec<PropertyResult>,
    pub gate: GateResult,
}

pub fn build_report(
    profile: &AssessmentProfile,
    rows: Vec<CorrelatedRow>,
    policy: CoveragePolicy,
) -> Result<CoverageReport, CoverageError> {
    let digest = profile_digest_sha256(profile)?;
    let mut counts = ReportCounts {
        applicable: 0,
        not_applicable: 0,
        not_tested: 0,
        out_of_scope: 0,
        blocked: 0,
        pass: 0,
        fail: 0,
        inconclusive: 0,
        error: 0,
    };
    let mut eligible = 0_u32;
    let mut tested = 0_u32;
    let mut required_eligible = 0_u32;
    let mut required_tested = 0_u32;
    let mut required_blocked = 0_u32;
    let mut properties = Vec::with_capacity(rows.len());

    for row in rows {
        match row.coverage_status {
            CoverageStatus::Applicable => counts.applicable += 1,
            CoverageStatus::NotApplicable => counts.not_applicable += 1,
            CoverageStatus::NotTested => counts.not_tested += 1,
            CoverageStatus::OutOfScope => counts.out_of_scope += 1,
            CoverageStatus::Blocked => counts.blocked += 1,
        }
        if let Some(v) = row.verdict {
            match v {
                Verdict::Pass => counts.pass += 1,
                Verdict::Fail => counts.fail += 1,
                Verdict::Inconclusive => counts.inconclusive += 1,
                Verdict::Error => counts.error += 1,
            }
        }
        if eligible_count(row.coverage_status, row.verdict) {
            eligible += 1;
        }
        if tested_count(row.coverage_status, row.verdict) {
            tested += 1;
        }
        if required_eligible_count(row.requirement, row.coverage_status, row.verdict) {
            required_eligible += 1;
        }
        if required_tested_count(row.requirement, row.coverage_status, row.verdict) {
            required_tested += 1;
        }
        if row.requirement == RequirementLevel::Required
            && row.coverage_status == CoverageStatus::Blocked
        {
            required_blocked += 1;
        }
        properties.push(PropertyResult {
            property_id: row.property_id,
            requirement: row.requirement,
            coverage_status: row.coverage_status,
            verdict: row.verdict,
            evidence_ids: row.evidence_ids,
            rationale: row.rationale,
        });
    }

    let overall = coverage_ratio(tested, eligible);
    let required = coverage_ratio(required_tested, required_eligible);
    let gate = evaluate_gate(required, required_blocked, policy);

    let report = CoverageReport {
        schema: SchemaRef {
            id: REPORT_SCHEMA_V1_ID.to_owned(),
            version: "1.0.0".to_owned(),
        },
        profile: ProfileRef {
            id: profile.id.clone(),
            version: profile.version.clone(),
        },
        profile_digest_sha256: digest,
        overall_coverage: overall,
        required_coverage: required,
        eligible,
        tested,
        required_eligible,
        required_tested,
        counts,
        properties,
        gate,
    };
    validate_report(&report)?;
    Ok(report)
}

pub fn evaluate_gate(
    required_coverage: f64,
    required_blocked: u32,
    policy: CoveragePolicy,
) -> GateResult {
    let mut reasons = Vec::new();
    if required_coverage + f64::EPSILON < policy.min_required_coverage {
        reasons.push(format!(
            "required_coverage {required_coverage:.4} < min {}",
            policy.min_required_coverage
        ));
    }
    if policy.fail_on_required_blocked && required_blocked > 0 {
        reasons.push(format!("required properties BLOCKED: {required_blocked}"));
    }
    GateResult {
        ok: reasons.is_empty(),
        reasons,
    }
}

pub fn validate_report(report: &CoverageReport) -> Result<(), CoverageError> {
    let value = serde_json::to_value(report).map_err(|_| CoverageError::Serialization {
        kind: "report-json",
    })?;
    validate_report_instance(&value)
}

pub fn validate_report_instance(instance: &Value) -> Result<(), CoverageError> {
    let schema: Value =
        serde_json::from_str(REPORT_SCHEMA_V1_JSON).map_err(|_| CoverageError::Serialization {
            kind: "report-schema",
        })?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| CoverageError::schema("/", err.to_string()))?;
    if validator.is_valid(instance) {
        return Ok(());
    }
    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(CoverageError::schema(
            err.instance_path().to_string(),
            err.to_string(),
        )),
        None => Err(CoverageError::schema("/", "report failed schema")),
    }
}

impl CoverageReport {
    pub fn summary_markdown(&self) -> String {
        format!(
            "\n## Coverage\n\n\
             | Field | Value |\n\
             |---|---|\n\
             | Profile | {}@{} |\n\
             | Profile digest | `{}` |\n\
             | Required coverage | {:.2}% |\n\
             | Overall coverage | {:.2}% |\n\
             | NOT_TESTED | {} |\n\
             | BLOCKED | {} |\n\
             | OUT_OF_SCOPE | {} |\n\
             | NOT_APPLICABLE | {} |\n\
             | Coverage gate | {} |\n",
            self.profile.id,
            self.profile.version,
            self.profile_digest_sha256,
            self.required_coverage * 100.0,
            self.overall_coverage * 100.0,
            self.counts.not_tested,
            self.counts.blocked,
            self.counts.out_of_scope,
            self.counts.not_applicable,
            if self.gate.ok { "PASS" } else { "FAIL" },
        )
    }
}
