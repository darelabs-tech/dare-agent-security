//! Coverage-aware eligibility for prevalence denominators.

use dare_coverage::CoverageStatus;
use dare_security_evidence::Verdict;

use crate::lineage::PrevalenceInclusion;
use crate::policy::BenchmarkPolicy;
use crate::record::{BenchmarkRecord, PropertyResultRow};

pub fn record_eligible_for_prevalence(record: &BenchmarkRecord, policy: &BenchmarkPolicy) -> bool {
    if record.coverage.assessment_coverage + f64::EPSILON
        < policy.min_assessment_coverage_for_prevalence
    {
        return false;
    }
    let total = record.findings.pass
        + record.findings.fail
        + record.findings.inconclusive
        + record.findings.error;
    if total == 0 {
        return false;
    }
    let error_ratio = f64::from(record.findings.error) / f64::from(total);
    error_ratio <= policy.max_error_ratio + f64::EPSILON
}

pub fn eligible_for_property_prevalence(
    record: &BenchmarkRecord,
    row: &PropertyResultRow,
    policy: &BenchmarkPolicy,
    lineage_inclusion: PrevalenceInclusion,
) -> bool {
    if lineage_inclusion != PrevalenceInclusion::Include {
        return false;
    }
    if !record_eligible_for_prevalence(record, policy) {
        return false;
    }
    if row.coverage_status != CoverageStatus::Applicable {
        return false;
    }
    match row.verdict {
        Some(Verdict::Error) | None => false,
        Some(_) => {
            let confidence = row.confidence.unwrap_or(1.0);
            confidence + f64::EPSILON >= policy.min_confidence_for_prevalence
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::SchemaRef;
    use crate::record::{AssessmentMeta, CoverageCounts, FindingCounts, TargetRef};
    use crate::run::RunnerMode;

    fn sample_record(coverage: f64, error: u32) -> BenchmarkRecord {
        BenchmarkRecord {
            schema: SchemaRef {
                id: crate::record::RECORD_SCHEMA_V1_ID.to_owned(),
                version: "1.0.0".to_owned(),
            },
            benchmark_run_id: "run-1".to_owned(),
            target: TargetRef {
                id: "mcp-target-000001".to_owned(),
                repository: "fixture/demo".to_owned(),
                commit: "b".repeat(40),
            },
            assessment: AssessmentMeta {
                mode: RunnerMode::LocalPassive,
                plan_digest: "c".repeat(64),
                evidence_bundle_digest: None,
            },
            coverage: CoverageCounts {
                assessment_coverage: coverage,
                execution_coverage: None,
                not_applicable: 0,
                out_of_scope: 0,
                not_tested: 0,
                blocked: 0,
                error: 0,
            },
            findings: FindingCounts {
                pass: 5,
                fail: 1,
                inconclusive: 0,
                error,
            },
            property_results: vec![],
            publication: None,
        }
    }

    #[test]
    fn low_coverage_excluded_from_prevalence() {
        let policy = BenchmarkPolicy {
            version: "1.0.0".to_owned(),
            min_assessment_coverage_for_prevalence: 0.8,
            max_error_ratio: 0.05,
            min_confidence_for_prevalence: 0.7,
            min_eligible_targets_for_rate: 5,
            default_runner_mode: "LOCAL_PASSIVE".to_owned(),
            allow_authorized_dynamic: false,
        };
        assert!(!record_eligible_for_prevalence(
            &sample_record(0.41, 0),
            &policy
        ));
        assert!(record_eligible_for_prevalence(
            &sample_record(0.96, 0),
            &policy
        ));
    }
}
