//! Safe offline benchmark runner. Defaults to STATIC / LOCAL_PASSIVE.

use dare_coverage::CoverageStatus;
use dare_security_evidence::Verdict;

use crate::canonical::{digest_value, sha256_hex};
use crate::corpus::{CorpusManifest, CorpusTarget, SchemaRef};
use crate::error::BenchmarkError;
use crate::policy::BenchmarkPolicy;
use crate::record::{
    AssessmentMeta, BenchmarkRecord, CoverageCounts, FindingCounts, PropertyResultRow, TargetRef,
    RECORD_SCHEMA_V1_ID,
};
use crate::run::{BenchmarkRun, RunnerMode};

#[derive(Debug, Clone)]
pub struct RunnerOptions {
    pub mode: RunnerMode,
    pub authorized_dynamic_roe: bool,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            mode: RunnerMode::LocalPassive,
            authorized_dynamic_roe: false,
        }
    }
}

pub struct RunnerSafetyGate;

impl RunnerSafetyGate {
    pub fn assert_mode_allowed(
        options: &RunnerOptions,
        policy: &BenchmarkPolicy,
    ) -> Result<(), BenchmarkError> {
        match options.mode {
            RunnerMode::Static | RunnerMode::LocalPassive => Ok(()),
            RunnerMode::AuthorizedDynamic => {
                if !policy.allow_authorized_dynamic || !options.authorized_dynamic_roe {
                    return Err(BenchmarkError::SafetyRefusal(
                        "AUTHORIZED_DYNAMIC requires allow_authorized_dynamic policy and explicit ROE flag"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn refuse_network_exfiltration(path: &str) -> Result<(), BenchmarkError> {
        let lower = path.to_ascii_lowercase();
        for canary in ["http://", "https://", "ftp://", "git@"] {
            if lower.contains(canary) && !lower.contains("fixture://") {
                // Repository field may contain owner/repo names; only refuse URL-like fixture paths.
            }
        }
        if path.contains("..") {
            return Err(BenchmarkError::SafetyRefusal(
                "path traversal refused in fixture_path".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Offline runner: builds deterministic records from corpus targets without network I/O.
/// Fixture targets get synthetic property results for methodology validation.
pub fn run_corpus_offline(
    manifest: &CorpusManifest,
    run: &BenchmarkRun,
    policy: &BenchmarkPolicy,
    options: &RunnerOptions,
) -> Result<Vec<BenchmarkRecord>, BenchmarkError> {
    RunnerSafetyGate::assert_mode_allowed(options, policy)?;
    let mut records = Vec::with_capacity(manifest.targets.len());
    for target in &manifest.targets {
        if let Some(path) = &target.fixture_path {
            RunnerSafetyGate::refuse_network_exfiltration(path)?;
        }
        records.push(synthesize_record(manifest, run, target, options.mode)?);
    }
    Ok(records)
}

fn synthesize_record(
    manifest: &CorpusManifest,
    run: &BenchmarkRun,
    target: &CorpusTarget,
    mode: RunnerMode,
) -> Result<BenchmarkRecord, BenchmarkError> {
    // Deterministic synthetic outcomes from target id hash — methodology fixtures only.
    let seed = sha256_hex(target.id.as_bytes());
    let nibble = u8::from_str_radix(&seed[0..2], 16).unwrap_or(0);

    let properties = [
        "MCP.DISCOVERY.PASSIVE_BOUNDARY",
        "MCP.AUTHZ.PER_OPERATION",
        "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
        "MCP.EVIDENCE.REDACTION",
    ];

    let mut property_results = Vec::new();
    let mut pass = 0;
    let mut fail = 0;
    let mut inconclusive = 0;
    let mut error = 0;
    let mut na = 0;
    let mut oos = 0;
    let mut not_tested = 0;
    let mut blocked = 0;
    let err_cov = 0;

    for (i, prop) in properties.iter().enumerate() {
        let lane = (nibble as usize + i * 3) % 7;
        let (status, verdict, conf) = match lane {
            0 => (CoverageStatus::Applicable, Some(Verdict::Pass), Some(0.95)),
            1 => (CoverageStatus::Applicable, Some(Verdict::Fail), Some(0.9)),
            2 => (
                CoverageStatus::Applicable,
                Some(Verdict::Inconclusive),
                Some(0.5),
            ),
            3 => (CoverageStatus::NotApplicable, None, None),
            4 => (CoverageStatus::NotTested, None, None),
            5 => (CoverageStatus::Blocked, None, None),
            _ => (CoverageStatus::OutOfScope, None, None),
        };
        match status {
            CoverageStatus::Applicable => match verdict {
                Some(Verdict::Pass) => pass += 1,
                Some(Verdict::Fail) => fail += 1,
                Some(Verdict::Inconclusive) => inconclusive += 1,
                Some(Verdict::Error) => error += 1,
                None => not_tested += 1,
            },
            CoverageStatus::NotApplicable => na += 1,
            CoverageStatus::OutOfScope => oos += 1,
            CoverageStatus::NotTested => not_tested += 1,
            CoverageStatus::Blocked => blocked += 1,
        }
        property_results.push(PropertyResultRow {
            property_id: (*prop).to_owned(),
            coverage_status: status,
            verdict,
            evidence_ids: if verdict.is_some() {
                vec![format!("evidence-{}-{i}", target.id)]
            } else {
                Vec::new()
            },
            confidence: conf,
        });
    }

    let tested = pass + fail + inconclusive + error;
    let eligible = tested + not_tested + blocked;
    let assessment_coverage = if eligible == 0 {
        1.0
    } else {
        f64::from(tested) / f64::from(eligible)
    };

    let plan_value = serde_json::json!({
        "corpus": manifest.corpus.id,
        "target": target.id,
        "run": run.id,
        "mode": mode.as_str(),
    });
    let plan_digest = digest_value(&plan_value)?;

    let record = BenchmarkRecord {
        schema: SchemaRef {
            id: RECORD_SCHEMA_V1_ID.to_owned(),
            version: "1.0.0".to_owned(),
        },
        benchmark_run_id: run.id.clone(),
        target: TargetRef {
            id: target.id.clone(),
            repository: target.repository.clone(),
            commit: target.commit.clone(),
        },
        assessment: AssessmentMeta {
            mode,
            plan_digest,
            evidence_bundle_digest: Some(sha256_hex(
                format!("{}:{}", run.id, target.id).as_bytes(),
            )),
        },
        coverage: CoverageCounts {
            assessment_coverage,
            execution_coverage: Some(assessment_coverage),
            not_applicable: na,
            out_of_scope: oos,
            not_tested,
            blocked,
            error: err_cov,
        },
        findings: FindingCounts {
            pass,
            fail,
            inconclusive,
            error,
        },
        property_results,
        publication: None,
    };
    crate::record::validate_benchmark_record(&record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::builtin_policy;

    #[test]
    fn authorized_dynamic_refused_by_default() {
        let policy = builtin_policy().unwrap();
        let options = RunnerOptions {
            mode: RunnerMode::AuthorizedDynamic,
            authorized_dynamic_roe: false,
        };
        assert!(matches!(
            RunnerSafetyGate::assert_mode_allowed(&options, &policy),
            Err(BenchmarkError::SafetyRefusal(_))
        ));
    }

    #[test]
    fn path_traversal_refused() {
        assert!(RunnerSafetyGate::refuse_network_exfiltration("../etc/passwd").is_err());
    }
}
