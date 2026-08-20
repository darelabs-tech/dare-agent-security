//! Aggregate statistics with property-specific denominators.

use std::collections::{BTreeMap, BTreeSet};

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::corpus::{CorpusManifest, CorpusTarget};
use crate::eligibility::{eligible_for_property_prevalence, record_eligible_for_prevalence};
use crate::lineage::classify_for_prevalence;
use crate::policy::BenchmarkPolicy;
use crate::record::BenchmarkRecord;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyPrevalence {
    pub property_id: String,
    pub eligible: u32,
    pub failed: u32,
    pub failure_rate: Option<f64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageDistribution {
    pub median: f64,
    pub p25: f64,
    pub p75: f64,
    pub minimum: f64,
    pub maximum: f64,
    pub n: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindSpotRatios {
    pub error_ratio: f64,
    pub blocked_ratio: f64,
    pub not_tested_ratio: f64,
    pub out_of_scope_ratio: f64,
    pub not_applicable_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregateReport {
    pub corpus_id: String,
    pub corpus_version: String,
    pub target_count: u32,
    pub prevalence_eligible_targets: u32,
    pub finding_count_fail: u32,
    pub affected_target_count_fail: u32,
    pub coverage: CoverageDistribution,
    pub blind_spots: BlindSpotRatios,
    pub property_prevalence: Vec<PropertyPrevalence>,
    pub disclaimer: String,
}

pub fn aggregate_records(
    manifest: &CorpusManifest,
    records: &[BenchmarkRecord],
    policy: &BenchmarkPolicy,
) -> AggregateReport {
    let by_id: BTreeMap<&str, &CorpusTarget> = manifest
        .targets
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();

    let mut coverages = Vec::new();
    let mut finding_fail = 0_u32;
    let mut affected_fail = 0_u32;
    let mut prevalence_eligible = 0_u32;

    let mut sum_error = 0_u32;
    let mut sum_blocked = 0_u32;
    let mut sum_not_tested = 0_u32;
    let mut sum_oos = 0_u32;
    let mut sum_na = 0_u32;
    let mut sum_props = 0_u32;

    let mut property_stats: BTreeMap<String, (u32, u32)> = BTreeMap::new();

    for record in records {
        coverages.push(record.coverage.assessment_coverage);
        finding_fail += record.findings.fail;
        if record.findings.fail > 0 {
            affected_fail += 1;
        }

        let lineage = by_id
            .get(record.target.id.as_str())
            .map(|t| classify_for_prevalence(t))
            .unwrap_or(crate::lineage::PrevalenceInclusion::ExcludeFromPrevalence);

        if record_eligible_for_prevalence(record, policy)
            && lineage == crate::lineage::PrevalenceInclusion::Include
        {
            prevalence_eligible += 1;
        }

        sum_error += record.coverage.error;
        sum_blocked += record.coverage.blocked;
        sum_not_tested += record.coverage.not_tested;
        sum_oos += record.coverage.out_of_scope;
        sum_na += record.coverage.not_applicable;
        sum_props += record.property_results.len() as u32;

        for row in &record.property_results {
            if eligible_for_property_prevalence(record, row, policy, lineage) {
                let entry = property_stats
                    .entry(row.property_id.clone())
                    .or_insert((0, 0));
                entry.0 += 1;
                if row.verdict == Some(Verdict::Fail) {
                    entry.1 += 1;
                }
            }
        }
    }

    let property_prevalence = property_stats
        .into_iter()
        .map(|(property_id, (eligible, failed))| {
            let (failure_rate, note) = if eligible < policy.min_eligible_targets_for_rate {
                (
                    None,
                    Some(format!(
                        "N/A: eligible {eligible} < min {}",
                        policy.min_eligible_targets_for_rate
                    )),
                )
            } else {
                (Some(f64::from(failed) / f64::from(eligible)), None)
            };
            PropertyPrevalence {
                property_id,
                eligible,
                failed,
                failure_rate,
                note,
            }
        })
        .collect();

    let denom = if sum_props == 0 {
        1.0
    } else {
        f64::from(sum_props)
    };

    AggregateReport {
        corpus_id: manifest.corpus.id.clone(),
        corpus_version: manifest.corpus.version.clone(),
        target_count: records.len() as u32,
        prevalence_eligible_targets: prevalence_eligible,
        finding_count_fail: finding_fail,
        affected_target_count_fail: affected_fail,
        coverage: coverage_distribution(&coverages),
        blind_spots: BlindSpotRatios {
            error_ratio: f64::from(sum_error) / denom,
            blocked_ratio: f64::from(sum_blocked) / denom,
            not_tested_ratio: f64::from(sum_not_tested) / denom,
            out_of_scope_ratio: f64::from(sum_oos) / denom,
            not_applicable_ratio: f64::from(sum_na) / denom,
        },
        property_prevalence,
        disclaimer:
            "Descriptive pilot statistics only. Not a population inference about all MCP servers."
                .to_owned(),
    }
}

fn coverage_distribution(values: &[f64]) -> CoverageDistribution {
    if values.is_empty() {
        return CoverageDistribution {
            median: 0.0,
            p25: 0.0,
            p75: 0.0,
            minimum: 0.0,
            maximum: 0.0,
            n: 0,
        };
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    CoverageDistribution {
        median: percentile(&sorted, 0.50),
        p25: percentile(&sorted, 0.25),
        p75: percentile(&sorted, 0.75),
        minimum: sorted[0],
        maximum: sorted[n - 1],
        n: n as u32,
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn unique_property_ids(records: &[BenchmarkRecord]) -> BTreeSet<String> {
    records
        .iter()
        .flat_map(|r| r.property_results.iter().map(|p| p.property_id.clone()))
        .collect()
}
