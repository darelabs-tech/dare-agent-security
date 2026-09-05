//! Additive Agentic risk-family coverage view.
//! This module never changes Cycle 006 denominator semantics or the v1 coverage-report schema.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::math::{coverage_ratio, eligible_count, tested_count};
use crate::property::{PropertyRegistry, RiskFamily};
use crate::report::CoverageReport;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskFamilyCoverage {
    pub risk_family: RiskFamily,
    pub properties: u32,
    pub eligible: u32,
    pub tested: u32,
    pub not_tested: u32,
    pub blocked: u32,
    pub not_applicable: u32,
    /// None means there were no eligible properties. It never means secure.
    pub coverage: Option<f64>,
    /// Human-safe state that never labels an untested family secure.
    pub assessment_state: String,
}

pub fn derive_risk_family_coverage(
    report: &CoverageReport,
    registry: &PropertyRegistry,
) -> Vec<RiskFamilyCoverage> {
    let mut grouped: BTreeMap<String, RiskFamilyCoverage> = BTreeMap::new();

    for result in &report.properties {
        let Some(property) = registry.get(&result.property_id) else {
            continue;
        };
        let Some(family) = property.risk_family else {
            continue;
        };
        let key = format!("{family:?}");
        let entry = grouped.entry(key).or_insert(RiskFamilyCoverage {
            risk_family: family,
            properties: 0,
            eligible: 0,
            tested: 0,
            not_tested: 0,
            blocked: 0,
            not_applicable: 0,
            coverage: None,
            assessment_state: "UNASSESSED".to_owned(),
        });
        entry.properties += 1;
        if eligible_count(result.coverage_status, result.verdict) {
            entry.eligible += 1;
        }
        if tested_count(result.coverage_status, result.verdict) {
            entry.tested += 1;
        }
        match result.coverage_status {
            crate::CoverageStatus::NotTested => entry.not_tested += 1,
            crate::CoverageStatus::Blocked => entry.blocked += 1,
            crate::CoverageStatus::NotApplicable => entry.not_applicable += 1,
            crate::CoverageStatus::Applicable | crate::CoverageStatus::OutOfScope => {}
        }
    }

    for entry in grouped.values_mut() {
        entry.coverage = if entry.eligible == 0 {
            None
        } else {
            Some(coverage_ratio(entry.tested, entry.eligible))
        };
        entry.assessment_state = if entry.tested == 0 {
            "UNASSESSED".to_owned()
        } else if entry.tested < entry.eligible {
            "PARTIALLY_ASSESSED".to_owned()
        } else {
            "ASSESSED".to_owned()
        };
    }

    grouped.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agentic_profile, agentic_registry, run_assessment, AssessmentFacts, CoveragePolicy,
        TransportKind,
    };

    #[test]
    fn untested_families_are_never_labeled_secure() {
        let profile = agentic_profile().unwrap();
        let registry = agentic_registry().unwrap();
        let facts = AssessmentFacts {
            tools_count: 1,
            resources_count: 1,
            prompts_count: 1,
            transport: TransportKind::Http,
            authorization_present: true,
            dynamic_authorization_allowed: false,
            execution_integrity_supported: true,
            confused_deputy_supported: true,
            agent_present: true,
            memory_present: true,
            rag_present: true,
            multi_agent_present: true,
            code_execution_present: true,
            human_approval_present: true,
            delegated_identity_present: true,
            external_components_present: true,
            stateful_agent_present: true,
            runtime_dynamic_allowed: false,
            user_prompt_present: true,
            untrusted_external_content_present: true,
            tool_metadata_present: true,
            tool_output_present: true,
            tool_chaining_present: true,
            out_of_scope_property_ids: vec![],
        };
        let report =
            run_assessment(&profile, &registry, &facts, &[], CoveragePolicy::default()).unwrap();
        let groups = derive_risk_family_coverage(&report, &registry);
        assert_eq!(groups.len(), 10);
        assert!(groups
            .iter()
            .all(|group| group.assessment_state != "SECURE"));
        assert!(groups.iter().all(|group| group.tested == 0));
    }
}
