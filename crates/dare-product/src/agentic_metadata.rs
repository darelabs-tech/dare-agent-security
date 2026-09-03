//! Additive Agentic product metadata derived from existing v1 artifacts.
//! No existing summary/findings/coverage schema is modified.

use std::collections::BTreeMap;

use dare_coverage::{
    agentic_profile, agentic_registry, derive_risk_family_coverage, CoverageReport, RiskFamily,
};

use crate::error::{ProductError, Result};
use crate::view_model::ProductViewModel;

pub fn build_agentic_metadata(vm: &ProductViewModel) -> Result<Option<serde_json::Value>> {
    if vm.summary.profile != "agentic-security-baseline-2026" {
        return Ok(None);
    }

    let registry = agentic_registry().map_err(|e| ProductError::internal(e.to_string()))?;
    let profile = agentic_profile().map_err(|e| ProductError::internal(e.to_string()))?;
    let coverage_report = serde_json::from_value::<CoverageReport>(vm.coverage.clone()).ok();

    let risk_family_coverage = if let Some(report) = coverage_report.as_ref() {
        serde_json::to_value(derive_risk_family_coverage(report, &registry))?
    } else {
        let mut grouped: BTreeMap<String, (RiskFamily, u32)> = BTreeMap::new();
        for selected in &profile.properties {
            let property = registry
                .get(&selected.id)
                .ok_or_else(|| ProductError::internal("Agentic profile property missing"))?;
            let family = property
                .risk_family
                .ok_or_else(|| ProductError::internal("Agentic property missing risk family"))?;
            let key = format!("{family:?}");
            grouped
                .entry(key)
                .and_modify(|entry| entry.1 += 1)
                .or_insert((family, 1));
        }
        serde_json::Value::Array(
            grouped
                .into_values()
                .map(|(family, count)| {
                    serde_json::json!({
                        "risk_family": family,
                        "properties": count,
                        "eligible": 0,
                        "tested": 0,
                        "coverage": null,
                        "assessment_state": "UNASSESSED"
                    })
                })
                .collect(),
        )
    };

    let property_metadata = profile
        .properties
        .iter()
        .map(|selected| {
            let property = registry
                .get(&selected.id)
                .ok_or_else(|| ProductError::internal("Agentic profile property missing"))?;
            let coverage_status = coverage_report
                .as_ref()
                .and_then(|report| {
                    report
                        .properties
                        .iter()
                        .find(|row| row.property_id == property.id)
                })
                .map(|row| format!("{:?}", row.coverage_status).to_ascii_uppercase())
                .unwrap_or_else(|| "NOT_TESTED".to_owned());
            Ok(serde_json::json!({
                "property_id": property.id,
                "requirement": selected.requirement,
                "risk_family": property.risk_family,
                "category": property.category,
                "coverage_status": coverage_status,
                "standards": property.standards,
                "evidence_required": property.evidence.required_for_confirmed_verdict,
                "maturity": property.maturity
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(serde_json::json!({
        "schema": {
            "id": "https://darelabs.tech/schemas/product/additive/agentic-metadata-2026",
            "version": "1.0.0"
        },
        "profile": vm.summary.profile,
        "risk_family_coverage": risk_family_coverage,
        "properties": property_metadata,
        "assurance_note": "UNASSESSED and NOT_TESTED states do not imply security. Only evidence-backed verdicts establish tested outcomes."
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::Classification;
    use crate::view_model::{GateResult, ProductSummary, SeverityCounts};

    fn vm(profile: &str) -> ProductViewModel {
        ProductViewModel {
            summary: ProductSummary {
                schema_id: crate::view_model::SUMMARY_SCHEMA_ID.to_owned(),
                schema_version: crate::PRODUCT_SCHEMA_VERSION.to_owned(),
                run_id: "run-test".to_owned(),
                project_name: "agentic-demo".to_owned(),
                profile: profile.to_owned(),
                profile_version: "1.0.0".to_owned(),
                gate: GateResult::Partial,
                overall_coverage: 0.0,
                required_coverage: 0.0,
                severity_counts: SeverityCounts::default(),
                top_finding_ids: vec![],
                attack_path_summary: "none".to_owned(),
                validation_status: "plan-only".to_owned(),
                limitations: vec![],
                classification: Classification::default(),
                privacy_mode: "confidential".to_owned(),
                offline: true,
                generated_at: "2026-09-03T00:00:00Z".to_owned(),
            },
            findings: vec![],
            coverage: serde_json::json!({"note":"no coverage facts"}),
            attack_graph: serde_json::json!({}),
            validation: serde_json::json!({}),
            drift: serde_json::json!({}),
        }
    }

    #[test]
    fn unassessed_agentic_metadata_never_claims_secure() {
        let metadata = build_agentic_metadata(&vm("agentic-security-baseline-2026"))
            .unwrap()
            .unwrap();
        let text = serde_json::to_string(&metadata).unwrap();
        assert!(text.contains("UNASSESSED"));
        assert!(text.contains("NOT_TESTED"));
        assert!(!text.contains("SECURE"));
    }

    #[test]
    fn mcp_profile_has_no_agentic_metadata() {
        assert!(build_agentic_metadata(&vm("mcp-security-baseline"))
            .unwrap()
            .is_none());
    }
}
