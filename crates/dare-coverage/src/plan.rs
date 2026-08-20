//! Assessment plan generated before security analyzers run.

use serde::{Deserialize, Serialize};

use crate::applicability::evaluate_applicability;
use crate::error::CoverageError;
use crate::facts::AssessmentFacts;
use crate::profile::{AssessmentProfile, RequirementLevel};
use crate::property::PropertyRegistry;
use crate::status::CoverageStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedProperty {
    pub property_id: String,
    pub requirement: RequirementLevel,
    pub coverage_status: CoverageStatus,
    pub execution_mode: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentPlan {
    pub profile_id: String,
    pub profile_version: String,
    pub properties: Vec<PlannedProperty>,
}

pub fn build_assessment_plan(
    profile: &AssessmentProfile,
    registry: &PropertyRegistry,
    facts: &AssessmentFacts,
) -> Result<AssessmentPlan, CoverageError> {
    crate::profile::validate_profile(profile, registry)?;
    let mut properties = Vec::with_capacity(profile.properties.len());
    for entry in &profile.properties {
        let def = registry.require(&entry.id)?;
        let decision = evaluate_applicability(def, facts)?;
        let execution_mode = match def.supported_modes.first() {
            Some(crate::property::SupportedMode::Passive) => "passive",
            Some(crate::property::SupportedMode::Dynamic) => "dynamic",
            _ => "static",
        }
        .to_owned();
        properties.push(PlannedProperty {
            property_id: entry.id.clone(),
            requirement: entry.requirement,
            coverage_status: decision.status,
            execution_mode,
            rationale: decision.rationale,
        });
    }
    Ok(AssessmentPlan {
        profile_id: profile.id.clone(),
        profile_version: profile.version.clone(),
        properties,
    })
}
