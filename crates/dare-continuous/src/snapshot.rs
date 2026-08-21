use std::{collections::BTreeMap, fs, path::Path};

use dare_attack_graph::PathStatus;
use dare_coverage::CoverageStatus;
use dare_security_evidence::{SeverityLevel, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{canonical::digest, ContinuousError, Result};

pub const SNAPSHOT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/continuous/v1/security-state-snapshot.schema.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetState {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFact {
    pub digest: String,
    pub destructive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityFacts {
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_code_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_model_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roe_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_vector_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_evidence_digest: Option<String>,
    pub capabilities: BTreeMap<String, CapabilityFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyState {
    pub coverage_status: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<SeverityLevel>,
    pub evidence_ids: Vec<String>,
    pub dependency_digests: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackPathState {
    pub digest: String,
    pub property_ids: Vec<String>,
    pub status: PathStatus,
    pub destructive: bool,
    pub cross_tenant: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationMode {
    PlanOnly,
    Simulated,
    LocalSynthetic,
    AuthorizedDynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationState {
    pub digest: String,
    pub property_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_id: Option<String>,
    pub mode: ValidationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub evidence_ids: Vec<String>,
    pub dependency_digests: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityState {
    pub id: String,
    pub target: TargetState,
    pub inventory_digest: String,
    pub property_registry_digest: String,
    pub profile_digest: String,
    pub assessment_plan_digest: String,
    pub evidence_bundle_digest: String,
    pub coverage_digest: String,
    pub attack_graph_digest: String,
    pub validation_results_digest: String,
    pub policies: BTreeMap<String, String>,
    pub facts: SecurityFacts,
    pub property_results: BTreeMap<String, PropertyState>,
    pub attack_paths: BTreeMap<String, AttackPathState>,
    pub validation_results: BTreeMap<String, ValidationState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityStateSnapshot {
    pub schema_version: String,
    pub security_state: SecurityState,
}

impl SecurityStateSnapshot {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        validate_snapshot_value(&value)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn validate(&self) -> Result<()> {
        validate_snapshot_value(&serde_json::to_value(self)?)
    }

    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

pub fn validate_snapshot_value(value: &Value) -> Result<()> {
    let schema: Value = serde_json::from_str(SNAPSHOT_SCHEMA_V1_JSON)?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| ContinuousError::Schema {
            path: "/".to_owned(),
            message: error.to_string(),
        })?;
    if validator.is_valid(value) {
        return Ok(());
    }
    let error = validator
        .iter_errors(value)
        .next()
        .ok_or_else(|| ContinuousError::Invalid("snapshot failed schema".to_owned()))?;
    Err(ContinuousError::Schema {
        path: error.instance_path().to_string(),
        message: error.to_string(),
    })
}
