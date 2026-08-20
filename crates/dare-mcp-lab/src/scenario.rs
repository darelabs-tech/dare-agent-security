//! Scenario manifest types and schema validation (Cycle 005 task-002).

use std::path::{Path, PathBuf};

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::LabError;

/// Canonical `$id` for lab scenario schema v1.
pub const SCENARIO_SCHEMA_V1_ID: &str = "https://darelabs.tech/schemas/lab/v1/scenario.schema.json";

/// Embedded schema document. Kept in sync with `schemas/lab/v1/scenario.schema.json`.
pub const SCENARIO_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/lab/v1/scenario.schema.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioFamily {
    PassiveBoundary,
    AuthorizationPresence,
    ConfusedDeputy,
    AuthorizationIntegrity,
    McpRouting,
    ModernAuthorization,
    Mrtr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpProfile {
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityProperty {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    Applicable,
    NotApplicable,
    NotTested,
    OutOfScope,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    pub coverage_status: CoverageStatus,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantSpec {
    pub target: String,
    pub expected: ExpectedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variants {
    pub secure: VariantSpec,
    pub vulnerable: VariantSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StandardsStatus {
    Normative,
    Draft,
    OpenProposal,
    DraftOrOpenProposal,
    Informative,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardMapping {
    pub source: String,
    pub reference: String,
    pub status: StandardsStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyMetadata {
    pub destructive: bool,
    pub external_network: bool,
    pub real_credentials: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Versioned machine-readable lab scenario contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioManifest {
    pub schema: SchemaRef,
    pub id: String,
    pub revision: String,
    pub title: String,
    pub family: ScenarioFamily,
    pub mcp: McpProfile,
    pub property: SecurityProperty,
    pub variants: Variants,
    pub standards: Vec<StandardMapping>,
    pub safety: SafetyMetadata,
}

pub fn scenario_schema_v1() -> Result<Value, LabError> {
    serde_json::from_str(SCENARIO_SCHEMA_V1_JSON).map_err(|_| LabError::Serialization {
        kind: "schema-json",
    })
}

pub fn scenario_schema_v1_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/lab/v1/scenario.schema.json")
}

pub fn validate_scenario_instance(instance: &Value) -> Result<(), LabError> {
    let schema = scenario_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| LabError::StructuralValidation {
            path: "/".to_owned(),
            reason: compact(&err.to_string()),
        })?;

    if validator.is_valid(instance) {
        return Ok(());
    }

    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(LabError::StructuralValidation {
            path: err.instance_path().to_string(),
            reason: compact(&err.to_string()),
        }),
        None => Err(LabError::StructuralValidation {
            path: "/".to_owned(),
            reason: "instance failed schema validation".to_owned(),
        }),
    }
}

/// Structural + semantic validation for a typed manifest.
pub fn validate_scenario(manifest: &ScenarioManifest) -> Result<(), LabError> {
    let value = serde_json::to_value(manifest).map_err(|_| LabError::Serialization {
        kind: "scenario-json",
    })?;
    validate_scenario_instance(&value)?;
    validate_semantics(manifest)?;
    assert_safety_policy(manifest)?;
    Ok(())
}

pub fn parse_scenario(raw: &str) -> Result<ScenarioManifest, LabError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| LabError::Serialization {
        kind: "scenario-parse",
    })?;
    validate_scenario_instance(&value)?;
    let manifest: ScenarioManifest =
        serde_json::from_value(value).map_err(|_| LabError::Serialization {
            kind: "scenario-typed",
        })?;
    validate_semantics(&manifest)?;
    assert_safety_policy(&manifest)?;
    Ok(manifest)
}

pub fn load_scenario_file(path: impl AsRef<Path>) -> Result<ScenarioManifest, LabError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| LabError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    parse_scenario(raw)
}

/// Corpus safety gate: external network and real credentials are refused.
pub fn assert_safety_policy(manifest: &ScenarioManifest) -> Result<(), LabError> {
    if manifest.safety.external_network {
        return Err(LabError::SafetyPolicy {
            reason: "external_network must be false for CI-safe lab scenarios".to_owned(),
        });
    }
    if manifest.safety.real_credentials {
        return Err(LabError::SafetyPolicy {
            reason: "real_credentials must be false for lab scenarios".to_owned(),
        });
    }
    if manifest.safety.destructive {
        return Err(LabError::SafetyPolicy {
            reason: "destructive must be false for lab scenarios".to_owned(),
        });
    }
    Ok(())
}

fn validate_semantics(manifest: &ScenarioManifest) -> Result<(), LabError> {
    if manifest.variants.secure.target != "secure" {
        return Err(LabError::SemanticValidation {
            reason: "variants.secure.target must be \"secure\"".to_owned(),
        });
    }
    if manifest.variants.vulnerable.target != "vulnerable" {
        return Err(LabError::SemanticValidation {
            reason: "variants.vulnerable.target must be \"vulnerable\"".to_owned(),
        });
    }
    if manifest.variants.secure.expected.verdict != Verdict::Pass {
        return Err(LabError::SemanticValidation {
            reason: "secure variant expected verdict must be PASS for corpus scenarios".to_owned(),
        });
    }
    if manifest.variants.vulnerable.expected.verdict != Verdict::Fail {
        return Err(LabError::SemanticValidation {
            reason: "vulnerable variant expected verdict must be FAIL for corpus scenarios"
                .to_owned(),
        });
    }
    if manifest.schema.id != SCENARIO_SCHEMA_V1_ID {
        return Err(LabError::SemanticValidation {
            reason: format!("schema.id must be {SCENARIO_SCHEMA_V1_ID}"),
        });
    }
    Ok(())
}

fn compact(message: &str) -> String {
    message.chars().take(240).collect()
}

/// Sample MCP-LAB-001 manifest for tests and docs.
pub fn sample_scenario_passive_boundary() -> ScenarioManifest {
    ScenarioManifest {
        schema: SchemaRef {
            id: SCENARIO_SCHEMA_V1_ID.to_owned(),
            version: "1.0.0".to_owned(),
        },
        id: "MCP-LAB-001".to_owned(),
        revision: "1.0.0".to_owned(),
        title: "Passive discovery boundary".to_owned(),
        family: ScenarioFamily::PassiveBoundary,
        mcp: McpProfile {
            revision: "2026-07-28".to_owned(),
            profile: Some("passive-list-only".to_owned()),
        },
        property: SecurityProperty {
            id: "PASSIVE_DISCOVERY_BOUNDARY".to_owned(),
            description: "Passive mode never dispatches active or state-changing operations"
                .to_owned(),
        },
        variants: Variants {
            secure: VariantSpec {
                target: "secure".to_owned(),
                expected: ExpectedOutcome {
                    coverage_status: CoverageStatus::Applicable,
                    verdict: Verdict::Pass,
                },
            },
            vulnerable: VariantSpec {
                target: "vulnerable".to_owned(),
                expected: ExpectedOutcome {
                    coverage_status: CoverageStatus::Applicable,
                    verdict: Verdict::Fail,
                },
            },
        },
        standards: vec![StandardMapping {
            source: "MCP".to_owned(),
            reference: "tools/list vs tools/call boundary".to_owned(),
            status: StandardsStatus::Normative,
        }],
        safety: SafetyMetadata {
            destructive: false,
            external_network: false,
            real_credentials: false,
            notes: Some("synthetic local fixtures only".to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_file_matches_embedded_copy() {
        let disk = std::fs::read_to_string(scenario_schema_v1_path()).expect("read schema");
        assert_eq!(disk, SCENARIO_SCHEMA_V1_JSON);
    }

    #[test]
    fn sample_manifest_validates() {
        let sample = sample_scenario_passive_boundary();
        validate_scenario(&sample).expect("valid sample");
    }
}
