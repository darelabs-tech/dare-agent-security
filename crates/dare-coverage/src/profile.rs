//! Assessment profiles are versioned data, not executable code.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::CoverageError;
use crate::property::PropertyRegistry;

pub const PROFILE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/coverage/v1/profile.schema.json";
pub const PROFILE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/coverage/v1/profile.schema.json");
pub const BUILTIN_PROFILE_JSON: &str = include_str!("../../../profiles/mcp-security-baseline.json");
pub const AGENTIC_PROFILE_JSON: &str =
    include_str!("../../../profiles/agentic-security-baseline-2026.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequirementLevel {
    Required,
    Conditional,
    Optional,
}

impl RequirementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "REQUIRED",
            Self::Conditional => "CONDITIONAL",
            Self::Optional => "OPTIONAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileProperty {
    pub id: String,
    pub requirement: RequirementLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentProfile {
    pub schema: SchemaRef,
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub properties: Vec<ProfileProperty>,
}

pub fn profile_schema_v1() -> Result<Value, CoverageError> {
    serde_json::from_str(PROFILE_SCHEMA_V1_JSON).map_err(|_| CoverageError::Serialization {
        kind: "profile-schema",
    })
}

pub fn validate_profile_instance(instance: &Value) -> Result<(), CoverageError> {
    let schema = profile_schema_v1()?;
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
        None => Err(CoverageError::schema("/", "profile failed schema")),
    }
}

pub fn load_profile(raw: &str) -> Result<AssessmentProfile, CoverageError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| CoverageError::Serialization {
        kind: "profile-parse",
    })?;
    validate_profile_instance(&value)?;
    serde_json::from_value(value).map_err(|_| CoverageError::Serialization {
        kind: "profile-typed",
    })
}

pub fn validate_profile(
    profile: &AssessmentProfile,
    registry: &PropertyRegistry,
) -> Result<(), CoverageError> {
    let mut seen = HashSet::new();
    for entry in &profile.properties {
        if !seen.insert(entry.id.clone()) {
            return Err(CoverageError::DuplicateProperty(entry.id.clone()));
        }
        registry.require(&entry.id)?;
    }
    Ok(())
}

pub fn builtin_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(BUILTIN_PROFILE_JSON)
}

pub fn agentic_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(AGENTIC_PROFILE_JSON)
}

pub fn load_profile_file(path: impl AsRef<Path>) -> Result<AssessmentProfile, CoverageError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| CoverageError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_profile(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}

pub fn resolve_profile(spec: &str) -> Result<AssessmentProfile, CoverageError> {
    match spec {
        "mcp-security-baseline" => builtin_profile(),
        "agentic-security-baseline-2026" => agentic_profile(),
        _ => load_profile_file(PathBuf::from(spec)),
    }
}

pub fn profile_digest_sha256(profile: &AssessmentProfile) -> Result<String, CoverageError> {
    let bytes = serde_json::to_vec(profile).map_err(|_| CoverageError::Serialization {
        kind: "profile-digest",
    })?;
    Ok(hex_encode(Sha256::digest(&bytes).as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::{agentic_registry, builtin_registry};

    #[test]
    fn builtin_profile_validates_against_registry() {
        let profile = builtin_profile().expect("profile");
        let registry = builtin_registry().expect("registry");
        validate_profile(&profile, &registry).expect("valid");
        assert_eq!(profile.id, "mcp-security-baseline");
        let digest = profile_digest_sha256(&profile).unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn agentic_profile_validates_against_agentic_registry() {
        let profile = agentic_profile().expect("profile");
        let registry = agentic_registry().expect("registry");
        validate_profile(&profile, &registry).expect("valid");
        assert_eq!(profile.id, "agentic-security-baseline-2026");
        assert_eq!(profile.properties.len(), 10);
    }

    #[test]
    fn unknown_property_in_profile_is_rejected() {
        let registry = builtin_registry().unwrap();
        let mut profile = builtin_profile().unwrap();
        profile.properties.push(ProfileProperty {
            id: "MCP.INJECTED.FAKE".to_owned(),
            requirement: RequirementLevel::Required,
        });
        assert!(matches!(
            validate_profile(&profile, &registry),
            Err(CoverageError::UnknownProperty(_))
        ));
    }
}
