//! Product config v1 loader and defaults.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::classification::Classification;
use crate::error::{ProductError, Result};
use crate::privacy::{NetworkMode, PrivacyMode, PrivacyPolicy};

pub const CONFIG_SCHEMA_V1_ID: &str = "https://darelabs.tech/schemas/product/v1/config.schema.json";
pub const CONFIG_FILE_NAMES: &[&str] = &[
    "dare-security.yaml",
    "dare-security.yml",
    "dare-security.json",
    ".dare-security/config.yaml",
    ".dare-security/config.yml",
    ".dare-security/config.json",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductConfig {
    pub version: String,
    pub project: ProjectSection,
    #[serde(default)]
    pub assessment: AssessmentSection,
    #[serde(default)]
    pub privacy: PrivacySection,
    #[serde(default)]
    pub reporting: ReportingSection,
    #[serde(default)]
    pub classification: Classification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSection {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSection {
    #[serde(default = "default_profile")]
    pub profile: String,
}

fn default_profile() -> String {
    "mcp-security-baseline".to_owned()
}

impl Default for AssessmentSection {
    fn default() -> Self {
        Self {
            profile: default_profile(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacySection {
    #[serde(default)]
    pub mode: PrivacyMode,
    #[serde(default)]
    pub telemetry: bool,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

impl Default for PrivacySection {
    fn default() -> Self {
        Self {
            mode: PrivacyMode::Standard,
            telemetry: false,
            network: NetworkMode::Restricted,
            offline: false,
            retention_days: Some(30),
        }
    }
}

impl PrivacySection {
    pub fn to_policy(&self) -> PrivacyPolicy {
        PrivacyPolicy {
            mode: self.mode,
            telemetry: self.telemetry,
            network: self.network,
            offline: self.offline,
            retention_days: self.retention_days,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingSection {
    #[serde(default = "default_formats")]
    pub formats: Vec<String>,
}

fn default_formats() -> Vec<String> {
    vec!["html".to_owned(), "json".to_owned()]
}

impl Default for ReportingSection {
    fn default() -> Self {
        Self {
            formats: default_formats(),
        }
    }
}

impl Default for ProductConfig {
    fn default() -> Self {
        Self {
            version: "1".to_owned(),
            project: ProjectSection {
                name: "unnamed-project".to_owned(),
            },
            assessment: AssessmentSection::default(),
            privacy: PrivacySection::default(),
            reporting: ReportingSection::default(),
            classification: Classification::default(),
        }
    }
}

impl ProductConfig {
    pub fn validate(&self) -> Result<()> {
        if self.version != "1" && !self.version.starts_with("1.") {
            return Err(ProductError::configuration(format!(
                "unsupported config version `{}`; expected `1`",
                self.version
            )));
        }
        if self.project.name.trim().is_empty() {
            return Err(ProductError::configuration(
                "project.name must not be empty",
            ));
        }
        if self.assessment.profile.trim().is_empty() {
            return Err(ProductError::configuration(
                "assessment.profile must not be empty",
            ));
        }
        let policy = self.privacy.to_policy();
        policy.validate_fail_closed()?;
        Ok(())
    }

    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }
}

/// Load config from an explicit path or search under `root`.
pub fn load_config(root: &Path, explicit: Option<&Path>) -> Result<(ProductConfig, PathBuf)> {
    if let Some(path) = explicit {
        let cfg = parse_config_file(path)?;
        cfg.validate()?;
        return Ok((cfg, path.to_path_buf()));
    }
    for name in CONFIG_FILE_NAMES {
        let candidate = root.join(name);
        if candidate.is_file() {
            let cfg = parse_config_file(&candidate)?;
            cfg.validate()?;
            return Ok((cfg, candidate));
        }
    }
    let mut cfg = ProductConfig::default();
    if let Some(name) = root
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
    {
        cfg.project.name = name.to_owned();
    }
    cfg.validate()?;
    Ok((cfg, root.join(".dare-security/config.yaml")))
}

fn parse_config_file(path: &Path) -> Result<ProductConfig> {
    let raw = fs::read_to_string(path).map_err(|e| {
        ProductError::environment(format!("unable to read config {}: {e}", path.display()))
    })?;
    let trimmed = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let cfg: ProductConfig = if ext == "json" {
        serde_json::from_str(trimmed)?
    } else {
        serde_yaml::from_str(trimmed)?
    };
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let cfg = ProductConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(!cfg.privacy.telemetry);
    }

    #[test]
    fn rejects_bad_version() {
        let cfg = ProductConfig {
            version: "2".to_owned(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
