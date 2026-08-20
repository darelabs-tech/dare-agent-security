//! Corpus manifest types and schema validation.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::digest_value;
use crate::error::BenchmarkError;

pub const CORPUS_MANIFEST_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/benchmark/v1/corpus-manifest.schema.json";
pub const CORPUS_MANIFEST_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/benchmark/v1/corpus-manifest.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageType {
    Canonical,
    MaterialFork,
    Mirror,
    VendorCopy,
    Example,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageInfo {
    #[serde(rename = "type")]
    pub lineage_type: LineageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_target_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusMeta {
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPolicy {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub population: Option<String>,
    pub inclusion: Vec<String>,
    pub exclusion: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stratification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainer_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusTarget {
    pub id: String,
    pub repository: String,
    pub commit: String,
    pub license: String,
    pub discovered_at: String,
    pub lineage: LineageInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stratification: Option<Stratification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixture_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub schema: SchemaRef,
    pub corpus: CorpusMeta,
    pub selection: SelectionPolicy,
    pub targets: Vec<CorpusTarget>,
}

pub fn validate_corpus_instance(instance: &Value) -> Result<(), BenchmarkError> {
    let schema: Value = serde_json::from_str(CORPUS_MANIFEST_SCHEMA_V1_JSON).map_err(|_| {
        BenchmarkError::Serialization {
            kind: "corpus-schema",
        }
    })?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| BenchmarkError::schema("/", err.to_string()))?;
    if validator.is_valid(instance) {
        return Ok(());
    }
    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(BenchmarkError::schema(
            err.instance_path().to_string(),
            err.to_string(),
        )),
        None => Err(BenchmarkError::schema("/", "corpus failed schema")),
    }
}

pub fn validate_corpus_manifest(manifest: &CorpusManifest) -> Result<(), BenchmarkError> {
    let value = serde_json::to_value(manifest).map_err(|_| BenchmarkError::Serialization {
        kind: "corpus-json",
    })?;
    validate_corpus_instance(&value)?;
    let mut ids = std::collections::HashSet::new();
    for target in &manifest.targets {
        if !ids.insert(target.id.clone()) {
            return Err(BenchmarkError::InvalidState(format!(
                "duplicate target id {}",
                target.id
            )));
        }
        if target.commit.len() != 40 || !target.commit.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BenchmarkError::InvalidState(format!(
                "target {} missing pinned commit SHA",
                target.id
            )));
        }
        if matches!(
            target.lineage.lineage_type,
            LineageType::MaterialFork | LineageType::Mirror | LineageType::VendorCopy
        ) && target.lineage.parent_target_id.is_none()
        {
            return Err(BenchmarkError::InvalidState(format!(
                "target {} lineage requires parent_target_id",
                target.id
            )));
        }
    }
    Ok(())
}

pub fn load_corpus_manifest(raw: &str) -> Result<CorpusManifest, BenchmarkError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| BenchmarkError::Serialization {
        kind: "corpus-parse",
    })?;
    validate_corpus_instance(&value)?;
    let manifest: CorpusManifest =
        serde_json::from_value(value).map_err(|_| BenchmarkError::Serialization {
            kind: "corpus-typed",
        })?;
    validate_corpus_manifest(&manifest)?;
    Ok(manifest)
}

pub fn load_corpus_file(path: impl AsRef<Path>) -> Result<CorpusManifest, BenchmarkError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| BenchmarkError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_corpus_manifest(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}

pub fn corpus_digest(manifest: &CorpusManifest) -> Result<String, BenchmarkError> {
    let value = serde_json::to_value(manifest).map_err(|_| BenchmarkError::Serialization {
        kind: "corpus-digest",
    })?;
    digest_value(&value)
}
