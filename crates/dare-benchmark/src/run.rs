//! Benchmark Run identity (frozen corpus/engine/profile/policy).

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::digest_value;
use crate::corpus::{corpus_digest, CorpusManifest, SchemaRef};
use crate::error::BenchmarkError;
use crate::policy::{policy_digest, BenchmarkPolicy};

pub const RUN_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/benchmark/v1/benchmark-run.schema.json";
pub const RUN_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/benchmark/v1/benchmark-run.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunnerMode {
    Static,
    LocalPassive,
    AuthorizedDynamic,
}

impl RunnerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "STATIC",
            Self::LocalPassive => "LOCAL_PASSIVE",
            Self::AuthorizedDynamic => "AUTHORIZED_DYNAMIC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRef {
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRunRef {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineRef {
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRunRef {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoliciesRef {
    pub coverage: DigestRef,
    pub severity: DigestRef,
    pub confidence: DigestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRef {
    pub version: String,
    pub default_mode: RunnerMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRef {
    pub network_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRun {
    pub schema: SchemaRef,
    pub id: String,
    pub corpus: CorpusRunRef,
    pub engine: EngineRef,
    pub property_registry: DigestRef,
    pub assessment_profile: ProfileRunRef,
    pub policies: PoliciesRef,
    pub runner: RunnerRef,
    pub environment: EnvironmentRef,
}

pub fn validate_run_instance(instance: &Value) -> Result<(), BenchmarkError> {
    let schema: Value = serde_json::from_str(RUN_SCHEMA_V1_JSON)
        .map_err(|_| BenchmarkError::Serialization { kind: "run-schema" })?;
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
        None => Err(BenchmarkError::schema("/", "run failed schema")),
    }
}

pub fn validate_benchmark_run(run: &BenchmarkRun) -> Result<(), BenchmarkError> {
    let value = serde_json::to_value(run)
        .map_err(|_| BenchmarkError::Serialization { kind: "run-json" })?;
    validate_run_instance(&value)
}

pub fn load_benchmark_run(raw: &str) -> Result<BenchmarkRun, BenchmarkError> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| BenchmarkError::Serialization { kind: "run-parse" })?;
    validate_run_instance(&value)?;
    serde_json::from_value(value).map_err(|_| BenchmarkError::Serialization { kind: "run-typed" })
}

pub fn load_run_file(path: impl AsRef<Path>) -> Result<BenchmarkRun, BenchmarkError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| BenchmarkError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_benchmark_run(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}

#[allow(clippy::too_many_arguments)]
pub fn build_benchmark_run(
    run_id: &str,
    manifest: &CorpusManifest,
    policy: &BenchmarkPolicy,
    profile_id: &str,
    profile_version: &str,
    profile_digest: &str,
    registry_version: &str,
    registry_digest: &str,
    engine_commit: &str,
    default_mode: RunnerMode,
) -> Result<BenchmarkRun, BenchmarkError> {
    let policy_d = policy_digest(policy)?;
    let run = BenchmarkRun {
        schema: SchemaRef {
            id: RUN_SCHEMA_V1_ID.to_owned(),
            version: "1.0.0".to_owned(),
        },
        id: run_id.to_owned(),
        corpus: CorpusRunRef {
            id: manifest.corpus.id.clone(),
            version: manifest.corpus.version.clone(),
            digest: corpus_digest(manifest)?,
        },
        engine: EngineRef {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: engine_commit.to_owned(),
        },
        property_registry: DigestRef {
            version: registry_version.to_owned(),
            digest: registry_digest.to_owned(),
        },
        assessment_profile: ProfileRunRef {
            id: profile_id.to_owned(),
            version: profile_version.to_owned(),
            digest: profile_digest.to_owned(),
        },
        policies: PoliciesRef {
            coverage: DigestRef {
                version: policy.version.clone(),
                digest: policy_d.clone(),
            },
            severity: DigestRef {
                version: policy.version.clone(),
                digest: policy_d.clone(),
            },
            confidence: DigestRef {
                version: policy.version.clone(),
                digest: policy_d,
            },
        },
        runner: RunnerRef {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            default_mode,
        },
        environment: EnvironmentRef {
            network_mode: "restricted".to_owned(),
            os: None,
            arch: None,
            container_digest: None,
        },
    };
    validate_benchmark_run(&run)?;
    Ok(run)
}

pub fn run_digest(run: &BenchmarkRun) -> Result<String, BenchmarkError> {
    let value = serde_json::to_value(run)
        .map_err(|_| BenchmarkError::Serialization { kind: "run-digest" })?;
    digest_value(&value)
}
