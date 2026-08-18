#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use dare_security_evidence::{validate, validate_instance, SecurityEvidence, Verdict};
use serde_json::Value;

pub fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/evidence")
}

pub fn load_json(name: &str) -> Value {
    let path = examples_dir().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!("{} is not valid JSON: {err}", path.display());
    })
}

pub fn load_evidence(name: &str) -> SecurityEvidence {
    serde_json::from_value(load_json(name)).expect("deserialize fixture")
}

pub fn assert_fixture(path: &str, verdict: Verdict) {
    let json = load_json(path);
    validate_instance(&json).expect("json schema");
    let evidence: SecurityEvidence = serde_json::from_value(json).expect("rust model");
    validate(&evidence).expect("semantic");
    assert_eq!(evidence.verdict, verdict);
    assert_eq!(evidence.target.id, "synthetic-payment-mcp");
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn repo_file_exists(relative: impl AsRef<Path>) -> bool {
    repo_root().join(relative).exists()
}
