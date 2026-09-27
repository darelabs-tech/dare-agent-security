//! Compiled-in JSON Schemas and validation against them.
//!
//! The schemas under `schemas/multi-turn-security/v1/` are embedded with
//! `include_str!`. `schemas/` is one of the directories the Action image's
//! `Dockerfile` copies (Blueprint AD-10), so embedding from here cannot break the
//! image build. Each schema is self-contained: no `$ref` leaves its own file,
//! so validation resolves nothing from anywhere, even though the `$id`s are URLs.

use jsonschema::Validator;
use serde_json::Value;

use crate::error::{MultiTurnError, Result};

/// The only schema version this engine accepts.
pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

pub const SCENARIO_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/multi-turn-security/v1/scenario.schema.json");
pub const STRATEGY_GRAPH_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/multi-turn-security/v1/strategy-graph.schema.json");
pub const TRANSCRIPT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/multi-turn-security/v1/transcript.schema.json");
pub const RESULT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/multi-turn-security/v1/result.schema.json");

/// The documents this engine reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Scenario,
    StrategyGraph,
    Transcript,
    Result,
}

impl DocumentKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Scenario => "scenario",
            Self::StrategyGraph => "strategy graph",
            Self::Transcript => "transcript",
            Self::Result => "result",
        }
    }

    pub fn schema_json(self) -> &'static str {
        match self {
            Self::Scenario => SCENARIO_SCHEMA_V1_JSON,
            Self::StrategyGraph => STRATEGY_GRAPH_SCHEMA_V1_JSON,
            Self::Transcript => TRANSCRIPT_SCHEMA_V1_JSON,
            Self::Result => RESULT_SCHEMA_V1_JSON,
        }
    }
}

fn compile(kind: DocumentKind) -> Result<Validator> {
    let schema: Value = serde_json::from_str(kind.schema_json())
        .map_err(|_| MultiTurnError::Schema(format!("{} schema is not JSON", kind.label())))?;
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|_| MultiTurnError::Schema(format!("{} schema does not compile", kind.label())))
}

/// Validate `instance` against the schema for `kind`.
///
/// The error names the failing location (a JSON pointer built from schema
/// keys and array indices), never the offending value.
pub fn validate(instance: &Value, kind: DocumentKind) -> Result<()> {
    let validator = compile(kind)?;
    match validator.validate(instance) {
        Ok(()) => Ok(()),
        Err(error) => Err(MultiTurnError::Schema(format!(
            "{} does not match its schema at `{}`",
            kind.label(),
            error.instance_path()
        ))),
    }
}

/// Require the exact supported schema version.
pub fn assert_supported_version(value: &Value, kind: DocumentKind) -> Result<()> {
    match value.get("schema_version").and_then(Value::as_str) {
        Some(SUPPORTED_SCHEMA_VERSION) => Ok(()),
        Some(_) => Err(MultiTurnError::Schema(format!(
            "unsupported {} schema_version",
            kind.label()
        ))),
        None => Err(MultiTurnError::Schema(format!(
            "{} has no schema_version",
            kind.label()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [DocumentKind; 4] = [
        DocumentKind::Scenario,
        DocumentKind::StrategyGraph,
        DocumentKind::Transcript,
        DocumentKind::Result,
    ];

    #[test]
    fn every_embedded_schema_compiles_and_self_describes() {
        for kind in ALL {
            let schema: Value = serde_json::from_str(kind.schema_json()).expect("json");
            assert!(compile(kind).is_ok(), "{} schema compiles", kind.label());
            assert_eq!(schema["additionalProperties"], Value::Bool(false));
            assert!(schema["$id"].as_str().is_some_and(
                |id| id.starts_with("https://darelabs.tech/schemas/multi-turn-security/v1/")
            ));
        }
    }

    #[test]
    fn the_embedded_copies_equal_the_files_on_disk() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/multi-turn-security/v1/"
        );
        for (kind, file) in [
            (DocumentKind::Scenario, "scenario.schema.json"),
            (DocumentKind::StrategyGraph, "strategy-graph.schema.json"),
            (DocumentKind::Transcript, "transcript.schema.json"),
            (DocumentKind::Result, "result.schema.json"),
        ] {
            let on_disk = std::fs::read_to_string(format!("{dir}{file}")).expect("readable");
            assert_eq!(on_disk, kind.schema_json(), "{file}");
        }
    }

    #[test]
    fn no_schema_reaches_outside_its_own_file() {
        for kind in ALL {
            for (index, _) in kind.schema_json().match_indices("\"$ref\"") {
                let after = &kind.schema_json()[index..];
                assert!(
                    after.contains("\"#/$defs/"),
                    "{}: $ref must be local",
                    kind.label()
                );
                let target = after.split('"').nth(3).unwrap_or_default();
                assert!(
                    target.starts_with("#/$defs/"),
                    "{}: `{target}`",
                    kind.label()
                );
            }
        }
    }

    #[test]
    fn the_graph_schema_has_no_generation_field_and_no_unclassifiable_edge() {
        let schema = STRATEGY_GRAPH_SCHEMA_V1_JSON;
        for word in [
            "generate",
            "mutate",
            "template",
            "paraphrase",
            "seed",
            "temperature",
            "model",
        ] {
            assert!(
                !schema.contains(&format!("\"{word}\"")),
                "`{word}` must not be a field"
            );
        }
        let graph: Value = serde_json::from_str(schema).expect("json");
        let edge_classes = &graph["properties"]["edges"]["items"]["properties"]["on"]["enum"];
        assert!(!edge_classes
            .as_array()
            .expect("enum")
            .contains(&Value::from("UNCLASSIFIABLE")));
    }

    #[test]
    fn an_unknown_field_is_rejected_and_the_value_is_not_echoed() {
        let doc = serde_json::json!({
            "schema_version": "1", "id": "g", "root": "n1",
            "nodes": [], "edges": [], "extra": "SENSITIVE-VALUE"
        });
        let error = validate(&doc, DocumentKind::StrategyGraph).expect_err("rejected");
        assert!(!error.to_string().contains("SENSITIVE-VALUE"));
    }

    #[test]
    fn versions_other_than_one_are_refused() {
        for doc in [
            serde_json::json!({"schema_version": "2"}),
            serde_json::json!({}),
        ] {
            assert!(matches!(
                assert_supported_version(&doc, DocumentKind::Scenario),
                Err(MultiTurnError::Schema(_))
            ));
        }
        assert!(assert_supported_version(
            &serde_json::json!({"schema_version": "1"}),
            DocumentKind::Scenario
        )
        .is_ok());
    }
}
