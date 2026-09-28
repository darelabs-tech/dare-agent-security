//! Embedded JSON schemas (`schemas/remote-validation/v1`).
//!
//! Every schema is embedded from a directory the Action image's `Dockerfile`
//! copies (BLUEPRINT AD-16). A validation failure reports the instance
//! pointer only, never the value found there.

use jsonschema::Validator;
use serde_json::Value;

use crate::error::{RemoteError, Result};

pub const SCHEMA_ID_PREFIX: &str = "https://darelabs.tech/schemas/remote-validation/v1/";

pub const AUTHORIZATION_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/authorization.schema.json");
pub const PLAN_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/plan.schema.json");
pub const CAPTURE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/capture.schema.json");
pub const AUDIT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/audit.schema.json");
pub const RESULT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/result.schema.json");
pub const CONVERSATION_REQUEST_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/conversation-request.schema.json");
pub const CONVERSATION_RESPONSE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/conversation-response.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Authorization,
    Plan,
    Capture,
    Audit,
    Result,
    ConversationRequest,
    ConversationResponse,
}

impl DocumentKind {
    pub const ALL: [DocumentKind; 7] = [
        Self::Authorization,
        Self::Plan,
        Self::Capture,
        Self::Audit,
        Self::Result,
        Self::ConversationRequest,
        Self::ConversationResponse,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Plan => "plan",
            Self::Capture => "capture",
            Self::Audit => "audit record",
            Self::Result => "result",
            Self::ConversationRequest => "conversation request",
            Self::ConversationResponse => "conversation response",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Authorization => "authorization.schema.json",
            Self::Plan => "plan.schema.json",
            Self::Capture => "capture.schema.json",
            Self::Audit => "audit.schema.json",
            Self::Result => "result.schema.json",
            Self::ConversationRequest => "conversation-request.schema.json",
            Self::ConversationResponse => "conversation-response.schema.json",
        }
    }

    pub fn schema_json(self) -> &'static str {
        match self {
            Self::Authorization => AUTHORIZATION_SCHEMA_V1_JSON,
            Self::Plan => PLAN_SCHEMA_V1_JSON,
            Self::Capture => CAPTURE_SCHEMA_V1_JSON,
            Self::Audit => AUDIT_SCHEMA_V1_JSON,
            Self::Result => RESULT_SCHEMA_V1_JSON,
            Self::ConversationRequest => CONVERSATION_REQUEST_SCHEMA_V1_JSON,
            Self::ConversationResponse => CONVERSATION_RESPONSE_SCHEMA_V1_JSON,
        }
    }
}

fn compile(kind: DocumentKind) -> Result<Validator> {
    let schema: Value = serde_json::from_str(kind.schema_json())
        .map_err(|_| RemoteError::Serialization("embedded schema"))?;
    jsonschema::options()
        .build(&schema)
        .map_err(|_| RemoteError::Serialization("embedded schema"))
}

/// Refuse a document whose `schema_version` is not `"1"`, before anything
/// else looks at it.
pub fn assert_supported_version(value: &Value, kind: DocumentKind) -> Result<()> {
    match value.get("schema_version").and_then(Value::as_str) {
        Some("1") => Ok(()),
        _ => Err(RemoteError::Refused(match kind {
            DocumentKind::Authorization => "authorization schema_version must be \"1\"",
            DocumentKind::Plan => "plan schema_version must be \"1\"",
            DocumentKind::Capture => "capture schema_version must be \"1\"",
            DocumentKind::Audit => "audit schema_version must be \"1\"",
            DocumentKind::Result => "result schema_version must be \"1\"",
            DocumentKind::ConversationRequest | DocumentKind::ConversationResponse => {
                "conversation schema_version must be \"1\""
            }
        })),
    }
}

/// Validate against the embedded schema; report the first failing pointer.
pub fn validate(value: &Value, kind: DocumentKind) -> Result<()> {
    let validator = compile(kind)?;
    let first = validator
        .iter_errors(value)
        .next()
        .map(|error| error.instance_path().to_string());
    match first {
        None => Ok(()),
        Some(pointer) => Err(RemoteError::Schema { pointer }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_schema_compiles_and_self_describes() {
        for kind in DocumentKind::ALL {
            assert!(compile(kind).is_ok(), "{}", kind.label());
            let schema: Value = serde_json::from_str(kind.schema_json()).unwrap();
            assert_eq!(
                schema["$id"],
                format!("{SCHEMA_ID_PREFIX}{}", kind.file_name())
            );
            assert_eq!(schema["additionalProperties"], false, "{}", kind.label());
        }
    }

    #[test]
    fn the_embedded_copies_equal_the_files_on_disk() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/remote-validation/v1");
        for kind in DocumentKind::ALL {
            let on_disk = std::fs::read_to_string(root.join(kind.file_name())).expect("file");
            assert_eq!(on_disk, kind.schema_json(), "{}", kind.label());
        }
    }

    #[test]
    fn a_violation_reports_the_pointer_not_the_value() {
        let value = serde_json::json!({"schema_version": "1", "conversation_id": "c", "turn_index": 99, "principal_id": "p", "content": "x"});
        match validate(&value, DocumentKind::ConversationRequest) {
            Err(RemoteError::Schema { pointer }) => assert_eq!(pointer, "/turn_index"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_request_schema_has_no_field_that_could_reveal_the_test() {
        let schema: Value = serde_json::from_str(CONVERSATION_REQUEST_SCHEMA_V1_JSON).unwrap();
        let fields: Vec<&str> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for leak in [
            "node_id",
            "invariant",
            "canary",
            "expected",
            "verdict",
            "scenario_id",
        ] {
            assert!(!fields.contains(&leak), "{leak}");
        }
    }
}
