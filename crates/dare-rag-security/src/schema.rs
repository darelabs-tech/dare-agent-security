//! Schemas and the gates every untrusted document passes before it is read.
//!
//! Documents reaching this engine — scenarios, traces, corpus entries — are
//! authored outside it. They are treated accordingly, and in a deliberate
//! order: size, then version, then a hostile sweep over names *and* values at
//! every depth, then the JSON Schema, then a typed decode with
//! `deny_unknown_fields`, then the structural rules a schema cannot express.
//!
//! The ordering is the point. A JSON Schema validator reports a failure by
//! quoting the value that failed, so letting it see a provider URL or a
//! credential first would print the very thing the refusal exists to suppress
//! into a log line. Cycle 016 shipped exactly that bug; the sweep runs first
//! here because of it.
//!
//! Two gates, not one: the schema and `deny_unknown_fields` check overlapping
//! things by different means. A field that slipped past one is caught by the
//! other, and a schema drifting from its Rust type shows up as a decode failure
//! rather than as a silently ignored field.

use jsonschema::Validator;
use serde_json::Value;

use crate::error::{RagSecurityError, Result};

/// The only schema version this engine implements.
pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

/// Largest document accepted, before parsing.
pub const MAX_DOCUMENT_BYTES: usize = 131_072;

/// Field names that could name something to run.
pub const FORBIDDEN_EXECUTABLE_FIELD_NAMES: [&str; 18] = [
    "shell",
    "sh",
    "bash",
    "cmd",
    "command",
    "exec",
    "execute",
    "eval",
    "script",
    "callback",
    "hook",
    "plugin",
    "run",
    "entrypoint",
    "handler",
    "dispatch",
    "subprocess",
    "spawn",
];

/// Field names that could carry credential material.
pub const FORBIDDEN_CREDENTIAL_FIELD_NAMES: [&str; 22] = [
    "api_key",
    "apikey",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "credential",
    "credentials",
    "authorization",
    "auth_header",
    "private_key",
    "secret_key",
    "bearer",
    "jwt",
    "jwks",
    "cookie",
    "session_token",
    "connection_string",
];

/// Field names that could name a remote store, index or provider.
///
/// Cycle 017 has no client for any of these. A fixture naming one is describing
/// a capability that does not exist, which is a fixture error rather than a
/// scenario. The vector-store names are listed explicitly because this is the
/// cycle where someone would most plausibly reach for them.
pub const FORBIDDEN_REMOTE_FIELD_NAMES: [&str; 28] = [
    "url",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "port",
    "provider",
    "remote",
    "base_url",
    "server_url",
    "webhook",
    "upstream",
    "redis",
    "postgres",
    "postgresql",
    "pgvector",
    "mongodb",
    "vector_db",
    "vectordb",
    "index_url",
    "pinecone",
    "weaviate",
    "qdrant",
    "chroma",
    "milvus",
    "opensearch",
    "elasticsearch",
    "elastic",
];

/// Field names by which a fixture could state its own outcome.
///
/// A fixture that could declare its verdict would reduce the evaluator to
/// agreeing with whoever wrote it.
pub const FORBIDDEN_VERDICT_FIELD_NAMES: [&str; 12] = [
    "verdict",
    "expected",
    "expected_verdict",
    "expected_result",
    "expected_outcome",
    "expected_violation",
    "should_fail",
    "should_pass",
    "is_vulnerable",
    "is_poisoned",
    "is_leaked",
    "is_authorized",
];

/// Substrings that indicate real credential material rather than fixture prose.
pub const CREDENTIAL_SHAPED_VALUES: [&str; 11] = [
    "sk-live-",
    "sk_live_",
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin openssh private key-----",
    "-----begin ec private key-----",
    "aws_secret_access_key",
    "xoxb-",
    "xoxp-",
    "ghp_",
    "eyjhbgci",
];

/// URL schemes that would mean reaching a store or provider.
pub const FORBIDDEN_URL_SCHEMES: [&str; 8] = [
    "http://",
    "https://",
    "redis://",
    "rediss://",
    "postgres://",
    "postgresql://",
    "mongodb://",
    "grpc://",
];

/// Minimum length for the token after `bearer ` to count as credential material.
///
/// Without this, the word "bearer" in ordinary prose is indistinguishable from
/// a real header value, and honest sentences such as "this corpus holds no
/// bearer token" become unwritable. The same minimum is used by the Cycle 013,
/// 014, 015 and 016 redaction helpers, for the same reason.
const MIN_BEARER_TOKEN_LEN: usize = 16;

/// Whether the text carries a `bearer ` followed by something token-shaped.
pub fn contains_bearer_credential(lowered: &str) -> bool {
    const MARKER: &str = "bearer ";
    let mut rest = lowered;
    while let Some(index) = rest.find(MARKER) {
        let after = &rest[index + MARKER.len()..];
        let token: String = after
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .collect();
        if token.len() >= MIN_BEARER_TOKEN_LEN {
            return true;
        }
        rest = &rest[index + MARKER.len()..];
    }
    false
}

/// Refuse a document larger than the approved ceiling, before parsing it.
pub fn enforce_document_size(raw: &[u8], label: &str) -> Result<()> {
    if raw.len() > MAX_DOCUMENT_BYTES {
        return Err(RagSecurityError::refusal(format!(
            "{label} is {} bytes; the ceiling is {MAX_DOCUMENT_BYTES}",
            raw.len()
        )));
    }
    Ok(())
}

/// Require the exact supported schema version.
pub fn assert_supported_version(value: &Value, label: &str) -> Result<()> {
    match value.get("schema_version").and_then(Value::as_str) {
        Some(SUPPORTED_SCHEMA_VERSION) => Ok(()),
        Some(other) => Err(RagSecurityError::schema(format!(
            "{label} declares schema version `{other}`; only `{SUPPORTED_SCHEMA_VERSION}` is \
             supported"
        ))),
        None => Err(RagSecurityError::schema(format!(
            "{label} declares no schema version"
        ))),
    }
}

/// Refuse presentation-hostile text.
///
/// What is refused is the machinery of presentation: terminal control
/// sequences, carriage returns that overwrite a rendered line, and the Unicode
/// bidi and zero-width characters that make one string display as another. A
/// document id that renders as a different document id is a substitution in
/// this cycle specifically, not merely a formatting problem.
pub fn assert_no_hostile_text(text: &str, label: &str, where_found: &str) -> Result<()> {
    for character in text.chars() {
        let refused = match character {
            '\n' | '\t' => false,
            control if control.is_control() => true,
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => true,
            '\u{200b}'..='\u{200d}' | '\u{feff}' => true,
            _ => false,
        };
        if refused {
            return Err(RagSecurityError::refusal(format!(
                "{label} contains a control or direction-override character (U+{:04X}) in \
                 {where_found}; such text can forge a log line or make two identifiers render \
                 identically",
                character as u32
            )));
        }
    }
    Ok(())
}

/// Refuse a value that carries credential material.
///
/// Anchored on shape. Prose about credentials stays writable; a credential does
/// not. A check that fires on the word "token" is a check someone deletes the
/// first time they need to document the boundary.
pub fn assert_no_credential_value(text: &str, label: &str) -> Result<()> {
    let lowered = text.to_ascii_lowercase();
    for marker in CREDENTIAL_SHAPED_VALUES {
        if lowered.contains(marker) {
            return Err(RagSecurityError::refusal(format!(
                "{label} contains credential-shaped content and was refused"
            )));
        }
    }
    if contains_bearer_credential(&lowered) {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a bearer credential and was refused"
        )));
    }
    Ok(())
}

/// Refuse a value that names something fetchable.
///
/// The message names the *category*, never the endpoint. Echoing the URL back
/// would put an operator one copy-paste away from the store this cycle exists
/// not to reach.
pub fn assert_no_remote_target(text: &str, label: &str) -> Result<()> {
    let lowered = text.to_ascii_lowercase();
    for scheme in FORBIDDEN_URL_SCHEMES {
        if lowered.contains(scheme) {
            return Err(RagSecurityError::refusal(format!(
                "{label} names a remote target and was refused"
            )));
        }
    }
    Ok(())
}

/// Sweep a whole document for hostile field names and values, at every depth.
///
/// Names *and* values: a `provider_url` field is caught by its name, and a URL
/// hiding in a `title` is caught by its shape. Checking only names was a
/// Cycle 015 lesson learned the hard way.
pub fn assert_no_hostile_fields(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                let banned = FORBIDDEN_EXECUTABLE_FIELD_NAMES
                    .iter()
                    .chain(FORBIDDEN_CREDENTIAL_FIELD_NAMES.iter())
                    .chain(FORBIDDEN_REMOTE_FIELD_NAMES.iter())
                    .chain(FORBIDDEN_VERDICT_FIELD_NAMES.iter())
                    .any(|forbidden| *forbidden == lowered);
                if banned {
                    return Err(RagSecurityError::refusal(format!(
                        "{label} carries the forbidden field `{key}`"
                    )));
                }
                assert_no_hostile_text(key, label, "a field name")?;
                assert_no_hostile_fields(child, label)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                assert_no_hostile_fields(item, label)?;
            }
            Ok(())
        }
        Value::String(text) => {
            assert_no_credential_value(text, label)?;
            assert_no_remote_target(text, label)?;
            assert_no_hostile_text(text, label, "a value")
        }
        _ => Ok(()),
    }
}

// --- compiled-in schemas -----------------------------------------------------
//
// Compiled in with `include_str!` rather than read from disk. A schema loaded at
// runtime is a schema that can be swapped; one compiled into the binary cannot
// be, and `$ref` resolution below is done from memory so nothing is ever
// fetched.

pub const DOCUMENT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/document.schema.json";
pub const DOCUMENT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/document.schema.json");

pub const DOCUMENT_STORE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/document-store.schema.json";
pub const DOCUMENT_STORE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/document-store.schema.json");

pub const RETRIEVAL_POLICY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/retrieval-policy.schema.json";
pub const RETRIEVAL_POLICY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/retrieval-policy.schema.json");

pub const RETRIEVAL_CONTEXT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/retrieval-context.schema.json";
pub const RETRIEVAL_CONTEXT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/retrieval-context.schema.json");

pub const SCENARIO_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/scenario.schema.json";
pub const SCENARIO_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/scenario.schema.json");

pub const TRACE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/trace.schema.json";
pub const TRACE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/trace.schema.json");

pub const CORPUS_ENTRY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/corpus-entry.schema.json";
pub const CORPUS_ENTRY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/corpus-entry.schema.json");

pub const CORPUS_REGISTRY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/rag-security/v1/corpus-registry.schema.json";
pub const CORPUS_REGISTRY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/rag-security/v1/corpus-registry.schema.json");

fn compile(schema_json: &str, label: &str) -> Result<Validator> {
    let schema: Value = serde_json::from_str(schema_json)
        .map_err(|err| RagSecurityError::schema(format!("{label} schema: {err}")))?;
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| RagSecurityError::schema(format!("{label} schema: {err}")))
}

/// Validate an instance against a compiled-in schema.
pub fn validate_against(instance: &Value, schema_json: &str, label: &str) -> Result<()> {
    let validator = compile(schema_json, label)?;
    if let Err(error) = validator.validate(instance) {
        return Err(RagSecurityError::schema(format!(
            "{label}: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// The scenario schema, with its referenced schemas resolved from memory.
///
/// Resources are registered from compiled-in strings, so `$ref` resolution
/// never touches the network or the filesystem.
fn scenario_validator() -> Result<Validator> {
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| RagSecurityError::schema(format!("{label} schema: {err}")))
    };

    let scenario = parse(SCENARIO_SCHEMA_V1_JSON, "scenario")?;

    jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            DOCUMENT_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(DOCUMENT_SCHEMA_V1_JSON, "document")?),
        )
        .with_resource(
            DOCUMENT_STORE_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                DOCUMENT_STORE_SCHEMA_V1_JSON,
                "document store",
            )?),
        )
        .with_resource(
            RETRIEVAL_POLICY_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                RETRIEVAL_POLICY_SCHEMA_V1_JSON,
                "retrieval policy",
            )?),
        )
        .with_resource(
            RETRIEVAL_CONTEXT_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                RETRIEVAL_CONTEXT_SCHEMA_V1_JSON,
                "retrieval context",
            )?),
        )
        .build(&scenario)
        .map_err(|err| RagSecurityError::schema(format!("scenario schema: {err}")))
}

/// Validate a scenario document: version, hostile sweep, then schema.
pub fn validate_scenario_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "scenario")?;
    assert_no_hostile_fields(value, "scenario")?;
    let validator = scenario_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(RagSecurityError::schema(format!(
            "scenario: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// The replay-trace schema, with its referenced schemas resolved from memory.
fn trace_validator() -> Result<Validator> {
    let trace: Value = serde_json::from_str(TRACE_SCHEMA_V1_JSON)
        .map_err(|err| RagSecurityError::schema(format!("trace schema: {err}")))?;
    jsonschema::options()
        .should_validate_formats(true)
        .build(&trace)
        .map_err(|err| RagSecurityError::schema(format!("trace schema: {err}")))
}

/// Validate a replay trace: version, hostile sweep, then schema.
pub fn validate_trace_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "replay trace")?;
    assert_no_hostile_fields(value, "replay trace")?;
    let validator = trace_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(RagSecurityError::schema(format!(
            "replay trace: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

pub fn validate_document_store_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "document store")?;
    assert_no_hostile_fields(value, "document store")?;
    validate_against(value, DOCUMENT_STORE_SCHEMA_V1_JSON, "document store")
}

pub fn validate_retrieval_policy_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "retrieval policy")?;
    assert_no_hostile_fields(value, "retrieval policy")?;
    validate_against(value, RETRIEVAL_POLICY_SCHEMA_V1_JSON, "retrieval policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_compiled_schema_compiles() {
        for (json, label) in [
            (DOCUMENT_SCHEMA_V1_JSON, "document"),
            (DOCUMENT_STORE_SCHEMA_V1_JSON, "document store"),
            (RETRIEVAL_POLICY_SCHEMA_V1_JSON, "retrieval policy"),
            (RETRIEVAL_CONTEXT_SCHEMA_V1_JSON, "retrieval context"),
            (CORPUS_ENTRY_SCHEMA_V1_JSON, "corpus entry"),
            (CORPUS_REGISTRY_SCHEMA_V1_JSON, "corpus registry"),
        ] {
            compile(json, label).unwrap_or_else(|err| panic!("{label}: {err}"));
        }
        scenario_validator().expect("scenario schema compiles with its references");
        trace_validator().expect("trace schema compiles");
    }

    #[test]
    fn an_executable_field_is_refused_at_any_depth() {
        for document in [
            json!({"schema_version": "1", "command": "rm -rf /"}),
            json!({"schema_version": "1", "store": {"callback": "reindex"}}),
            json!({"schema_version": "1", "documents": [{"eval": "retrieve()"}]}),
            json!({"schema_version": "1", "a": {"b": {"c": {"shell": "sh"}}}}),
        ] {
            let err = assert_no_hostile_fields(&document, "test").expect_err("must be refused");
            assert!(err.is_refusal());
        }
    }

    #[test]
    fn every_vector_store_name_is_refused_as_a_field() {
        // This is the cycle where someone would most plausibly reach for one.
        for store in [
            "pinecone",
            "weaviate",
            "qdrant",
            "chroma",
            "milvus",
            "opensearch",
            "elasticsearch",
            "pgvector",
            "vector_db",
            "index_url",
        ] {
            let document = json!({"schema_version": "1", store: "anything"});
            assert!(
                assert_no_hostile_fields(&document, "test").is_err(),
                "`{store}` was accepted as a field name"
            );
        }
    }

    #[test]
    fn a_remote_target_is_refused_by_value_even_in_an_allowed_field() {
        // The field name is not what makes it dangerous. A URL hiding in a
        // title is still a URL.
        for url in [
            "https://index.example.invalid",
            "http://localhost:9200",
            "redis://localhost:6379",
            "postgresql://user@db/vectors",
            "mongodb://host/db",
        ] {
            let document = json!({"schema_version": "1", "title": url});
            let err = assert_no_hostile_fields(&document, "test").expect_err("must be refused");
            assert!(err.is_refusal());
            // And the refusal must not repeat the endpoint back.
            assert!(!err.to_string().contains("example.invalid"));
            assert!(!err.to_string().contains("localhost"));
        }
    }

    #[test]
    fn a_verdict_field_is_refused() {
        for field in [
            "verdict",
            "expected_verdict",
            "should_pass",
            "should_fail",
            "is_leaked",
            "is_authorized",
        ] {
            let document = json!({"schema_version": "1", field: "PASS"});
            assert!(
                assert_no_hostile_fields(&document, "test").is_err(),
                "`{field}` was accepted"
            );
        }
    }

    #[test]
    fn a_credential_shaped_value_is_refused_wherever_it_appears() {
        for value in [
            "sk-live-000000000000000000000000",
            "-----BEGIN PRIVATE KEY-----",
            "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb",
            "Authorization: Bearer aaaaaaaaaaaaaaaaaaaa",
        ] {
            let document = json!({"schema_version": "1", "title": value});
            let err = assert_no_hostile_fields(&document, "test").expect_err("must be refused");
            assert!(err.is_refusal());
            // The refusal names the category and not the secret.
            assert!(!err.to_string().contains("sk-live-"));
        }
    }

    #[test]
    fn prose_about_credentials_stays_writable() {
        // A check that fires on the vocabulary is a check someone deletes the
        // first time they document the boundary it protects.
        for prose in [
            "this corpus holds no bearer token",
            "a document containing an api key must not be returned",
            "the retriever never sees a password",
        ] {
            let document = json!({"schema_version": "1", "title": prose});
            assert_no_hostile_fields(&document, "test")
                .unwrap_or_else(|err| panic!("`{prose}` was refused: {err}"));
        }
    }

    #[test]
    fn a_short_bearer_like_string_is_not_treated_as_a_credential() {
        assert!(!contains_bearer_credential("bearer of bad news"));
        assert!(!contains_bearer_credential("bearer short"));
        assert!(contains_bearer_credential(
            "bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn hostile_presentation_text_is_refused() {
        for hostile in [
            "document\u{202e}reversed",
            "document\u{200b}hidden",
            "document\u{feff}bom",
            "document\u{7}bell",
            "document\rrewritten",
        ] {
            let document = json!({"schema_version": "1", "title": hostile});
            assert!(
                assert_no_hostile_fields(&document, "test").is_err(),
                "{} was accepted",
                hostile.escape_debug()
            );
        }
    }

    #[test]
    fn a_newline_stays_allowed_in_free_form_text() {
        // Prose fields legitimately wrap. Identifier-level single-line checks
        // live in `canonical::assert_safe_identifier`, where they belong.
        let document = json!({"schema_version": "1", "note": "first line\nsecond line"});
        assert_no_hostile_fields(&document, "test").expect("a newline in prose is allowed");
    }

    #[test]
    fn an_unsupported_or_missing_version_is_refused() {
        assert!(assert_supported_version(&json!({"schema_version": "2"}), "test").is_err());
        assert!(assert_supported_version(&json!({"schema_version": "0"}), "test").is_err());
        assert!(assert_supported_version(&json!({}), "test").is_err());
        assert_supported_version(&json!({"schema_version": "1"}), "test").expect("supported");
    }

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        let raw = vec![b'a'; MAX_DOCUMENT_BYTES + 1];
        let err = enforce_document_size(&raw, "test").expect_err("must be refused");
        assert!(err.is_refusal());
        enforce_document_size(&vec![b'a'; MAX_DOCUMENT_BYTES], "test").expect("at the bound");
    }

    #[test]
    fn the_forbidden_lists_have_no_duplicates() {
        // A duplicate entry is harmless but signals a list edited twice, which
        // is usually a sign one of the edits was meant to be something else.
        for list in [
            FORBIDDEN_EXECUTABLE_FIELD_NAMES.to_vec(),
            FORBIDDEN_CREDENTIAL_FIELD_NAMES.to_vec(),
            FORBIDDEN_REMOTE_FIELD_NAMES.to_vec(),
            FORBIDDEN_VERDICT_FIELD_NAMES.to_vec(),
        ] {
            let unique: std::collections::BTreeSet<&&str> = list.iter().collect();
            assert_eq!(unique.len(), list.len());
        }
    }
}
