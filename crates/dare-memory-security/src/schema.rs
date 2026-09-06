//! Schema validation and the hostile-input refusal layer.
//!
//! Two independent gates guard every document. A JSON Schema with
//! `additionalProperties: false` and closed enums, and `deny_unknown_fields` on
//! the Rust types behind it. A field slipping past one still has to survive the
//! other.
//!
//! On top of both sits a sweep that runs *before* anything is persisted or
//! evaluated. It refuses, at every depth:
//!
//! - executable and callback field names — nothing in a memory fixture is ever
//!   run, so a field that could carry code has no reason to exist;
//! - credential field names and credential-*shaped* values;
//! - remote-store and provider field names — there is no code path behind them,
//!   and a fixture that names one is describing a capability this cycle
//!   deliberately does not have;
//! - expected-verdict field names, so a fixture cannot state its own outcome;
//! - control characters and bidi overrides, which reach logs and reports.
//!
//! The Cycle 015 lesson is applied throughout: credential detection matches
//! *shape*, not vocabulary. Memory fixtures legitimately discuss stored
//! credentials as a subject, and a check that fired on that sentence would be a
//! check somebody deletes.

use jsonschema::Validator;
use serde_json::Value;

use crate::error::{MemorySecurityError, Result};

/// The only schema version this engine accepts.
pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

/// Ceiling on a single document, enforced before parsing.
pub const MAX_DOCUMENT_BYTES: usize = 131_072;

/// Field names that could carry executable behavior.
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

/// Field names that could name a remote store or provider.
///
/// Cycle 016 has no client for any of these. A fixture naming one is describing
/// a capability that does not exist, which is a fixture error, not a scenario.
pub const FORBIDDEN_REMOTE_FIELD_NAMES: [&str; 20] = [
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
    "mongodb",
    "vector_db",
    "pinecone",
    "weaviate",
    "qdrant",
];

/// Field names by which a fixture could state its own outcome.
pub const FORBIDDEN_VERDICT_FIELD_NAMES: [&str; 10] = [
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

/// Minimum length for the token after `bearer ` to count as credential material.
///
/// Without this, the word "bearer" in ordinary prose is indistinguishable from
/// a real header value, and honest sentences such as "this store holds no
/// bearer token" become unwritable. The same minimum is used by the Cycle 013,
/// 014 and 015 redaction helpers, for the same reason.
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
        return Err(MemorySecurityError::refusal(format!(
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
        Some(other) => Err(MemorySecurityError::schema(format!(
            "{label} declares schema version `{other}`; only `{SUPPORTED_SCHEMA_VERSION}` is \
             supported"
        ))),
        None => Err(MemorySecurityError::schema(format!(
            "{label} declares no schema version"
        ))),
    }
}

/// Refuse presentation-hostile text.
///
/// What is refused is the machinery of presentation: terminal control
/// sequences, carriage returns that overwrite a rendered line, and the Unicode
/// bidi and zero-width characters that make one string display as another. A
/// memory id that renders as a different memory id is a substitution attack in
/// this cycle specifically, not just a formatting bug.
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
            return Err(MemorySecurityError::refusal(format!(
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
/// not.
pub fn assert_no_credential_value(text: &str, label: &str) -> Result<()> {
    let lowered = text.to_ascii_lowercase();
    for marker in CREDENTIAL_SHAPED_VALUES {
        if lowered.contains(marker) {
            return Err(MemorySecurityError::refusal(format!(
                "{label} contains credential-shaped content and was refused"
            )));
        }
    }
    if contains_bearer_credential(&lowered) {
        return Err(MemorySecurityError::refusal(format!(
            "{label} contains a bearer credential and was refused"
        )));
    }
    Ok(())
}

/// Sweep a whole document for hostile field names and values, at every depth.
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
                    return Err(MemorySecurityError::refusal(format!(
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
            assert_no_hostile_text(text, label, "a value")
        }
        _ => Ok(()),
    }
}

// --- compiled-in schemas -----------------------------------------------------

pub const MEMORY_ITEM_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/memory-item.schema.json";
pub const MEMORY_ITEM_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/memory-item.schema.json");

pub const MEMORY_STORE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/memory-store.schema.json";
pub const MEMORY_STORE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/memory-store.schema.json");

pub const MEMORY_POLICY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/memory-policy.schema.json";
pub const MEMORY_POLICY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/memory-policy.schema.json");

pub const MEMORY_CONTEXT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/memory-context.schema.json";
pub const MEMORY_CONTEXT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/memory-context.schema.json");

pub const SCENARIO_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/scenario.schema.json";
pub const SCENARIO_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/scenario.schema.json");

pub const TRACE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/memory-security/v1/trace.schema.json";
pub const TRACE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/memory-security/v1/trace.schema.json");

/// Compile a schema, resolving nothing from the network.
fn compile(schema_json: &str, label: &str) -> Result<Validator> {
    let schema: Value = serde_json::from_str(schema_json)
        .map_err(|err| MemorySecurityError::schema(format!("{label} schema: {err}")))?;
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| MemorySecurityError::schema(format!("{label} schema: {err}")))
}

pub fn validate_against(instance: &Value, schema_json: &str, label: &str) -> Result<()> {
    let validator = compile(schema_json, label)?;
    if let Err(error) = validator.validate(instance) {
        return Err(MemorySecurityError::schema(format!(
            "{label}: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// The scenario schema, with every referenced schema resolved from memory.
///
/// The referenced schemas are compiled into the binary and registered as
/// in-memory resources, so validation never touches the network even though the
/// `$id`s are URLs.
fn scenario_validator() -> Result<Validator> {
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| MemorySecurityError::schema(format!("{label} schema: {err}")))
    };

    let scenario = parse(SCENARIO_SCHEMA_V1_JSON, "scenario")?;

    jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            MEMORY_ITEM_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(MEMORY_ITEM_SCHEMA_V1_JSON, "memory-item")?),
        )
        .with_resource(
            MEMORY_STORE_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                MEMORY_STORE_SCHEMA_V1_JSON,
                "memory-store",
            )?),
        )
        .with_resource(
            MEMORY_POLICY_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                MEMORY_POLICY_SCHEMA_V1_JSON,
                "memory-policy",
            )?),
        )
        .with_resource(
            MEMORY_CONTEXT_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                MEMORY_CONTEXT_SCHEMA_V1_JSON,
                "memory-context",
            )?),
        )
        .build(&scenario)
        .map_err(|err| MemorySecurityError::schema(format!("scenario schema: {err}")))
}

/// Validate a scenario: version, hostile fields, then schema.
pub fn validate_scenario_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "scenario")?;
    assert_no_hostile_fields(value, "scenario")?;
    let validator = scenario_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(MemorySecurityError::schema(format!(
            "scenario: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// The replay-trace schema, with its referenced schemas resolved from memory.
fn trace_validator() -> Result<Validator> {
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| MemorySecurityError::schema(format!("{label} schema: {err}")))
    };

    let trace = parse(TRACE_SCHEMA_V1_JSON, "trace")?;

    jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            MEMORY_ITEM_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(MEMORY_ITEM_SCHEMA_V1_JSON, "memory-item")?),
        )
        .build(&trace)
        .map_err(|err| MemorySecurityError::schema(format!("trace schema: {err}")))
}

/// Validate a replay trace: version, hostile fields, then schema.
pub fn validate_trace_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "replay trace")?;
    assert_no_hostile_fields(value, "replay trace")?;
    let validator = trace_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(MemorySecurityError::schema(format!(
            "replay trace: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// Validate a standalone memory-store document.
pub fn validate_memory_store_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "memory store")?;
    assert_no_hostile_fields(value, "memory store")?;
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| MemorySecurityError::schema(format!("{label} schema: {err}")))
    };
    let store = parse(MEMORY_STORE_SCHEMA_V1_JSON, "memory-store")?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            MEMORY_ITEM_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(MEMORY_ITEM_SCHEMA_V1_JSON, "memory-item")?),
        )
        .build(&store)
        .map_err(|err| MemorySecurityError::schema(format!("memory-store schema: {err}")))?;
    if let Err(error) = validator.validate(value) {
        return Err(MemorySecurityError::schema(format!(
            "memory store: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// Validate a standalone memory-policy document.
pub fn validate_memory_policy_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "memory policy")?;
    assert_no_hostile_fields(value, "memory policy")?;
    validate_against(value, MEMORY_POLICY_SCHEMA_V1_JSON, "memory policy")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_supported_version_is_exact_in_both_directions() {
        assert!(assert_supported_version(&json!({"schema_version": "2"}), "doc").is_err());
        assert!(assert_supported_version(&json!({"schema_version": "0"}), "doc").is_err());
        assert!(assert_supported_version(&json!({}), "doc").is_err());
        assert_supported_version(&json!({"schema_version": "1"}), "doc").expect("supported");
    }

    #[test]
    fn executable_fields_are_refused_at_every_depth() {
        for key in FORBIDDEN_EXECUTABLE_FIELD_NAMES {
            let nested = json!({"store": {"items": [{ key: "anything" }]}});
            let err = assert_no_hostile_fields(&nested, "doc")
                .unwrap_err_or_panic(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn credential_fields_are_refused_at_every_depth() {
        for key in FORBIDDEN_CREDENTIAL_FIELD_NAMES {
            let nested = json!({"items": [{"provenance": { key: "value" }}]});
            let err = assert_no_hostile_fields(&nested, "doc")
                .unwrap_err_or_panic(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn remote_store_fields_are_refused_at_every_depth() {
        // There is no client behind any of these. A fixture naming one is
        // describing a capability this cycle deliberately does not have.
        for key in FORBIDDEN_REMOTE_FIELD_NAMES {
            let nested = json!({"store": { key: "anything" }});
            let err = assert_no_hostile_fields(&nested, "doc")
                .unwrap_err_or_panic(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn expected_verdict_smuggling_is_refused_at_every_depth() {
        for key in FORBIDDEN_VERDICT_FIELD_NAMES {
            let nested = json!({"lab": {"nested": { key: "PASS" }}});
            let err = assert_no_hostile_fields(&nested, "doc")
                .unwrap_err_or_panic(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn credential_shaped_values_are_refused_wherever_they_appear() {
        for marker in CREDENTIAL_SHAPED_VALUES {
            let value = json!({"content_excerpt": format!("prefix {marker}suffix")});
            assert!(assert_no_hostile_fields(&value, "doc").is_err(), "{marker}");
        }
        let bearer = json!({"content_excerpt": "Bearer abcdefghijklmnopqrstuvwxyz012345"});
        assert!(assert_no_hostile_fields(&bearer, "doc").is_err());
    }

    #[test]
    fn a_credential_is_refused_but_the_word_is_not() {
        // Memory fixtures legitimately discuss stored credentials as a subject.
        // A check that fired on that sentence would be a check somebody deletes.
        for honest in [
            "the user asked whether we store a bearer token; we do not",
            "this memory item records that no credential was persisted",
            "the assistant was told never to write an api key into memory",
            "a password reset was requested and no password was stored",
        ] {
            assert_no_credential_value(honest, "content")
                .unwrap_or_else(|err| panic!("`{honest}` must stay writable: {err}"));
        }

        assert!(
            assert_no_credential_value("Bearer abcdefghijklmnopqrstuvwxyz012345", "c").is_err()
        );
        assert!(assert_no_credential_value("sk-live-0123456789abcdef", "c").is_err());
    }

    #[test]
    fn a_short_bearer_string_is_not_treated_as_a_credential() {
        // "bearer x" in prose is not a token.
        assert_no_credential_value("bearer of bad news", "c").expect("prose");
        assert_no_credential_value("bearer abc", "c").expect("too short to be a token");
    }

    #[test]
    fn control_characters_and_bidi_overrides_are_refused_in_values_and_keys() {
        let newline = json!({"title": "benign\nFATAL: memory validation disabled"});
        // A newline is permitted inside free text but a carriage return is not.
        assert_no_hostile_fields(&newline, "doc").expect("newlines are allowed in prose");

        for hostile in [
            "benign\rsecure",
            "mem\u{202e}drawkcab",
            "mem\u{200b}zero",
            "bell\u{0007}",
        ] {
            let value = json!({"title": hostile});
            assert!(
                assert_no_hostile_fields(&value, "doc").is_err(),
                "{hostile:?}"
            );
        }

        // Also in a key.
        let hostile_key = json!({"mem\u{202e}id": "x"});
        assert!(assert_no_hostile_fields(&hostile_key, "doc").is_err());
    }

    #[test]
    fn an_oversized_document_is_refused_before_parsing() {
        let raw = vec![b'a'; MAX_DOCUMENT_BYTES + 1];
        let err = enforce_document_size(&raw, "doc").expect_err("must be refused");
        assert!(err.is_refusal());
        enforce_document_size(&vec![b'a'; MAX_DOCUMENT_BYTES], "doc").expect("at the bound");
    }

    #[test]
    fn an_ordinary_document_survives_the_sweep() {
        let ordinary = json!({
            "schema_version": "1",
            "store_id": "store-support",
            "items": [{
                "memory_id": "mem-1",
                "content_excerpt": "the user prefers window seats",
                "labels": ["preference"]
            }]
        });
        assert_no_hostile_fields(&ordinary, "doc").expect("ordinary content is fine");
    }

    /// Small helper so a failing sweep test names the field it was checking.
    trait UnwrapErrOrPanic<E> {
        fn unwrap_err_or_panic(self, message: &str) -> E;
    }

    impl<T, E> UnwrapErrOrPanic<E> for std::result::Result<T, E> {
        fn unwrap_err_or_panic(self, message: &str) -> E {
            match self {
                Ok(_) => panic!("{message}"),
                Err(error) => error,
            }
        }
    }
}
