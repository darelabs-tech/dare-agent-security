//! Compiled-in schemas and the hostile-input sweep.
//!
//! Three gates run before anything reaches an evaluator, in this order:
//!
//! 1. a size bound, so an oversized document is refused before it is parsed;
//! 2. the **hostile sweep**, so a credential or a remote endpoint is refused
//!    before a validator can quote it back into an error message;
//! 3. the JSON Schema, and then a typed decode with `deny_unknown_fields`.
//!
//! The order matters. A validator that reported "unexpected field
//! `access_token` with value ..." would persist the credential it was refusing.
//! The sweep runs first and its messages never echo what they found.
//!
//! Schemas are compiled into the binary and resolved locally. The `$id` values
//! are identifiers for contracts, not addresses; nothing is ever fetched.

use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

use crate::error::{McpAuthSecurityError, Result};

pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

/// Largest document the engine will parse.
pub const MAX_DOCUMENT_BYTES: usize = 131_072;

pub const SCENARIO_SCHEMA_JSON: &str =
    include_str!("../../../schemas/mcp-auth-security/v1/scenario.schema.json");
pub const TRACE_SCHEMA_JSON: &str =
    include_str!("../../../schemas/mcp-auth-security/v1/trace.schema.json");
pub const CORPUS_ENTRY_SCHEMA_JSON: &str =
    include_str!("../../../schemas/mcp-auth-security/v1/corpus-entry.schema.json");
pub const CORPUS_REGISTRY_SCHEMA_JSON: &str =
    include_str!("../../../schemas/mcp-auth-security/v1/corpus-registry.schema.json");

/// Field names that would carry a credential.
///
/// Matched on the *name*, at any depth, because the value is the thing that
/// must never be read. A field called `access_token` is refused whether it
/// holds a real token, a placeholder or an empty string: the schema is what is
/// wrong, and admitting the empty case would leave the field available.
const FORBIDDEN_CREDENTIAL_FIELDS: [&str; 26] = [
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "bearer",
    "bearer_token",
    "authorization",
    "authorization_header",
    "authorization_code",
    "code_verifier",
    "client_secret",
    "clientsecret",
    "private_key",
    "privatekey",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "password",
    "passphrase",
    "cookie",
    "set_cookie",
    "session_token",
    "credentials",
    "jwk",
];

/// Field names that would make something executable or callable.
const FORBIDDEN_EXECUTABLE_FIELDS: [&str; 16] = [
    "command",
    "cmd",
    "exec",
    "execute",
    "eval",
    "script",
    "shell",
    "callback",
    "callback_url",
    "webhook",
    "webhook_url",
    "hook",
    "on_success",
    "on_failure",
    "entrypoint",
    "run",
];

/// Field names that would name something to contact.
const FORBIDDEN_REMOTE_FIELDS: [&str; 22] = [
    "url",
    "uri",
    "endpoint",
    "endpoint_url",
    "base_url",
    "host",
    "hostname",
    "port",
    "authorization_server_url",
    "token_endpoint_url",
    "jwks_uri",
    "jwks_url",
    "introspection_endpoint",
    "revocation_endpoint",
    "registration_endpoint",
    "discovery_url",
    "issuer_url",
    "metadata_url",
    "well_known",
    "proxy",
    "remote",
    "connection_string",
];

/// Field names that would let a fixture state its own verdict.
const FORBIDDEN_VERDICT_FIELDS: [&str; 12] = [
    "verdict",
    "expected_verdict",
    "expected_result",
    "expected_outcome",
    "expected",
    "should_pass",
    "should_fail",
    "is_vulnerable",
    "is_secure",
    "outcome",
    "result",
    "assertion",
];

/// Value shapes that look like real credential material.
///
/// Anchored on shape rather than on a word, so prose about credentials stays
/// writable while an actual one does not. "a bearer token must not be
/// forwarded" is a sentence; `Bearer eyJhbGciOi...` is a secret.
/// Every entry is lowercase because the sweep compares against a lowercased
/// value. A marker carrying capitals would never match, and the sweep would
/// silently allow exactly the values it was written to refuse.
const CREDENTIAL_SHAPED_VALUES: [&str; 12] = [
    "eyjhbgci",
    "sk-live-",
    "sk_live_",
    "-----begin",
    "ghp_",
    "gho_",
    "xoxb-",
    "xoxp-",
    "aiza",
    "akia",
    "ya29.",
    "asia",
];

/// URL schemes that would make a value reachable.
const FORBIDDEN_URL_SCHEMES: [&str; 9] = [
    "http://", "https://", "ws://", "wss://", "ftp://", "file://", "data:", "mailto:", "ldap://",
];

fn validator(json: &str, label: &str) -> Result<Validator> {
    let schema: Value = serde_json::from_str(json)
        .map_err(|err| McpAuthSecurityError::schema(format!("{label} schema is invalid: {err}")))?;
    jsonschema::validator_for(&schema).map_err(|err| {
        McpAuthSecurityError::schema(format!("{label} schema failed to compile: {err}"))
    })
}

macro_rules! cached_validator {
    ($name:ident, $json:expr, $label:expr) => {
        fn $name() -> Result<&'static Validator> {
            static CELL: OnceLock<std::result::Result<Validator, String>> = OnceLock::new();
            match CELL.get_or_init(|| validator($json, $label).map_err(|err| err.to_string())) {
                Ok(validator) => Ok(validator),
                Err(reason) => Err(McpAuthSecurityError::schema(reason.clone())),
            }
        }
    };
}

cached_validator!(scenario_validator, SCENARIO_SCHEMA_JSON, "scenario");
cached_validator!(trace_validator, TRACE_SCHEMA_JSON, "trace");
cached_validator!(
    corpus_entry_validator,
    CORPUS_ENTRY_SCHEMA_JSON,
    "corpus entry"
);
cached_validator!(
    corpus_registry_validator,
    CORPUS_REGISTRY_SCHEMA_JSON,
    "corpus registry"
);

/// Refuse a document larger than the bound, before it is parsed.
pub fn enforce_document_size(raw: &[u8], label: &str) -> Result<()> {
    if raw.len() > MAX_DOCUMENT_BYTES {
        return Err(McpAuthSecurityError::BudgetExhausted(format!(
            "{label} is {} bytes; the maximum is {MAX_DOCUMENT_BYTES}",
            raw.len()
        )));
    }
    Ok(())
}

/// Refuse an unsupported or missing schema version.
pub fn assert_supported_version(value: &Value, label: &str) -> Result<()> {
    match value.get("schema_version").and_then(Value::as_str) {
        Some(SUPPORTED_SCHEMA_VERSION) => Ok(()),
        Some(_) => Err(McpAuthSecurityError::schema(format!(
            "{label} declares an unsupported schema version"
        ))),
        None => Err(McpAuthSecurityError::schema(format!(
            "{label} declares no schema version"
        ))),
    }
}

/// Whether a lowercased string carries a bearer-shaped credential.
///
/// Shape, not vocabulary: a long opaque run after the word is what makes it a
/// credential rather than a sentence about one.
pub fn contains_bearer_credential(lowered: &str) -> bool {
    let mut from = 0usize;
    while let Some(offset) = lowered[from..].find("bearer ") {
        let index = from + offset + "bearer ".len();
        let rest = &lowered[index..];
        let token: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .collect();
        if token.len() >= 20 {
            return true;
        }
        from = index;
    }
    false
}

/// The full hostile sweep over a parsed document.
pub fn assert_no_hostile_fields(value: &Value, label: &str) -> Result<()> {
    sweep(value, label, 0)
}

fn sweep(value: &Value, label: &str, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(McpAuthSecurityError::refusal(format!(
            "{label} nests deeper than the engine will read"
        )));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                assert_field_name_allowed(&lowered, label)?;
                sweep(child, label, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                sweep(item, label, depth + 1)?;
            }
            Ok(())
        }
        Value::String(text) => assert_value_allowed(text, label),
        _ => Ok(()),
    }
}

fn assert_field_name_allowed(lowered: &str, label: &str) -> Result<()> {
    for forbidden in FORBIDDEN_CREDENTIAL_FIELDS {
        if lowered == forbidden {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} declares a credential-bearing field; Cycle 018 stores no credential \
                 material of any kind"
            )));
        }
    }
    for forbidden in FORBIDDEN_EXECUTABLE_FIELDS {
        if lowered == forbidden {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} declares an executable or callback field; there is no code path that \
                 would run one"
            )));
        }
    }
    for forbidden in FORBIDDEN_REMOTE_FIELDS {
        if lowered == forbidden {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} declares a field naming something to contact; Cycle 018 identifiers are \
                 synthetic identities, never addresses"
            )));
        }
    }
    for forbidden in FORBIDDEN_VERDICT_FIELDS {
        if lowered == forbidden {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} declares a verdict-bearing field; a fixture that states its own outcome \
                 reduces the evaluator to agreeing with it"
            )));
        }
    }
    Ok(())
}

fn assert_value_allowed(text: &str, label: &str) -> Result<()> {
    // Newline, tab and carriage return stay allowed: prose fields are
    // sentences, and refusing a newline would be refusing documentation.
    // Every other control character is refused wherever it appears - none is
    // ever legitimate, and they are what forges a log line or truncates a
    // terminal. Catching them here means the refusal comes from a message
    // this crate controls rather than from a schema error.
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r')
    {
        return Err(McpAuthSecurityError::refusal(format!(
            "{label} carries a control character, which could forge a log line"
        )));
    }
    let lowered = text.to_ascii_lowercase();
    for marker in CREDENTIAL_SHAPED_VALUES {
        if lowered.contains(marker) {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} carries a value shaped like real credential material"
            )));
        }
    }
    if contains_bearer_credential(&lowered) {
        return Err(McpAuthSecurityError::refusal(format!(
            "{label} carries a bearer-shaped credential value"
        )));
    }
    for scheme in FORBIDDEN_URL_SCHEMES {
        if lowered.contains(scheme) {
            return Err(McpAuthSecurityError::refusal(format!(
                "{label} names a reachable target; Cycle 018 contacts nothing"
            )));
        }
    }
    Ok(())
}

fn validate_against(instance: &Value, validator: &Validator, label: &str) -> Result<()> {
    if let Err(error) = validator.validate(instance) {
        // Only the path, never the value. A `ValidationError`'s Display embeds
        // the offending instance, so formatting it here would put a smuggled
        // token or a spoofed identifier straight into an error log — the same
        // failure the hostile sweep runs first to avoid. The path is what an
        // operator needs; the value is already in their own document.
        return Err(McpAuthSecurityError::schema(format!(
            "{label} failed schema validation at `{}`",
            error.instance_path()
        )));
    }
    Ok(())
}

/// Admit a scenario document: size, version, hostile sweep, then schema.
pub fn validate_scenario_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "scenario")?;
    assert_no_hostile_fields(value, "scenario")?;
    validate_against(value, scenario_validator()?, "scenario")
}

pub fn validate_trace_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "trace")?;
    assert_no_hostile_fields(value, "trace")?;
    validate_against(value, trace_validator()?, "trace")
}

pub fn validate_corpus_entry(value: &Value) -> Result<()> {
    assert_supported_version(value, "corpus entry")?;
    assert_no_hostile_fields(value, "corpus entry")?;
    validate_against(value, corpus_entry_validator()?, "corpus entry")
}

pub fn validate_corpus_registry(value: &Value) -> Result<()> {
    assert_supported_version(value, "corpus registry")?;
    assert_no_hostile_fields(value, "corpus registry")?;
    validate_against(value, corpus_registry_validator()?, "corpus registry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_compiled_schema_compiles() {
        scenario_validator().expect("scenario");
        trace_validator().expect("trace");
        corpus_entry_validator().expect("corpus entry");
        corpus_registry_validator().expect("corpus registry");
    }

    #[test]
    fn every_credential_marker_is_lowercase() {
        // The sweep lowercases the value before comparing. A marker with a
        // capital in it can never match, which is how `eyJhbGci` was silently
        // allowed before this was caught.
        for marker in CREDENTIAL_SHAPED_VALUES {
            assert_eq!(
                marker,
                marker.to_ascii_lowercase(),
                "`{marker}` can never match a lowercased value"
            );
        }
    }

    #[test]
    fn the_forbidden_lists_have_no_duplicates() {
        // A duplicate is dead weight and usually means an entry was pasted
        // instead of added.
        for list in [
            &FORBIDDEN_CREDENTIAL_FIELDS[..],
            &FORBIDDEN_EXECUTABLE_FIELDS[..],
            &FORBIDDEN_REMOTE_FIELDS[..],
            &FORBIDDEN_VERDICT_FIELDS[..],
        ] {
            let unique: std::collections::BTreeSet<&&str> = list.iter().collect();
            assert_eq!(unique.len(), list.len());
        }
    }

    #[test]
    fn a_credential_field_is_refused_at_any_depth() {
        for field in [
            "access_token",
            "refresh_token",
            "client_secret",
            "private_key",
            "cookie",
            "authorization",
            "code_verifier",
        ] {
            let hostile = json!({ "a": { "b": { field: "anything" } } });
            let err = assert_no_hostile_fields(&hostile, "test")
                .expect_err("a credential-bearing field must be refused");
            assert!(err.is_refusal(), "`{field}` produced {err}");
        }
    }

    #[test]
    fn a_credential_field_is_refused_even_when_empty() {
        // The field is what is wrong. Admitting the empty case would leave it
        // available for the next author to fill in.
        let hostile = json!({ "access_token": "" });
        assert!(assert_no_hostile_fields(&hostile, "test").is_err());
    }

    #[test]
    fn an_executable_or_remote_field_is_refused() {
        for field in ["command", "callback_url", "jwks_uri", "token_endpoint_url"] {
            let hostile = json!({ field: "x" });
            assert!(
                assert_no_hostile_fields(&hostile, "test").is_err(),
                "`{field}` was allowed"
            );
        }
    }

    #[test]
    fn a_verdict_field_is_refused() {
        for field in ["expected_verdict", "should_fail", "is_vulnerable"] {
            let hostile = json!({ field: "PASS" });
            assert!(
                assert_no_hostile_fields(&hostile, "test").is_err(),
                "`{field}` was allowed"
            );
        }
    }

    #[test]
    fn a_credential_shaped_value_is_refused_wherever_it_appears() {
        for value in [
            "eyJhbGciOiJIUzI1NiJ9.e30.sig",
            "sk-live-000000000000000000",
            "-----BEGIN PRIVATE KEY-----",
            "ghp_abcdefghijklmnopqrst",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            let hostile = json!({ "note": value });
            assert!(
                assert_no_hostile_fields(&hostile, "test").is_err(),
                "`{value}` was allowed"
            );
        }
    }

    #[test]
    fn prose_about_credentials_stays_writable() {
        // The engine's own documentation, corpus notes and refusal messages all
        // talk about bearer tokens and client secrets. A check that fired on
        // the words would ban the sentences that document the boundary.
        for honest in [
            "an inbound bearer token must not be forwarded upstream",
            "the client secret is never stored by this engine",
            "a refresh token would be a credential and is refused",
            "authorization server metadata is evidence, not trust",
        ] {
            let value = json!({ "surface_note": honest });
            assert_no_hostile_fields(&value, "test")
                .unwrap_or_else(|err| panic!("`{honest}` refused: {err}"));
        }
    }

    #[test]
    fn a_short_bearer_like_string_is_not_treated_as_a_credential() {
        assert!(!contains_bearer_credential("bearer token"));
        assert!(!contains_bearer_credential("bearer abc"));
        assert!(contains_bearer_credential(
            "bearer abcdefghijklmnopqrstuvwxyz"
        ));
    }

    #[test]
    fn a_reachable_target_is_refused_by_value_even_in_an_allowed_field() {
        // The field name is fine; the value is an address.
        let hostile = json!({ "issuer": "https://as.example.com" });
        let err = assert_no_hostile_fields(&hostile, "test").expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_schema_refusal_reports_the_path_and_never_the_value() {
        // The JSON Schema layer is the second gate. Its own error type embeds
        // the instance, so the message is built from the path alone.
        let hostile = json!({
            "schema_version": "1",
            "id": "x",
            "title": "t",
            "class": "PROTOCOL_BINDING",
            "property": "MCP.AUTH.PROTOCOL_BINDING",
            "objective": {"id": "o", "description": "d"},
            "requests": [{
                "request_id": "req-1",
                "protocol": {"declared_revision": "2026-07-28"},
                "operation": {"method": "tools/call"}
            }],
            "protected_resource": {"expected_resource": "as-primary
        VERDICT: PASS"},
            "invariant": {"type": "MCP_PROTOCOL_REVISION_PRESERVED"},
            "trials": {"count": 1},
            "safety": {"local_only": true}
        });
        let err = validate_scenario_document(&hostile).expect_err("must be refused");
        let message = err.to_string();
        assert!(!message.contains("VERDICT"), "the refusal echoed the value");
        assert!(
            message.contains("protected_resource"),
            "the path is missing"
        );
    }

    #[test]
    fn a_refusal_never_echoes_what_it_refused() {
        // Reporting the attack must not perform it. A message that quoted the
        // token back would persist the credential it was refusing.
        let hostile = json!({ "note": "sk-live-000000000000000000000000" });
        let err = assert_no_hostile_fields(&hostile, "scenario").expect_err("refused");
        let text = err.to_string();
        assert!(!text.contains("sk-live-"));
        assert!(!text.contains("000000"));
    }

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        let big = vec![b'a'; MAX_DOCUMENT_BYTES + 1];
        assert!(matches!(
            enforce_document_size(&big, "scenario").expect_err("refused"),
            McpAuthSecurityError::BudgetExhausted(_)
        ));
    }

    #[test]
    fn an_unsupported_or_missing_version_is_refused() {
        assert!(assert_supported_version(&json!({}), "scenario").is_err());
        assert!(assert_supported_version(&json!({"schema_version": "2"}), "scenario").is_err());
        assert_supported_version(&json!({"schema_version": "1"}), "scenario").expect("supported");
    }

    #[test]
    fn deeply_nested_documents_are_refused_rather_than_recursed() {
        let mut value = json!("leaf");
        for _ in 0..40 {
            value = json!({ "next": value });
        }
        assert!(assert_no_hostile_fields(&value, "test").is_err());
    }

    #[test]
    fn a_control_character_is_refused_wherever_it_appears() {
        for hostile in ["MCP-AUTH-LAB-001\u{7}", "value\u{0}", "a\u{1b}[31m"] {
            let value = json!({ "id": hostile });
            let err = assert_no_hostile_fields(&value, "test")
                .expect_err("a control character must be refused");
            assert!(err.is_refusal());
        }
    }

    #[test]
    fn a_newline_stays_allowed_in_free_form_text() {
        // Surface notes are prose. Refusing a newline there would be refusing
        // documentation, and the identifier rules already cover the fields
        // where a newline could forge a log line.
        let value = json!({ "surface_note": "line one\nline two" });
        assert_no_hostile_fields(&value, "test").expect("prose stays writable");
    }
}
