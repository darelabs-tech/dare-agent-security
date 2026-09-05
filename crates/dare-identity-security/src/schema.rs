//! Versioned schemas and the fail-closed input gates in front of them.
//!
//! Every document the engine reads is untrusted: scenarios, principal sets,
//! delegation chains, authorities, resource contexts, policies, decisions,
//! operations, corpus entries and replay traces. Four independent gates run in
//! order, and each can refuse on its own:
//!
//! 1. the declared schema version must be exactly the supported one;
//! 2. a hostile-field sweep over every key and string at any depth;
//! 3. the versioned JSON Schema, with `additionalProperties: false`;
//! 4. the typed layer, with serde `deny_unknown_fields`.
//!
//! # Why the credential sweep is stricter here than in earlier cycles
//!
//! Identity work is exactly the place where someone would be tempted to paste a
//! real token into a fixture "just to test the parser". So the sweep refuses
//! token-shaped *field names* and token-shaped *values*, and it does so before
//! the document is ever parsed into typed form or written anywhere.

use serde_json::Value;

use crate::error::{IdentitySecurityError, Result};

pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

/// Ceiling on any single document, applied before parsing.
pub const MAX_DOCUMENT_BYTES: usize = 131_072;

/// Field names that would turn declarative data into an execution path.
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
    "expression",
    "condition",
    "rule_expression",
];

/// Field names that would carry credential material.
///
/// Longer and stricter than earlier cycles on purpose: an identity fixture is
/// the most plausible place for a real secret to be pasted by accident.
pub const FORBIDDEN_CREDENTIAL_FIELD_NAMES: [&str; 22] = [
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "bearer",
    "authorization_header",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "password",
    "passphrase",
    "credential",
    "credentials",
    "private_key",
    "secret_key",
    "session_cookie",
    "cookie",
    "assertion_jwt",
    "jwt",
    "signature",
    "proof_of_possession",
];

/// Field names that would name a live provider or reachable endpoint.
pub const FORBIDDEN_REMOTE_FIELD_NAMES: [&str; 16] = [
    "url",
    "endpoint",
    "issuer",
    "jwks",
    "jwks_uri",
    "authorization_endpoint",
    "token_endpoint",
    "introspection_endpoint",
    "pdp_url",
    "authzen_url",
    "host",
    "provider",
    "remote",
    "base_url",
    "mcp_server",
    "transport",
];

/// Field names that would let a fixture tell the engine its own verdict.
pub const FORBIDDEN_VERDICT_FIELD_NAMES: [&str; 9] = [
    "expected_verdict",
    "verdict",
    "expected_result",
    "expected_outcome",
    "should_fail",
    "should_pass",
    "is_vulnerable",
    "expected_violation",
    "expected_decision",
];

/// Value prefixes and shapes that indicate real credential material.
const CREDENTIAL_SHAPED_VALUES: [&str; 11] = [
    "eyj",
    "sk-live-",
    "sk_live_",
    "xoxb-",
    "ghp_",
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin openssh private key-----",
    "aws_secret_access_key",
    "client_secret=",
    "refresh_token=",
];

pub const PRINCIPAL_SET_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/principal-set.schema.json";
pub const PRINCIPAL_SET_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/principal-set.schema.json");

pub const AUTHORITY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/authority.schema.json";
pub const AUTHORITY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/authority.schema.json");

pub const DELEGATION_CHAIN_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/delegation-chain.schema.json";
pub const DELEGATION_CHAIN_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/delegation-chain.schema.json");

pub const RESOURCE_CONTEXT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/resource-context.schema.json";
pub const RESOURCE_CONTEXT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/resource-context.schema.json");

pub const AUTHORIZATION_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/authorization.schema.json";
pub const AUTHORIZATION_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/authorization.schema.json");

pub const OPERATION_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/operation.schema.json";
pub const OPERATION_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/operation.schema.json");

pub const SCENARIO_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/scenario.schema.json";
pub const SCENARIO_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/scenario.schema.json");

pub const TRACE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/trace.schema.json";
pub const TRACE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/trace.schema.json");

/// Refuse a document larger than the approved ceiling, before parsing it.
pub fn enforce_document_size(raw: &[u8], label: &str) -> Result<()> {
    if raw.len() > MAX_DOCUMENT_BYTES {
        return Err(IdentitySecurityError::refusal(format!(
            "{label} is {} bytes, which exceeds the {MAX_DOCUMENT_BYTES}-byte maximum",
            raw.len()
        )));
    }
    Ok(())
}

/// Refuse a document whose declared schema version is not the supported one.
///
/// Both an upgrade and a downgrade are refused: a future version might mean
/// something different, and an older one might mean less.
pub fn assert_supported_version(value: &Value, label: &str) -> Result<()> {
    let declared = value
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            IdentitySecurityError::schema(format!("{label} has no schema_version string"))
        })?;
    if declared != SUPPORTED_SCHEMA_VERSION {
        return Err(IdentitySecurityError::refusal(format!(
            "{label} declares unsupported schema_version `{declared}`"
        )));
    }
    Ok(())
}

/// Refuse text that can forge a line in a log, a report or a terminal.
///
/// Corpus payloads legitimately carry adversarial prose, and that prose is
/// data. What is refused here is the machinery of presentation: terminal
/// control sequences, carriage returns that overwrite a rendered line, and the
/// Unicode bidi and zero-width characters that make one string display as
/// another. An identifier that renders as a different identifier is a
/// substitution attack in this cycle specifically, not just a formatting bug.
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
            return Err(IdentitySecurityError::refusal(format!(
                "{label} contains a control or direction-override character (U+{:04X}) in \
                 {where_found}; such text can forge a log line or make two identifiers render \
                 identically",
                character as u32
            )));
        }
    }
    Ok(())
}

/// Minimum length for the token after `bearer ` to count as credential material.
///
/// Without this, the word "bearer" in ordinary prose is indistinguishable from
/// a real header value, and honest sentences like "issues no bearer token"
/// become unwritable. The same minimum is used by the Cycle 013 and 014
/// redaction helpers, for the same reason.
const MIN_BEARER_TOKEN_LEN: usize = 16;

/// Whether the text carries a `bearer ` followed by something token-shaped.
fn contains_bearer_credential(lowered: &str) -> bool {
    const MARKER: &str = "bearer ";
    let mut rest = lowered;
    while let Some(index) = rest.find(MARKER) {
        let after = &rest[index + MARKER.len()..];
        let token_len = after
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .count();
        if token_len >= MIN_BEARER_TOKEN_LEN {
            return true;
        }
        rest = &after[token_len.min(after.len())..];
    }
    false
}

/// Refuse a value that looks like real credential material.
///
/// Shape, not vocabulary. A fixture may say the word "token" in a sentence; it
/// may not carry one. Matching the vocabulary instead would make every honest
/// description of this boundary unwritable, which is how a security check ends
/// up being disabled by the people it inconveniences.
pub fn assert_no_credential_value(text: &str, label: &str) -> Result<()> {
    let lowered = text.to_ascii_lowercase();
    let credential_shaped = CREDENTIAL_SHAPED_VALUES
        .iter()
        .any(|marker| lowered.contains(marker))
        || contains_bearer_credential(&lowered);

    if credential_shaped {
        return Err(IdentitySecurityError::refusal(format!(
            "{label} contains credential-shaped content and was refused; Cycle 015 models \
             authority declaratively and never accepts token material"
        )));
    }
    Ok(())
}

/// Recursively refuse executable, credential, remote-target and verdict keys,
/// hostile text, and credential-shaped values.
pub fn assert_no_hostile_fields(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::String(text) => {
            assert_no_hostile_text(text, label, "a string value")?;
            assert_no_credential_value(text, label)
        }
        Value::Object(map) => {
            for (key, child) in map {
                assert_no_hostile_text(key, label, "a field name")?;
                let lowered = key.to_ascii_lowercase();

                if FORBIDDEN_EXECUTABLE_FIELD_NAMES.contains(&lowered.as_str()) {
                    return Err(IdentitySecurityError::refusal(format!(
                        "{label} declares forbidden executable field `{key}`; authority is \
                         compared, never executed"
                    )));
                }
                if FORBIDDEN_CREDENTIAL_FIELD_NAMES.contains(&lowered.as_str()) {
                    return Err(IdentitySecurityError::refusal(format!(
                        "{label} declares forbidden credential field `{key}`; a credential context \
                         is synthetic metadata, never secret material"
                    )));
                }
                if FORBIDDEN_REMOTE_FIELD_NAMES.contains(&lowered.as_str()) {
                    return Err(IdentitySecurityError::refusal(format!(
                        "{label} declares forbidden remote-target field `{key}`; Cycle 015 has no \
                         identity provider, PDP or network path"
                    )));
                }
                if FORBIDDEN_VERDICT_FIELD_NAMES.contains(&lowered.as_str()) {
                    return Err(IdentitySecurityError::refusal(format!(
                        "{label} declares `{key}`; a fixture must never carry the verdict the \
                         engine is supposed to compute"
                    )));
                }

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
        _ => Ok(()),
    }
}

fn compile(schema_json: &str, label: &str) -> Result<jsonschema::Validator> {
    let schema: Value = serde_json::from_str(schema_json)
        .map_err(|err| IdentitySecurityError::schema(format!("{label} schema: {err}")))?;
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| IdentitySecurityError::schema(format!("{label} schema: {err}")))
}

/// Validate an instance against a compiled-in schema.
///
/// The schemas are embedded in the binary and resolved locally, so validation
/// never touches the network even though the `$id`s are URLs.
pub fn validate_against(instance: &Value, schema_json: &str, label: &str) -> Result<()> {
    let validator = compile(schema_json, label)?;
    if let Err(error) = validator.validate(instance) {
        return Err(IdentitySecurityError::schema(format!(
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
fn scenario_validator() -> Result<jsonschema::Validator> {
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| IdentitySecurityError::schema(format!("{label} schema: {err}")))
    };

    let scenario = parse(SCENARIO_SCHEMA_V1_JSON, "scenario")?;

    jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            PRINCIPAL_SET_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                PRINCIPAL_SET_SCHEMA_V1_JSON,
                "principal-set",
            )?),
        )
        .with_resource(
            AUTHORITY_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(AUTHORITY_SCHEMA_V1_JSON, "authority")?),
        )
        .with_resource(
            DELEGATION_CHAIN_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                DELEGATION_CHAIN_SCHEMA_V1_JSON,
                "delegation-chain",
            )?),
        )
        .with_resource(
            RESOURCE_CONTEXT_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                RESOURCE_CONTEXT_SCHEMA_V1_JSON,
                "resource-context",
            )?),
        )
        .with_resource(
            AUTHORIZATION_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                AUTHORIZATION_SCHEMA_V1_JSON,
                "authorization",
            )?),
        )
        .with_resource(
            OPERATION_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(OPERATION_SCHEMA_V1_JSON, "operation")?),
        )
        .build(&scenario)
        .map_err(|err| IdentitySecurityError::schema(format!("scenario schema: {err}")))
}

/// The replay-trace schema, with its referenced schemas resolved from memory.
fn trace_validator() -> Result<jsonschema::Validator> {
    let parse = |json: &str, label: &str| -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|err| IdentitySecurityError::schema(format!("{label} schema: {err}")))
    };

    let trace = parse(TRACE_SCHEMA_V1_JSON, "trace")?;

    jsonschema::options()
        .should_validate_formats(true)
        .with_resource(
            RESOURCE_CONTEXT_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(
                RESOURCE_CONTEXT_SCHEMA_V1_JSON,
                "resource-context",
            )?),
        )
        .with_resource(
            OPERATION_SCHEMA_V1_ID.to_owned(),
            jsonschema::Resource::from_contents(parse(OPERATION_SCHEMA_V1_JSON, "operation")?),
        )
        .build(&trace)
        .map_err(|err| IdentitySecurityError::schema(format!("trace schema: {err}")))
}

/// Validate a replay trace: version, hostile fields, then schema.
pub fn validate_trace_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "replay trace")?;
    assert_no_hostile_fields(value, "replay trace")?;
    let validator = trace_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(IdentitySecurityError::schema(format!(
            "replay trace: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// Validate a scenario: version, hostile fields, then schema.
pub fn validate_scenario_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "scenario")?;
    assert_no_hostile_fields(value, "scenario")?;
    let validator = scenario_validator()?;
    if let Err(error) = validator.validate(value) {
        return Err(IdentitySecurityError::schema(format!(
            "scenario: {error} at {}",
            error.instance_path()
        )));
    }
    Ok(())
}

/// Validate a standalone principal-set document.
pub fn validate_principal_set_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "principal set")?;
    assert_no_hostile_fields(value, "principal set")?;
    validate_against(value, PRINCIPAL_SET_SCHEMA_V1_JSON, "principal set")
}

/// Validate a standalone delegation-chain document.
pub fn validate_delegation_chain_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "delegation chain")?;
    assert_no_hostile_fields(value, "delegation chain")?;
    validate_against(value, DELEGATION_CHAIN_SCHEMA_V1_JSON, "delegation chain")
}

/// Validate a standalone authorization-policy document.
pub fn validate_authorization_document(value: &Value) -> Result<()> {
    assert_supported_version(value, "authorization policy")?;
    assert_no_hostile_fields(value, "authorization policy")?;
    validate_against(value, AUTHORIZATION_SCHEMA_V1_JSON, "authorization policy")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_supported_version_is_exact_in_both_directions() {
        let newer = json!({"schema_version": "2"});
        let older = json!({"schema_version": "0"});
        let missing = json!({});
        assert!(assert_supported_version(&newer, "doc").is_err());
        assert!(assert_supported_version(&older, "doc").is_err());
        assert!(assert_supported_version(&missing, "doc").is_err());
        assert!(assert_supported_version(&json!({"schema_version": "1"}), "doc").is_ok());
    }

    #[test]
    fn executable_fields_are_refused_at_every_depth() {
        for key in FORBIDDEN_EXECUTABLE_FIELD_NAMES {
            let nested = json!({"a": {"b": [{ key: "anything" }]}});
            let err = assert_no_hostile_fields(&nested, "doc")
                .expect_err(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn credential_fields_are_refused_at_every_depth() {
        for key in FORBIDDEN_CREDENTIAL_FIELD_NAMES {
            let nested = json!({"principals": [{"context": { key: "value" }}]});
            let err = assert_no_hostile_fields(&nested, "doc")
                .expect_err(&format!("{key} must be refused"));
            assert!(err.is_refusal(), "{key}");
        }
    }

    #[test]
    fn remote_target_fields_are_refused_at_every_depth() {
        for key in FORBIDDEN_REMOTE_FIELD_NAMES {
            let nested = json!({"policy": {"provider_config": { key: "x" }}});
            assert!(
                assert_no_hostile_fields(&nested, "doc").is_err(),
                "{key} must be refused"
            );
        }
    }

    #[test]
    fn expected_verdict_smuggling_is_refused_at_every_depth() {
        for key in FORBIDDEN_VERDICT_FIELD_NAMES {
            let nested = json!({"vector": {"meta": { key: "PASS" }}});
            let err = assert_no_hostile_fields(&nested, "doc")
                .expect_err(&format!("{key} must be refused"));
            assert!(err.to_string().contains("verdict"), "{key}");
        }
    }

    #[test]
    fn credential_shaped_values_are_refused_even_under_an_innocent_key() {
        // The field name is only half the surface. A JWT pasted into a
        // `display_label` is still a JWT.
        for value in [
            "Bearer ya29.a0ARrdaM9example",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc",
            "sk-live-4f9c2ab117de",
            "xoxb-1234-5678",
            "ghp_abcdefghijklmnop",
            "-----BEGIN PRIVATE KEY-----MIIEvQ",
            "client_secret=hunter2",
        ] {
            let document = json!({"display_label": value});
            let err = assert_no_hostile_fields(&document, "doc")
                .expect_err(&format!("{value} must be refused"));
            assert!(err.is_refusal());
        }
    }

    #[test]
    fn ordinary_identity_prose_is_not_mistaken_for_a_credential() {
        // The sweep must not fire on a fixture that merely *discusses* tokens,
        // or every honest description becomes unwritable.
        for value in [
            "the delegation is modelled declaratively and issues no token",
            "a service credential context with admin capability labels",
            "authorization decision recorded without any bearer material",
            "this scenario never performs token exchange",
        ] {
            assert_no_hostile_fields(&json!({"note": value}), "doc")
                .unwrap_or_else(|err| panic!("{value} must be allowed: {err}"));
        }
    }

    #[test]
    fn a_bearer_credential_is_refused_but_the_word_bearer_is_not() {
        // The defect this pins: matching the literal prefix `bearer ` fired on
        // the sentence "without any bearer material", making an honest
        // description of this very boundary unwritable. Shape, not vocabulary.
        assert!(contains_bearer_credential(
            "bearer ya29.a0arrdam9examplevalue"
        ));
        assert!(contains_bearer_credential(
            "authorization: bearer abcdefghijklmnopqrstuvwxyz"
        ));

        assert!(!contains_bearer_credential("without any bearer material"));
        assert!(!contains_bearer_credential(
            "the bearer token is never stored"
        ));
        assert!(!contains_bearer_credential("bearer short"));

        // And the same asymmetry through the public gate.
        assert!(assert_no_credential_value("bearer ya29.a0arrdam9examplevalue", "doc").is_err());
        assert!(assert_no_credential_value("issues no bearer token at all", "doc").is_ok());
    }

    #[test]
    fn hostile_unicode_and_control_characters_are_refused() {
        for value in [
            "user\u{202e}7",
            "user\u{200b}7",
            "benign\u{1b}[2K\rDECISION: PERMIT",
            "line\roverwrite",
        ] {
            assert!(
                assert_no_hostile_fields(&json!({"id": value}), "doc").is_err(),
                "{value:?} must be refused"
            );
        }
        // Newline and tab stay legal so multi-line prose remains writable.
        assert!(
            assert_no_hostile_fields(&json!({"note": "line one\nline two\ttabbed"}), "doc").is_ok()
        );
    }

    #[test]
    fn a_hostile_field_name_is_refused_as_well_as_a_hostile_value() {
        let document = json!({"user\u{202e}id": "value"});
        let err = assert_no_hostile_fields(&document, "doc").expect_err("refused");
        assert!(err.to_string().contains("a field name"));
    }

    #[test]
    fn an_oversized_document_is_refused_before_parsing() {
        let oversized = vec![b'x'; MAX_DOCUMENT_BYTES + 1];
        let err = enforce_document_size(&oversized, "scenario").expect_err("refused");
        assert!(err.to_string().contains("exceeds"));
        assert!(enforce_document_size(&[b'x'; 16], "scenario").is_ok());
    }

    #[test]
    fn the_forbidden_name_sets_do_not_overlap_each_other() {
        // Overlap would mean one refusal message shadowing another, making the
        // reason a reader sees depend on list order rather than on the input.
        use std::collections::BTreeSet;
        let executable: BTreeSet<&str> = FORBIDDEN_EXECUTABLE_FIELD_NAMES.into_iter().collect();
        let credential: BTreeSet<&str> = FORBIDDEN_CREDENTIAL_FIELD_NAMES.into_iter().collect();
        let remote: BTreeSet<&str> = FORBIDDEN_REMOTE_FIELD_NAMES.into_iter().collect();
        let verdict: BTreeSet<&str> = FORBIDDEN_VERDICT_FIELD_NAMES.into_iter().collect();

        assert!(executable.is_disjoint(&credential));
        assert!(executable.is_disjoint(&remote));
        assert!(executable.is_disjoint(&verdict));
        assert!(credential.is_disjoint(&remote));
        assert!(credential.is_disjoint(&verdict));
        assert!(remote.is_disjoint(&verdict));
    }
}
