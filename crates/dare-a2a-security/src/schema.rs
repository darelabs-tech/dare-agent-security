//! The document gate.
//!
//! An Agent Card is a file somebody else produced, describing a peer nobody
//! here controls. A captured trace is the same, one layer further out. This is
//! the widest input surface the engine has, so there are **three gates**, each
//! catching what the others structurally cannot:
//!
//! 1. the **sweep** visits every value at every depth, including inside fields
//!    no model has a place for — a hostile field placed where nothing will
//!    decode it is still a field in a document about to be accepted;
//! 2. the **size and depth bounds** run before the parser, because a document
//!    refused after parsing has already been parsed;
//! 3. `deny_unknown_fields` on every model catches anything that reached the
//!    decoder despite both.
//!
//! # The hard part: coordinates are legitimate
//!
//! An Agent Card *is* a list of places. It carries interface URLs, a token
//! endpoint, an issuer, sometimes a `jku`; a push-notification configuration is
//! a URL by construction. Refusing those fields would refuse every real
//! document, and a check that refuses everything gets turned off by the first
//! person who hits it.
//!
//! So the rule is not "no URLs". The rule is:
//!
//! - a field naming a **location** is read and stored as inert metadata;
//! - a field naming an **action** — `fetch`, `download`, `auto_refresh`,
//!   `probe_webhook` — is refused, because a location is a place and an
//!   instruction is a request;
//! - a **scheme** that is not `https`, `http`, `grpc` or `grpcs` is refused,
//!   because `file://`, `javascript:` and `data:` in an Agent Card are not
//!   endpoints at all.
//!
//! Nothing in this crate resolves a location either way. The field rules are
//! the second line, not the first.

use serde_json::Value;

use crate::error::{A2aSecurityError, Result};
use crate::limits;

/// Field names that carry credential material.
///
/// Refused by name whatever they hold, including when empty: the field is what
/// is wrong, and admitting the empty case leaves it available for the next
/// author.
const FORBIDDEN_CREDENTIAL_FIELDS: [&str; 26] = [
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "bearer_token",
    "client_secret",
    "client_credentials",
    "password",
    "passphrase",
    "secret",
    "secret_key",
    "private_key",
    "privatekey",
    "signing_key",
    "session_token",
    "auth_token",
    "authorization_header",
    "cookie",
    "set_cookie",
    "credential",
    "credentials",
    "pem",
    "pkcs12",
    "keystore",
    "truststore",
];

/// Field names that ask for something to be executed.
///
/// An Agent Card describes what a peer can do. It never carries what to run.
const FORBIDDEN_EXECUTABLE_FIELDS: [&str; 16] = [
    "command",
    "cmd",
    "exec",
    "execute",
    "entrypoint",
    "shell",
    "script",
    "eval",
    "run_script",
    "post_install",
    "pre_install",
    "hook",
    "hooks",
    "callback_command",
    "plugin_path",
    "dylib",
];

/// Field names that ask for a location to be **resolved**.
///
/// Deliberately narrow. `url`, `endpoint`, `issuer`, `jku`, `jwks_uri`,
/// `token_endpoint`, `webhook`, `callback_url` and `agent_card_url` are all
/// absent from this list: they name places, real documents carry them, and this
/// engine stores them inert. What is refused is a field whose name asserts an
/// **action**.
const FORBIDDEN_FETCH_FIELDS: [&str; 14] = [
    "fetch",
    "fetch_url",
    "auto_fetch",
    "download",
    "download_url",
    "resolve_key",
    "auto_resolve",
    "refresh_keys",
    "probe",
    "probe_webhook",
    "verify_remote",
    "follow_redirects",
    "connect_on_load",
    "prefetch",
];

/// Field names that would let a document declare its own outcome.
const FORBIDDEN_VERDICT_FIELDS: [&str; 12] = [
    "verdict",
    "expected_verdict",
    "expected_findings",
    "expected_outcome",
    "is_secure",
    "secure",
    "should_fail",
    "should_pass",
    "trusted",
    "authorized",
    "approved",
    "evaluator_override",
];

/// Value prefixes that are credential material whatever field carries them.
///
/// All lowercase. Cycle 018 shipped a list with `AKIA` and `eyJhbGci` in it,
/// compared against a lowercased string — the list looked right and matched
/// nothing.
const CREDENTIAL_SHAPED_VALUES: [&str; 12] = [
    "sk-live-",
    "sk_live_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "akia",
    "asia",
    "eyjhbgci",
    "-----begin",
    "aws_secret",
    "glpat-",
];

/// Schemes that are not endpoints at all.
///
/// `https` and `http` are absent: they are what an Agent Card interface is.
/// `grpc` and `grpcs` likewise. What is refused is a scheme that could not be
/// an A2A interface and therefore has no reason to appear in one.
const FORBIDDEN_URL_SCHEMES: [&str; 9] = [
    "file://",
    "javascript:",
    "data:",
    "vbscript:",
    "jar:",
    "ftp://",
    "gopher://",
    "ldap://",
    "dict://",
];

/// Refuse a document larger than the engine will read.
///
/// Called before `serde_json` sees the bytes. A 40 MB card refused after
/// parsing has already been parsed.
pub fn enforce_document_size(raw: &[u8], label: &str) -> Result<()> {
    if raw.len() > limits::HARD_MAX_DOCUMENT_BYTES {
        return Err(A2aSecurityError::BudgetExhausted(format!(
            "{label} is {} bytes; the hard maximum is {}",
            raw.len(),
            limits::HARD_MAX_DOCUMENT_BYTES
        )));
    }
    Ok(())
}

/// Sweep a parsed document for anything the engine will not read.
///
/// Runs over the whole value at every depth, including inside objects no model
/// has a field for — which is the point. A hostile field placed where nothing
/// will decode it is still a field in a document the engine is about to accept.
pub fn assert_no_hostile_fields(value: &Value, label: &str) -> Result<()> {
    sweep(value, label, 0)
}

fn sweep(value: &Value, label: &str, depth: usize) -> Result<()> {
    if depth > limits::HARD_MAX_JSON_DEPTH {
        return Err(A2aSecurityError::refusal(format!(
            "{label} nests deeper than {} levels",
            limits::HARD_MAX_JSON_DEPTH
        )));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert_field_name_is_readable(key, label)?;
                sweep(child, label, depth + 1)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                sweep(item, label, depth + 1)?;
            }
        }
        Value::String(text) => assert_value_is_readable(text, label)?,
        _ => {}
    }
    Ok(())
}

/// Normalize a field name before comparing it.
///
/// `api-key`, `api key` and `apiKey` are the same field wearing different
/// clothes, and a list that only knew one of them would be a list that looked
/// right.
fn normalize_field(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>()
        .replace(' ', "_")
}

fn assert_field_name_is_readable(key: &str, label: &str) -> Result<()> {
    let normalized = normalize_field(key);
    let normalized_underscored = key
        .to_ascii_lowercase()
        .replace([' ', '-', '.'], "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>();

    for candidate in [normalized.as_str(), normalized_underscored.as_str()] {
        for forbidden in FORBIDDEN_CREDENTIAL_FIELDS {
            if candidate == forbidden.replace('_', "") || candidate == forbidden {
                return Err(A2aSecurityError::refusal(format!(
                    "{label} carries a credential field; an Agent Card describes a peer and \
                     never carries the means to authenticate as one"
                )));
            }
        }
        for forbidden in FORBIDDEN_EXECUTABLE_FIELDS {
            if candidate == forbidden.replace('_', "") || candidate == forbidden {
                return Err(A2aSecurityError::refusal(format!(
                    "{label} carries an executable field; a description of what a peer can do \
                     is not a description of what to run"
                )));
            }
        }
        for forbidden in FORBIDDEN_FETCH_FIELDS {
            if candidate == forbidden.replace('_', "") || candidate == forbidden {
                return Err(A2aSecurityError::refusal(format!(
                    "{label} carries a field that asks for a location to be resolved; a \
                     coordinate names a place and this engine goes to none of them"
                )));
            }
        }
        for forbidden in FORBIDDEN_VERDICT_FIELDS {
            if candidate == forbidden.replace('_', "") || candidate == forbidden {
                return Err(A2aSecurityError::refusal(format!(
                    "{label} carries a verdict field; the evaluator is the only verdict \
                     authority and a document that could state an outcome would replace it"
                )));
            }
        }
    }
    Ok(())
}

fn assert_value_is_readable(text: &str, label: &str) -> Result<()> {
    let lowered = text.to_ascii_lowercase();

    for marker in CREDENTIAL_SHAPED_VALUES {
        if lowered.contains(marker) {
            return Err(A2aSecurityError::refusal(format!(
                "{label} carries a credential-shaped value"
            )));
        }
    }
    if contains_bearer_credential(&lowered) {
        return Err(A2aSecurityError::refusal(format!(
            "{label} carries something shaped like a bearer credential"
        )));
    }
    for scheme in FORBIDDEN_URL_SCHEMES {
        if lowered.contains(scheme) {
            return Err(A2aSecurityError::refusal(format!(
                "{label} carries a `{scheme}` value, which is not an A2A interface"
            )));
        }
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(A2aSecurityError::refusal(format!(
            "{label} carries a control character"
        )));
    }
    Ok(())
}

/// Whether a lowercased string carries a bearer credential *value*.
///
/// Anchored on shape rather than the word, so an honest sentence about bearer
/// tokens — including this crate's own documentation — stays writable while a
/// real one is refused.
pub fn contains_bearer_credential(lowered: &str) -> bool {
    for (index, _) in lowered.match_indices("bearer ") {
        let tail: String = lowered[index + "bearer ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "._~+/-".contains(*c))
            .collect();
        if tail.len() >= 16 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        let raw = vec![b'x'; limits::HARD_MAX_DOCUMENT_BYTES + 1];
        assert!(enforce_document_size(&raw, "an Agent Card").is_err());
        assert!(enforce_document_size(b"{}", "an Agent Card").is_ok());
    }

    #[test]
    fn a_credential_field_is_refused_at_any_depth() {
        // Inside a field no model has a place for, which is the point: a
        // hostile field where nothing will decode it is still in a document the
        // engine is about to accept.
        let hostile = json!({
            "name": "planner",
            "provider": { "extra": { "nested": { "client_secret": "" } } }
        });
        assert!(assert_no_hostile_fields(&hostile, "an Agent Card").is_err());
    }

    #[test]
    fn a_credential_field_is_refused_even_when_empty() {
        // The field is what is wrong. Admitting the empty case leaves it
        // available for the next author.
        assert!(assert_no_hostile_fields(&json!({ "api_key": "" }), "a card").is_err());
        assert!(assert_no_hostile_fields(&json!({ "private_key": null }), "a card").is_err());
    }

    #[test]
    fn a_hyphenated_or_spaced_field_name_is_normalized_before_comparison() {
        // `api-key`, `api key` and `apiKey` are the same field wearing
        // different clothes.
        for spelling in ["api-key", "api key", "apiKey", "API_KEY", "Api.Key"] {
            let hostile = json!({ spelling: "value" });
            assert!(
                assert_no_hostile_fields(&hostile, "a card").is_err(),
                "`{spelling}` was admitted"
            );
        }
    }

    #[test]
    fn every_credential_marker_is_lowercase() {
        // Cycle 018 shipped a list with `AKIA` and `eyJhbGci` in it, compared
        // against a lowercased string. The list looked right and matched
        // nothing.
        for marker in CREDENTIAL_SHAPED_VALUES {
            assert_eq!(marker, &marker.to_ascii_lowercase(), "`{marker}`");
        }
    }

    #[test]
    fn a_credential_shaped_value_is_refused_wherever_it_appears() {
        for value in [
            "ghp_0123456789abcdef0123456789abcdef0123",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
        ] {
            let hostile = json!({ "description": value });
            assert!(
                assert_no_hostile_fields(&hostile, "a card").is_err(),
                "`{value}` was admitted"
            );
        }
    }

    #[test]
    fn an_executable_or_fetch_field_is_refused() {
        assert!(assert_no_hostile_fields(&json!({ "command": "sh -c x" }), "a card").is_err());
        assert!(assert_no_hostile_fields(&json!({ "entrypoint": "/bin/sh" }), "a card").is_err());
        assert!(assert_no_hostile_fields(&json!({ "auto_fetch": true }), "a card").is_err());
        assert!(assert_no_hostile_fields(&json!({ "probe_webhook": true }), "a card").is_err());
        assert!(assert_no_hostile_fields(&json!({ "resolve_key": true }), "a card").is_err());
    }

    #[test]
    fn a_verdict_field_is_refused() {
        for field in ["verdict", "is_secure", "should_fail", "trusted", "approved"] {
            let hostile = json!({ field: true });
            assert!(
                assert_no_hostile_fields(&hostile, "a card").is_err(),
                "`{field}` was admitted"
            );
        }
    }

    #[test]
    fn ordinary_agent_card_location_fields_stay_readable() {
        // The control, and the one that decides whether this gate survives
        // contact with a real document. An Agent Card *is* a list of places.
        // Refusing them would refuse every real card, and a check that refuses
        // everything gets turned off by the first person who hits it.
        let realistic = json!({
            "name": "planner-agent",
            "url": "https://peer.example/a2a",
            "preferredTransport": "JSONRPC",
            "additionalInterfaces": [
                { "url": "https://peer.example/a2a/grpc", "transport": "GRPC" }
            ],
            "provider": { "organization": "Acme", "url": "https://acme.example" },
            "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "tokenUrl": "https://issuer.example/token",
                    "issuer": "https://issuer.example"
                }
            },
            "signatures": [{ "protected": "eyJ", "header": { "jku": "https://peer.example/jwks" } }],
            "pushNotificationConfig": { "url": "https://callback.example/hook" }
        });
        assert_no_hostile_fields(&realistic, "an Agent Card")
            .expect("a realistic Agent Card is readable");
    }

    #[test]
    fn a_scheme_that_could_not_be_an_interface_is_refused() {
        // `https` and `grpc` are what an interface is. `file://` and
        // `javascript:` are not endpoints at all, and have no reason to appear.
        for hostile in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "ftp://peer.example/card",
        ] {
            let document = json!({ "url": hostile });
            assert!(
                assert_no_hostile_fields(&document, "a card").is_err(),
                "`{hostile}` was admitted"
            );
        }
    }

    #[test]
    fn deeply_nested_documents_are_refused_rather_than_recursed() {
        // A document nested past the ceiling is a stack-exhaustion attempt
        // dressed as data, and checking depth explicitly is cheaper than
        // recursing to find out.
        let mut value = json!("leaf");
        for _ in 0..(limits::HARD_MAX_JSON_DEPTH + 5) {
            value = json!({ "next": value });
        }
        assert!(assert_no_hostile_fields(&value, "a card").is_err());
    }

    #[test]
    fn a_refusal_never_echoes_what_it_refused() {
        // An error log is a persistence surface like any other. A message
        // quoting a smuggled token back would store the credential it declined
        // to store.
        let hostile = json!({ "description": "ghp_0123456789abcdef0123456789abcdef0123" });
        let error = assert_no_hostile_fields(&hostile, "a card").expect_err("refused");
        assert!(!error.to_string().contains("ghp_"));
    }

    #[test]
    fn no_refusal_reads_as_a_security_verdict() {
        let refusals = [
            assert_no_hostile_fields(&json!({ "api_key": "x" }), "a card").unwrap_err(),
            assert_no_hostile_fields(&json!({ "command": "x" }), "a card").unwrap_err(),
            assert_no_hostile_fields(&json!({ "url": "file:///x" }), "a card").unwrap_err(),
        ];
        for refusal in refusals {
            let text = refusal.to_string().to_uppercase();
            let words: Vec<&str> = text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect();
            for verdict in ["PASS", "FAIL", "VULNERABLE", "INSECURE"] {
                assert!(!words.contains(&verdict), "`{text}` reads as {verdict}");
            }
        }
    }

    #[test]
    fn prose_about_credentials_stays_writable() {
        // The engine's own documentation talks about bearer tokens. A checker
        // anchored on the word rather than the shape would refuse the text
        // explaining why it refuses things.
        assert!(!contains_bearer_credential(
            "a bearer token is not proof of authorization"
        ));
        assert!(contains_bearer_credential(
            "authorization: bearer abcdefghijklmnopqrstuvwxyz"
        ));
    }

    #[test]
    fn the_forbidden_lists_have_no_duplicates() {
        // A duplicate is usually a sign that two authors added the same entry
        // and one of them meant something slightly different.
        for list in [
            &FORBIDDEN_CREDENTIAL_FIELDS[..],
            &FORBIDDEN_EXECUTABLE_FIELDS[..],
            &FORBIDDEN_FETCH_FIELDS[..],
            &FORBIDDEN_VERDICT_FIELDS[..],
            &CREDENTIAL_SHAPED_VALUES[..],
            &FORBIDDEN_URL_SCHEMES[..],
        ] {
            let unique: std::collections::BTreeSet<&&str> = list.iter().collect();
            assert_eq!(unique.len(), list.len(), "{list:?}");
        }
    }

    #[test]
    fn the_fetch_list_refuses_actions_and_not_locations() {
        // The distinction this whole gate turns on, asserted directly.
        for location_field in [
            "url",
            "endpoint",
            "issuer",
            "jku",
            "jwks_uri",
            "token_endpoint",
            "webhook",
            "callback_url",
            "agent_card_url",
        ] {
            assert!(
                !FORBIDDEN_FETCH_FIELDS.contains(&location_field),
                "`{location_field}` names a place and would refuse every real document"
            );
        }
        for action_field in ["fetch", "download", "auto_resolve", "probe_webhook"] {
            assert!(FORBIDDEN_FETCH_FIELDS.contains(&action_field));
        }
    }
}
