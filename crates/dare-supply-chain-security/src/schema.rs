//! The document gate: what this engine refuses to read at all.
//!
//! A bill of materials is a file somebody else produced, often by a tool
//! nobody in the room has audited, describing artifacts from places nobody in
//! the room controls. It arrives before any of this cycle's reasoning starts,
//! which makes it the widest input surface the engine has.
//!
//! So the sweep runs **before** the schema, and the schema runs before the
//! typed decode. Three gates rather than one, because each catches something
//! the others structurally cannot:
//!
//! 1. the sweep sees *every* value at every depth, including inside fields no
//!    model has a place for;
//! 2. the schema enforces shape and closes the object;
//! 3. `deny_unknown_fields` on the typed model catches anything that reached
//!    the decoder despite both.
//!
//! Two rules govern what the refusals may say. A refusal must not echo what it
//! refused — a message quoting a smuggled token back would persist the
//! credential it declined to store, and an error log is a persistence surface
//! like any other. And a refusal must not read as a verdict: it is a statement
//! about a document, never about the security of the system that document
//! describes.

use serde_json::Value;

use crate::error::{Result, SupplyChainError};
use crate::limits;

/// Field names that would carry a credential.
///
/// The *name* is what is refused, whatever it holds. An empty `private_key`
/// field is refused too: leaving it available is leaving it for the next author
/// to fill in.
const FORBIDDEN_CREDENTIAL_FIELDS: [&str; 24] = [
    "password",
    "passwd",
    "secret",
    "client_secret",
    "clientsecret",
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "bearer_token",
    "bearertoken",
    "private_key",
    "privatekey",
    "signing_key",
    "signingkey",
    "credential",
    "credentials",
    "cookie",
    "session_token",
    "authorization",
    "auth_header",
];

/// Field names that would ask the engine to run something.
///
/// A bill of materials describes what a system is made of. Nothing in it is an
/// instruction, and a field that looks like one is either a mistake or an
/// attempt to turn a parser into an executor.
const FORBIDDEN_EXECUTABLE_FIELDS: [&str; 18] = [
    "command",
    "cmd",
    "exec",
    "execute",
    "entrypoint",
    "shell",
    "script",
    "run",
    "run_script",
    "preinstall",
    "postinstall",
    "install_script",
    "hook",
    "hooks",
    "callback",
    "callback_url",
    "webhook",
    "eval",
];

/// Field names that would ask the engine to go and get something.
///
/// Note what is *not* here: `purl`, `download_location`, `external_references`,
/// `repository`. Those are legitimate BOM fields carrying coordinates, and
/// coordinates are inert metadata in this model. What is refused is a field
/// whose name asserts an *action* rather than a location.
const FORBIDDEN_FETCH_FIELDS: [&str; 14] = [
    "fetch",
    "fetch_url",
    "download",
    "download_url",
    "pull",
    "pull_policy",
    "resolve_remote",
    "registry_credentials",
    "auto_update",
    "auto_fetch",
    "remote_exec",
    "clone_url_action",
    "verify_remote",
    "transparency_log_url",
];

/// Field names that would let a document state its own verdict.
///
/// The evaluator is the only verdict authority. A document that could declare
/// its own outcome would reduce the engine to agreeing with whoever wrote it.
const FORBIDDEN_VERDICT_FIELDS: [&str; 12] = [
    "verdict",
    "expected_verdict",
    "expected_outcome",
    "expected_findings",
    "should_pass",
    "should_fail",
    "is_secure",
    "is_vulnerable",
    "security_verdict",
    "assessment_result",
    "risk_score",
    "confidence",
];

/// Value fragments that indicate real credential material.
///
/// All lowercase, because the check lowercases the value first. A marker with
/// capitals here would never match, which is a bug Cycle 018 shipped and this
/// crate's `every_credential_marker_is_lowercase` prevents.
const CREDENTIAL_SHAPED_VALUES: [&str; 12] = [
    "-----begin",
    "sk-live-",
    "sk_live_",
    "ghp_",
    "gho_",
    "ghs_",
    "xoxb-",
    "xoxp-",
    "akia",
    "ya29.",
    "eyjhbgci",
    "aws_secret_access_key",
];

/// URL schemes that would name something fetchable if anything here fetched.
const FORBIDDEN_URL_SCHEMES: [&str; 9] = [
    "file://",
    "ftp://",
    "ssh://",
    "ws://",
    "wss://",
    "gopher://",
    "jar:",
    "data:text/html",
    "javascript:",
];

/// Refuse a document that is larger than the engine will read.
///
/// Called before `serde_json` sees the bytes. A 40 MB document refused after
/// parsing has already been parsed.
pub fn enforce_document_size(raw: &[u8], label: &str) -> Result<()> {
    if raw.len() > limits::HARD_MAX_BOM_BYTES {
        return Err(SupplyChainError::BudgetExhausted(format!(
            "{label} is {} bytes; the hard maximum is {}",
            raw.len(),
            limits::HARD_MAX_BOM_BYTES
        )));
    }
    Ok(())
}

/// Maximum nesting a document may reach.
///
/// A deeply nested document is a stack-exhaustion attempt dressed as data, and
/// checking depth explicitly is cheaper than recursing to find out.
const MAX_DEPTH: usize = 64;

/// Sweep a parsed document for anything the engine will not read.
///
/// Runs over the whole value at every depth, including inside objects no model
/// has a field for — which is the point. A hostile field placed where nothing
/// will decode it is still a field in a document the engine is about to accept.
pub fn assert_no_hostile_fields(value: &Value, label: &str) -> Result<()> {
    sweep(value, label, 0)
}

fn sweep(value: &Value, label: &str, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(SupplyChainError::refusal(format!(
            "{label} nests deeper than {MAX_DEPTH} levels"
        )));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert_field_allowed(key, label)?;
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

fn assert_field_allowed(field: &str, label: &str) -> Result<()> {
    let lowered = field.to_ascii_lowercase();
    let normalized = lowered.replace(['-', ' '], "_");

    for forbidden in FORBIDDEN_CREDENTIAL_FIELDS {
        if normalized == forbidden {
            return Err(SupplyChainError::refusal(format!(
                "{label} carries a credential field; this engine reads bills of materials, and \
                 a bill of materials has no reason to contain one"
            )));
        }
    }
    for forbidden in FORBIDDEN_EXECUTABLE_FIELDS {
        if normalized == forbidden {
            return Err(SupplyChainError::refusal(format!(
                "{label} carries an executable field; a bill of materials describes what a \
                 system is made of and never what to run"
            )));
        }
    }
    for forbidden in FORBIDDEN_FETCH_FIELDS {
        if normalized == forbidden {
            return Err(SupplyChainError::refusal(format!(
                "{label} carries a field asserting a remote action; a coordinate is inert \
                 metadata here, and an instruction is not"
            )));
        }
    }
    for forbidden in FORBIDDEN_VERDICT_FIELDS {
        if normalized == forbidden {
            return Err(SupplyChainError::refusal(format!(
                "{label} carries a verdict field; the evaluator is the only verdict authority"
            )));
        }
    }
    Ok(())
}

fn assert_value_allowed(text: &str, label: &str) -> Result<()> {
    // Newline, tab and carriage return stay allowed: description fields are
    // prose, and refusing a newline would be refusing documentation. Every
    // other control character is refused wherever it appears — none is ever
    // legitimate, and they are what forges a log line or truncates a terminal.
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r')
    {
        return Err(SupplyChainError::refusal(format!(
            "{label} carries a control character, which could forge a log line"
        )));
    }

    let lowered = text.to_ascii_lowercase();
    for marker in CREDENTIAL_SHAPED_VALUES {
        if lowered.contains(marker) {
            return Err(SupplyChainError::refusal(format!(
                "{label} carries a value shaped like real credential material"
            )));
        }
    }
    if contains_bearer_credential(&lowered) {
        return Err(SupplyChainError::refusal(format!(
            "{label} carries a value shaped like a bearer credential"
        )));
    }
    for scheme in FORBIDDEN_URL_SCHEMES {
        if lowered.contains(scheme) {
            return Err(SupplyChainError::refusal(format!(
                "{label} names a target with a scheme this engine will not record"
            )));
        }
    }
    Ok(())
}

/// Whether a lowercased string carries something shaped like a bearer token.
///
/// Anchored on shape rather than on the word, so an honest sentence — "an
/// inbound bearer credential must not become upstream authority" — stays
/// writable while a real one does not.
pub fn contains_bearer_credential(lowered: &str) -> bool {
    let Some(offset) = lowered.find("bearer ") else {
        return false;
    };
    let rest = &lowered[offset + "bearer ".len()..];
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '='))
        .collect();
    token.len() >= 20
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_credential_marker_is_lowercase() {
        // Cycle 018 shipped markers with capitals compared against a lowercased
        // string, so `AKIA` and `eyJhbGci` never matched anything. The bug was
        // invisible: the list looked right.
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
        for list in [
            &FORBIDDEN_CREDENTIAL_FIELDS[..],
            &FORBIDDEN_EXECUTABLE_FIELDS[..],
            &FORBIDDEN_FETCH_FIELDS[..],
            &FORBIDDEN_VERDICT_FIELDS[..],
        ] {
            let unique: std::collections::BTreeSet<_> = list.iter().collect();
            assert_eq!(unique.len(), list.len(), "a forbidden list repeats itself");
        }
    }

    #[test]
    fn a_credential_field_is_refused_at_any_depth() {
        // The reason the sweep runs over the whole document rather than over
        // the fields a model declares: a hostile field placed where nothing
        // will decode it is still in a document about to be accepted.
        let hostile = json!({
            "components": [{
                "name": "react",
                "properties": { "build": { "env": { "api_key": "x" } } }
            }]
        });
        let err = assert_no_hostile_fields(&hostile, "bom").expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_credential_field_is_refused_even_when_empty() {
        // The field is what is wrong. Admitting the empty case leaves it
        // available for the next author to fill in.
        let hostile = json!({ "private_key": "" });
        assert!(assert_no_hostile_fields(&hostile, "bom").is_err());
    }

    #[test]
    fn an_executable_or_fetch_field_is_refused() {
        for field in [
            "command",
            "entrypoint",
            "postinstall",
            "hook",
            "callback_url",
            "download_url",
            "pull_policy",
            "auto_fetch",
            "transparency_log_url",
        ] {
            let hostile = json!({ "components": [{ field: "anything" }] });
            assert!(
                assert_no_hostile_fields(&hostile, "bom").is_err(),
                "`{field}` was admitted"
            );
        }
    }

    #[test]
    fn ordinary_bom_coordinate_fields_stay_readable() {
        // The other half, and the one that matters for usefulness. A BOM is
        // *made of* coordinates: a purl, a download location, external
        // references, a repository. Those are inert metadata in this model, and
        // an engine that refused them would refuse every real document.
        let ordinary = json!({
            "components": [{
                "name": "react",
                "version": "18.3.1",
                "purl": "pkg:npm/react@18.3.1",
                "downloadLocation": "registry.npmjs.org/react/-/react-18.3.1.tgz",
                "externalReferences": [
                    { "type": "distribution", "url": "registry.npmjs.org/react" }
                ],
                "repository": "github.com/facebook/react",
                "supplier": { "name": "Meta" }
            }]
        });
        assert_no_hostile_fields(&ordinary, "bom").expect("a real BOM must stay readable");
    }

    #[test]
    fn a_verdict_field_is_refused() {
        // A document that could declare its own outcome would reduce the
        // evaluator to agreeing with whoever wrote it.
        for field in [
            "verdict",
            "expected_verdict",
            "should_fail",
            "is_secure",
            "risk_score",
        ] {
            let hostile = json!({ field: "PASS" });
            assert!(
                assert_no_hostile_fields(&hostile, "bom").is_err(),
                "`{field}` was admitted"
            );
        }
    }

    #[test]
    fn a_credential_shaped_value_is_refused_wherever_it_appears() {
        for hostile in [
            "-----BEGIN PRIVATE KEY-----",
            "sk-live-000000000000000000000000",
            "ghp_0000000000000000000000000000000000",
            "AKIAIOSFODNN7EXAMPLE",
            "ya29.a0AfH6SMB000",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
        ] {
            let document = json!({ "components": [{ "name": hostile }] });
            assert!(
                assert_no_hostile_fields(&document, "bom").is_err(),
                "`{hostile}` was admitted"
            );
        }
    }

    #[test]
    fn prose_about_credentials_stays_writable() {
        // Anchored on shape, so a description field can discuss the subject.
        let ordinary = json!({
            "components": [{
                "name": "auth-helper",
                "description": "Handles bearer tokens and API keys without logging them."
            }]
        });
        assert_no_hostile_fields(&ordinary, "bom").expect("prose must stay writable");
        assert!(!contains_bearer_credential("bearer tokens are not logged"));
        assert!(contains_bearer_credential(
            "authorization: bearer abcdefghijklmnopqrstuvwx"
        ));
    }

    #[test]
    fn a_control_character_is_refused_and_a_newline_is_not() {
        let hostile = json!({ "components": [{ "name": "react\u{7}" }] });
        assert!(assert_no_hostile_fields(&hostile, "bom").is_err());

        let prose = json!({ "components": [{ "description": "line one\nline two\ttabbed" }] });
        assert_no_hostile_fields(&prose, "bom").expect("prose fields are sentences");
    }

    #[test]
    fn a_refusal_never_echoes_what_it_refused() {
        // Reporting the attack must not perform it. An error log is a
        // persistence surface like any other.
        let hostile = json!({
            "components": [{ "name": "sk-live-000000000000000000000000" }],
            "api_key": "ghp_0000000000000000000000000000000000"
        });
        let err = assert_no_hostile_fields(&hostile, "bom").expect_err("refused");
        let message = err.to_string();
        for marker in ["sk-live-", "ghp_", "api_key"] {
            assert!(!message.contains(marker), "the refusal echoed `{marker}`");
        }
    }

    #[test]
    fn no_refusal_reads_as_a_security_verdict() {
        let cases = [
            json!({ "command": "rm -rf /" }),
            json!({ "verdict": "PASS" }),
            json!({ "password": "x" }),
            json!({ "components": [{ "name": "a\u{202E}b" }] }),
        ];
        for case in cases {
            let Err(err) = assert_no_hostile_fields(&case, "bom") else {
                continue;
            };
            let message = err.to_string();
            for verdict in ["PASS", "FAIL", "INCONCLUSIVE"] {
                assert!(
                    !message.contains(verdict),
                    "a refusal reads as the verdict {verdict}"
                );
            }
        }
    }

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        let big = vec![b'x'; limits::HARD_MAX_BOM_BYTES + 1];
        assert!(enforce_document_size(&big, "bom").is_err());
        assert!(enforce_document_size(&big[..limits::HARD_MAX_BOM_BYTES], "bom").is_ok());
    }

    #[test]
    fn deeply_nested_documents_are_refused_rather_than_recursed() {
        let mut value = json!("leaf");
        for _ in 0..(MAX_DEPTH + 5) {
            value = json!({ "child": value });
        }
        assert!(assert_no_hostile_fields(&value, "bom").is_err());
    }

    #[test]
    fn a_hyphenated_or_spaced_field_name_is_normalized_before_comparison() {
        // `api-key` and `api key` are the same field wearing different
        // punctuation, and a check that missed them would be trivially evaded.
        for field in ["api-key", "api key", "API_KEY", "Private-Key"] {
            let hostile = json!({ field: "x" });
            assert!(
                assert_no_hostile_fields(&hostile, "bom").is_err(),
                "`{field}` was admitted"
            );
        }
    }

    #[test]
    fn a_forbidden_scheme_is_refused_and_a_plain_coordinate_is_not() {
        for hostile in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ssh://host/repo",
        ] {
            let document = json!({ "components": [{ "name": "x", "reference": hostile }] });
            assert!(
                assert_no_hostile_fields(&document, "bom").is_err(),
                "`{hostile}` was admitted"
            );
        }
        // A registry coordinate without a scheme is exactly what a real BOM
        // carries, and refusing it would refuse every real document.
        let ordinary = json!({ "components": [{ "reference": "registry.npmjs.org/react" }] });
        assert_no_hostile_fields(&ordinary, "bom").expect("a coordinate is inert metadata");
    }
}
