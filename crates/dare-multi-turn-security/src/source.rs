//! Admission: everything a document must survive before it becomes a value.
//!
//! The order is frozen (Blueprint §1.1) and every step runs before any domain
//! type is constructed:
//!
//! ```text
//! bytes ≤ MAX_INPUT_FILE_BYTES
//!   → UTF-8 JSON
//!   → nesting ≤ MAX_JSON_DEPTH
//!   → schema_version == "1"
//!   → hostile sweep: forbidden field names, control/bidi text, credential-shaped values
//!   → JSON Schema (additionalProperties: false, closed enums)
//! ```
//!
//! The hostile sweep runs before the schema so that a refused field is
//! reported as what it is (a field this engine will not read) rather than as a
//! generic schema mismatch. Neither the sweep nor the schema ever echoes a
//! rejected value.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::error::{MultiTurnError, Result};
use crate::ids::is_forbidden_char;
use crate::limits::{MAX_INPUT_FILE_BYTES, MAX_JSON_DEPTH};
use crate::schema::{assert_supported_version, validate, DocumentKind};

/// Field names that could carry executable behaviour. Nothing here is run.
pub const FORBIDDEN_EXECUTABLE_FIELD_NAMES: [&str; 14] = [
    "shell",
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
    "entrypoint",
    "subprocess",
    "spawn",
];

/// Field names that could carry credential material.
pub const FORBIDDEN_CREDENTIAL_FIELD_NAMES: [&str; 16] = [
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "credential",
    "credentials",
    "authorization",
    "private_key",
    "bearer",
    "jwt",
    "cookie",
];

/// Field names that could point at a model, provider or remote target.
/// Live and remote targets belong to Cycle 022.
pub const FORBIDDEN_REMOTE_FIELD_NAMES: [&str; 8] = [
    "endpoint", "url", "base_url", "host", "model", "provider", "api_base", "webhook",
];

/// Field names that would turn selection into generation (DESIGN RS-06).
pub const FORBIDDEN_GENERATION_FIELD_NAMES: [&str; 12] = [
    "generate",
    "generator",
    "mutate",
    "mutation",
    "mutator",
    "template",
    "prompt_template",
    "paraphrase",
    "rewrite",
    "seed",
    "temperature",
    "sampler",
];

/// Field names by which a fixture could state its own outcome.
pub const FORBIDDEN_VERDICT_FIELD_NAMES: [&str; 10] = [
    "verdict",
    "expected",
    "expected_verdict",
    "expected_result",
    "expected_outcome",
    "should_fail",
    "should_pass",
    "is_vulnerable",
    "is_secure",
    "outcome",
];

/// Substrings that indicate real credential material rather than prose about it.
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

/// Minimum length after `bearer ` for the text to count as a credential, so
/// that prose such as "never send a bearer token" stays writable.
const MIN_BEARER_TOKEN_LEN: usize = 16;

/// Read a file with a hard byte ceiling, never reading past it.
pub fn read_bounded(path: &Path, label: &'static str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(MultiTurnError::Io(format!("{label} is not a regular file")));
    }
    let mut buffer = Vec::new();
    fs::File::open(path)?
        .take(MAX_INPUT_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buffer)?;
    enforce_size(&buffer, label)?;
    Ok(buffer)
}

/// Refuse a document above the byte ceiling.
pub fn enforce_size(raw: &[u8], label: &'static str) -> Result<()> {
    if raw.len() > MAX_INPUT_FILE_BYTES {
        return Err(MultiTurnError::InputTooLarge {
            label,
            len: raw.len(),
            max: MAX_INPUT_FILE_BYTES,
        });
    }
    Ok(())
}

/// Refuse nesting deeper than `MAX_JSON_DEPTH`. Iterative, so a hostile
/// document cannot exhaust the stack of the check meant to stop it.
pub fn check_depth(value: &Value, label: &'static str) -> Result<()> {
    let mut stack = vec![(value, 1usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(MultiTurnError::DepthExceeded {
                label,
                max: MAX_JSON_DEPTH,
            });
        }
        match node {
            Value::Object(map) => stack.extend(map.values().map(|child| (child, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn forbidden_field(key: &str) -> Option<MultiTurnError> {
    let lowered = key.to_ascii_lowercase();
    let groups: [(&[&'static str], &'static str); 5] = [
        (
            &FORBIDDEN_EXECUTABLE_FIELD_NAMES,
            "executable behaviour is never run",
        ),
        (
            &FORBIDDEN_CREDENTIAL_FIELD_NAMES,
            "credential material is never accepted",
        ),
        (
            &FORBIDDEN_REMOTE_FIELD_NAMES,
            "remote targets belong to Cycle 022",
        ),
        (&FORBIDDEN_GENERATION_FIELD_NAMES, "turn generation"),
        (
            &FORBIDDEN_VERDICT_FIELD_NAMES,
            "a fixture may not state its own outcome",
        ),
    ];
    groups.into_iter().find_map(|(names, category)| {
        names
            .iter()
            .find(|name| **name == lowered)
            .map(|name| MultiTurnError::ForbiddenField { name, category })
    })
}

fn contains_bearer_credential(lowered: &str) -> bool {
    const MARKER: &str = "bearer ";
    lowered.match_indices(MARKER).any(|(index, _)| {
        lowered[index + MARKER.len()..]
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .count()
            >= MIN_BEARER_TOKEN_LEN
    })
}

/// Refuse text that is credential-shaped or carries presentation-hostile characters.
///
/// Newline and tab are allowed in values (turn content is prose); every other
/// control, bidi and zero-width character is refused, because it reaches logs
/// and reports.
pub fn check_text(text: &str, field: &'static str, allow_layout: bool) -> Result<()> {
    if let Some(ch) = text
        .chars()
        .find(|c| is_forbidden_char(*c) && !(allow_layout && matches!(c, '\n' | '\t')))
    {
        return Err(MultiTurnError::ForbiddenCharacter {
            field,
            codepoint: ch as u32,
        });
    }
    let lowered = text.to_ascii_lowercase();
    if CREDENTIAL_SHAPED_VALUES.iter().any(|m| lowered.contains(m))
        || contains_bearer_credential(&lowered)
    {
        return Err(MultiTurnError::SecretLikeContent { field });
    }
    Ok(())
}

/// Sweep a document for hostile field names and values at every depth.
pub fn sweep_hostile(value: &Value) -> Result<()> {
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                for (key, child) in map {
                    check_text(key, "field name", false)?;
                    if let Some(error) = forbidden_field(key) {
                        return Err(error);
                    }
                    stack.push(child);
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::String(text) => check_text(text, "value", true)?,
            _ => {}
        }
    }
    Ok(())
}

/// Run the whole admission pipeline over raw bytes.
pub fn admit(raw: &[u8], kind: DocumentKind) -> Result<Value> {
    let label = kind.label();
    enforce_size(raw, label)?;
    let value: Value = serde_json::from_slice(raw)
        .map_err(|_| MultiTurnError::Schema(format!("{label} is not valid JSON")))?;
    check_depth(&value, label)?;
    assert_supported_version(&value, kind)?;
    sweep_hostile(&value)?;
    validate(&value, kind)?;
    Ok(value)
}

/// Read and admit a local file.
pub fn admit_file(path: &Path, kind: DocumentKind) -> Result<Value> {
    admit(&read_bounded(path, kind.label())?, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph() -> Value {
        json!({
            "schema_version": "1", "id": "g1", "root": "n1",
            "nodes": [{"id": "n1", "terminal": true,
                       "turn": {"role": "USER", "request_class": "c1", "content": "hello\nthere"}}],
            "edges": []
        })
    }

    fn admit_value(value: &Value) -> Result<Value> {
        admit(
            &serde_json::to_vec(value).expect("json"),
            DocumentKind::StrategyGraph,
        )
    }

    #[test]
    fn a_well_formed_graph_is_admitted() {
        assert!(admit_value(&graph()).is_ok());
    }

    #[test]
    fn an_oversized_document_is_refused_before_parsing() {
        let raw = vec![b' '; MAX_INPUT_FILE_BYTES + 1];
        assert!(matches!(
            admit(&raw, DocumentKind::Scenario),
            Err(MultiTurnError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut deep = json!(1);
        for _ in 0..MAX_JSON_DEPTH {
            deep = json!([deep]);
        }
        assert!(matches!(
            check_depth(&deep, "t"),
            Err(MultiTurnError::DepthExceeded { .. })
        ));
        let mut shallow = json!(1);
        for _ in 0..MAX_JSON_DEPTH - 1 {
            shallow = json!([shallow]);
        }
        assert!(check_depth(&shallow, "t").is_ok());
    }

    #[test]
    fn every_forbidden_field_group_is_refused_by_name() {
        for (field, name) in [
            ("shell", "shell"),
            ("token", "token"),
            ("endpoint", "endpoint"),
            ("mutate", "mutate"),
            ("TEMPERATURE", "temperature"),
            ("expected_verdict", "expected_verdict"),
        ] {
            let mut doc = graph();
            doc["nodes"][0]["turn"][field] = json!("x");
            match admit_value(&doc) {
                Err(MultiTurnError::ForbiddenField { name: got, .. }) => assert_eq!(got, name),
                other => panic!("`{field}` should be a forbidden field, got {other:?}"),
            }
        }
    }

    #[test]
    fn bidi_and_control_text_is_refused_but_newlines_in_content_are_not() {
        let mut doc = graph();
        doc["nodes"][0]["turn"]["content"] = json!("ok\u{202e}evil");
        assert_eq!(
            admit_value(&doc),
            Err(MultiTurnError::ForbiddenCharacter {
                field: "value",
                codepoint: 0x202e
            })
        );
        assert!(
            admit_value(&graph()).is_ok(),
            "\\n in content is layout, not an attack"
        );
    }

    #[test]
    fn credential_shaped_values_are_refused_but_prose_about_them_is_not() {
        for secret in [
            "key sk-live-abc",
            "Authorization: Bearer abcdefghijklmnopqrstu",
            "ghp_0123",
        ] {
            let mut doc = graph();
            doc["nodes"][0]["turn"]["content"] = json!(secret);
            assert_eq!(
                admit_value(&doc),
                Err(MultiTurnError::SecretLikeContent { field: "value" })
            );
        }
        let mut doc = graph();
        doc["nodes"][0]["turn"]["content"] = json!("never paste a bearer token into chat");
        assert!(admit_value(&doc).is_ok());
    }

    #[test]
    fn urls_inside_content_are_inert_and_admitted() {
        let mut doc = graph();
        doc["nodes"][0]["turn"]["content"] =
            json!("see https://attacker.example/steal for details");
        assert!(admit_value(&doc).is_ok());
    }

    #[test]
    fn a_wrong_version_is_refused_before_the_sweep() {
        let mut doc = graph();
        doc["schema_version"] = json!("2");
        assert!(matches!(admit_value(&doc), Err(MultiTurnError::Schema(_))));
    }

    #[test]
    fn read_bounded_refuses_directories_and_reads_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            read_bounded(dir.path(), "t"),
            Err(MultiTurnError::Io(_))
        ));
        let file = dir.path().join("g.json");
        std::fs::write(&file, serde_json::to_vec(&graph()).expect("json")).expect("write");
        assert!(admit_file(&file, DocumentKind::StrategyGraph).is_ok());
    }
}
