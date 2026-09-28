//! Admission of every input document (BLUEPRINT §3, task-011).
//!
//! Order: byte ceiling, JSON parse, depth, version, hostile sweep, schema,
//! then deserialization into domain types. A document refused here never
//! becomes a Rust value, and a refusal never echoes what it refused.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{RemoteError, Result};
use crate::ids::is_forbidden_char;
use crate::limits::{MAX_INPUT_BYTES, MAX_JSON_DEPTH};
use crate::schema::{assert_supported_version, validate, DocumentKind};

/// Field names that would carry a secret, a raw target, a transport override,
/// executable behaviour, generated content or a self-declared outcome. The
/// match is exact and case-insensitive, so `credential_ref` and `endpoints`
/// (which name, rather than carry) stay admissible.
pub const FORBIDDEN_FIELD_NAMES: [&str; 44] = [
    // credential material
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
    // raw targets and transport overrides
    "url",
    "base_url",
    "endpoint",
    "header",
    "headers",
    "proxy",
    "insecure",
    "follow_redirects",
    "skip_tls_verify",
    "ca_bundle",
    // executable behaviour
    "shell",
    "command",
    "exec",
    "script",
    "callback",
    "plugin",
    // generation
    "generate",
    "generator",
    "mutate",
    "template",
    "seed",
    "temperature",
    // self-declared outcomes
    "verdict",
    "expected_verdict",
    "should_fail",
    "should_pass",
    "is_secure",
    "is_vulnerable",
];

/// Case-insensitive substrings of real credential material.
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
    "github_pat_",
];

/// Read a file with a hard byte ceiling, never reading past it.
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(RemoteError::Refused("input is not a regular file"));
    }
    let mut buffer = Vec::new();
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut buffer)?;
    if buffer.len() > max {
        return Err(RemoteError::Refused("input exceeds its byte ceiling"));
    }
    Ok(buffer)
}

/// Refuse nesting deeper than `MAX_JSON_DEPTH`, iteratively.
pub fn check_depth(value: &Value) -> Result<()> {
    let mut stack = vec![(value, 1usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(RemoteError::Refused("input nests deeper than 32"));
        }
        match node {
            Value::Object(map) => stack.extend(map.values().map(|child| (child, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn credential_shaped(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    if CREDENTIAL_SHAPED_VALUES.iter().any(|m| lowered.contains(m)) {
        return true;
    }
    let jwt = lowered.contains("eyj")
        && text
            .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
            .any(|t| t.starts_with("eyJ") && t.matches('.').count() >= 2 && t.len() >= 20);
    let bearer = lowered.match_indices("bearer ").any(|(i, _)| {
        lowered[i + 7..]
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .count()
            >= 16
    });
    jwt || bearer
}

/// Sweep field names and string values at every depth.
pub fn sweep_hostile(value: &Value) -> Result<()> {
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                for (key, child) in map {
                    if let Some(ch) = key.chars().find(|c| is_forbidden_char(*c)) {
                        return Err(RemoteError::ForbiddenCharacter {
                            field: "field name",
                            codepoint: ch as u32,
                        });
                    }
                    let lowered = key.to_ascii_lowercase();
                    if FORBIDDEN_FIELD_NAMES.contains(&lowered.as_str()) {
                        return Err(RemoteError::Refused("a forbidden field name is present"));
                    }
                    stack.push(child);
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::String(text) => {
                if let Some(ch) = text.chars().find(|c| is_forbidden_char(*c)) {
                    return Err(RemoteError::ForbiddenCharacter {
                        field: "value",
                        codepoint: ch as u32,
                    });
                }
                if credential_shaped(text) {
                    return Err(RemoteError::Refused("a value is credential-shaped"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run the admission pipeline and deserialize.
pub fn admit<T: DeserializeOwned>(raw: &[u8], kind: DocumentKind) -> Result<T> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(RemoteError::Refused("input exceeds its byte ceiling"));
    }
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| RemoteError::Refused("input is not valid JSON"))?;
    check_depth(&value)?;
    assert_supported_version(&value, kind)?;
    sweep_hostile(&value)?;
    validate(&value, kind)?;
    serde_json::from_value(value)
        .map_err(|_| RemoteError::Refused("input does not match its model"))
}

/// Read and admit a local file.
pub fn admit_file<T: DeserializeOwned>(path: &Path, kind: DocumentKind) -> Result<T> {
    admit(&read_bounded(path, MAX_INPUT_BYTES)?, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{tests::authorization, Authorization};
    use crate::plan::{tests::plan, RemotePlan};

    fn auth_bytes() -> Vec<u8> {
        serde_json::to_vec(&authorization()).unwrap()
    }

    fn with(mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(&auth_bytes()).unwrap();
        mutate(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn well_formed_documents_are_admitted() {
        let a: Authorization =
            admit(&auth_bytes(), DocumentKind::Authorization).expect("authorization");
        assert_eq!(a, authorization());
        let p: RemotePlan =
            admit(&serde_json::to_vec(&plan()).unwrap(), DocumentKind::Plan).expect("plan");
        assert_eq!(p, plan());
    }

    #[test]
    fn oversize_and_deep_documents_are_refused_before_parsing() {
        let big = vec![b' '; MAX_INPUT_BYTES + 1];
        assert!(matches!(
            admit::<Value>(&big, DocumentKind::Plan),
            Err(RemoteError::Refused(_))
        ));
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert!(matches!(
            admit::<Value>(deep.as_bytes(), DocumentKind::Plan),
            Err(RemoteError::Refused("input nests deeper than 32"))
        ));
    }

    #[test]
    fn a_wrong_version_is_refused_first() {
        let raw = with(|v| v["schema_version"] = "2".into());
        assert!(
            matches!(admit::<Authorization>(&raw, DocumentKind::Authorization), Err(RemoteError::Refused(m)) if m.contains("schema_version"))
        );
    }

    #[test]
    fn every_forbidden_field_name_is_refused_in_any_case() {
        for name in FORBIDDEN_FIELD_NAMES {
            for spelled in [name.to_owned(), name.to_ascii_uppercase()] {
                let raw =
                    with(|v| v["target_owner_extra"] = serde_json::json!({ spelled.clone(): "x" }));
                assert!(
                    admit::<Authorization>(&raw, DocumentKind::Authorization).is_err(),
                    "{spelled}"
                );
            }
        }
        let raw = with(|v| v["endpoints"]["url"] = "https://x.test".into());
        assert!(matches!(
            admit::<Authorization>(&raw, DocumentKind::Authorization),
            Err(RemoteError::Refused(_))
        ));
    }

    #[test]
    fn credential_shaped_values_are_refused_but_the_reference_is_not() {
        for secret in [
            &["sk-", "live-0123456789"].concat(),
            "Bearer abcdefghijklmnopqrstu",
            &["eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxIn0.x"].concat(),
            &["-----BEGIN", " PRIVATE KEY-----"].concat(),
        ] {
            let raw = with(|v| v["target_owner"] = secret.into());
            assert!(
                matches!(
                    admit::<Authorization>(&raw, DocumentKind::Authorization),
                    Err(RemoteError::Refused(_))
                ),
                "{secret}"
            );
        }
        let a: Authorization = admit(&auth_bytes(), DocumentKind::Authorization).unwrap();
        assert_eq!(a.credential_ref.as_deref(), Some("DARE_REMOTE_LAB_TOKEN"));
    }

    #[test]
    fn control_and_bidi_characters_are_refused_by_codepoint() {
        let raw = with(|v| v["approved_by"] = "Product\u{202e}Owner".into());
        assert!(matches!(
            admit::<Authorization>(&raw, DocumentKind::Authorization),
            Err(RemoteError::ForbiddenCharacter {
                codepoint: 0x202e,
                ..
            })
        ));
    }

    #[test]
    fn schema_violations_report_the_pointer() {
        let raw = with(|v| v["origins"] = serde_json::json!([]));
        match admit::<Authorization>(&raw, DocumentKind::Authorization) {
            Err(RemoteError::Schema { pointer }) => assert_eq!(pointer, "/origins"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn read_bounded_refuses_directories_and_oversize_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_bounded(dir.path(), 10).is_err());
        let file = dir.path().join("a.json");
        fs::write(&file, b"0123456789A").unwrap();
        assert!(read_bounded(&file, 10).is_err());
        assert_eq!(read_bounded(&file, 11).unwrap().len(), 11);
    }
}
