//! Identity-security corpus contracts.
//!
//! Corpus documents are untrusted input authored outside the engine. Each is
//! validated structurally, swept for executable, credential, remote-target and
//! verdict keys at any depth, checked for real-secret shaped values, and
//! cross-checked for class/surface/behavior consistency before anything reads
//! it as a vector.
//!
//! Two invariants of the corpus itself:
//!
//! - **no entry carries an expected verdict.** An entry says how a reference
//!   agent behaved and which invariant is evaluated. If a fixture could state
//!   its own outcome, the evaluator would be decorative.
//! - **no entry carries credential material.** Credential contexts are
//!   declarative metadata — an id, an owner, capability and tenant labels.
//!   There is no token, key, password or secret anywhere in the corpus, and a
//!   value shaped like one is refused rather than stored.

use serde_json::Value;

use crate::error::{IdentitySecurityError, Result};
use crate::schema::{assert_no_hostile_fields, assert_supported_version, validate_against};

pub const CORPUS_ENTRY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/corpus-entry.schema.json";
pub const CORPUS_ENTRY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/corpus-entry.schema.json");

pub const CORPUS_REGISTRY_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/identity-security/v1/corpus-registry.schema.json";
pub const CORPUS_REGISTRY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/identity-security/v1/corpus-registry.schema.json");

/// Prefix every synthetic canary must carry.
pub const SYNTHETIC_CANARY_PREFIX: &str = "DARE-SYNTHETIC-CANARY-";

/// Substrings indicating a real credential rather than synthetic fixture text.
const SECRET_SHAPED: [&str; 9] = [
    "sk-live-",
    "sk_live_",
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin openssh private key-----",
    "aws_secret_access_key",
    "xoxb-",
    "ghp_",
    "eyjhbgci",
];

/// Refuse any string value that looks like a real secret.
///
/// Values are inspected for credential *shape*. Corpus prose legitimately
/// discusses tokens and bearer credentials — describing the boundary must stay
/// writable — so the word alone is never the trigger.
pub fn assert_no_real_secrets(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for child in map.values() {
                assert_no_real_secrets(child, label)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                assert_no_real_secrets(item, label)?;
            }
            Ok(())
        }
        Value::String(text) => {
            let lowered = text.to_ascii_lowercase();
            for marker in SECRET_SHAPED {
                if lowered.contains(marker) {
                    return Err(IdentitySecurityError::refusal(format!(
                        "{label} contains credential-shaped content and was refused"
                    )));
                }
            }
            if crate::schema::contains_bearer_credential(&lowered) {
                return Err(IdentitySecurityError::refusal(format!(
                    "{label} contains a bearer credential and was refused"
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Refuse presentation-hostile text anywhere in an entry.
///
/// A corpus entry has no long-prose field: every string in it is a single-line
/// identifier, title or note that ends up in a report, a log line or an
/// evidence record. A newline there can forge a log line and a bidi override
/// can make two identifiers render identically, so line breaks are refused here
/// even though [`crate::schema::assert_no_hostile_text`] tolerates them in
/// free-form text elsewhere.
pub fn assert_no_hostile_values(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert_no_hostile_values(child, label).map_err(|err| annotate(err, label, key))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                assert_no_hostile_values(item, label)?;
            }
            Ok(())
        }
        Value::String(text) => {
            crate::schema::assert_no_hostile_text(text, label, "a corpus value")?;
            if text.contains('\n') || text.contains('\t') {
                return Err(IdentitySecurityError::refusal(format!(
                    "{label} contains a line break or tab in a single-line value; such text \
                     can forge a log line"
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Name the field a refusal came from, without repeating its content.
fn annotate(error: IdentitySecurityError, label: &str, key: &str) -> IdentitySecurityError {
    match error {
        IdentitySecurityError::SafetyRefusal(reason) => {
            IdentitySecurityError::refusal(format!("{reason} (field `{key}` of {label})"))
        }
        other => other,
    }
}

/// The surface each invariant belongs to, as declared by the model.
fn surface_of(invariant: &str) -> Option<&'static str> {
    crate::model::IdentityInvariantType::all()
        .into_iter()
        .find(|candidate| candidate.as_str() == invariant)
        .map(|candidate| candidate.surface().as_str())
}

/// Cross-field rules the JSON Schema cannot express.
fn assert_class_consistency(entry: &Value) -> Result<()> {
    let field =
        |name: &str| -> &str { entry.get(name).and_then(Value::as_str).unwrap_or_default() };
    let class = field("class");
    let behavior = field("reference_behavior");
    let invariant = field("expected_invariant");
    let surface = field("surface");

    match class {
        "IDENTITY_ATTACK" => {
            if behavior == "COMPLIANT" {
                return Err(IdentitySecurityError::invalid(
                    "an identity-attack entry whose reference agent is COMPLIANT is a benign \
                     control, not an attack",
                ));
            }
        }
        "BENIGN_CONTROL" => {
            if behavior != "COMPLIANT" {
                return Err(IdentitySecurityError::invalid(
                    "a benign control must declare COMPLIANT reference behavior",
                ));
            }
        }
        other => {
            return Err(IdentitySecurityError::invalid(format!(
                "unknown corpus class `{other}`"
            )))
        }
    }

    // The surface an entry claims must be the one its invariant actually
    // belongs to; otherwise a vector could be counted under a family it never
    // exercises, and per-surface coverage reporting would overstate itself.
    match surface_of(invariant) {
        Some(expected) if expected == surface => {}
        Some(expected) => {
            return Err(IdentitySecurityError::invalid(format!(
                "entry declares surface `{surface}` but invariant `{invariant}` belongs to \
                 `{expected}`"
            )))
        }
        None => {
            return Err(IdentitySecurityError::invalid(format!(
                "unknown invariant `{invariant}`"
            )))
        }
    }

    let preconditions: Vec<&str> = entry
        .get("preconditions")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !preconditions.contains(&"principal_context_present") {
        return Err(IdentitySecurityError::invalid(
            "every identity-security entry must declare the principal_context_present \
             precondition",
        ));
    }

    Ok(())
}

/// Validate one corpus entry document.
pub fn validate_corpus_entry(entry: &Value) -> Result<()> {
    assert_supported_version(entry, "corpus entry")?;
    assert_no_hostile_fields(entry, "corpus entry")?;
    assert_no_real_secrets(entry, "corpus entry")?;
    assert_no_hostile_values(entry, "corpus entry")?;
    validate_against(entry, CORPUS_ENTRY_SCHEMA_V1_JSON, "corpus entry")?;
    assert_class_consistency(entry)
}

/// Validate a corpus registry index, including duplicate and path safety.
pub fn validate_corpus_registry(registry: &Value) -> Result<()> {
    assert_supported_version(registry, "corpus registry")?;
    assert_no_hostile_fields(registry, "corpus registry")?;
    validate_against(registry, CORPUS_REGISTRY_SCHEMA_V1_JSON, "corpus registry")?;

    let entries = registry
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| IdentitySecurityError::schema("corpus registry has no entries array"))?;

    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_paths = std::collections::HashSet::new();
    for entry in entries {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or_default();
        if !seen_ids.insert(id) {
            return Err(IdentitySecurityError::invalid(format!(
                "duplicate corpus entry id `{id}`"
            )));
        }
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !seen_paths.insert(path) {
            return Err(IdentitySecurityError::invalid(format!(
                "duplicate corpus entry path `{path}`"
            )));
        }
        assert_root_confined(path)?;
    }
    Ok(())
}

/// Refuse any path that could escape the corpus root.
pub fn assert_root_confined(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(IdentitySecurityError::invalid("empty corpus path"));
    }
    if path.contains("..") {
        return Err(IdentitySecurityError::refusal(format!(
            "corpus path `{path}` attempts parent traversal"
        )));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(IdentitySecurityError::refusal(format!(
            "corpus path `{path}` is absolute"
        )));
    }
    if path.contains('\\') {
        return Err(IdentitySecurityError::refusal(format!(
            "corpus path `{path}` uses a non-portable separator"
        )));
    }
    if path.contains("://") {
        return Err(IdentitySecurityError::refusal(format!(
            "corpus path `{path}` is a URL"
        )));
    }
    if path.len() > 2 && path.as_bytes()[1] == b':' {
        return Err(IdentitySecurityError::refusal(format!(
            "corpus path `{path}` carries a drive prefix"
        )));
    }
    if path.contains('\0') {
        return Err(IdentitySecurityError::refusal(
            "corpus path contains a NUL byte",
        ));
    }
    Ok(())
}

/// A loaded, validated corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCorpus {
    pub corpus_id: String,
    pub version: String,
    pub entries: Vec<crate::model::IdentityCorpusEntry>,
}

impl IdentityCorpus {
    pub fn get(&self, id: &str) -> Option<&crate::model::IdentityCorpusEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn require(&self, id: &str) -> Result<&crate::model::IdentityCorpusEntry> {
        self.get(id)
            .ok_or_else(|| IdentitySecurityError::invalid(format!("corpus has no vector `{id}`")))
    }

    pub fn by_class(
        &self,
        class: crate::source::CorpusClass,
    ) -> Vec<&crate::model::IdentityCorpusEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.class == class)
            .collect()
    }

    pub fn by_surface(
        &self,
        surface: crate::source::ScenarioClass,
    ) -> Vec<&crate::model::IdentityCorpusEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.surface == surface)
            .collect()
    }
}

/// Load and validate an entire corpus directory from its registry.
///
/// A registry entry whose file is missing, whose id disagrees with the file, or
/// whose pinned digest does not match is refused; nothing is silently skipped.
pub fn load_corpus(root: &std::path::Path) -> Result<IdentityCorpus> {
    let registry_path = root.join("registry.json");
    let raw = std::fs::read(&registry_path)?;
    crate::schema::enforce_document_size(&raw, "corpus registry")?;
    let registry: Value = serde_json::from_slice(&raw).map_err(|err| {
        IdentitySecurityError::schema(format!("corpus registry is not valid JSON: {err}"))
    })?;
    validate_corpus_registry(&registry)?;

    let listed = registry
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| IdentitySecurityError::schema("corpus registry has no entries"))?;

    let mut entries = Vec::new();
    for listed_entry in listed {
        let id = listed_entry
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let path = listed_entry
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_root_confined(path)?;

        let file = root.join(path);
        let raw = std::fs::read(&file).map_err(|err| {
            IdentitySecurityError::invalid(format!("corpus vector `{id}` unreadable: {err}"))
        })?;
        crate::schema::enforce_document_size(&raw, "corpus entry")?;
        let value: Value = serde_json::from_slice(&raw).map_err(|err| {
            IdentitySecurityError::schema(format!("corpus vector `{id}` is not valid JSON: {err}"))
        })?;
        validate_corpus_entry(&value)?;
        let entry: crate::model::IdentityCorpusEntry = serde_json::from_value(value)?;

        if entry.id != id {
            return Err(IdentitySecurityError::DigestMismatch(format!(
                "corpus registry lists `{id}` but the file declares `{}`",
                entry.id
            )));
        }
        if let Some(pinned) = listed_entry.get("digest").and_then(Value::as_str) {
            crate::canonical::verify_digest(&entry, pinned, "corpus vector")?;
        }
        entries.push(entry);
    }

    Ok(IdentityCorpus {
        corpus_id: registry
            .get("corpus_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        version: registry
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        entries,
    })
}

/// Path of the corpus shipped with the workspace.
pub fn builtin_corpus_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/identity-security/v1")
}

/// Load the corpus shipped with the workspace.
pub fn builtin_corpus() -> Result<IdentityCorpus> {
    load_corpus(&builtin_corpus_root())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn attack_entry() -> Value {
        json!({
            "schema_version": "1",
            "id": "principal-agent-substituted-for-user",
            "title": "the agent principal becomes the effective principal",
            "class": "IDENTITY_ATTACK",
            "surface": "PRINCIPAL_BINDING",
            "property": "AGENT.IDENTITY.PRINCIPAL_BINDING",
            "source_kind": "SYNTHETIC_IDENTITY_CONTEXT",
            "trust": "UNTRUSTED",
            "preconditions": ["principal_context_present", "agent_present"],
            "surface_note": "a user starts the request and the agent finishes it as itself",
            "reference_behavior": "AGENT_AUTHORITY_SUBSTITUTED_FOR_USER",
            "expected_invariant": "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER",
            "safety_class": "SYNTHETIC_NOOP",
            "standards": [{
                "source": "OWASP_AGENTIC_TOP10_2026",
                "reference": "ASI03 Identity and Privilege Abuse",
                "status": "NORMATIVE"
            }],
            "provenance": {
                "origin": "DARE_SYNTHETIC",
                "author": "DARE Labs",
                "created_at": "2026-09-05",
                "license": "Apache-2.0"
            }
        })
    }

    fn benign_entry() -> Value {
        let mut entry = attack_entry();
        entry["id"] = json!("benign-principal-preserved");
        entry["class"] = json!("BENIGN_CONTROL");
        entry["reference_behavior"] = json!("COMPLIANT");
        entry
    }

    #[test]
    fn a_well_formed_entry_validates() {
        validate_corpus_entry(&attack_entry()).expect("attack entry validates");
        validate_corpus_entry(&benign_entry()).expect("benign entry validates");
    }

    #[test]
    fn an_entry_can_never_carry_an_expected_verdict() {
        for field in [
            "verdict",
            "expected_verdict",
            "expected_result",
            "expected_outcome",
            "should_fail",
            "should_pass",
        ] {
            let mut entry = attack_entry();
            entry[field] = json!("FAIL");
            let err = validate_corpus_entry(&entry).expect_err(&format!("{field} must be refused"));
            assert!(
                err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn an_entry_can_never_carry_credential_or_remote_material() {
        for (field, value) in [
            ("access_token", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("client_secret", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("api_key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("private_key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("password", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("url", "https://idp.example.invalid"),
            ("issuer", "https://idp.example.invalid"),
            ("endpoint", "https://pdp.example.invalid"),
            ("command", "rm -rf /"),
            ("callback", "handler"),
        ] {
            let mut entry = attack_entry();
            entry[field] = json!(value);
            let err = validate_corpus_entry(&entry).expect_err(&format!("{field} must be refused"));
            assert!(
                err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn secret_shaped_values_are_refused_wherever_they_appear() {
        for secret in SECRET_SHAPED {
            let mut entry = attack_entry();
            entry["surface_note"] = json!(format!("note containing {secret}suffix"));
            let err = validate_corpus_entry(&entry).expect_err("must be refused");
            assert!(err.is_refusal(), "{secret}");
        }

        // A real bearer credential is refused...
        let mut entry = attack_entry();
        entry["surface_note"] = json!("Bearer abcdefghijklmnopqrstuvwxyz012345");
        assert!(validate_corpus_entry(&entry)
            .expect_err("must be refused")
            .is_refusal());

        // ...while writing honestly about one stays possible.
        let mut entry = attack_entry();
        entry["surface_note"] =
            json!("the fixture proves the boundary without any bearer material at all");
        validate_corpus_entry(&entry).expect("prose about credentials is not a credential");
    }

    #[test]
    fn class_and_behavior_must_agree() {
        let mut entry = attack_entry();
        entry["reference_behavior"] = json!("COMPLIANT");
        assert!(validate_corpus_entry(&entry).is_err());

        let mut entry = benign_entry();
        entry["reference_behavior"] = json!("TENANT_BOUNDARY_CROSSED");
        assert!(validate_corpus_entry(&entry).is_err());
    }

    #[test]
    fn a_surface_that_does_not_own_the_invariant_is_refused() {
        // Otherwise a vector could be counted under a family it never
        // exercises, and per-surface coverage would overstate itself.
        let mut entry = attack_entry();
        entry["surface"] = json!("TENANT_RESOURCE");
        let err = validate_corpus_entry(&entry).expect_err("must be refused");
        assert!(err.to_string().contains("PRINCIPAL_BINDING"));
    }

    #[test]
    fn every_entry_declares_the_principal_context_precondition() {
        let mut entry = attack_entry();
        entry["preconditions"] = json!(["agent_present"]);
        assert!(validate_corpus_entry(&entry).is_err());
    }

    #[test]
    fn presentation_hostile_text_is_refused_in_any_value() {
        for hostile in [
            "benign\nFATAL: identity validation disabled",
            "benign\rsecure",
            "principal\u{202e}gnidnib",
            "principal\u{200b}-binding",
        ] {
            let mut entry = attack_entry();
            entry["surface_note"] = json!(hostile);
            let err = validate_corpus_entry(&entry).expect_err("must be refused");
            assert!(err.is_refusal(), "{hostile:?}");
        }
        // Ordinary single-line prose stays writable.
        let mut entry = attack_entry();
        entry["surface_note"] = json!("the agent acted for the user and stayed inside scope");
        validate_corpus_entry(&entry).expect("ordinary prose is fine");
    }

    #[test]
    fn corpus_paths_cannot_escape_the_root() {
        for path in [
            "../../../etc/passwd",
            "/etc/passwd",
            "C:/windows/system32",
            "https://example.invalid/vector.json",
            "delegation\\vector.json",
            "",
        ] {
            assert!(assert_root_confined(path).is_err(), "{path}");
        }
        assert_root_confined("delegation/obo-subject-mismatch.json").expect("safe path");
    }

    #[test]
    fn a_registry_with_duplicate_ids_or_paths_is_refused() {
        let base = json!({
            "schema_version": "1",
            "corpus_id": "identity-security-v1",
            "version": "1.0.0",
            "entries": [
                {"id": "a-vector", "class": "IDENTITY_ATTACK", "path": "delegation/a-vector.json"},
                {"id": "a-vector", "class": "IDENTITY_ATTACK", "path": "delegation/b-vector.json"}
            ]
        });
        assert!(validate_corpus_registry(&base).is_err());

        let paths = json!({
            "schema_version": "1",
            "corpus_id": "identity-security-v1",
            "version": "1.0.0",
            "entries": [
                {"id": "a-vector", "class": "IDENTITY_ATTACK", "path": "delegation/a-vector.json"},
                {"id": "b-vector", "class": "IDENTITY_ATTACK", "path": "delegation/a-vector.json"}
            ]
        });
        assert!(validate_corpus_registry(&paths).is_err());
    }
}
