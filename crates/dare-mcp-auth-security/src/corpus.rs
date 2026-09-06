//! The corpus registry and its entries.
//!
//! An entry describes one vector: which surface it exercises, which invariant
//! it expects to be judged against, and how a reference implementation behaves.
//! It records a **behaviour**, never a verdict — an entry that could state its
//! own outcome would make the evaluator ceremonial.
//!
//! Two consistency rules are enforced rather than trusted: the declared surface
//! must be the one the declared invariant actually reports under, and an attack
//! may not declare compliant behaviour (nor a control a crossing one). A vector
//! filed under the wrong surface would overstate per-surface coverage.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{McpAuthSecurityError, Result};
use crate::model::McpAuthCorpusEntry;
use crate::source::CorpusClass;

/// The loaded corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuthCorpus {
    pub corpus_id: String,
    pub version: String,
    pub entries: Vec<McpAuthCorpusEntry>,
}

impl McpAuthCorpus {
    pub fn get(&self, id: &str) -> Option<&McpAuthCorpusEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn require(&self, id: &str) -> Result<&McpAuthCorpusEntry> {
        self.get(id)
            .ok_or_else(|| McpAuthSecurityError::invalid(format!("corpus has no vector `{id}`")))
    }

    /// Resolve the vector a scenario names.
    ///
    /// Three outcomes, kept apart on purpose: no reference, a reference to the
    /// corpus as a whole, or a reference to one entry. A bare `get` would
    /// answer `None` to both the second and a *missing* entry, so a scenario
    /// naming a renamed or removed vector would run as though it had named
    /// nothing.
    pub fn resolve(
        &self,
        reference: Option<&crate::model::McpAuthVectorRef>,
    ) -> Result<Option<&McpAuthCorpusEntry>> {
        let Some(reference) = reference else {
            return Ok(None);
        };
        if reference.corpus_id == self.corpus_id {
            return Ok(None);
        }
        match self.get(&reference.corpus_id) {
            Some(entry) => Ok(Some(entry)),
            None => Err(McpAuthSecurityError::invalid(format!(
                "scenario names corpus vector `{}`, which corpus `{}` does not contain",
                reference.corpus_id, self.corpus_id
            ))),
        }
    }
}

/// Structural checks on one entry.
pub fn validate_entry(entry: &McpAuthCorpusEntry) -> Result<()> {
    crate::canonical::assert_safe_identifier(&entry.id, "corpus entry id")?;

    if entry.expected_invariant.surface() != entry.surface {
        return Err(McpAuthSecurityError::invalid(format!(
            "corpus entry `{}` declares surface `{}` but an invariant that reports under `{}`",
            entry.id,
            entry.surface.as_str(),
            entry.expected_invariant.surface().as_str()
        )));
    }

    let legitimate = entry.reference_behavior.is_legitimate();
    match entry.class {
        CorpusClass::McpAuthAttack if legitimate => {
            return Err(McpAuthSecurityError::invalid(format!(
                "corpus entry `{}` is filed as an attack but declares compliant behaviour; that \
                 is a control, and mislabeling it would overstate attack coverage",
                entry.id
            )));
        }
        CorpusClass::BenignControl if !legitimate => {
            return Err(McpAuthSecurityError::invalid(format!(
                "corpus entry `{}` is filed as a control but declares a boundary crossing",
                entry.id
            )));
        }
        _ => {}
    }

    if entry.safety_class != "SYNTHETIC_NOOP" {
        return Err(McpAuthSecurityError::refusal(format!(
            "corpus entry `{}` declares a safety class other than SYNTHETIC_NOOP",
            entry.id
        )));
    }
    if !entry
        .preconditions
        .iter()
        .any(|precondition| precondition == "mcp_current_protocol_present")
    {
        return Err(McpAuthSecurityError::invalid(format!(
            "corpus entry `{}` does not require the current MCP protocol; without it there is no \
             Cycle 018 question to ask",
            entry.id
        )));
    }
    Ok(())
}

/// Refuse a registry path that could escape the corpus root.
pub fn assert_root_confined(path: &str) -> Result<()> {
    if path.contains("..")
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains("://")
        || path.len() > 2 && path.as_bytes()[1] == b':'
    {
        return Err(McpAuthSecurityError::refusal(
            "a corpus registry path must stay inside the corpus root".to_owned(),
        ));
    }
    Ok(())
}

/// Load and validate a corpus from a root directory.
pub fn load_corpus(root: &Path) -> Result<McpAuthCorpus> {
    let registry_path = root.join("registry.json");
    let raw = std::fs::read(&registry_path)?;
    crate::schema::enforce_document_size(&raw, "corpus registry")?;
    let registry: Value = serde_json::from_slice(&raw).map_err(|err| {
        McpAuthSecurityError::schema(format!("corpus registry is not valid JSON: {err}"))
    })?;
    crate::schema::validate_corpus_registry(&registry)?;

    let listed = registry
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| McpAuthSecurityError::schema("corpus registry has no entries"))?;

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
        // The specific path check runs first so a refusal names the entry an
        // operator has to fix, rather than reporting a generic hostile value.
        assert_root_confined(path)?;

        let file = root.join(path);
        let raw = std::fs::read(&file).map_err(|err| {
            McpAuthSecurityError::invalid(format!("corpus vector `{id}` unreadable: {err}"))
        })?;
        crate::schema::enforce_document_size(&raw, "corpus entry")?;
        let value: Value = serde_json::from_slice(&raw).map_err(|err| {
            McpAuthSecurityError::schema(format!("corpus vector `{id}` is not valid JSON: {err}"))
        })?;
        crate::schema::validate_corpus_entry(&value)?;
        let entry: McpAuthCorpusEntry = serde_json::from_value(value)?;

        if entry.id != id {
            return Err(McpAuthSecurityError::DigestMismatch(format!(
                "corpus registry lists `{id}` but the file declares `{}`",
                entry.id
            )));
        }
        if let Some(pinned) = listed_entry.get("digest").and_then(Value::as_str) {
            crate::canonical::verify_digest(&entry, pinned, "corpus vector")?;
        }
        validate_entry(&entry)?;
        entries.push(entry);
    }

    Ok(McpAuthCorpus {
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
pub fn builtin_corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/mcp-auth-security/v1")
}

/// Load the corpus shipped with the workspace.
pub fn builtin_corpus() -> Result<McpAuthCorpus> {
    load_corpus(&builtin_corpus_root())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{
        McpAuthInvariantType, McpAuthProperty, McpAuthStandardRef, ReferenceBehavior,
    };
    use crate::source::ScenarioClass;

    pub(crate) fn attack_entry() -> McpAuthCorpusEntry {
        McpAuthCorpusEntry {
            schema_version: "1".to_owned(),
            id: "protocol-method-header-body-mismatch".to_owned(),
            title: "routing metadata names a method the body did not request".to_owned(),
            class: CorpusClass::McpAuthAttack,
            surface: ScenarioClass::ProtocolBinding,
            property: McpAuthProperty::ProtocolBinding,
            expected_invariant: McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            reference_behavior: ReferenceBehavior::MethodHeaderBodyMismatch,
            preconditions: vec![
                "mcp_current_protocol_present".to_owned(),
                "mcp_http_transport_present".to_owned(),
            ],
            surface_note: "a gateway routes on metadata while the server executes the body"
                .to_owned(),
            safety_class: "SYNTHETIC_NOOP".to_owned(),
            standards: vec![McpAuthStandardRef {
                source: "MCP".to_owned(),
                reference: "2026-07-28 request routing metadata".to_owned(),
                status: "NORMATIVE".to_owned(),
            }],
        }
    }

    #[test]
    fn a_well_formed_attack_entry_validates() {
        validate_entry(&attack_entry()).expect("valid");
    }

    #[test]
    fn an_entry_whose_surface_does_not_own_its_invariant_is_refused() {
        // A vector filed under the wrong surface would overstate per-surface
        // coverage.
        let mut entry = attack_entry();
        entry.surface = ScenarioClass::TokenBinding;
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn an_attack_declaring_compliant_behaviour_is_refused() {
        let mut entry = attack_entry();
        entry.reference_behavior = ReferenceBehavior::Compliant;
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn a_control_declaring_a_crossing_is_refused_for_the_mirror_reason() {
        let mut entry = attack_entry();
        entry.class = CorpusClass::BenignControl;
        assert!(validate_entry(&entry).is_err());

        entry.reference_behavior = ReferenceBehavior::Compliant;
        validate_entry(&entry).expect("a control declaring compliant behaviour is valid");
    }

    #[test]
    fn an_entry_must_require_the_current_protocol() {
        let mut entry = attack_entry();
        entry.preconditions = vec!["mcp_http_transport_present".to_owned()];
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn a_non_synthetic_safety_class_is_refused() {
        let mut entry = attack_entry();
        entry.safety_class = "LIVE".to_owned();
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn every_traversal_shape_is_refused() {
        for hostile in [
            "../secrets.json",
            "/etc/passwd",
            "a\\b.json",
            "https://example.invalid/x.json",
            "c:/x.json",
        ] {
            assert!(
                assert_root_confined(hostile).is_err(),
                "`{hostile}` was allowed"
            );
        }
        assert_root_confined("protocol/method-mismatch.json").expect("ordinary path");
    }

    #[test]
    fn a_scenario_naming_a_vector_the_corpus_does_not_have_is_refused() {
        // A bare `get` answers None both to "the corpus as a whole" and to "no
        // such vector", so a renamed vector would run as though nothing had
        // been named.
        let corpus = McpAuthCorpus {
            corpus_id: "mcp-auth-security-v1".to_owned(),
            version: "1.0.0".to_owned(),
            entries: vec![attack_entry()],
        };
        let missing = crate::model::McpAuthVectorRef {
            corpus_id: "vector-that-was-renamed".to_owned(),
            corpus_digest: None,
        };
        assert!(corpus.get(&missing.corpus_id).is_none());
        assert!(corpus.resolve(Some(&missing)).is_err());

        let whole = crate::model::McpAuthVectorRef {
            corpus_id: "mcp-auth-security-v1".to_owned(),
            corpus_digest: None,
        };
        assert!(corpus.resolve(Some(&whole)).expect("resolves").is_none());
        assert!(corpus.resolve(None).expect("resolves").is_none());
    }
}
