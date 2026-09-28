//! Node identifiers (BLUEPRINT §4.3, AD-07).
//!
//! Unaliased nodes are scoped by run: `node:<type>:<engine>:<run>:<token>`.
//! Aliased nodes are `node:<type>:<entity_id>`, and an entity id may not
//! contain `:`, so the two forms can never collide. A local id outside the
//! safe token set is replaced by `x-` plus 32 hex digits of its SHA-256; the
//! raw text is never emitted.
use std::fmt;

use dare_attack_graph::{validate_safe_label, NodeType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineSlug {
    PromptInjection,
    Tool,
    Identity,
    Memory,
    Rag,
    McpAuth,
    SupplyChain,
    A2a,
    MultiTurn,
    Remote,
}

impl EngineSlug {
    pub const ALL: [EngineSlug; 10] = [
        Self::PromptInjection,
        Self::Tool,
        Self::Identity,
        Self::Memory,
        Self::Rag,
        Self::McpAuth,
        Self::SupplyChain,
        Self::A2a,
        Self::MultiTurn,
        Self::Remote,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PromptInjection => "prompt-injection",
            Self::Tool => "tool",
            Self::Identity => "identity",
            Self::Memory => "memory",
            Self::Rag => "rag",
            Self::McpAuth => "mcp-auth",
            Self::SupplyChain => "supply-chain",
            Self::A2a => "a2a",
            Self::MultiTurn => "multi-turn",
            Self::Remote => "remote",
        }
    }
}

impl fmt::Display for EngineSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The first 12 hex digits of the SHA-256 of a result file's bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunTag(String);

impl RunTag {
    pub fn from_result_bytes(bytes: &[u8]) -> Self {
        Self(hex(&Sha256::digest(bytes))[..12].to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sha256:` + hex over raw bytes.
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn is_token(raw: &str) -> bool {
    (1..=96).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn local_token(raw: &str) -> String {
    if is_token(raw) {
        raw.to_owned()
    } else {
        format!("x-{}", &hex(&Sha256::digest(raw.as_bytes()))[..32])
    }
}

pub fn scoped_node_id(node_type: NodeType, engine: EngineSlug, run: &RunTag, raw: &str) -> String {
    format!(
        "node:{}:{}:{}:{}",
        node_type.slug(),
        engine.as_str(),
        run.as_str(),
        local_token(raw)
    )
}

/// `^[a-z0-9][a-z0-9._-]{0,95}$`
pub fn is_entity_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 96
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// `None` when `entity_id` is not a usable entity id.
pub fn entity_node_id(node_type: NodeType, entity_id: &str) -> Option<String> {
    is_entity_id(entity_id).then(|| format!("node:{}:{entity_id}", node_type.slug()))
}

/// The raw label when it is safe, otherwise `<type-slug> <token>`.
pub fn display_name(raw: &str, node_type: NodeType) -> String {
    let trimmed: String = raw.chars().take(160).collect();
    if validate_safe_label(&trimmed).is_ok() && !trimmed.chars().any(char::is_control) {
        trimmed
    } else {
        format!("{} {}", node_type.slug(), local_token(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_ID_PATTERN: fn(&str) -> bool = |id| {
        let mut parts = id.splitn(3, ':');
        parts.next() == Some("node")
            && parts.next().is_some_and(|t| {
                !t.is_empty() && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            })
            && parts.next().is_some_and(|rest| {
                !rest.is_empty()
                    && rest.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')
                    })
            })
    };

    #[test]
    fn safe_tokens_pass_through_and_everything_else_is_hashed() {
        assert_eq!(local_token("tool-export_v2.1"), "tool-export_v2.1");
        for raw in [
            "a:b",
            "with space",
            "bidi\u{202e}txt",
            "Bearer abcdefgh",
            "",
            &"x".repeat(97),
        ] {
            let token = local_token(raw);
            assert!(
                token.starts_with("x-") && token.len() == 34,
                "{raw:?} -> {token}"
            );
            assert!(!token.contains(':'));
        }
        assert_eq!(local_token("a:b"), local_token("a:b"));
        assert_ne!(local_token("a:b"), local_token("a:c"));
    }

    #[test]
    fn produced_ids_match_the_v1_node_id_pattern_and_never_collide() {
        let run = RunTag::from_result_bytes(b"{}");
        assert_eq!(run.as_str().len(), 12);
        let scoped = scoped_node_id(NodeType::Tool, EngineSlug::Tool, &run, "weird id:1");
        assert!(NODE_ID_PATTERN(&scoped), "{scoped}");
        let entity = entity_node_id(NodeType::Tool, "crm.export").unwrap();
        assert!(NODE_ID_PATTERN(&entity));
        // An entity id cannot contain ':' and a scoped id always has three
        // ':'-separated segments after the type, so the forms never collide.
        assert!(entity_node_id(NodeType::Tool, "tool:abc:x").is_none());
        assert_eq!(scoped.matches(':').count(), 4);
        assert_eq!(entity.matches(':').count(), 2);
    }

    #[test]
    fn entity_ids_follow_their_grammar() {
        for good in ["a", "0", "support-agent", "crm.export_v2"] {
            assert!(is_entity_id(good), "{good}");
        }
        for bad in ["", "A", "-a", "a:b", "a b", &"a".repeat(97)] {
            assert!(!is_entity_id(bad), "{bad}");
        }
    }

    #[test]
    fn unsafe_labels_are_replaced_by_the_hashed_token() {
        assert_eq!(display_name("CRM export", NodeType::Tool), "CRM export");
        let hidden = display_name("Bearer abcdefgh1234", NodeType::Credential);
        assert!(hidden.starts_with("credential x-"), "{hidden}");
        assert!(!hidden.to_ascii_lowercase().contains("bearer"));
        assert!(display_name("line\nbreak", NodeType::Data).starts_with("data x-"));
    }

    #[test]
    fn engine_slugs_are_kebab_case_and_serialize_as_such() {
        for engine in EngineSlug::ALL {
            assert_eq!(
                serde_json::to_value(engine).unwrap(),
                serde_json::json!(engine.as_str())
            );
        }
    }
}
