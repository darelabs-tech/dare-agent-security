//! Identifiers, validated at construction.
//!
//! Every identifier in a scenario, graph or transcript is ASCII matching
//! `^[a-z0-9][a-z0-9._-]{0,63}$`. The grammar is deliberately narrow: it has no
//! room for a bidi override, a zero-width joiner, a homoglyph or a control
//! character, so an identifier that renders as one thing and compares as
//! another cannot be constructed. Deserialization goes through `TryFrom`, so
//! an invalid identifier never exists as a value.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{MultiTurnError, Result};

/// Longest accepted identifier.
pub const MAX_ID_LEN: usize = 64;

/// Check `value` against the identifier grammar without echoing it on failure.
pub fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    let bytes = value.as_bytes();
    if let Some(ch) = value.chars().find(|c| is_forbidden_char(*c)) {
        return Err(MultiTurnError::ForbiddenCharacter {
            field,
            codepoint: ch as u32,
        });
    }
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_ID_LEN
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(MultiTurnError::InvalidIdentifier { field })
    }
}

/// Bidi controls, zero-width characters and C0/C1 controls.
pub fn is_forbidden_char(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = MultiTurnError;
            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(
    /// A strategy-graph node, graph, principal, tenant or target identifier.
    NodeId, "node_id"
);
identifier!(
    /// A request, action or objective class.
    ClassId, "class_id"
);
identifier!(
    /// One conversation within a scenario.
    ConversationId, "conversation_id"
);
identifier!(
    /// A declared canary.
    CanaryId, "canary_id"
);
identifier!(
    /// A human approval disclosed on an approval turn.
    ApprovalId, "approval_id"
);
identifier!(
    /// An action reported by the target.
    ActionId, "action_id"
);
identifier!(
    /// A scenario.
    ScenarioId, "scenario_id"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grammar_accepts_ordinary_identifiers() {
        for ok in ["n1", "multiturn-lab-001", "a.b_c-d", "0", &"a".repeat(64)] {
            assert!(NodeId::new(ok).is_ok(), "`{ok}` should be accepted");
        }
    }

    #[test]
    fn the_grammar_rejects_everything_else_without_echoing_it() {
        for bad in [
            "",
            "N1",
            "-lead",
            ".lead",
            "a b",
            "a/b",
            "é",
            &"a".repeat(65),
        ] {
            let error = NodeId::new(bad).expect_err("must be rejected");
            assert_eq!(
                error,
                MultiTurnError::InvalidIdentifier { field: "node_id" }
            );
        }
    }

    #[test]
    fn bidi_zero_width_and_control_characters_are_named_by_codepoint() {
        for (bad, cp) in [
            ("a\u{202e}b", 0x202e),
            ("a\u{200b}", 0x200b),
            ("a\u{2066}", 0x2066),
            ("a\u{0007}", 0x7),
            ("\u{feff}a", 0xfeff),
        ] {
            assert_eq!(
                ClassId::new(bad),
                Err(MultiTurnError::ForbiddenCharacter {
                    field: "class_id",
                    codepoint: cp
                })
            );
        }
    }

    #[test]
    fn deserialization_cannot_construct_an_invalid_identifier() {
        let parsed: std::result::Result<ConversationId, _> = serde_json::from_str("\"Conv\"");
        assert!(parsed.is_err());
        let parsed: ConversationId = serde_json::from_str("\"conv-a\"").expect("valid");
        assert_eq!(parsed.as_str(), "conv-a");
        assert_eq!(
            serde_json::to_string(&parsed).expect("serializes"),
            "\"conv-a\""
        );
    }
}
