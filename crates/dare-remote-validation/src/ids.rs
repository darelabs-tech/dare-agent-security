//! Identifiers, validated at construction.
//!
//! Two grammars, both ASCII-only so a bidi override, zero-width character,
//! homoglyph or control character can never be part of one:
//!
//! - document identifiers (`authorization_id`, `plan_id`):
//!   `^[a-z0-9][a-z0-9._-]{2,63}$`;
//! - scenario references, which must accept every engine's own spelling
//!   (`PI-LAB-001`, `multiturn-lab-001`): `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
//!
//! Failures name the field and, for a forbidden character, its code point;
//! they never echo the value.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{RemoteError, Result};

/// Bidi controls, zero-width characters and C0/C1 controls.
pub fn is_forbidden_char(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// The first forbidden character in `value`, as an error for `field`.
pub fn refuse_forbidden_chars(value: &str, field: &'static str) -> Result<()> {
    match value.chars().find(|c| is_forbidden_char(*c)) {
        Some(ch) => Err(RemoteError::ForbiddenCharacter {
            field,
            codepoint: ch as u32,
        }),
        None => Ok(()),
    }
}

fn document_id_ok(bytes: &[u8]) -> bool {
    (3..=64).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn reference_ok(bytes: &[u8]) -> bool {
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Check a document identifier without echoing it.
pub fn validate_document_id(value: &str, field: &'static str) -> Result<()> {
    refuse_forbidden_chars(value, field)?;
    if document_id_ok(value.as_bytes()) {
        Ok(())
    } else {
        Err(RemoteError::InvalidIdentifier { field })
    }
}

/// Check a scenario or conversation reference without echoing it.
pub fn validate_reference(value: &str, field: &'static str) -> Result<()> {
    refuse_forbidden_chars(value, field)?;
    if reference_ok(value.as_bytes()) {
        Ok(())
    } else {
        Err(RemoteError::InvalidIdentifier { field })
    }
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $field:literal, $check:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                $check(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = RemoteError;
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
    /// `authorization_id`.
    AuthorizationId,
    "authorization_id",
    validate_document_id
);
identifier!(
    /// `plan_id`.
    PlanId,
    "plan_id",
    validate_document_id
);
identifier!(
    /// An engine scenario id, in the engine's own spelling.
    ScenarioRefId,
    "scenario_id",
    validate_reference
);
identifier!(
    /// A conversation id inside a scenario.
    ConversationRefId,
    "conversation_id",
    validate_reference
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_ids_accept_the_grammar() {
        for ok in ["lab-auth-1", "a.b_c-d", "000", &"a".repeat(64)] {
            assert!(AuthorizationId::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn document_ids_refuse_everything_else_without_echoing() {
        for bad in [
            "ab",
            "Upper-case",
            "-lead",
            "has space",
            "slash/x",
            &"a".repeat(65),
            "",
        ] {
            let error = AuthorizationId::new(bad).expect_err(bad).to_string();
            assert!(bad.is_empty() || !error.contains(bad), "{error}");
        }
    }

    #[test]
    fn references_accept_every_engine_spelling() {
        for ok in [
            "PI-LAB-001",
            "multiturn-lab-001",
            "A2A-LAB-064",
            "SUPPLY-LAB-041",
            "conv-a",
        ] {
            assert!(ScenarioRefId::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn bidi_zero_width_and_control_characters_are_named_by_codepoint() {
        for (value, cp) in [
            ("a\u{202e}b", 0x202e),
            ("a\u{200b}b", 0x200b),
            ("a\u{0007}b", 0x7),
            ("a\u{feff}", 0xfeff),
        ] {
            match ScenarioRefId::new(value) {
                Err(RemoteError::ForbiddenCharacter { codepoint, .. }) => assert_eq!(codepoint, cp),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn deserialization_cannot_construct_an_invalid_identifier() {
        assert!(serde_json::from_str::<AuthorizationId>("\"Bad Id\"").is_err());
        assert!(serde_json::from_str::<AuthorizationId>("\"lab-auth-1\"").is_ok());
    }
}
