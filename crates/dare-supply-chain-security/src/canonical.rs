//! Canonical digests and safe identifiers.
//!
//! Two jobs. The first is turning a value into a digest that is stable across
//! runs and machines, so "the same component" means the same thing tomorrow.
//! The second is refusing identifiers that could deceive whoever reads them.
//!
//! The second is the less obvious one and matters more than it looks. Component
//! names come out of documents somebody else wrote, and they end up in logs, in
//! reports and next to each other in tables. An identifier carrying a newline
//! can forge a log line; one carrying a right-to-left override can render as a
//! different name than it compares as. Neither is a parsing problem — both
//! parse fine — and both are ways of making a reader believe something the data
//! does not say.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Result, SupplyChainError};

/// Longest identifier this engine will accept.
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Digest a serializable value with a canonical key order.
///
/// `serde_json::to_vec` on a `BTreeMap`-backed value is already key-ordered,
/// and every model in this crate uses ordered collections for exactly that
/// reason: two documents that mean the same thing must digest the same, or
/// cross-format equivalence cannot be checked at all.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| SupplyChainError::Serialization {
        kind: "canonical-digest",
    })?;
    Ok(digest_bytes(&bytes))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Whether a string is a well-formed `sha256:`-prefixed digest.
pub fn assert_digest_shape(value: &str, where_found: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SupplyChainError::invalid(format!(
            "{where_found} is not a sha256-prefixed digest"
        )));
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SupplyChainError::invalid(format!(
            "{where_found} is not a 64-character hexadecimal digest"
        )));
    }
    Ok(())
}

/// Recompute a value's digest and compare it against a pinned one.
pub fn verify_digest<T: Serialize>(value: &T, pinned: &str, where_found: &str) -> Result<()> {
    assert_digest_shape(pinned, where_found)?;
    let actual = digest(value)?;
    if actual != pinned {
        return Err(SupplyChainError::BindingMismatch(format!(
            "{where_found} does not match its pinned digest"
        )));
    }
    Ok(())
}

/// Refuse an identifier that could deceive a reader or forge a log line.
///
/// The rules, and why each exists:
///
/// - **Empty or oversized.** An empty identifier identifies nothing; an
///   oversized one is a payload wearing an identifier's clothes.
/// - **Control characters.** A newline in a component name forges a log line.
///   None of them is ever legitimate in an identifier.
/// - **Bidirectional overrides.** These render a string differently from how it
///   compares, so two components can look identical in a report and be
///   different in the graph. That is a spoof, not a formatting choice.
/// - **Path shapes.** `..`, a leading slash, a drive letter or a backslash in
///   something used as a name is either a mistake or an attempt to escape a
///   root somewhere downstream.
/// - **URL schemes.** A coordinate is inert metadata elsewhere in the model, but
///   an *identifier* that is a URL invites a reader — or a later cycle — to
///   treat it as fetchable.
/// - **Leading or trailing whitespace.** ` react` and `react ` compare as
///   different components while rendering as the same one, which is a
///   duplicate-identity trap that costs nothing to close.
pub fn assert_safe_identifier(value: &str, where_found: &str) -> Result<()> {
    if value.is_empty() {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} is empty and identifies nothing"
        )));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} is longer than {MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} carries a control character, which could forge a log line"
        )));
    }
    if value.chars().any(is_bidi_or_invisible) {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} carries a bidirectional or invisible character, so it would render \
             differently from how it compares"
        )));
    }
    if value.trim() != value {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} has leading or trailing whitespace, which reads as one identifier \
             and compares as another"
        )));
    }
    if value.contains("..")
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(":\\")
    {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} is shaped like a path"
        )));
    }
    if value.contains("://") {
        return Err(SupplyChainError::refusal(format!(
            "{where_found} is shaped like a URL; a coordinate belongs in a reference field, \
             where it is inert, and never in an identity"
        )));
    }
    Ok(())
}

fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn digests_are_deterministic_and_prefixed() {
        let value = json!({ "component": "react", "version": "18.3.1" });
        let first = digest(&value).expect("digests");
        assert_eq!(first, digest(&value).expect("digests"));
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), 71);
    }

    #[test]
    fn a_changed_field_changes_the_digest() {
        // The whole point: two components that differ must not compare equal.
        let left = json!({ "name": "react", "version": "18.3.1" });
        let right = json!({ "name": "react", "version": "18.3.2" });
        assert_ne!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn a_value_that_is_not_a_digest_is_refused() {
        for hostile in [
            "react",
            "sha256:",
            "sha256:zzzz",
            "md5:0123456789abcdef0123456789abcdef",
            &format!("sha256:{}", "a".repeat(63)),
            &format!("sha256:{}", "a".repeat(65)),
        ] {
            assert!(
                assert_digest_shape(hostile, "test").is_err(),
                "`{hostile}` was accepted as a digest"
            );
        }
        assert!(assert_digest_shape(&format!("sha256:{}", "a".repeat(64)), "test").is_ok());
    }

    #[test]
    fn verifying_a_pinned_digest_catches_a_substitution() {
        let value = json!({ "name": "react" });
        let pinned = digest(&value).expect("digests");
        assert!(verify_digest(&value, &pinned, "component").is_ok());

        let substituted = json!({ "name": "preact" });
        assert!(verify_digest(&substituted, &pinned, "component").is_err());
    }

    #[test]
    fn an_identifier_that_could_forge_a_log_line_is_refused() {
        for hostile in [
            "react\nWARN: nothing to see",
            "react\r\nOK",
            "react\u{0}",
            "react\u{1b}[31m",
        ] {
            let err = assert_safe_identifier(hostile, "component name")
                .expect_err("a control character must be refused");
            assert!(err.is_refusal());
        }
    }

    #[test]
    fn an_identifier_that_renders_differently_from_how_it_compares_is_refused() {
        // Two components can look identical in a report and be different rows
        // in the graph. That is a spoof, and it parses perfectly.
        for hostile in [
            "react\u{202E}gnp.exe",
            "react\u{200B}",
            "\u{FEFF}react",
            "react\u{2066}x\u{2069}",
        ] {
            assert!(
                assert_safe_identifier(hostile, "component name").is_err(),
                "`{}` was accepted",
                hostile.escape_unicode()
            );
        }
    }

    #[test]
    fn an_identifier_shaped_like_a_path_is_refused() {
        for hostile in [
            "../../etc/passwd",
            "/absolute/name",
            "..",
            "C:\\Windows\\System32",
            "name\\with\\backslash",
        ] {
            assert!(
                assert_safe_identifier(hostile, "component name").is_err(),
                "`{hostile}` was accepted"
            );
        }
    }

    #[test]
    fn an_identifier_shaped_like_a_url_is_refused() {
        // A coordinate is inert where the model puts coordinates. An identity
        // that *is* a URL invites a reader, or a later cycle, to treat it as
        // fetchable.
        for hostile in [
            "https://registry.npmjs.org/react",
            "oci://ghcr.io/org/image",
            "git+ssh://host/repo",
            "file:///etc/passwd",
        ] {
            assert!(
                assert_safe_identifier(hostile, "component name").is_err(),
                "`{hostile}` was accepted"
            );
        }
    }

    #[test]
    fn padding_is_refused_because_it_makes_lookalikes_compare_differently() {
        for hostile in [" react", "react ", "\treact", "react\t"] {
            assert!(
                assert_safe_identifier(hostile, "component name").is_err(),
                "`{}` was accepted",
                hostile.escape_debug()
            );
        }
    }

    #[test]
    fn an_empty_or_oversized_identifier_is_refused() {
        assert!(assert_safe_identifier("", "component name").is_err());
        assert!(assert_safe_identifier(&"a".repeat(257), "component name").is_err());
        assert!(assert_safe_identifier(&"a".repeat(256), "component name").is_ok());
    }

    #[test]
    fn ordinary_identifiers_stay_usable() {
        // Tightening a refusal is only correct if real names still pass.
        // Package names, purls, model ids and image tags all appear here.
        for ordinary in [
            "react",
            "@scope/package",
            "pkg:npm/react@18.3.1",
            "meta-llama/Llama-3-8B",
            "ghcr.io/org/image:1.2.3",
            "component-with-dashes_and_underscores.1",
            "urn:uuid:8f3a1c2e-0000-4000-8000-000000000000",
        ] {
            assert!(
                assert_safe_identifier(ordinary, "component name").is_ok(),
                "`{ordinary}` was refused"
            );
        }
    }

    #[test]
    fn a_refusal_never_echoes_the_identifier_it_refused() {
        // Reporting the problem must not reproduce it. An identifier carrying a
        // credential would otherwise be written into a log by the error
        // declining to store it.
        let hostile = "sk-live-000000000000000000000000\u{202E}";
        let err = assert_safe_identifier(hostile, "component name").expect_err("refused");
        assert!(!err.to_string().contains("sk-live-"));
    }
}
