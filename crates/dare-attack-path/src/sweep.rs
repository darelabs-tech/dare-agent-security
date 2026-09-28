//! Artifact secret sweep (BLUEPRINT AD-12).
//!
//! The same markers the engine CLIs refuse to write, plus a bearer
//! credential. Every artifact's bytes pass this check before they are
//! written, so a credential that reached an identifier or label cannot leave
//! through `attack-paths`.
use crate::error::{Refusal, Result};

pub const MARKERS: [&str; 6] = [
    "DARE-SYNTHETIC-CANARY-",
    "sk-live-",
    "-----BEGIN",
    "ghp_",
    "xoxb-",
    "eyJhbGci",
];

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

/// `bearer ` followed by at least eight token characters.
pub fn contains_bearer_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(offset) = lower[from..].find("bearer ") {
        let start = from + offset + "bearer ".len();
        let run = bytes[start..]
            .iter()
            .take_while(|b| is_token_char(**b))
            .count();
        if run >= 8 {
            return true;
        }
        from = start;
    }
    false
}

pub fn sweep(file: &'static str, bytes: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    if MARKERS.iter().any(|marker| text.contains(marker)) || contains_bearer_credential(&text) {
        return Err(Refusal::SensitiveOutput { file }.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_marker_and_a_bearer_credential_is_refused() {
        for marker in MARKERS {
            let bytes = format!("{{\"label\":\"x{marker}y\"}}");
            assert!(
                sweep("attack-graph.json", bytes.as_bytes()).is_err(),
                "{marker}"
            );
        }
        assert!(sweep("summary.md", b"Authorization: Bearer abcdefgh1234").is_err());
        assert!(sweep("summary.md", b"authorization: BEARER abcdefgh1234").is_err());
    }

    #[test]
    fn ordinary_text_passes() {
        assert!(sweep("summary.md", b"the bearer of this path is short").is_ok());
        assert!(sweep("summary.md", b"bearer abc").is_ok());
        assert!(sweep("summary.md", b"node:tool:tool:0123456789ab:export").is_ok());
    }
}
