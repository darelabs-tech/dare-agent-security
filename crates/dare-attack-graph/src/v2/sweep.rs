//! Output secret sweep (Cycle 023 AD-12; moved here by Cycle 024 AD-03 so
//! every graph-analysis artifact, from paths or from reach, passes the same
//! check before it is written).
//!
//! The same markers the engine CLIs refuse to write, plus a bearer
//! credential.
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

/// True when the bytes carry a marker or a bearer credential.
pub fn is_sensitive(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    MARKERS.iter().any(|marker| text.contains(marker)) || contains_bearer_credential(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_marker_and_a_bearer_credential_is_sensitive() {
        for marker in MARKERS {
            assert!(is_sensitive(format!("x{marker}y").as_bytes()), "{marker}");
        }
        assert!(is_sensitive(b"Authorization: Bearer abcdefgh12345678"));
        assert!(!is_sensitive(b"bearer tokens are described here"));
        assert!(!is_sensitive(b"{\"label\":\"support-desk-tools\"}"));
    }
}
