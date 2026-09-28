//! Credential by reference, and the scrubber (BLUEPRINT §4.7).
//!
//! The authorization names an environment variable; the value is read once,
//! held in zeroizing memory, marked sensitive on the wire, and never printed.
//! Everything recorded from a response or request is scrubbed of the value in
//! the forms a server could echo it (raw, base64, URL-safe base64,
//! percent-encoded) and of credential shapes in general, before it is stored
//! anywhere that is later serialized.

use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION};
use zeroize::Zeroizing;

use crate::error::{AuthorizationRefusal, RemoteError, Result};

/// Longest accepted credential value.
pub const MAX_CREDENTIAL_BYTES: usize = 4_096;

/// The replacement for an exact credential match.
pub const REDACTED_CREDENTIAL: &str = "[REDACTED:CREDENTIAL]";
/// The replacement for a credential-shaped match.
pub const REDACTED_SHAPE: &str = "[REDACTED:SHAPE]";

/// Whether a reference name matches `^DARE_REMOTE_[A-Z0-9_]{1,48}$`.
pub fn valid_reference(name: &str) -> bool {
    name.strip_prefix("DARE_REMOTE_").is_some_and(|rest| {
        (1..=48).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

pub struct Credential {
    value: Zeroizing<String>,
}

impl Credential {
    /// Read the referenced variable through `lookup` (the environment in
    /// production, a map in tests).
    pub fn from_lookup(
        reference: &str,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Credential> {
        let refuse = || RemoteError::Authorization(AuthorizationRefusal::CredentialMissing);
        if !valid_reference(reference) {
            return Err(refuse());
        }
        let value = Zeroizing::new(lookup(reference).ok_or_else(refuse)?);
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_BYTES
            || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(refuse());
        }
        Ok(Credential { value })
    }

    /// `Authorization: Bearer <value>`, marked sensitive so the HTTP stack
    /// never includes it in its own debug output.
    pub fn header(&self) -> Result<(HeaderName, HeaderValue)> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.value.as_str()))
            .map_err(|_| RemoteError::Authorization(AuthorizationRefusal::CredentialMissing))?;
        value.set_sensitive(true);
        Ok((AUTHORIZATION, value))
    }

    pub(crate) fn secret(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64 over `alphabet`. Padding is dropped so a match does not
/// depend on how the echo was padded.
fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let emit = chunk.len() + 1;
        for i in 0..emit {
            out.push(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]);
        }
    }
    out
}

fn percent_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// Case-insensitive substrings that mark real credential material.
const SHAPES: [&str; 11] = [
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

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
}

pub struct Scrubber {
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl Scrubber {
    pub fn new(credential: Option<&Credential>) -> Scrubber {
        let mut needles = Vec::new();
        if let Some(credential) = credential {
            let raw = credential.secret().as_bytes();
            for form in [
                raw.to_vec(),
                base64(raw, STANDARD),
                base64(raw, URL_SAFE),
                percent_encode(raw),
            ] {
                if !needles
                    .iter()
                    .any(|n: &Zeroizing<Vec<u8>>| n.as_slice() == form.as_slice())
                {
                    needles.push(Zeroizing::new(form));
                }
            }
            // Longest first, so a longer encoding is never half-replaced by a
            // shorter one it contains.
            needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        }
        Scrubber { needles }
    }

    /// Scrub `bytes`. Returns the scrubbed bytes, the number of exact
    /// credential replacements (a server echoing the credential is a kill
    /// trigger) and the number of shape replacements.
    pub fn scrub(&self, bytes: &[u8]) -> (Vec<u8>, u32, u32) {
        let mut current = bytes.to_vec();
        let mut exact = 0u32;
        for needle in &self.needles {
            let (next, count) = replace_all(&current, needle, REDACTED_CREDENTIAL.as_bytes());
            current = next;
            exact += count;
        }
        let (current, shapes) = scrub_shapes(&current);
        (current, exact, shapes)
    }
}

fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> (Vec<u8>, u32) {
    if needle.is_empty() || haystack.len() < needle.len() {
        return (haystack.to_vec(), 0);
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut count = 0;
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
            count += 1;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, count)
}

/// Replace every credential-shaped run: a known prefix, or `bearer ` followed
/// by at least 16 token characters, or a JWT (`eyJ…​.eyJ…`). The whole run of
/// token characters starting at the match is replaced.
fn scrub_shapes(bytes: &[u8]) -> (Vec<u8>, u32) {
    let lowered: Vec<u8> = bytes.to_ascii_lowercase();
    let mut out = Vec::with_capacity(bytes.len());
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        let rest = &lowered[i..];
        let start = if let Some(shape) = SHAPES.iter().find(|s| rest.starts_with(s.as_bytes())) {
            Some(shape.len())
        } else if rest.starts_with(b"bearer ") {
            let run = rest[7..].iter().take_while(|b| is_token_char(**b)).count();
            (run >= 16).then_some(7)
        } else if bytes[i..].starts_with(b"eyJ") {
            let run = bytes[i..].iter().take_while(|b| is_token_char(**b)).count();
            let token = &bytes[i..i + run];
            (run >= 20 && token.windows(4).any(|w| w == b".eyJ")).then_some(0)
        } else {
            None
        };
        match start {
            Some(skip) => {
                let run = bytes[i + skip..]
                    .iter()
                    .take_while(|b| is_token_char(**b))
                    .count();
                out.extend_from_slice(REDACTED_SHAPE.as_bytes());
                i += skip + run;
                count += 1;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn lookup(map: BTreeMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |name| map.get(name).map(|v| (*v).to_owned())
    }

    fn credential(value: &'static str) -> Credential {
        let env = lookup(BTreeMap::from([("DARE_REMOTE_TOKEN", value)]));
        Credential::from_lookup("DARE_REMOTE_TOKEN", &env).expect("credential")
    }

    #[test]
    fn reference_names_follow_the_pattern() {
        for ok in ["DARE_REMOTE_TOKEN", "DARE_REMOTE_A", "DARE_REMOTE_LAB_1"] {
            assert!(valid_reference(ok), "{ok}");
        }
        for bad in [
            "TOKEN",
            "DARE_REMOTE_",
            "dare_remote_x",
            "DARE_REMOTE_a",
            "DARE_REMOTE_X-Y",
            &format!("DARE_REMOTE_{}", "A".repeat(49)),
        ] {
            assert!(!valid_reference(bad), "{bad}");
        }
    }

    #[test]
    fn a_missing_empty_oversized_or_non_printable_value_is_refused() {
        let env = lookup(BTreeMap::from([
            ("DARE_REMOTE_EMPTY", ""),
            ("DARE_REMOTE_SPACE", "a b"),
        ]));
        for name in [
            "DARE_REMOTE_UNSET",
            "DARE_REMOTE_EMPTY",
            "DARE_REMOTE_SPACE",
            "NOT_A_REFERENCE",
        ] {
            assert!(matches!(
                Credential::from_lookup(name, &env),
                Err(RemoteError::Authorization(
                    AuthorizationRefusal::CredentialMissing
                ))
            ));
        }
        let big = "x".repeat(MAX_CREDENTIAL_BYTES + 1);
        let env = move |_: &str| Some(big.clone());
        assert!(Credential::from_lookup("DARE_REMOTE_BIG", &env).is_err());
    }

    #[test]
    fn debug_never_shows_the_value_and_the_header_is_sensitive() {
        let c = credential("lab-canary-4f1d2c");
        assert_eq!(format!("{c:?}"), "Credential(<redacted>)");
        let (name, value) = c.header().unwrap();
        assert_eq!(name, AUTHORIZATION);
        assert!(value.is_sensitive());
        assert!(!format!("{value:?}").contains("lab-canary"));
    }

    #[test]
    fn every_echo_form_is_scrubbed_and_counted() {
        let secret = "lab-canary-4f1d2c?&=";
        let c = credential(secret);
        let scrubber = Scrubber::new(Some(&c));
        let forms = [
            secret.as_bytes().to_vec(),
            base64(secret.as_bytes(), STANDARD),
            base64(secret.as_bytes(), URL_SAFE),
            percent_encode(secret.as_bytes()),
        ];
        for form in forms {
            let mut body = b"{\"echo\":\"".to_vec();
            body.extend_from_slice(&form);
            body.extend_from_slice(b"\"}");
            let (out, exact, _) = scrubber.scrub(&body);
            assert!(exact >= 1, "{}", String::from_utf8_lossy(&form));
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains("lab-canary"), "{text}");
            assert!(text.contains(REDACTED_CREDENTIAL));
        }
    }

    #[test]
    fn padded_base64_is_still_scrubbed() {
        let c = credential("abcd");
        let (out, exact, _) = Scrubber::new(Some(&c)).scrub(b"YWJjZA==");
        assert_eq!(exact, 1);
        assert_eq!(out, format!("{REDACTED_CREDENTIAL}==").into_bytes());
    }

    #[test]
    fn credential_shapes_are_scrubbed_without_a_credential() {
        let scrubber = Scrubber::new(None);
        for body in [
            "key=sk-live-0123456789abcdef",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "-----BEGIN PRIVATE KEY-----MIIB",
            "t=ghp_0123456789abcdefghij",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        ] {
            let (out, exact, shapes) = scrubber.scrub(body.as_bytes());
            assert_eq!(exact, 0);
            assert!(shapes >= 1, "{body}");
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains(REDACTED_SHAPE), "{text}");
        }
    }

    #[test]
    fn prose_about_credentials_is_left_alone() {
        let scrubber = Scrubber::new(None);
        for body in [
            "never send a bearer token",
            "WWW-Authenticate: Bearer realm=\"mcp\"",
            "the token was rejected",
        ] {
            let (out, _, shapes) = scrubber.scrub(body.as_bytes());
            assert_eq!(shapes, 0, "{body}");
            assert_eq!(out, body.as_bytes());
        }
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors_unpadded() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes(), STANDARD), expected.as_bytes());
        }
        assert_eq!(base64(&[0xfb, 0xff], URL_SAFE), b"-_8");
        assert_eq!(base64(&[0xfb, 0xff], STANDARD), b"+/8");
    }
}
