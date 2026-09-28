//! Exact origins (BLUEPRINT §4.3).
//!
//! An origin is `https://host[:port]` and nothing else: no path, query,
//! fragment, userinfo or wildcard, ASCII only (an IDN must arrive punycoded),
//! no trailing dot, and no shorthand numeric IPv4 (`2130706433`, `0x7f.1`,
//! `127.1`) that a resolver would silently expand. Port 443 normalizes away so
//! two spellings of one origin compare equal.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::{AuthorizationRefusal, RemoteError, Result};
use crate::ids::refuse_forbidden_chars;

/// The host part of an origin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// Lowercase ASCII domain.
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl Host {
    /// The literal address, when the host is one.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Domain(_) => None,
            Self::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Self::Ipv6(ip) => Some(IpAddr::V6(*ip)),
        }
    }

    /// The name a resolver or TLS client uses for this host.
    pub fn name(&self) -> String {
        match self {
            Self::Domain(domain) => domain.clone(),
            Self::Ipv4(ip) => ip.to_string(),
            Self::Ipv6(ip) => ip.to_string(),
        }
    }
}

/// A parsed, normalized `https` origin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    host: Host,
    port: u16,
}

fn refuse() -> RemoteError {
    RemoteError::Authorization(AuthorizationRefusal::Origin)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn parse_dotted_quad(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (slot, part) in octets.iter_mut().zip(&parts) {
        // Decimal only, no leading zeros (which some parsers read as octal).
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// Whether every label is numeric or hex-looking, the shapes a resolver may
/// read as a shorthand IPv4 address.
fn looks_numeric(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && (label.bytes().all(|b| b.is_ascii_digit())
                || (label.starts_with("0x") && label[2..].bytes().all(|b| b.is_ascii_hexdigit())))
    })
}

impl Origin {
    /// Parse and normalize. Every refusal is `AuthorizationRefusal::Origin`
    /// (or `ForbiddenCharacter`), and never echoes the input.
    pub fn parse(input: &str) -> Result<Origin> {
        refuse_forbidden_chars(input, "origin")?;
        if input.is_empty() || input.len() > 262 || !input.is_ascii() {
            return Err(refuse());
        }
        let rest = input.strip_prefix("https://").ok_or_else(refuse)?;
        if rest.contains(['/', '?', '#', '@', '*', '\\', ' ']) {
            return Err(refuse());
        }
        let (host_part, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (inside, after) = bracketed.split_once(']').ok_or_else(refuse)?;
            let ip: Ipv6Addr = inside.parse().map_err(|_| refuse())?;
            (Host::Ipv6(ip), after)
        } else {
            let (host, after) = match rest.rfind(':') {
                Some(index) => (&rest[..index], &rest[index..]),
                None => (rest, ""),
            };
            let lowered = host.to_ascii_lowercase();
            if lowered.is_empty() || lowered.len() > 253 || lowered.ends_with('.') {
                return Err(refuse());
            }
            if let Some(ip) = parse_dotted_quad(&lowered) {
                (Host::Ipv4(ip), after)
            } else if looks_numeric(&lowered) {
                return Err(refuse());
            } else if lowered.split('.').all(valid_label) {
                (Host::Domain(lowered), after)
            } else {
                return Err(refuse());
            }
        };
        let port = match port {
            "" => 443,
            p => {
                let digits = p.strip_prefix(':').ok_or_else(refuse)?;
                if digits.is_empty()
                    || digits.len() > 5
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(refuse());
                }
                let value: u32 = digits.parse().map_err(|_| refuse())?;
                if !(1..=65_535).contains(&value) {
                    return Err(refuse());
                }
                value as u16
            }
        };
        Ok(Origin {
            host: host_part,
            port,
        })
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// `https://host` or `https://host:port`.
    pub fn as_string(&self) -> String {
        let host = match &self.host {
            Host::Ipv6(ip) => format!("[{ip}]"),
            other => other.name(),
        };
        if self.port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.port)
        }
    }

    /// Whether the host is a loopback name or address.
    pub fn is_loopback(&self) -> bool {
        match &self.host {
            Host::Domain(domain) => domain == "localhost",
            Host::Ipv4(ip) => ip.is_loopback(),
            Host::Ipv6(ip) => ip.is_loopback(),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_string())
    }
}

impl Serialize for Origin {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Origin::parse(&raw).map_err(|_| serde::de::Error::custom("invalid origin"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_origins_parse_and_normalize() {
        for (input, normalized) in [
            ("https://agent.example.test", "https://agent.example.test"),
            ("https://Agent.Example.TEST", "https://agent.example.test"),
            (
                "https://agent.example.test:443",
                "https://agent.example.test",
            ),
            (
                "https://agent.example.test:8443",
                "https://agent.example.test:8443",
            ),
            ("https://127.0.0.1:18443", "https://127.0.0.1:18443"),
            ("https://[::1]:9000", "https://[::1]:9000"),
            (
                "https://xn--bcher-kva.example",
                "https://xn--bcher-kva.example",
            ),
            ("https://localhost:4443", "https://localhost:4443"),
        ] {
            assert_eq!(Origin::parse(input).expect(input).as_string(), normalized);
        }
        assert_eq!(
            Origin::parse("https://a.test:443").unwrap(),
            Origin::parse("https://a.test").unwrap()
        );
    }

    #[test]
    fn every_refused_shape_is_refused_without_echo() {
        for bad in [
            "http://agent.example.test",
            "ws://agent.example.test",
            "file:///etc/passwd",
            "https://agent.example.test/",
            "https://agent.example.test/a2a",
            "https://agent.example.test?x=1",
            "https://agent.example.test#frag",
            "https://user:pw@agent.example.test",
            "https://*.example.test",
            "https://agent.example.test.",
            "https://bücher.example",
            "https://-bad.example",
            "https://bad-.example",
            "https://agent..example",
            "https://2130706433",
            "https://0x7f.0.0.1",
            "https://127.1",
            "https://010.0.0.1",
            "https://agent.example.test:0",
            "https://agent.example.test:65536",
            "https://agent.example.test:",
            "https://agent.example.test:80a",
            "https://[not-an-ip]",
            "https://",
            "",
            "https://agent example.test",
        ] {
            let error = Origin::parse(bad).expect_err(bad);
            let message = error.to_string();
            assert!(
                bad.len() < 9 || !message.contains(&bad[8..]),
                "{bad}: {message}"
            );
        }
    }

    #[test]
    fn control_and_bidi_characters_are_named_by_codepoint() {
        match Origin::parse("https://a\u{202e}.test") {
            Err(RemoteError::ForbiddenCharacter { codepoint, .. }) => assert_eq!(codepoint, 0x202e),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn serde_round_trips_the_normalized_form_and_refuses_bad_values() {
        let origin: Origin = serde_json::from_str("\"https://A.test:443\"").unwrap();
        assert_eq!(
            serde_json::to_string(&origin).unwrap(),
            "\"https://a.test\""
        );
        assert!(serde_json::from_str::<Origin>("\"http://a.test\"").is_err());
    }

    #[test]
    fn loopback_detection() {
        assert!(Origin::parse("https://127.0.0.1:1").unwrap().is_loopback());
        assert!(Origin::parse("https://[::1]:1").unwrap().is_loopback());
        assert!(Origin::parse("https://localhost:1").unwrap().is_loopback());
        assert!(!Origin::parse("https://agent.example.test")
            .unwrap()
            .is_loopback());
    }
}
