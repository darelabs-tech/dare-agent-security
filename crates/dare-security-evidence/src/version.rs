//! Schema version parsing for the public evidence contract.
//!
//! Versions are serialized as `MAJOR.MINOR.PATCH` strings. Fail-closed
//! handling of unsupported majors belongs to semantic validation.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Parsed evidence schema version (`MAJOR.MINOR.PATCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersion {
    /// Breaking contract revision.
    pub major: u64,
    /// Additive contract revision.
    pub minor: u64,
    /// Compatible contract revision.
    pub patch: u64,
}

impl SchemaVersion {
    /// Evidence contract v1.0.0.
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Construct a version triple.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Error raised when a schema version string is not `MAJOR.MINOR.PATCH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionParseError {
    input: String,
}

impl VersionParseError {
    /// Original rejected input, if it was well-formed enough to retain.
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "schema version must be MAJOR.MINOR.PATCH, got {:?}",
            self.input
        )
    }
}

impl std::error::Error for VersionParseError {}

impl FromStr for SchemaVersion {
    type Err = VersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || VersionParseError {
            input: s.to_owned(),
        };
        let mut parts = s.split('.');
        let major = parts.next().and_then(parse_numeric_component);
        let minor = parts.next().and_then(parse_numeric_component);
        let patch = parts.next().and_then(parse_numeric_component);
        if parts.next().is_some() {
            return Err(err());
        }
        match (major, minor, patch) {
            (Some(major), Some(minor), Some(patch)) => Ok(Self {
                major,
                minor,
                patch,
            }),
            _ => Err(err()),
        }
    }
}

fn parse_numeric_component(part: &str) -> Option<u64> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    part.parse().ok()
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::SchemaVersion;

    #[test]
    fn parses_and_displays_semver_triple() {
        let v: SchemaVersion = "1.0.0".parse().expect("parse");
        assert_eq!(v, SchemaVersion::V1);
        assert_eq!(v.to_string(), "1.0.0");
    }

    #[test]
    fn rejects_malformed_versions() {
        for input in ["", "1", "1.0", "1.0.0.1", "v1.0.0", "01.0.0", "1.0.x"] {
            assert!(
                input.parse::<SchemaVersion>().is_err(),
                "expected {input:?} to fail"
            );
        }
    }

    #[test]
    fn serde_round_trips_as_string() {
        let json = serde_json::to_string(&SchemaVersion::V1).unwrap();
        assert_eq!(json, "\"1.0.0\"");
        let parsed: SchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SchemaVersion::V1);
    }
}
