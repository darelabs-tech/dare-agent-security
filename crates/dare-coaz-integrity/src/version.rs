//! Schema version parsing for COAZ integrity vector/result contracts.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Parsed contract schema version (`MAJOR.MINOR.PATCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SchemaVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionParseError {
    input: String,
}

impl VersionParseError {
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
