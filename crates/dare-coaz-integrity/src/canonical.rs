//! Semantic normalization and deterministic canonical serialization for JSON-like values.
//!
//! Canonicalization pipeline:
//! ```text
//! raw JSON value -> semantic normalization -> canonical UTF-8 bytes -> SHA-256 digest
//! ```

use std::collections::BTreeMap;
use std::fmt::{self, Write as FmtWrite};
use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Normalized JSON-like domain value with deterministic equality semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Number(CanonicalNumber),
    String(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

/// Deterministic numeric representation after semantic normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalNumber {
    Integer(i64),
    Unsigned(u64),
    Float(OrderedFloat),
}

/// Float wrapper with total ordering for canonical equality (rejects non-finite at parse time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedFloat(u64);

impl OrderedFloat {
    fn new(value: f64) -> Result<Self, CanonicalError> {
        if !value.is_finite() {
            return Err(CanonicalError::NonFiniteNumber);
        }
        let bits = if value == 0.0 {
            0.0_f64.to_bits()
        } else {
            value.to_bits()
        };
        Ok(Self(bits))
    }

    fn get(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// Errors raised while normalizing raw JSON into [`CanonicalValue`].
#[derive(Debug, PartialEq, Eq)]
pub enum CanonicalError {
    InvalidJson,
    NonFiniteNumber,
    InvalidNumber,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => f.write_str("invalid JSON input"),
            Self::NonFiniteNumber => f.write_str("non-finite numeric value is not allowed"),
            Self::InvalidNumber => f.write_str("invalid numeric value"),
        }
    }
}

impl std::error::Error for CanonicalError {}

impl CanonicalValue {
    /// Normalizes a parsed JSON value into the project-owned semantic representation.
    pub fn normalize(value: &Value) -> Result<Self, CanonicalError> {
        match value {
            Value::Null => Ok(Self::Null),
            Value::Bool(b) => Ok(Self::Bool(*b)),
            Value::Number(n) => Ok(Self::Number(normalize_json_number(n)?)),
            Value::String(s) => Ok(Self::String(s.clone())),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(Self::normalize(item)?);
                }
                Ok(Self::Array(out))
            }
            Value::Object(map) => {
                let mut out = BTreeMap::new();
                for (key, item) in map {
                    out.insert(key.clone(), Self::normalize(item)?);
                }
                Ok(Self::Object(out))
            }
        }
    }

    /// Parses JSON text, normalizes semantics, and returns the canonical value.
    pub fn from_json_str(raw: &str) -> Result<Self, CanonicalError> {
        let value: Value = serde_json::from_str(raw).map_err(|_| CanonicalError::InvalidJson)?;
        Self::normalize(&value)
    }

    /// Returns deterministic UTF-8 bytes for the canonical serialized form.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        write_canonical(&mut buffer, self).expect("canonical write to Vec cannot fail");
        buffer
    }

    /// Returns deterministic UTF-8 text for the canonical serialized form.
    pub fn canonical_string(&self) -> String {
        String::from_utf8(self.canonical_bytes()).expect("canonical form is valid UTF-8")
    }

    /// Returns lowercase hex SHA-256 digest of the canonical serialized form.
    pub fn digest(&self) -> String {
        hex_lower(Sha256::digest(self.canonical_bytes()))
    }
}

impl CanonicalNumber {
    /// Normalizes a finite floating-point scalar into the canonical numeric domain.
    pub fn try_from_f64(value: f64) -> Result<Self, CanonicalError> {
        if !value.is_finite() {
            return Err(CanonicalError::NonFiniteNumber);
        }
        if value.fract() == 0.0 {
            if value >= i64::MIN as f64 && value <= i64::MAX as f64 {
                return Ok(Self::Integer(value as i64));
            }
            if value >= 0.0 && value <= u64::MAX as f64 {
                return Ok(Self::Unsigned(value as u64));
            }
        }
        Ok(Self::Float(OrderedFloat::new(value)?))
    }
}

fn normalize_json_number(number: &serde_json::Number) -> Result<CanonicalNumber, CanonicalError> {
    if let Some(value) = number.as_i64() {
        return Ok(CanonicalNumber::Integer(value));
    }
    if let Some(value) = number.as_u64() {
        return Ok(CanonicalNumber::Unsigned(value));
    }
    if let Some(value) = number.as_f64() {
        return CanonicalNumber::try_from_f64(value);
    }
    Err(CanonicalError::InvalidNumber)
}

fn write_canonical(writer: &mut impl Write, value: &CanonicalValue) -> io::Result<()> {
    match value {
        CanonicalValue::Null => writer.write_all(b"null"),
        CanonicalValue::Bool(true) => writer.write_all(b"true"),
        CanonicalValue::Bool(false) => writer.write_all(b"false"),
        CanonicalValue::Number(number) => write_canonical_number(writer, *number),
        CanonicalValue::String(text) => write_json_string(writer, text),
        CanonicalValue::Array(items) => {
            writer.write_all(b"[")?;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                write_canonical(writer, item)?;
            }
            writer.write_all(b"]")
        }
        CanonicalValue::Object(map) => {
            writer.write_all(b"{")?;
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                write_json_string(writer, key)?;
                writer.write_all(b":")?;
                write_canonical(writer, item)?;
            }
            writer.write_all(b"}")
        }
    }
}

fn write_canonical_number(writer: &mut impl Write, number: CanonicalNumber) -> io::Result<()> {
    match number {
        CanonicalNumber::Integer(value) => write!(writer, "{value}"),
        CanonicalNumber::Unsigned(value) => write!(writer, "{value}"),
        CanonicalNumber::Float(value) => write!(writer, "{}", format_canonical_float(value.get())),
    }
}

fn format_canonical_float(value: f64) -> String {
    serde_json::Number::from_f64(value)
        .map(|number| number.to_string())
        .unwrap_or_else(|| value.to_string())
}

fn write_json_string(writer: &mut impl Write, text: &str) -> io::Result<()> {
    let mut escaped = String::with_capacity(text.len() + 2);
    escaped.push('"');
    for ch in text.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{0008}' => escaped.push_str("\\b"),
            '\u{000C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                let mut code = String::new();
                write!(code, "\\u{:04x}", ch as u32).expect("unicode escape fits");
                escaped.push_str(&code);
            }
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    writer.write_all(escaped.as_bytes())
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

impl fmt::Display for CanonicalValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_key_order_is_irrelevant() {
        let left = CanonicalValue::normalize(&json!({"a": 1, "b": 2})).expect("left");
        let right = CanonicalValue::normalize(&json!({"b": 2, "a": 1})).expect("right");
        assert_eq!(left, right);
        assert_eq!(left.canonical_string(), r#"{"a":1,"b":2}"#);
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn mapped_value_change_changes_digest() {
        let baseline = CanonicalValue::normalize(&json!({"a": 1, "b": 2})).expect("baseline");
        let changed = CanonicalValue::normalize(&json!({"a": 1, "b": 3})).expect("changed");
        assert_ne!(baseline.digest(), changed.digest());
    }

    #[test]
    fn rejects_non_finite_numbers() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                CanonicalNumber::try_from_f64(value),
                Err(CanonicalError::NonFiniteNumber)
            );
        }
    }

    #[test]
    fn canonical_form_is_repeatable() {
        let value =
            CanonicalValue::normalize(&json!({"nested": {"z": 1, "a": [3, 2, 1]}})).expect("value");
        let first = value.canonical_string();
        let second = value.canonical_string();
        assert_eq!(first, second);
        assert_eq!(value.digest(), value.digest());
    }
}
