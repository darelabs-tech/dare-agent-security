//! Normalized spans and value fingerprints (BLUEPRINT AD-07).
//!
//! An attribute value is held in memory only, inside [`NValue`], whose value
//! field is private and which has no `Serialize` implementation. Evaluators
//! read it through crate-private accessors. Everything that can reach an
//! artifact carries a [`Fingerprint`] instead: the kind, the length and the
//! SHA-256 of a canonical encoding. A value therefore cannot be written out by
//! accident: there is no type that would carry it.
use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::otlp::{AnyValue, Event, KeyValue, Kind, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueKind {
    Empty,
    String,
    Bool,
    Int,
    Double,
    Bytes,
    Array,
    Kvlist,
}

/// What an artifact may say about a value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Fingerprint {
    pub kind: ValueKind,
    /// Bytes for strings and bytes, items for arrays and kvlists, 0 otherwise.
    pub length: usize,
    /// `sha256:<hex>` of the canonical encoding.
    pub digest: String,
}

/// An attribute value, held in memory only.
#[derive(Debug, Clone, PartialEq)]
pub struct NValue {
    value: AnyValue,
    fingerprint: Fingerprint,
}

fn canonical(value: &AnyValue, out: &mut Vec<u8>) {
    // A tagged, length-prefixed encoding: two different values never share one.
    fn tagged(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        out.push(tag);
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    match value {
        AnyValue::Empty => out.push(b'E'),
        AnyValue::Str(s) => tagged(out, b'S', s.as_bytes()),
        AnyValue::Bool(b) => tagged(out, b'B', &[u8::from(*b)]),
        AnyValue::Int(i) => tagged(out, b'I', &i.to_be_bytes()),
        AnyValue::Double(d) => tagged(out, b'D', &d.to_bits().to_be_bytes()),
        AnyValue::Bytes(b) => tagged(out, b'Y', b.as_bytes()),
        AnyValue::Array(items) => {
            out.push(b'A');
            out.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for item in items {
                canonical(item, out);
            }
        }
        AnyValue::KvList(items) => {
            out.push(b'K');
            out.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for kv in items {
                tagged(out, b'k', kv.key.as_bytes());
                canonical(&kv.value, out);
            }
        }
    }
}

pub fn fingerprint(value: &AnyValue) -> Fingerprint {
    let (kind, length) = match value {
        AnyValue::Empty => (ValueKind::Empty, 0),
        AnyValue::Str(s) => (ValueKind::String, s.len()),
        AnyValue::Bool(_) => (ValueKind::Bool, 0),
        AnyValue::Int(_) => (ValueKind::Int, 0),
        AnyValue::Double(_) => (ValueKind::Double, 0),
        AnyValue::Bytes(b) => (ValueKind::Bytes, b.len()),
        AnyValue::Array(items) => (ValueKind::Array, items.len()),
        AnyValue::KvList(items) => (ValueKind::Kvlist, items.len()),
    };
    let mut bytes = Vec::new();
    canonical(value, &mut bytes);
    Fingerprint {
        kind,
        length,
        digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
    }
}

// The value accessors are read by the evaluators (tasks 013-016).
#[allow(dead_code)]
impl NValue {
    pub fn new(value: AnyValue) -> Self {
        let fingerprint = fingerprint(&value);
        Self { value, fingerprint }
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match &self.value {
            AnyValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match &self.value {
            AnyValue::Int(i) => Some(*i),
            AnyValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Every string and bytes text inside the value, nested ones included, for
    /// the confidentiality scan.
    pub(crate) fn texts(&self) -> Vec<&str> {
        fn walk<'a>(value: &'a AnyValue, out: &mut Vec<&'a str>) {
            match value {
                AnyValue::Str(s) | AnyValue::Bytes(s) => out.push(s),
                AnyValue::Array(items) => items.iter().for_each(|v| walk(v, out)),
                AnyValue::KvList(items) => items.iter().for_each(|kv| walk(&kv.value, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        walk(&self.value, &mut out);
        out
    }
}

pub type Attributes = BTreeMap<String, NValue>;

#[derive(Debug, Clone, PartialEq)]
pub struct NEvent {
    pub time: u64,
    pub name: String,
    pub attributes: Attributes,
    pub dropped_attributes: u32,
}

/// A span as the evaluators see it.
#[derive(Debug, Clone, PartialEq)]
pub struct NSpan {
    pub file: usize,
    pub trace_id: String,
    pub span_id: String,
    pub parent: Option<String>,
    /// The span name, held like a value: it can embed tool or agent names.
    pub name: NValue,
    pub kind: Kind,
    pub start: u64,
    pub end: u64,
    pub flags: Option<u32>,
    pub status_code: u8,
    pub attributes: Attributes,
    /// Keys given more than once on this span (OTLP requires unique keys).
    pub duplicate_keys: Vec<String>,
    pub resource: Attributes,
    pub events: Vec<NEvent>,
    pub links: usize,
    pub dropped_attributes: u32,
    pub dropped_events: u32,
    pub dropped_links: u32,
    pub dropped_resource_attributes: u32,
}

impl NSpan {
    /// The attribute `key`, looking at the span first, then its resource.
    pub fn attr(&self, key: &str) -> Option<&NValue> {
        self.attributes.get(key).or_else(|| self.resource.get(key))
    }

    /// W3C `sampled` flag; `None` when the export did not record flags.
    pub fn sampled(&self) -> Option<bool> {
        self.flags.map(|f| f & 1 == 1)
    }
}

fn attributes(items: &[KeyValue], duplicates: &mut Vec<String>) -> Attributes {
    let mut out = Attributes::new();
    for kv in items {
        // OTLP requires unique keys; a repeated key keeps its first value and is
        // reported, so a later entry cannot overwrite an earlier one unseen.
        if out.contains_key(&kv.key) {
            duplicates.push(kv.key.clone());
            continue;
        }
        out.insert(kv.key.clone(), NValue::new(kv.value.clone()));
    }
    out
}

fn event(event: &Event) -> NEvent {
    NEvent {
        time: event.time,
        name: event.name.clone(),
        attributes: attributes(&event.attributes, &mut Vec::new()),
        dropped_attributes: event.dropped_attributes,
    }
}

pub fn normalize(span: &Span, file: usize) -> NSpan {
    let mut duplicate_keys = Vec::new();
    let span_attributes = attributes(&span.attributes, &mut duplicate_keys);
    let resource = attributes(&span.resource, &mut Vec::new());
    duplicate_keys.sort();
    duplicate_keys.dedup();
    NSpan {
        file,
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent: span.parent_span_id.clone(),
        name: NValue::new(AnyValue::Str(span.name.clone())),
        kind: span.kind,
        start: span.start,
        end: span.end,
        flags: span.flags,
        status_code: span.status_code,
        attributes: span_attributes,
        duplicate_keys,
        resource,
        events: span.events.iter().map(event).collect(),
        links: span.links,
        dropped_attributes: span.dropped_attributes,
        dropped_events: span.dropped_events,
        dropped_links: span.dropped_links,
        dropped_resource_attributes: span.resource_dropped_attributes,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{error::Input, otlp::read_trace_file};

    fn kv(key: &str, value: AnyValue) -> KeyValue {
        KeyValue {
            key: key.into(),
            value,
        }
    }

    #[test]
    fn fingerprints_separate_kinds_and_values_and_carry_no_value() {
        let a = fingerprint(&AnyValue::Str("42".into()));
        let b = fingerprint(&AnyValue::Int(42));
        let c = fingerprint(&AnyValue::Str("42".into()));
        assert_ne!(a.digest, b.digest, "kind is part of the digest");
        assert_eq!(a, c, "deterministic");
        assert_eq!((a.kind, a.length), (ValueKind::String, 2));
        // Nested structure with the same flattened text differs.
        let x = fingerprint(&AnyValue::Array(vec![
            AnyValue::Str("ab".into()),
            AnyValue::Str("c".into()),
        ]));
        let y = fingerprint(&AnyValue::Array(vec![
            AnyValue::Str("a".into()),
            AnyValue::Str("bc".into()),
        ]));
        assert_ne!(x.digest, y.digest);
        let secret = "sk-live-CANARY-VALUE-1234";
        let text = serde_json::to_string(&fingerprint(&AnyValue::Str(secret.into()))).unwrap();
        assert!(!text.contains("CANARY"), "{text}");
        assert!(text.starts_with(r#"{"kind":"STRING","length":25,"digest":"sha256:"#));
    }

    #[test]
    fn normalization_keeps_first_of_duplicate_keys_and_reads_resource_as_fallback() {
        let value = json!({"resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}], "droppedAttributesCount": 1},
            "scopeSpans": [{"spans": [{
                "traceId": "5b8efff798038103d269b633813fc60c", "spanId": "eee19b7ec3c1b174",
                "parentSpanId": "aaa19b7ec3c1b174", "flags": 256,
                "name": "execute_tool x", "startTimeUnixNano": "1", "endTimeUnixNano": "2",
                "attributes": [
                    {"key": "gen_ai.tool.name", "value": {"stringValue": "first"}},
                    {"key": "gen_ai.tool.name", "value": {"stringValue": "second"}},
                    {"key": "n", "value": {"intValue": "5"}}
                ],
                "events": [{"name": "e", "timeUnixNano": "1", "attributes": [{"key": "k", "value": {"stringValue": "v"}}]}]
            }]}]
        }]});
        let file = read_trace_file(&value, Input::Trace(0)).unwrap();
        let span = normalize(&file.spans[0], 3);
        assert_eq!(span.file, 3);
        assert_eq!(
            span.attr("gen_ai.tool.name").unwrap().as_str(),
            Some("first")
        );
        assert_eq!(span.duplicate_keys, vec!["gen_ai.tool.name".to_owned()]);
        assert_eq!(span.attr("service.name").unwrap().as_str(), Some("svc"));
        assert_eq!(span.attr("n").unwrap().as_i64(), Some(5));
        assert_eq!(span.dropped_resource_attributes, 1);
        assert_eq!(span.parent.as_deref(), Some("aaa19b7ec3c1b174"));
        assert_eq!(span.sampled(), Some(false), "flags 256 has bit 0 clear");
        assert_eq!(span.events[0].attributes["k"].as_str(), Some("v"));
        assert_eq!(span.name.fingerprint().kind, ValueKind::String);
    }

    #[test]
    fn texts_reach_nested_strings_and_bytes() {
        let v = NValue::new(AnyValue::KvList(vec![
            kv("a", AnyValue::Str("one".into())),
            kv(
                "b",
                AnyValue::Array(vec![AnyValue::Bytes("dHdv".into()), AnyValue::Int(3)]),
            ),
        ]));
        assert_eq!(v.texts(), vec!["one", "dHdv"]);
    }

    /// AD-07: the value is reachable only inside the crate. This file is the
    /// only one that may name the private field, and `NValue` must not derive
    /// or implement `Serialize`.
    #[test]
    fn the_raw_value_has_no_serializer_and_no_public_accessor() {
        let source = include_str!("normalize.rs");
        let decl = source
            .find("pub struct NValue")
            .expect("NValue is declared here");
        let derive_line = source[..decl].lines().last().unwrap_or("");
        let derive_line = source[..decl]
            .lines()
            .rev()
            .find(|l| l.starts_with("#[derive"))
            .unwrap_or(derive_line);
        assert!(!derive_line.contains("Serialize"), "{derive_line}");
        assert!(!source.contains(&format!("impl {} for NValue", "Serialize")));
        assert!(
            source.contains("    value: AnyValue,\n"),
            "the field stays private"
        );
        for accessor in ["fn as_str", "fn as_i64", "fn texts"] {
            let at = source.find(accessor).unwrap();
            let line_start = source[..at].rfind('\n').unwrap() + 1;
            assert!(
                source[line_start..at].contains("pub(crate)"),
                "{accessor} must stay crate-private"
            );
        }
    }
}
