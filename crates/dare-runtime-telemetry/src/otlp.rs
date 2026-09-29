//! The OTLP/JSON trace encoding (BLUEPRINT AD-02), read without an
//! OpenTelemetry or protobuf dependency.
//!
//! The rules followed are those of the OTLP JSON mapping:
//! - keys are lowerCamelCase;
//! - trace and span ids are case-insensitive hex strings, normalized here to
//!   lowercase; an all-zero id is invalid;
//! - 64-bit integers (times, `intValue`) may be a decimal string or a number;
//! - enums (`kind`, `status.code`) are integers;
//! - `AnyValue` is a one-of.
//!
//! Unknown fields below the top level are ignored, as OTLP requires, and
//! counted. Every refusal names a fixed rule, never content.
use serde_json::{Map, Value};

use crate::{
    error::{Input, Refusal, Result},
    limits::MAX_ATTRIBUTES_PER_SPAN,
};

#[derive(Debug, Clone, PartialEq)]
pub enum AnyValue {
    Empty,
    Str(String),
    Bool(bool),
    Int(i64),
    Double(f64),
    /// Base64 text, kept as given: never decoded, only fingerprinted.
    Bytes(String),
    Array(Vec<AnyValue>),
    KvList(Vec<KeyValue>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyValue {
    pub key: String,
    pub value: AnyValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub time: u64,
    pub name: String,
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes: u32,
}

/// OTLP `Span.SpanKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Unspecified,
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    /// W3C trace flags; bit 0 is `sampled`. `None` when not recorded.
    pub flags: Option<u32>,
    pub name: String,
    pub kind: Kind,
    pub start: u64,
    pub end: u64,
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes: u32,
    pub events: Vec<Event>,
    pub dropped_events: u32,
    pub links: usize,
    pub dropped_links: u32,
    /// `Status.code`: 0 unset, 1 ok, 2 error.
    pub status_code: u8,
    pub resource: Vec<KeyValue>,
    pub resource_dropped_attributes: u32,
    pub scope_name: Option<String>,
}

/// One admitted export file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TraceFile {
    pub spans: Vec<Span>,
    pub unknown_fields: u64,
}

type Parse<T> = std::result::Result<T, &'static str>;

struct Reader {
    unknown: u64,
}

fn object(value: &Value) -> Parse<&Map<String, Value>> {
    value.as_object().ok_or("object")
}

fn array<'a>(map: &'a Map<String, Value>, key: &str) -> Parse<&'a [Value]> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err("array"),
    }
}

fn string(map: &Map<String, Value>, key: &str) -> Parse<Option<String>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err("string"),
    }
}

fn uint64(value: &Value, rule: &'static str) -> Parse<u64> {
    match value {
        Value::String(s)
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse().map_err(|_| rule)
        }
        Value::Number(n) => n.as_u64().ok_or(rule),
        _ => Err(rule),
    }
}

fn int64(value: &Value) -> Parse<i64> {
    match value {
        Value::String(s) => s.parse().map_err(|_| "int_value"),
        Value::Number(n) => n.as_i64().ok_or("int_value"),
        _ => Err("int_value"),
    }
}

fn count(map: &Map<String, Value>, key: &str) -> Parse<u32> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("dropped_count"),
    }
}

/// A hex id of `len` bytes, lowercased; all zeros is invalid.
fn hex_id(value: &str, len: usize, rule: &'static str) -> Parse<String> {
    if value.len() != len * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(rule);
    }
    let lower = value.to_ascii_lowercase();
    if lower.bytes().all(|b| b == b'0') {
        return Err(rule);
    }
    Ok(lower)
}

impl Reader {
    fn note_unknown(&mut self, map: &Map<String, Value>, known: &[&str]) {
        self.unknown += map.keys().filter(|k| !known.contains(&k.as_str())).count() as u64;
    }

    fn any_value(&mut self, value: &Value) -> Parse<AnyValue> {
        let map = object(value)?;
        const ONE_OF: [&str; 7] = [
            "stringValue",
            "boolValue",
            "intValue",
            "doubleValue",
            "arrayValue",
            "kvlistValue",
            "bytesValue",
        ];
        let present: Vec<&str> = ONE_OF
            .into_iter()
            .filter(|k| map.get(*k).is_some_and(|v| !v.is_null()))
            .collect();
        self.note_unknown(map, &ONE_OF);
        let [which] = present.as_slice() else {
            return if present.is_empty() {
                Ok(AnyValue::Empty)
            } else {
                Err("any_value_one_of")
            };
        };
        let v = &map[*which];
        Ok(match *which {
            "stringValue" => AnyValue::Str(v.as_str().ok_or("string_value")?.to_owned()),
            "boolValue" => AnyValue::Bool(v.as_bool().ok_or("bool_value")?),
            "intValue" => AnyValue::Int(int64(v)?),
            "doubleValue" => AnyValue::Double(match v {
                Value::Number(n) => n.as_f64().ok_or("double_value")?,
                Value::String(s) => s.parse().map_err(|_| "double_value")?,
                _ => return Err("double_value"),
            }),
            "bytesValue" => AnyValue::Bytes(v.as_str().ok_or("bytes_value")?.to_owned()),
            "arrayValue" => {
                let inner = object(v)?;
                self.note_unknown(inner, &["values"]);
                AnyValue::Array(
                    array(inner, "values")?
                        .iter()
                        .map(|item| self.any_value(item))
                        .collect::<Parse<_>>()?,
                )
            }
            _ => {
                let inner = object(v)?;
                self.note_unknown(inner, &["values"]);
                AnyValue::KvList(self.key_values(array(inner, "values")?)?)
            }
        })
    }

    fn key_values(&mut self, items: &[Value]) -> Parse<Vec<KeyValue>> {
        if items.len() > MAX_ATTRIBUTES_PER_SPAN {
            return Err("attributes");
        }
        items
            .iter()
            .map(|item| {
                let map = object(item)?;
                self.note_unknown(map, &["key", "value"]);
                let key = string(map, "key")?.ok_or("attribute_key")?;
                let value = match map.get("value") {
                    None | Some(Value::Null) => AnyValue::Empty,
                    Some(v) => self.any_value(v)?,
                };
                Ok(KeyValue { key, value })
            })
            .collect()
    }

    fn event(&mut self, value: &Value) -> Parse<Event> {
        let map = object(value)?;
        self.note_unknown(
            map,
            &[
                "timeUnixNano",
                "name",
                "attributes",
                "droppedAttributesCount",
            ],
        );
        Ok(Event {
            time: map
                .get("timeUnixNano")
                .map_or(Ok(0), |v| uint64(v, "event_time"))?,
            name: string(map, "name")?.unwrap_or_default(),
            attributes: self.key_values(array(map, "attributes")?)?,
            dropped_attributes: count(map, "droppedAttributesCount")?,
        })
    }

    fn span(
        &mut self,
        value: &Value,
        resource: &[KeyValue],
        resource_dropped: u32,
        scope_name: &Option<String>,
    ) -> Parse<Span> {
        let map = object(value)?;
        self.note_unknown(
            map,
            &[
                "traceId",
                "spanId",
                "traceState",
                "parentSpanId",
                "flags",
                "name",
                "kind",
                "startTimeUnixNano",
                "endTimeUnixNano",
                "attributes",
                "droppedAttributesCount",
                "events",
                "droppedEventsCount",
                "links",
                "droppedLinksCount",
                "status",
            ],
        );
        let trace_id = hex_id(&string(map, "traceId")?.ok_or("trace_id")?, 16, "trace_id")?;
        let span_id = hex_id(&string(map, "spanId")?.ok_or("span_id")?, 8, "span_id")?;
        let parent_span_id = match string(map, "parentSpanId")? {
            None => None,
            Some(p) if p.is_empty() => None,
            Some(p) => Some(hex_id(&p, 8, "parent_span_id")?),
        };
        let flags = match map.get("flags") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("flags")?,
            ),
        };
        let kind = match map.get("kind") {
            None | Some(Value::Null) => Kind::Unspecified,
            Some(v) => match v.as_u64().ok_or("kind")? {
                0 => Kind::Unspecified,
                1 => Kind::Internal,
                2 => Kind::Server,
                3 => Kind::Client,
                4 => Kind::Producer,
                5 => Kind::Consumer,
                _ => return Err("kind"),
            },
        };
        let status_code = match map.get("status") {
            None | Some(Value::Null) => 0,
            Some(status) => {
                let status = object(status)?;
                self.note_unknown(status, &["message", "code"]);
                match status.get("code") {
                    None | Some(Value::Null) => 0,
                    Some(c) => match c.as_u64().ok_or("status_code")? {
                        code @ 0..=2 => code as u8,
                        _ => return Err("status_code"),
                    },
                }
            }
        };
        Ok(Span {
            trace_id,
            span_id,
            parent_span_id,
            flags,
            name: string(map, "name")?.ok_or("name")?,
            kind,
            start: uint64(
                map.get("startTimeUnixNano").ok_or("start_time")?,
                "start_time",
            )?,
            end: uint64(map.get("endTimeUnixNano").ok_or("end_time")?, "end_time")?,
            attributes: self.key_values(array(map, "attributes")?)?,
            dropped_attributes: count(map, "droppedAttributesCount")?,
            events: array(map, "events")?
                .iter()
                .map(|e| self.event(e))
                .collect::<Parse<_>>()?,
            dropped_events: count(map, "droppedEventsCount")?,
            links: array(map, "links")?.len(),
            dropped_links: count(map, "droppedLinksCount")?,
            status_code,
            resource: resource.to_vec(),
            resource_dropped_attributes: resource_dropped,
            scope_name: scope_name.clone(),
        })
    }

    fn file(&mut self, value: &Value) -> Parse<Vec<Span>> {
        let top = object(value)?;
        if top.keys().any(|k| k != "resourceSpans") || !top.contains_key("resourceSpans") {
            return Err("top_level");
        }
        let mut spans = Vec::new();
        for rs in array(top, "resourceSpans")? {
            let rs = object(rs)?;
            self.note_unknown(rs, &["resource", "scopeSpans", "schemaUrl"]);
            let (resource, resource_dropped) = match rs.get("resource") {
                None | Some(Value::Null) => (Vec::new(), 0),
                Some(r) => {
                    let r = object(r)?;
                    self.note_unknown(r, &["attributes", "droppedAttributesCount"]);
                    (
                        self.key_values(array(r, "attributes")?)?,
                        count(r, "droppedAttributesCount")?,
                    )
                }
            };
            for ss in array(rs, "scopeSpans")? {
                let ss = object(ss)?;
                self.note_unknown(ss, &["scope", "spans", "schemaUrl"]);
                let scope_name = match ss.get("scope") {
                    None | Some(Value::Null) => None,
                    Some(scope) => string(object(scope)?, "name")?,
                };
                for span in array(ss, "spans")? {
                    spans.push(self.span(span, &resource, resource_dropped, &scope_name)?);
                }
            }
        }
        Ok(spans)
    }
}

/// Reads one admitted export. `input` names the file in refusals.
pub fn read_trace_file(value: &Value, input: Input) -> Result<TraceFile> {
    let mut reader = Reader { unknown: 0 };
    let spans = reader
        .file(value)
        .map_err(|reason| Refusal::InvalidTrace { input, reason })?;
    Ok(TraceFile {
        spans,
        unknown_fields: reader.unknown,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::error::TelemetryError;

    const T: Input = Input::Trace(0);
    const TRACE: &str = "5B8EFFF798038103D269B633813FC60C";
    const SPAN: &str = "EEE19B7EC3C1B174";

    fn export(span: Value) -> Value {
        json!({"resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agent"}}]},
            "scopeSpans": [{"scope": {"name": "lib"}, "spans": [span]}]
        }]})
    }

    fn span(extra: Value) -> Value {
        let mut base = json!({
            "traceId": TRACE, "spanId": SPAN, "name": "execute_tool search",
            "startTimeUnixNano": "1544712660000000000", "endTimeUnixNano": 1544712661000000000u64
        });
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        base
    }

    fn reason(value: Value) -> &'static str {
        match read_trace_file(&value, T) {
            Err(TelemetryError::Refused(Refusal::InvalidTrace { reason, .. })) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_span_reads_with_both_time_encodings_and_lowercased_ids() {
        let file = read_trace_file(
            &export(span(json!({"kind": 3, "flags": 1, "parentSpanId": ""}))),
            T,
        )
        .unwrap();
        let s = &file.spans[0];
        assert_eq!(s.trace_id, TRACE.to_ascii_lowercase());
        assert_eq!(s.span_id, SPAN.to_ascii_lowercase());
        assert_eq!(s.parent_span_id, None);
        assert_eq!((s.start, s.end), (1544712660000000000, 1544712661000000000));
        assert_eq!(s.kind, Kind::Client);
        assert_eq!(s.flags, Some(1));
        assert_eq!(s.resource[0].key, "service.name");
        assert_eq!(s.scope_name.as_deref(), Some("lib"));
        assert_eq!(file.unknown_fields, 0);
    }

    #[test]
    fn any_value_is_a_one_of_with_nested_arrays_and_kvlists() {
        let attrs = json!([
            {"key": "s", "value": {"stringValue": "x"}},
            {"key": "b", "value": {"boolValue": true}},
            {"key": "i", "value": {"intValue": "-42"}},
            {"key": "j", "value": {"intValue": 7}},
            {"key": "d", "value": {"doubleValue": 1.5}},
            {"key": "y", "value": {"bytesValue": "AAE="}},
            {"key": "a", "value": {"arrayValue": {"values": [{"stringValue": "p"}, {"intValue": "1"}]}}},
            {"key": "k", "value": {"kvlistValue": {"values": [{"key": "n", "value": {"stringValue": "q"}}]}}},
            {"key": "e"}
        ]);
        let file = read_trace_file(&export(span(json!({"attributes": attrs}))), T).unwrap();
        let v: Vec<&AnyValue> = file.spans[0]
            .attributes
            .iter()
            .map(|kv| &kv.value)
            .collect();
        assert_eq!(v[0], &AnyValue::Str("x".into()));
        assert_eq!(v[1], &AnyValue::Bool(true));
        assert_eq!(v[2], &AnyValue::Int(-42));
        assert_eq!(v[3], &AnyValue::Int(7));
        assert_eq!(v[4], &AnyValue::Double(1.5));
        assert_eq!(v[5], &AnyValue::Bytes("AAE=".into()));
        assert_eq!(
            v[6],
            &AnyValue::Array(vec![AnyValue::Str("p".into()), AnyValue::Int(1)])
        );
        assert!(matches!(v[7], AnyValue::KvList(items) if items[0].key == "n"));
        assert_eq!(v[8], &AnyValue::Empty);
        assert_eq!(
            reason(export(span(
                json!({"attributes": [{"key": "x", "value": {"stringValue": "a", "intValue": 1}}]})
            ))),
            "any_value_one_of"
        );
    }

    #[test]
    fn events_links_status_and_dropped_counts_are_read() {
        let file = read_trace_file(
            &export(span(json!({
                "events": [{"timeUnixNano": "5", "name": "approval", "attributes": [{"key": "tool", "value": {"stringValue": "t"}}]}],
                "links": [{}, {}],
                "droppedAttributesCount": 2, "droppedEventsCount": 1, "droppedLinksCount": 3,
                "status": {"code": 2, "message": "boom"}
            }))),
            T,
        )
        .unwrap();
        let s = &file.spans[0];
        assert_eq!(s.events[0].name, "approval");
        assert_eq!(s.events[0].time, 5);
        assert_eq!(s.links, 2);
        assert_eq!(
            (s.dropped_attributes, s.dropped_events, s.dropped_links),
            (2, 1, 3)
        );
        assert_eq!(s.status_code, 2);
    }

    #[test]
    fn unknown_fields_below_the_top_level_are_counted_and_the_top_level_is_closed() {
        let file =
            read_trace_file(&export(span(json!({"futureField": 1, "other": {}}))), T).unwrap();
        assert_eq!(file.unknown_fields, 2);
        let mut top = export(span(json!({})));
        top["extra"] = json!(1);
        assert_eq!(reason(top), "top_level");
        assert_eq!(reason(json!({"resourceLogs": []})), "top_level");
    }

    #[test]
    fn every_malformed_field_is_refused_with_its_rule() {
        for (bad, rule) in [
            (json!({"traceId": "abc"}), "trace_id"),
            (json!({"traceId": "0".repeat(32)}), "trace_id"),
            (json!({"traceId": "zz".repeat(16)}), "trace_id"),
            (json!({"spanId": "0000000000000000"}), "span_id"),
            (json!({"parentSpanId": "123"}), "parent_span_id"),
            (json!({"startTimeUnixNano": "-1"}), "start_time"),
            (json!({"endTimeUnixNano": 1.5}), "end_time"),
            (json!({"kind": 9}), "kind"),
            (json!({"kind": "SPAN_KIND_CLIENT"}), "kind"),
            (json!({"status": {"code": 7}}), "status_code"),
            (json!({"flags": -1}), "flags"),
            (json!({"name": 3}), "string"),
            (json!({"droppedAttributesCount": "x"}), "dropped_count"),
        ] {
            assert_eq!(reason(export(span(bad.clone()))), rule, "{bad}");
        }
        let too_many: Vec<Value> = (0..=MAX_ATTRIBUTES_PER_SPAN)
            .map(|i| json!({"key": format!("k{i}"), "value": {"intValue": 1}}))
            .collect();
        assert_eq!(
            reason(export(span(json!({"attributes": too_many})))),
            "attributes"
        );
    }
}
