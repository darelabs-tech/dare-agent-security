//! O-04 / RS-02 / AD-07: no input attribute value reaches any artifact
//! (task-025). Every artifact of every lab entry is scanned for every
//! attribute value, event attribute value and resource attribute value of
//! its inputs that is longer than 3 characters.
use std::collections::BTreeSet;

use dare_runtime_telemetry::{
    corpus::{run_case, LabClass, CORPUS},
    render::artifacts,
    result::Mode,
};
use serde_json::Value;

/// Every scalar inside an OTLP `AnyValue`, as text.
fn any_value_texts(value: &Value, out: &mut BTreeSet<String>) {
    let Some(object) = value.as_object() else {
        return;
    };
    for (kind, inner) in object {
        match (kind.as_str(), inner) {
            ("stringValue" | "bytesValue", Value::String(s)) => {
                out.insert(s.clone());
            }
            ("intValue" | "doubleValue", v) => {
                out.insert(v.as_str().map_or_else(|| v.to_string(), str::to_owned));
            }
            ("arrayValue", v) => {
                for item in v["values"].as_array().into_iter().flatten() {
                    any_value_texts(item, out);
                }
            }
            ("kvlistValue", v) => {
                for kv in v["values"].as_array().into_iter().flatten() {
                    any_value_texts(&kv["value"], out);
                }
            }
            _ => {}
        }
    }
}

/// Every attribute value in an export: span, event, resource and scope.
fn attribute_values(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(_)), Some(v)) = (map.get("key"), map.get("value")) {
                any_value_texts(v, out);
            }
            for v in map.values() {
                attribute_values(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                attribute_values(v, out);
            }
        }
        _ => {}
    }
}

#[test]
fn no_input_value_reaches_any_artifact_of_any_lab_entry() {
    let mut scanned = 0;
    for entry in CORPUS.iter().filter(|e| e.class != LabClass::Refusal) {
        let case = entry.case();
        let mut values = BTreeSet::new();
        for file in &case.files {
            attribute_values(file, &mut values);
        }
        values.retain(|v| v.chars().count() > 3);
        let mut run = run_case(&case, Mode::Simulated).expect(entry.id);
        let files = artifacts(&mut run, None).expect(entry.id);
        assert_eq!(files.len(), 4);
        for (name, bytes) in &files {
            let text = String::from_utf8_lossy(bytes);
            for value in &values {
                assert!(
                    !text.contains(value.as_str()),
                    "{}: {name} carries the input value {value:?}",
                    entry.id
                );
            }
            scanned += 1;
        }
    }
    assert!(scanned >= 4 * 50, "{scanned}");
}

#[test]
fn the_scan_would_see_a_leak() {
    // The scanner itself: a value planted in an artifact is found.
    let mut values = BTreeSet::new();
    attribute_values(
        &serde_json::json!({"attributes": [
            {"key": "a", "value": {"stringValue": "planted-value"}},
            {"key": "b", "value": {"arrayValue": {"values": [{"intValue": "123456"}]}}},
            {"key": "c", "value": {"kvlistValue": {"values": [
                {"key": "d", "value": {"stringValue": "nested-value"}}
            ]}}}
        ]}),
        &mut values,
    );
    assert!(values.contains("planted-value"));
    assert!(values.contains("123456"));
    assert!(values.contains("nested-value"));
}
