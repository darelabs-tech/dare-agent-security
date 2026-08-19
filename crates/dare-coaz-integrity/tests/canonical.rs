//! Table-driven canonicalization equivalence and inequality proofs.

use dare_coaz_integrity::{CanonicalError, CanonicalNumber, CanonicalValue};
use serde_json::json;

#[derive(Debug)]
struct EquivalenceCase {
    name: &'static str,
    left: serde_json::Value,
    right: serde_json::Value,
    expected_canonical: &'static str,
}

#[derive(Debug)]
struct InequalityCase {
    name: &'static str,
    left: serde_json::Value,
    right: serde_json::Value,
}

#[test]
fn table_equivalence_cases() {
    let cases = [
        EquivalenceCase {
            name: "object_key_reorder",
            left: json!({"a": 1, "b": 2}),
            right: json!({"b": 2, "a": 1}),
            expected_canonical: r#"{"a":1,"b":2}"#,
        },
        EquivalenceCase {
            name: "nested_object_key_reorder",
            left: json!({"outer": {"z": 1, "a": 2}, "list": [1, 2]}),
            right: json!({"list": [1, 2], "outer": {"a": 2, "z": 1}}),
            expected_canonical: r#"{"list":[1,2],"outer":{"a":2,"z":1}}"#,
        },
        EquivalenceCase {
            name: "integer_whole_float_normalization",
            left: json!({"rate": 1}),
            right: json!({"rate": 1.0}),
            expected_canonical: r#"{"rate":1}"#,
        },
        EquivalenceCase {
            name: "negative_zero_normalization",
            left: json!({"value": 0}),
            right: json!({"value": -0.0}),
            expected_canonical: r#"{"value":0}"#,
        },
        EquivalenceCase {
            name: "null_bool_string_primitives",
            left: json!({"flag": true, "note": "ok", "empty": null}),
            right: json!({"empty": null, "note": "ok", "flag": true}),
            expected_canonical: r#"{"empty":null,"flag":true,"note":"ok"}"#,
        },
    ];

    for case in cases {
        let left = CanonicalValue::normalize(&case.left).expect(case.name);
        let right = CanonicalValue::normalize(&case.right).expect(case.name);

        assert_eq!(left, right, "{}: semantic equality", case.name);
        assert_eq!(
            left.canonical_string(),
            case.expected_canonical,
            "{}: canonical string",
            case.name
        );
        assert_eq!(
            left.digest(),
            right.digest(),
            "{}: digest equality",
            case.name
        );
        assert!(
            !left.canonical_string().contains(' '),
            "{}: canonical form must not contain whitespace artifacts",
            case.name
        );
    }
}

#[test]
fn table_inequality_cases() {
    let cases = [
        InequalityCase {
            name: "mapped_scalar_change",
            left: json!({"a": 1, "b": 2}),
            right: json!({"a": 1, "b": 3}),
        },
        InequalityCase {
            name: "array_order_significant",
            left: json!({"items": [1, 2, 3]}),
            right: json!({"items": [3, 2, 1]}),
        },
        InequalityCase {
            name: "nested_value_change",
            left: json!({"nested": {"x": 1}}),
            right: json!({"nested": {"x": 2}}),
        },
        InequalityCase {
            name: "type_change_number_to_string",
            left: json!({"id": 42}),
            right: json!({"id": "42"}),
        },
    ];

    for case in cases {
        let left = CanonicalValue::normalize(&case.left).expect(case.name);
        let right = CanonicalValue::normalize(&case.right).expect(case.name);

        assert_ne!(left, right, "{}: semantic inequality", case.name);
        assert_ne!(
            left.digest(),
            right.digest(),
            "{}: digest inequality",
            case.name
        );
    }
}

#[test]
fn table_numeric_edge_cases() {
    let large = CanonicalValue::normalize(&json!(u64::MAX)).expect("unsigned max");
    assert_eq!(large.canonical_string(), u64::MAX.to_string());

    let negative = CanonicalValue::normalize(&json!(i64::MIN)).expect("signed min");
    assert_eq!(negative.canonical_string(), i64::MIN.to_string());

    let fractional = CanonicalValue::normalize(&json!(0.125)).expect("fraction");
    assert_eq!(fractional.canonical_string(), "0.125");
}

#[test]
fn table_non_finite_rejections() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            CanonicalNumber::try_from_f64(value),
            Err(CanonicalError::NonFiniteNumber)
        );
    }
}

#[test]
fn repeatability_across_serialize_deserialize() {
    let original = json!({
        "mapping": {"daily_rate": 120, "customer_id": "cust-1"},
        "claims": {"role": "agent", "scopes": ["read", "write"]}
    });

    let normalized = CanonicalValue::normalize(&original).expect("normalize");
    let canonical = normalized.canonical_string();
    let digest = normalized.digest();

    let reparsed = CanonicalValue::from_json_str(&canonical).expect("reparsed");
    assert_eq!(reparsed.canonical_string(), canonical);
    assert_eq!(reparsed.digest(), digest);

    let serde_roundtrip: CanonicalValue =
        serde_json::from_str(&serde_json::to_string(&normalized).expect("serde json"))
            .expect("serde roundtrip");
    assert_eq!(serde_roundtrip, normalized);
    assert_eq!(serde_roundtrip.digest(), digest);
}

#[test]
fn canonical_form_has_no_map_iteration_artifacts() {
    let values = [
        json!({"z": 3, "m": 2, "a": 1}),
        json!({"b": 2, "a": 1, "c": 3}),
        json!({"y": 9, "x": 8, "w": 7}),
    ];

    let digests: Vec<String> = values
        .iter()
        .map(|value| {
            CanonicalValue::normalize(value)
                .expect("normalize")
                .digest()
        })
        .collect();

    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[1], digests[2]);

    for value in values {
        let canonical = CanonicalValue::normalize(&value)
            .expect("normalize")
            .canonical_string();
        let keys: Vec<&str> = canonical
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .map(|pair| pair.split(':').next().expect("key").trim_matches('"'))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "object keys must be lexicographically sorted");
    }
}
