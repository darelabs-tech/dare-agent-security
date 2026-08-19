//! In-memory tool input-schema bounding.
//!
//! External JSON Schema `$ref` values are recorded as-is and never fetched.
//! Nesting is truncated at the configured depth. Schemas are never executed
//! as validators.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::inventory::DiscoveryHashRef;
use crate::inventory_validation::{MAX_INPUT_SCHEMA_DEPTH, MAX_INPUT_SCHEMA_NODES};

/// Result of bounding an advertised tool input schema.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BoundedSchema {
    /// Canonical in-memory object, when it stays within depth/node limits.
    pub object: Option<Map<String, Value>>,
    /// SHA-256 of the canonical JSON, when serialization succeeds.
    pub digest: Option<DiscoveryHashRef>,
    /// True when nesting exceeded `max_schema_depth`.
    pub depth_exceeded: bool,
    /// True when the in-memory node count exceeded the capture bound.
    pub nodes_exceeded: bool,
    /// True when an `http(s)` `$ref` was observed and left unresolved.
    pub external_ref: bool,
}

/// Bound `schema` without dereferencing remote `$ref` values.
pub(crate) fn bound_input_schema(schema: &Map<String, Value>, max_depth: usize) -> BoundedSchema {
    let depth_limit = max_depth.clamp(1, MAX_INPUT_SCHEMA_DEPTH);
    let mut depth_exceeded = false;
    let mut external_ref = false;
    let bounded = bound_value(
        &Value::Object(schema.clone()),
        1,
        depth_limit,
        &mut depth_exceeded,
        &mut external_ref,
    );
    let digest = canonical_digest(&bounded);
    let nodes = json_nodes(&bounded);
    let nodes_exceeded = nodes > MAX_INPUT_SCHEMA_NODES;
    let object = match bounded {
        Value::Object(map) if !depth_exceeded && !nodes_exceeded => Some(map),
        _ => None,
    };
    BoundedSchema {
        object,
        digest,
        depth_exceeded,
        nodes_exceeded,
        external_ref,
    }
}

fn bound_value(
    value: &Value,
    depth: usize,
    max_depth: usize,
    depth_exceeded: &mut bool,
    external_ref: &mut bool,
) -> Value {
    if depth > max_depth {
        *depth_exceeded = true;
        return match value {
            Value::Array(_) => Value::Array(Vec::new()),
            Value::Object(_) => Value::Object(Map::new()),
            other => other.clone(),
        };
    }
    match value {
        Value::Object(map) => {
            mark_external_ref(map, external_ref);
            let mut out = Map::new();
            for (key, child) in map {
                out.insert(
                    key.clone(),
                    bound_value(child, depth + 1, max_depth, depth_exceeded, external_ref),
                );
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let children = items
                .iter()
                .map(|item| bound_value(item, depth + 1, max_depth, depth_exceeded, external_ref))
                .collect();
            Value::Array(children)
        }
        other => other.clone(),
    }
}

fn mark_external_ref(map: &Map<String, Value>, external_ref: &mut bool) {
    if let Some(Value::String(reference)) = map.get("$ref") {
        if is_external_ref(reference) {
            *external_ref = true;
        }
    }
}

/// True when `reference` is an absolute HTTP(S) JSON Schema `$ref`.
pub(crate) fn is_external_ref(reference: &str) -> bool {
    let lowered = reference.trim().to_ascii_lowercase();
    lowered.starts_with("http://") || lowered.starts_with("https://")
}

fn canonical_digest(value: &Value) -> Option<DiscoveryHashRef> {
    let bytes = serde_json::to_vec(value).ok()?;
    Some(sha256_digest(&bytes))
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> DiscoveryHashRef {
    let digest = Sha256::digest(bytes);
    DiscoveryHashRef {
        alg: "sha256".to_owned(),
        digest: hex_lower(&digest),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn json_nodes(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_nodes).sum::<usize>(),
        Value::Array(items) => 1 + items.iter().map(json_nodes).sum::<usize>(),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn external_http_ref_is_recorded_and_not_rewritten() {
        let schema = json!({
            "type": "object",
            "properties": {
                "vehicle": { "$ref": "https://schemas.example.test/vehicle.json" }
            }
        })
        .as_object()
        .cloned()
        .expect("object");
        let bounded = bound_input_schema(&schema, 16);
        assert!(bounded.external_ref);
        assert!(!bounded.depth_exceeded);
        let captured = bounded.object.expect("in-bounds schema");
        assert_eq!(
            captured["properties"]["vehicle"]["$ref"],
            json!("https://schemas.example.test/vehicle.json")
        );
    }

    #[test]
    fn depth_limit_truncates_without_following_refs() {
        let schema = json!({
            "a": { "b": { "c": { "d": { "type": "string" } } } }
        })
        .as_object()
        .cloned()
        .expect("object");
        let bounded = bound_input_schema(&schema, 2);
        assert!(bounded.depth_exceeded);
        assert!(bounded.object.is_none());
        assert!(bounded.digest.is_some());
    }

    #[test]
    fn relative_ref_is_not_treated_as_external() {
        assert!(!is_external_ref("#/definitions/item"));
        assert!(!is_external_ref("definitions/item.json"));
        assert!(is_external_ref("https://example.test/a.json"));
        assert!(is_external_ref("http://example.test/a.json"));
    }
}
