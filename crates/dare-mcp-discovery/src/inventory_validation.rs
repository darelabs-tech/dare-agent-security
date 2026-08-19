//! Semantic validation for discovery inventory records.
//!
//! These checks are independent from JSON Schema and from serde. Unknown
//! schema majors fail closed. Error messages never echo rejected values.

use serde_json::Value;

use crate::inventory::{
    Completeness, DiscoveryHashRef, DiscoveryInventory, DiscoveryRedaction, RedactionStrategy,
};
use crate::inventory_error::InventoryError;
use crate::inventory_schema::INVENTORY_SCHEMA_ID;
use crate::inventory_version::InventorySchemaVersion;

/// Supported inventory schema major version for this crate release.
pub const SUPPORTED_SCHEMA_MAJOR: u64 = 1;

/// Maximum nesting depth accepted for captured tool input schemas.
pub const MAX_INPUT_SCHEMA_DEPTH: usize = 16;

/// Maximum JSON nodes accepted for a captured tool input schema.
pub const MAX_INPUT_SCHEMA_NODES: usize = 512;

/// Validate semantic invariants of a deserialized inventory record.
pub fn validate(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    validate_schema(&inventory.schema.id, inventory.schema.version)?;
    validate_identifiers(inventory)?;
    validate_safe_identities(inventory)?;
    validate_hashes(inventory)?;
    validate_input_schemas(inventory)?;
    validate_completeness(inventory)?;
    validate_redaction(&inventory.redaction)?;
    Ok(())
}

fn validate_schema(id: &str, version: InventorySchemaVersion) -> Result<(), InventoryError> {
    if id != INVENTORY_SCHEMA_ID {
        return Err(InventoryError::semantic(
            "schema.id",
            "schema id must equal the canonical discovery identifier",
        ));
    }
    if version.major != SUPPORTED_SCHEMA_MAJOR {
        return Err(InventoryError::UnsupportedSchemaVersion {
            found: Some(version),
            found_major: version.major,
            supported_major: SUPPORTED_SCHEMA_MAJOR,
        });
    }
    Ok(())
}

fn non_empty(label: &str, value: &str) -> Result<(), InventoryError> {
    if value.trim().is_empty() {
        return Err(InventoryError::semantic(
            label,
            "required identifier must be non-empty",
        ));
    }
    Ok(())
}

fn validate_identifiers(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    non_empty("schema.id", &inventory.schema.id)?;
    non_empty("target.id", &inventory.target.id)?;
    non_empty("protocol.revision", &inventory.protocol.revision)?;
    if let Some(server) = &inventory.server {
        non_empty("server.name", &server.name)?;
    }
    if let Some(scanner) = &inventory.scanner {
        non_empty("scanner.name", &scanner.name)?;
        non_empty("scanner.version", &scanner.version)?;
    }
    for (i, tool) in inventory.tools.iter().enumerate() {
        non_empty(&format!("tools.{i}.name"), &tool.name)?;
        if let Some(classification) = &tool.classification {
            non_empty(
                &format!("tools.{i}.classification.rationale_code"),
                &classification.rationale_code,
            )?;
        }
    }
    for (i, resource) in inventory.resources.iter().enumerate() {
        non_empty(&format!("resources.{i}.uri"), &resource.uri)?;
    }
    for (i, template) in inventory.resource_templates.iter().enumerate() {
        non_empty(
            &format!("resource_templates.{i}.uri_template"),
            &template.uri_template,
        )?;
    }
    for (i, prompt) in inventory.prompts.iter().enumerate() {
        non_empty(&format!("prompts.{i}.name"), &prompt.name)?;
    }
    for (i, indicator) in inventory.indicators.iter().enumerate() {
        non_empty(&format!("indicators.{i}.id"), &indicator.id)?;
        non_empty(&format!("indicators.{i}.code"), &indicator.code)?;
        non_empty(&format!("indicators.{i}.message"), &indicator.message)?;
    }
    for (i, warning) in inventory.warnings.iter().enumerate() {
        non_empty(&format!("warnings.{i}.message"), &warning.message)?;
    }
    Ok(())
}

fn is_unsafe_identity(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains('?')
        || value.contains('#')
        || value.contains('@')
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("api_key=")
        || lower.starts_with("bearer ")
}

fn validate_identity_field(label: &str, value: &str) -> Result<(), InventoryError> {
    if is_unsafe_identity(value) {
        return Err(InventoryError::semantic(
            label,
            "identity must be a sanitized host/path or fingerprint without userinfo, query, fragment, or secrets",
        ));
    }
    Ok(())
}

fn validate_safe_identities(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    if let Some(fingerprint) = &inventory.target.endpoint_fingerprint {
        validate_identity_field("target.endpoint_fingerprint", fingerprint)?;
    }
    if let Some(identity) = &inventory.transport.identity {
        validate_identity_field("transport.identity", identity)?;
    }
    Ok(())
}

fn validate_hash(prefix: &str, hash: &DiscoveryHashRef) -> Result<(), InventoryError> {
    let expected_len = match hash.alg.as_str() {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => {
            return Err(InventoryError::semantic(
                prefix,
                "hash algorithm must be sha256, sha384, or sha512",
            ));
        }
    };
    if hash.digest.len() != expected_len
        || !hash.digest.bytes().all(|b| b.is_ascii_hexdigit())
        || hash.digest.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(InventoryError::semantic(
            prefix,
            "hash digest must be lowercase hexadecimal with the length required by the algorithm",
        ));
    }
    Ok(())
}

fn validate_hashes(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    for (i, hash) in inventory.hashes.iter().enumerate() {
        validate_hash(&format!("hashes.{i}"), hash)?;
    }
    for (i, tool) in inventory.tools.iter().enumerate() {
        if let Some(digest) = &tool.input_schema_digest {
            validate_hash(&format!("tools.{i}.input_schema_digest"), digest)?;
        }
    }
    Ok(())
}

fn validate_input_schemas(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    for (i, tool) in inventory.tools.iter().enumerate() {
        if let Some(schema) = &tool.input_schema {
            let value = Value::Object(schema.clone());
            if json_depth(&value) > MAX_INPUT_SCHEMA_DEPTH {
                return Err(InventoryError::semantic(
                    format!("tools.{i}.input_schema"),
                    "input schema exceeds the maximum supported nesting depth",
                ));
            }
            if json_nodes(&value) > MAX_INPUT_SCHEMA_NODES {
                return Err(InventoryError::semantic(
                    format!("tools.{i}.input_schema"),
                    "input schema exceeds the maximum supported node count",
                ));
            }
        }
    }
    Ok(())
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn json_nodes(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_nodes).sum::<usize>(),
        Value::Array(items) => 1 + items.iter().map(json_nodes).sum::<usize>(),
        _ => 1,
    }
}

fn validate_completeness(inventory: &DiscoveryInventory) -> Result<(), InventoryError> {
    let has_partial_warning = inventory
        .warnings
        .iter()
        .any(|warning| warning.code.implies_partial());
    match inventory.completeness {
        Completeness::Complete if has_partial_warning => Err(InventoryError::semantic(
            "completeness",
            "COMPLETE cannot coexist with limit, timeout, or malformed-metadata warnings",
        )),
        Completeness::Complete | Completeness::Partial => Ok(()),
    }
}

fn validate_redaction(redaction: &DiscoveryRedaction) -> Result<(), InventoryError> {
    match (redaction.applied, redaction.strategy) {
        (false, RedactionStrategy::None) => Ok(()),
        (true, RedactionStrategy::Partial | RedactionStrategy::Full) => Ok(()),
        (true, RedactionStrategy::None) => Err(InventoryError::semantic(
            "redaction",
            "NONE strategy requires applied=false",
        )),
        (false, RedactionStrategy::Partial | RedactionStrategy::Full) => {
            Err(InventoryError::semantic(
                "redaction",
                "PARTIAL and FULL strategies require applied=true",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{sample_complete_inventory, DiscoveryWarning, WarningCode};
    use crate::inventory_version::InventorySchemaVersion;

    #[test]
    fn sample_v1_record_is_semantically_valid() {
        validate(&sample_complete_inventory()).expect("sample");
    }

    #[test]
    fn accepts_compatible_1_x_versions() {
        let mut inventory = sample_complete_inventory();
        inventory.schema.version = InventorySchemaVersion::new(1, 4, 2);
        validate(&inventory).expect("1.x is compatible");
    }

    #[test]
    fn unsupported_major_fails_closed() {
        let mut inventory = sample_complete_inventory();
        inventory.schema.version = InventorySchemaVersion::new(2, 0, 0);
        let err = validate(&inventory).expect_err("must fail");
        match err {
            InventoryError::UnsupportedSchemaVersion {
                found_major,
                supported_major,
                ..
            } => {
                assert_eq!(found_major, 2);
                assert_eq!(supported_major, 1);
            }
            other => panic!("unexpected {other}"),
        }
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn empty_semantic_ids_are_rejected() {
        let mut inventory = sample_complete_inventory();
        inventory.target.id = "   ".to_owned();
        let err = validate(&inventory).expect_err("must fail");
        match err {
            InventoryError::SemanticValidation { invariant, .. } => {
                assert_eq!(invariant, "target.id");
            }
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn complete_cannot_coexist_with_limit_warning() {
        let mut inventory = sample_complete_inventory();
        inventory.warnings.push(DiscoveryWarning {
            code: WarningCode::ItemLimitReached,
            message: "item bound reached".to_owned(),
        });
        assert!(matches!(
            validate(&inventory),
            Err(InventoryError::SemanticValidation { invariant, .. }) if invariant == "completeness"
        ));
    }

    #[test]
    fn partial_with_limit_warning_is_accepted() {
        let mut inventory = sample_complete_inventory();
        inventory.completeness = Completeness::Partial;
        inventory.warnings.push(DiscoveryWarning {
            code: WarningCode::Timeout,
            message: "overall timeout reached".to_owned(),
        });
        validate(&inventory).expect("partial");
    }

    #[test]
    fn credential_bearing_identity_is_rejected_without_echo() {
        let mut inventory = sample_complete_inventory();
        const MARKER: &str = "https://user:synth-token@mcp.example.test/mcp?x=1";
        inventory.transport.identity = Some(MARKER.to_owned());
        let err = validate(&inventory).expect_err("must fail");
        assert!(matches!(err, InventoryError::SemanticValidation { .. }));
        assert!(!err.to_string().contains(MARKER));
        assert!(!err.to_string().contains("synth-token"));
    }

    #[test]
    fn incoherent_hash_metadata_is_rejected() {
        let mut inventory = sample_complete_inventory();
        inventory.hashes[0].digest = "abcd".to_owned();
        assert!(matches!(
            validate(&inventory),
            Err(InventoryError::SemanticValidation { .. })
        ));
    }

    #[test]
    fn typed_errors_are_displayable_without_payloads() {
        let err = InventoryError::UnsupportedSchemaVersion {
            found: None,
            found_major: 9,
            supported_major: 1,
        };
        let text = err.to_string();
        assert!(text.contains("unsupported schema major version 9"));
        assert!(!text.contains('{'));
    }
}
