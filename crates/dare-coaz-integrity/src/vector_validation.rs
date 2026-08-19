//! Semantic validation for vector definitions.

use crate::error::IntegrityError;
use crate::secret_safety::validate_vector_secret_safety;
use crate::vector::VectorDefinition;
use crate::vector_schema::{validate_vector_instance, SUPPORTED_VECTOR_SCHEMA_MAJOR};
use crate::version::SchemaVersion;

/// Validate a vector definition structurally and semantically.
pub fn validate_vector(vector: &VectorDefinition) -> Result<(), IntegrityError> {
    let json = serde_json::to_value(vector).map_err(|_| IntegrityError::Serialization {
        kind: "vector-json".to_owned(),
    })?;
    validate_vector_instance(&json)?;
    validate_vector_schema_version(vector.schema_version)?;
    validate_vector_identifiers(vector)?;
    validate_standards_present(vector)?;
    validate_vector_secret_safety(vector)?;
    Ok(())
}

/// Parse JSON, validate structurally and semantically, and deserialize.
pub fn parse_and_validate_vector(json: &str) -> Result<VectorDefinition, IntegrityError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| IntegrityError::Serialization {
            kind: "vector-json".to_owned(),
        })?;
    validate_vector_instance(&value)?;
    let vector: VectorDefinition =
        serde_json::from_value(value).map_err(|_| IntegrityError::Serialization {
            kind: "vector-model".to_owned(),
        })?;
    validate_vector(&vector)?;
    Ok(vector)
}

fn validate_vector_schema_version(version: SchemaVersion) -> Result<(), IntegrityError> {
    if version.major != SUPPORTED_VECTOR_SCHEMA_MAJOR {
        return Err(IntegrityError::UnsupportedSchemaVersion {
            found: Some(version),
            found_major: version.major,
            supported_major: SUPPORTED_VECTOR_SCHEMA_MAJOR,
        });
    }
    Ok(())
}

fn non_empty(label: &str, value: &str) -> Result<(), IntegrityError> {
    if value.trim().is_empty() {
        return Err(IntegrityError::semantic(
            label,
            "required identifier must be non-empty",
        ));
    }
    Ok(())
}

fn validate_vector_identifiers(vector: &VectorDefinition) -> Result<(), IntegrityError> {
    non_empty("vector_id", &vector.vector_id)?;
    non_empty("title", &vector.title)?;
    non_empty("projector_fixture.id", &vector.projector_fixture.id)?;
    non_empty("pdp_fixture.id", &vector.pdp_fixture.id)?;
    non_empty("initial_operation.method", &vector.initial_operation.method)?;
    non_empty(
        "trusted_context.subject_id",
        &vector.trusted_context.subject_id,
    )?;
    if !vector.vector_id.starts_with("COAZ-INTEGRITY-")
        || vector.vector_id.len() != "COAZ-INTEGRITY-".len() + 3
    {
        return Err(IntegrityError::semantic(
            "vector_id",
            "vector_id must match COAZ-INTEGRITY-NNN",
        ));
    }
    Ok(())
}

fn validate_standards_present(vector: &VectorDefinition) -> Result<(), IntegrityError> {
    if vector.standards.references.is_empty() {
        return Err(IntegrityError::semantic(
            "standards.references",
            "standards metadata must include at least one reference",
        ));
    }
    if vector
        .standards
        .executable_scope
        .mcp_method_scope
        .trim()
        .is_empty()
    {
        return Err(IntegrityError::semantic(
            "standards.executable_scope",
            "executable scope must be explicit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::sample_vector_definition;
    use crate::version::SchemaVersion;

    #[test]
    fn sample_vector_is_semantically_valid() {
        validate_vector(&sample_vector_definition()).expect("sample");
    }

    #[test]
    fn unsupported_major_fails_closed() {
        let mut vector = sample_vector_definition();
        vector.schema_version = SchemaVersion::new(2, 0, 0);
        let err = validate_vector(&vector).unwrap_err();
        assert!(matches!(
            err,
            IntegrityError::UnsupportedSchemaVersion { found_major: 2, .. }
        ));
    }

    #[test]
    fn missing_standards_references_rejected() {
        let mut vector = sample_vector_definition();
        vector.standards.references.clear();
        assert!(validate_vector(&vector).is_err());
    }

    #[test]
    fn missing_vector_id_rejected_by_schema() {
        let mut vector = sample_vector_definition();
        vector.vector_id = "   ".to_owned();
        assert!(validate_vector(&vector).is_err());
    }

    #[test]
    fn round_trip_json() {
        let original = sample_vector_definition();
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let parsed = parse_and_validate_vector(&json).expect("parse");
        assert_eq!(parsed, original);
    }
}
