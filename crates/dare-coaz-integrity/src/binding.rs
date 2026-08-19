//! Authorization binding material and digest computation (Cycle 003 task-004).
//!
//! Binding digests are derived from canonical semantic values, not raw transport bytes.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::canonical::{CanonicalError, CanonicalValue};
use crate::result::{AuthorizationBinding, AuthorizationProjection, MappingIdentity};

/// Binding algorithm identifier exposed on public artifacts.
pub const BINDING_ALGORITHM: &str = "coaz-binding-v1";

/// Version tag embedded in binding material.
pub const BINDING_MATERIAL_VERSION: &str = "1.0.0";

/// Versioned semantic inputs hashed to produce an [`AuthorizationBinding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingMaterialV1 {
    pub binding_version: String,
    pub method: String,
    pub operation_name: Option<String>,
    pub mapping_identity: MappingIdentity,
    pub mapped_inputs: CanonicalValue,
    pub trusted_inputs: CanonicalValue,
    pub authzen_request_digest: String,
}

/// Errors raised while assembling or hashing binding material.
#[derive(Debug, PartialEq, Eq)]
pub enum BindingError {
    Canonical(CanonicalError),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(err) => write!(f, "canonical normalization failed: {err}"),
        }
    }
}

impl std::error::Error for BindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(err) => Some(err),
        }
    }
}

impl From<CanonicalError> for BindingError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

impl BindingMaterialV1 {
    /// Builds binding material from a projection snapshot and MCP call metadata.
    pub fn from_projection(
        method: &str,
        operation_name: Option<&str>,
        projection: &AuthorizationProjection,
    ) -> Result<Self, BindingError> {
        let mapped_inputs = CanonicalValue::normalize(&projection.mapped_inputs)?;
        let trusted_inputs = CanonicalValue::normalize(&projection.trusted_inputs)?;
        let authzen_request = CanonicalValue::normalize(&projection.authzen_request)?;

        Ok(Self {
            binding_version: BINDING_MATERIAL_VERSION.to_owned(),
            method: method.to_owned(),
            operation_name: operation_name.map(str::to_owned),
            mapping_identity: projection.mapping.clone(),
            mapped_inputs,
            trusted_inputs,
            authzen_request_digest: authzen_request.digest(),
        })
    }

    /// Returns the deterministic canonical value used as the SHA-256 preimage.
    pub fn to_canonical_value(&self) -> CanonicalValue {
        let mut mapping = BTreeMap::new();
        mapping.insert(
            "digest".to_owned(),
            CanonicalValue::String(self.mapping_identity.digest.clone()),
        );
        mapping.insert(
            "id".to_owned(),
            CanonicalValue::String(self.mapping_identity.id.clone()),
        );
        mapping.insert(
            "kind".to_owned(),
            CanonicalValue::String(self.mapping_identity.kind.clone()),
        );
        mapping.insert(
            "revision".to_owned(),
            match &self.mapping_identity.revision {
                Some(revision) => CanonicalValue::String(revision.clone()),
                None => CanonicalValue::Null,
            },
        );

        let mut root = BTreeMap::new();
        root.insert(
            "authzen_request_digest".to_owned(),
            CanonicalValue::String(self.authzen_request_digest.clone()),
        );
        root.insert(
            "binding_version".to_owned(),
            CanonicalValue::String(self.binding_version.clone()),
        );
        root.insert(
            "mapping_identity".to_owned(),
            CanonicalValue::Object(mapping),
        );
        root.insert("mapped_inputs".to_owned(), self.mapped_inputs.clone());
        root.insert(
            "method".to_owned(),
            CanonicalValue::String(self.method.clone()),
        );
        root.insert(
            "operation_name".to_owned(),
            match &self.operation_name {
                Some(name) => CanonicalValue::String(name.clone()),
                None => CanonicalValue::Null,
            },
        );
        root.insert("trusted_inputs".to_owned(), self.trusted_inputs.clone());

        CanonicalValue::Object(root)
    }

    /// Returns lowercase hex SHA-256 digest of the canonical binding material.
    pub fn digest(&self) -> String {
        self.to_canonical_value().digest()
    }
}

/// Computes the public authorization binding for the supplied material.
pub fn compute_authorization_binding(material: &BindingMaterialV1) -> AuthorizationBinding {
    AuthorizationBinding {
        algorithm: BINDING_ALGORITHM.to_owned(),
        digest: material.digest(),
    }
}

/// Returns whether two bindings refer to the same semantic authorization context.
pub fn bindings_equal(left: &AuthorizationBinding, right: &AuthorizationBinding) -> bool {
    left.algorithm == right.algorithm && left.digest == right.digest
}

/// Computes the SHA-256 digest of a JSON-like value after semantic normalization.
pub fn digest_json_value(value: &Value) -> Result<String, BindingError> {
    Ok(CanonicalValue::normalize(value)?.digest())
}

/// Builds binding material directly from normalized field values.
pub fn binding_material_v1(
    method: &str,
    operation_name: Option<&str>,
    mapping_identity: MappingIdentity,
    mapped_inputs: CanonicalValue,
    trusted_inputs: CanonicalValue,
    authzen_request_digest: impl Into<String>,
) -> BindingMaterialV1 {
    BindingMaterialV1 {
        binding_version: BINDING_MATERIAL_VERSION.to_owned(),
        method: method.to_owned(),
        operation_name: operation_name.map(str::to_owned),
        mapping_identity,
        mapped_inputs,
        trusted_inputs,
        authzen_request_digest: authzen_request_digest.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::AuthorizationProjection;
    use serde_json::json;

    fn sample_mapping() -> MappingIdentity {
        MappingIdentity {
            kind: "default".to_owned(),
            id: "default-tools-call".to_owned(),
            revision: None,
            digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        }
    }

    fn sample_projection() -> AuthorizationProjection {
        AuthorizationProjection {
            mapping: sample_mapping(),
            mapped_inputs: json!({
                "customer_id": "cust-synthetic-001",
                "vehicle_id": "vehicle-synthetic-001",
                "daily_rate": 50,
                "days": 3
            }),
            trusted_inputs: json!({
                "subject_id": "subject-synthetic-001",
                "agent_id": "agent-synthetic-001"
            }),
            authzen_request: json!({
                "subject": { "type": "user", "id": "subject-synthetic-001" },
                "resource": { "type": "mcp-tool", "id": "rental.quote" },
                "action": { "name": "invoke" }
            }),
        }
    }

    #[test]
    fn binding_digest_is_repeatable() {
        let material = BindingMaterialV1::from_projection(
            "tools/call",
            Some("rental.quote"),
            &sample_projection(),
        )
        .expect("material");
        let first = compute_authorization_binding(&material);
        let second = compute_authorization_binding(&material);
        assert_eq!(first, second);
        assert_eq!(first.algorithm, BINDING_ALGORITHM);
        assert_eq!(first.digest.len(), 64);
    }

    #[test]
    fn mapping_selection_change_changes_binding_even_with_same_authzen_digest() {
        let projection = sample_projection();
        let baseline =
            BindingMaterialV1::from_projection("tools/call", Some("rental.quote"), &projection)
                .expect("baseline");

        let mut alternate_mapping = sample_mapping();
        alternate_mapping.id = "alternate-tools-call".to_owned();
        alternate_mapping.digest =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned();

        let alternate = binding_material_v1(
            "tools/call",
            Some("rental.quote"),
            alternate_mapping,
            baseline.mapped_inputs.clone(),
            baseline.trusted_inputs.clone(),
            baseline.authzen_request_digest.clone(),
        );

        assert_ne!(
            compute_authorization_binding(&baseline),
            compute_authorization_binding(&alternate)
        );
    }
}
