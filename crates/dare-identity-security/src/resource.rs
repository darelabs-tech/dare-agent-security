//! Synthetic resource and tenant context.
//!
//! Every identifier here is a synthetic label. Proving a cross-tenant or
//! wrong-owner violation requires knowing which tenant and which owner an
//! operation named — not reading anything the resource contains. No real
//! protected resource is named, reached or accessed by this cycle, and the
//! classification is a label rather than a claim about real data.

use serde::{Deserialize, Serialize};

use crate::error::{IdentitySecurityError, Result};
use crate::principal::PrincipalSet;

/// Synthetic sensitivity label. Never a statement about real data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceClassification {
    SyntheticPublic,
    SyntheticInternal,
    SyntheticRestricted,
}

impl ResourceClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticPublic => "SYNTHETIC_PUBLIC",
            Self::SyntheticInternal => "SYNTHETIC_INTERNAL",
            Self::SyntheticRestricted => "SYNTHETIC_RESTRICTED",
        }
    }

    pub fn all() -> [Self; 3] {
        [
            Self::SyntheticPublic,
            Self::SyntheticInternal,
            Self::SyntheticRestricted,
        ]
    }
}

/// The resource an operation acts on, with its tenant and owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContext {
    pub resource_id: String,
    pub resource_type: String,
    pub tenant_id: String,
    pub owner_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<ResourceClassification>,
}

impl ResourceContext {
    /// Validate that the owner is a principal the scenario declared.
    ///
    /// An owner nobody declared cannot be compared against anything, so it is
    /// refused rather than treated as "some other owner".
    pub fn validate(&self, principals: &PrincipalSet) -> Result<()> {
        for (label, value) in [
            ("resource_id", &self.resource_id),
            ("resource_type", &self.resource_type),
            ("tenant_id", &self.tenant_id),
            ("owner_principal_id", &self.owner_principal_id),
        ] {
            if value.trim().is_empty() {
                return Err(IdentitySecurityError::invalid(format!(
                    "resource context has an empty {label}"
                )));
            }
        }
        principals.require(&self.owner_principal_id, "the resource owner")?;
        Ok(())
    }

    /// Whether this resource belongs to a given tenant.
    ///
    /// Exact identifier equality. Tenant boundaries are not approximate.
    pub fn belongs_to_tenant(&self, tenant_id: &str) -> bool {
        self.tenant_id == tenant_id
    }

    /// Whether a principal owns this resource.
    pub fn is_owned_by(&self, principal_id: &str) -> bool {
        self.owner_principal_id == principal_id
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::principal::tests::valid_principal_set;
    use serde_json::json;

    pub(crate) fn same_tenant_resource() -> ResourceContext {
        serde_json::from_value(json!({
            "resource_id": "document-123",
            "resource_type": "document",
            "tenant_id": "tenant-a",
            "owner_principal_id": "user-7",
            "classification": "SYNTHETIC_INTERNAL"
        }))
        .expect("resource decodes")
    }

    #[test]
    fn a_representative_resource_validates() {
        let resource = same_tenant_resource();
        resource.validate(&valid_principal_set()).expect("valid");
        assert!(resource.belongs_to_tenant("tenant-a"));
        assert!(resource.is_owned_by("user-7"));
    }

    #[test]
    fn tenant_and_owner_comparisons_are_exact() {
        let resource = same_tenant_resource();
        assert!(!resource.belongs_to_tenant("tenant-b"));
        assert!(!resource.belongs_to_tenant("tenant-a2"));
        assert!(!resource.belongs_to_tenant("Tenant-A"));
        assert!(!resource.is_owned_by("user-70"));
        assert!(!resource.is_owned_by("user-8"));
    }

    #[test]
    fn an_undeclared_owner_is_refused_rather_than_treated_as_another_owner() {
        let mut resource = same_tenant_resource();
        resource.owner_principal_id = "ghost".to_owned();
        let err = resource
            .validate(&valid_principal_set())
            .expect_err("unknown owner must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn an_empty_required_field_is_refused() {
        for field in ["resource_id", "resource_type", "tenant_id"] {
            let mut resource = same_tenant_resource();
            match field {
                "resource_id" => resource.resource_id = String::new(),
                "resource_type" => resource.resource_type = "  ".to_owned(),
                _ => resource.tenant_id = String::new(),
            }
            assert!(
                resource.validate(&valid_principal_set()).is_err(),
                "empty {field} must be refused"
            );
        }
    }

    #[test]
    fn the_classification_is_synthetic_by_construction() {
        // Every label says so in its own name, so an artifact can never suggest
        // that a real classified resource was involved.
        for classification in ResourceClassification::all() {
            assert!(
                classification.as_str().starts_with("SYNTHETIC_"),
                "{}",
                classification.as_str()
            );
        }
        assert!(serde_json::from_str::<ResourceClassification>("\"CONFIDENTIAL\"").is_err());
        assert!(serde_json::from_str::<ResourceClassification>("\"PII\"").is_err());
    }

    #[test]
    fn an_unknown_resource_field_fails_closed() {
        let hostile = json!({
            "resource_id": "document-123", "resource_type": "document",
            "tenant_id": "tenant-a", "owner_principal_id": "user-7",
            "content_url": "https://example.invalid/doc"
        });
        assert!(serde_json::from_value::<ResourceContext>(hostile).is_err());
    }
}
