//! Principal, tenant and namespace binding.
//!
//! Cycle 016 does not invent an identity vocabulary. `PrincipalKind` is
//! re-exported from Cycle 015 so a `HUMAN`, `AGENT`, `WORKLOAD` or `SERVICE`
//! means exactly what it means there, and a memory tenant is the same kind of
//! label an identity tenant is. Memory boundaries align with identity
//! semantics; they never redefine them.
//!
//! What this module adds is the third axis identity does not have: a
//! **namespace**. Two items can share a tenant and an owner and still belong to
//! partitions that must not see each other.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};

/// Reused verbatim from Cycle 015 rather than redefined.
pub use dare_identity_security::source::PrincipalKind;

/// The principal a memory operation runs under, plus its isolation labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPrincipal {
    pub principal_id: String,
    pub kind: PrincipalKind,
    pub tenant_id: String,
    /// Namespaces this principal may address. Empty means none: a principal
    /// with no declared namespace reaches no namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_label: Option<String>,
}

impl MemoryPrincipal {
    /// Whether this principal may address a namespace.
    pub fn reaches_namespace(&self, namespace_id: &str) -> bool {
        self.namespaces.iter().any(|name| name == namespace_id)
    }

    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.principal_id, "principal id")?;
        crate::canonical::assert_safe_identifier(&self.tenant_id, "tenant id")?;
        for namespace in &self.namespaces {
            crate::canonical::assert_safe_identifier(namespace, "namespace id")?;
        }
        Ok(())
    }
}

/// The context a memory operation is evaluated in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryContext {
    pub schema_version: String,
    pub context_id: String,
    /// Every principal the scenario declares.
    pub principals: Vec<MemoryPrincipal>,
    /// The principal acting in this scenario.
    pub acting_principal_id: String,
    /// The tenant the request runs under.
    pub tenant_id: String,
    /// The namespace the request addresses.
    pub namespace_id: String,
}

impl MemoryContext {
    pub fn get(&self, principal_id: &str) -> Option<&MemoryPrincipal> {
        self.principals
            .iter()
            .find(|principal| principal.principal_id == principal_id)
    }

    /// Look one principal up, refusing an unknown reference.
    pub fn require(&self, principal_id: &str, context: &str) -> Result<&MemoryPrincipal> {
        self.get(principal_id).ok_or_else(|| {
            MemorySecurityError::unknown_reference(format!(
                "{context} references principal `{principal_id}`, which the context does not \
                 declare"
            ))
        })
    }

    /// The principal actually acting.
    pub fn acting(&self) -> Result<&MemoryPrincipal> {
        self.require(&self.acting_principal_id, "the acting principal")
    }

    /// Whether an item's owner is the acting principal.
    pub fn owned_by_acting(&self, owner_principal_id: &str) -> bool {
        self.acting_principal_id == owner_principal_id
    }

    /// Whether the acting context is inside the item's tenant.
    pub fn same_tenant(&self, tenant_id: &str) -> bool {
        self.tenant_id == tenant_id
    }

    /// Whether the acting context is inside the item's namespace.
    pub fn same_namespace(&self, namespace_id: &str) -> bool {
        self.namespace_id == namespace_id
    }

    pub fn declared_tenants(&self) -> BTreeSet<&str> {
        self.principals
            .iter()
            .map(|principal| principal.tenant_id.as_str())
            .chain(std::iter::once(self.tenant_id.as_str()))
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(MemorySecurityError::schema(format!(
                "memory context `{}` declares schema version `{}`; only `{}` is supported",
                self.context_id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.context_id, "context id")?;
        crate::canonical::assert_safe_identifier(&self.tenant_id, "context tenant id")?;
        crate::canonical::assert_safe_identifier(&self.namespace_id, "context namespace id")?;

        let mut seen = BTreeSet::new();
        for principal in &self.principals {
            principal.validate()?;
            if !seen.insert(principal.principal_id.as_str()) {
                return Err(MemorySecurityError::invalid(format!(
                    "memory context `{}` declares principal `{}` more than once",
                    self.context_id, principal.principal_id
                )));
            }
        }

        // The acting principal must be one the context declares; otherwise the
        // whole evaluation runs against an identity nobody described.
        self.acting()?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn valid_context() -> MemoryContext {
        MemoryContext {
            schema_version: "1".to_owned(),
            context_id: "context-support".to_owned(),
            principals: vec![
                MemoryPrincipal {
                    principal_id: "user-7".to_owned(),
                    kind: PrincipalKind::Human,
                    tenant_id: "tenant-a".to_owned(),
                    namespaces: vec!["ns-support".to_owned()],
                    display_label: Some("support operator".to_owned()),
                },
                MemoryPrincipal {
                    principal_id: "agent-1".to_owned(),
                    kind: PrincipalKind::Agent,
                    tenant_id: "tenant-a".to_owned(),
                    namespaces: vec!["ns-support".to_owned()],
                    display_label: None,
                },
                MemoryPrincipal {
                    principal_id: "user-9".to_owned(),
                    kind: PrincipalKind::Human,
                    tenant_id: "tenant-b".to_owned(),
                    namespaces: vec!["ns-other".to_owned()],
                    display_label: Some("operator in the other tenant".to_owned()),
                },
            ],
            acting_principal_id: "user-7".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace_id: "ns-support".to_owned(),
        }
    }

    #[test]
    fn the_fixture_context_validates() {
        valid_context().validate().expect("valid");
    }

    #[test]
    fn principal_kinds_are_the_cycle_015_ones_not_a_parallel_vocabulary() {
        // Re-exported rather than redefined: a HUMAN here is a HUMAN there.
        assert_eq!(PrincipalKind::all().len(), 4);
        let wire = serde_json::to_string(&PrincipalKind::Human).expect("serializes");
        assert_eq!(wire, "\"HUMAN\"");
        assert!(PrincipalKind::Human.originates_authority());
        assert!(PrincipalKind::Service.is_technical_identity());
    }

    #[test]
    fn the_three_isolation_axes_are_independent() {
        // Owner, tenant and namespace each answer a different question. Two
        // items can share two axes and differ on the third.
        let context = valid_context();

        assert!(context.owned_by_acting("user-7"));
        assert!(!context.owned_by_acting("agent-1"));

        assert!(context.same_tenant("tenant-a"));
        assert!(!context.same_tenant("tenant-b"));

        assert!(context.same_namespace("ns-support"));
        assert!(!context.same_namespace("ns-other"));
    }

    #[test]
    fn a_principal_reaches_only_the_namespaces_it_declares() {
        let context = valid_context();
        let user = context.get("user-7").expect("declared");
        assert!(user.reaches_namespace("ns-support"));
        assert!(!user.reaches_namespace("ns-other"));

        // A principal with no declared namespace reaches none.
        let mut isolated = user.clone();
        isolated.namespaces.clear();
        assert!(!isolated.reaches_namespace("ns-support"));
    }

    #[test]
    fn an_unknown_principal_is_refused_rather_than_treated_as_absent() {
        let context = valid_context();
        let err = context
            .require("user-nowhere", "a recall")
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("user-nowhere"));
    }

    #[test]
    fn an_acting_principal_the_context_never_declared_is_refused() {
        let mut context = valid_context();
        context.acting_principal_id = "ghost-1".to_owned();
        let err = context.validate().expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_duplicate_principal_is_refused() {
        let mut context = valid_context();
        let duplicate = context.principals[0].clone();
        context.principals.push(duplicate);
        assert!(context.validate().is_err());
    }

    #[test]
    fn the_context_rejects_unknown_and_remote_fields() {
        assert!(serde_json::from_value::<MemoryContext>(serde_json::json!({
            "schema_version": "1", "context_id": "c", "principals": [],
            "acting_principal_id": "u", "tenant_id": "t", "namespace_id": "n",
            "store_url": "redis://localhost:6379"
        }))
        .is_err());

        assert!(
            serde_json::from_value::<MemoryPrincipal>(serde_json::json!({
                "principal_id": "u", "kind": "HUMAN", "tenant_id": "t",
                "api_key": "aaaaaaaaaaaaaaaaaaaaaaaa"
            }))
            .is_err()
        );
    }

    #[test]
    fn declared_tenants_include_the_acting_tenant() {
        let context = valid_context();
        let tenants = context.declared_tenants();
        assert!(tenants.contains("tenant-a"));
        assert!(tenants.contains("tenant-b"));
        assert_eq!(tenants.len(), 2);
    }
}
