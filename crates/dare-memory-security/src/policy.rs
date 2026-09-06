//! Declarative memory policy.
//!
//! A policy is data: sets of allowed writers, readers, tenants, namespaces and
//! source kinds, a trust ceiling, the objectives memory may influence, and the
//! fields memory may never populate. There is no expression language, no
//! callback, no regex-as-code and no external policy call — a policy that could
//! execute would be a second, unreviewed engine.
//!
//! Every comparison against a policy is set membership or an integer rank
//! comparison, which is what makes a policy decision reproducible.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};
use crate::source::{SourceKind, TrustClass};

/// A closed dimension of a policy.
///
/// `Any` must be written explicitly. An omitted dimension decodes to an empty
/// `Only`, which permits nothing — the fail-closed default. Making
/// "unconstrained" explicit means a policy author cannot widen a policy by
/// forgetting a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "constraint", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDimension {
    /// Deliberately unconstrained on this dimension.
    Any,
    /// Constrained to exactly these values. An empty list permits nothing.
    Only { values: Vec<String> },
}

impl Default for PolicyDimension {
    fn default() -> Self {
        Self::Only { values: Vec::new() }
    }
}

impl PolicyDimension {
    pub fn only<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Only {
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Only { values } if values.is_empty())
    }

    /// Whether this dimension permits a concrete value.
    pub fn permits(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only { values } => values.iter().any(|allowed| allowed == value),
        }
    }

    pub fn values(&self) -> BTreeSet<&str> {
        match self {
            Self::Any => BTreeSet::new(),
            Self::Only { values } => values.iter().map(String::as_str).collect(),
        }
    }
}

/// The declarative memory policy a scenario is evaluated against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPolicy {
    pub schema_version: String,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Principals permitted to write memory.
    #[serde(default)]
    pub allowed_writers: PolicyDimension,
    /// Principals permitted to read memory.
    #[serde(default)]
    pub allowed_readers: PolicyDimension,
    #[serde(default)]
    pub allowed_tenants: PolicyDimension,
    #[serde(default)]
    pub allowed_namespaces: PolicyDimension,
    /// Source kinds that may be persisted at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_source_kinds: Vec<SourceKind>,
    /// The highest trust class any written memory may carry.
    pub max_trust_class: TrustClass,
    /// Objectives recalled memory may influence.
    #[serde(default)]
    pub allowed_objective_ids: PolicyDimension,
    /// Fields memory may never populate, whatever its trust class.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<String>,
    /// Source kinds explicitly granted policy authority.
    ///
    /// The only machine-readable route to `TRUSTED_POLICY` above what a source
    /// allows by default. Absent means no grant, not an implied one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_elevation_grants: Vec<TrustElevationGrant>,
}

/// An explicit, policy-derived permission to raise trust.
///
/// Recorded as data so an elevation is auditable. Content can never grant
/// itself one of these by saying so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustElevationGrant {
    pub source_kind: SourceKind,
    /// The specific origin the grant applies to. A grant must name one: a
    /// blanket grant over a whole source kind would re-open the boundary this
    /// cycle exists to hold.
    pub source_id: String,
    pub granted_trust_class: TrustClass,
}

impl MemoryPolicy {
    /// Whether a principal may write memory under this policy.
    pub fn permits_writer(&self, principal_id: &str) -> bool {
        self.allowed_writers.permits(principal_id)
    }

    /// Whether a principal may read memory under this policy.
    pub fn permits_reader(&self, principal_id: &str) -> bool {
        self.allowed_readers.permits(principal_id)
    }

    pub fn permits_tenant(&self, tenant_id: &str) -> bool {
        self.allowed_tenants.permits(tenant_id)
    }

    pub fn permits_namespace(&self, namespace_id: &str) -> bool {
        self.allowed_namespaces.permits(namespace_id)
    }

    pub fn permits_objective(&self, objective_id: &str) -> bool {
        self.allowed_objective_ids.permits(objective_id)
    }

    /// Whether a source kind may be persisted at all.
    ///
    /// An empty list means the policy does not constrain source kinds, which is
    /// different from constraining them to nothing — the latter would make the
    /// policy unusable and is therefore not the meaning of "unset".
    pub fn permits_source_kind(&self, source_kind: SourceKind) -> bool {
        self.allowed_source_kinds.is_empty() || self.allowed_source_kinds.contains(&source_kind)
    }

    /// Whether a field is protected from memory-derived population.
    pub fn is_protected_field(&self, field: &str) -> bool {
        self.protected_fields.iter().any(|name| name == field)
    }

    /// The highest trust class this policy permits for a given origin.
    ///
    /// The source's own ceiling, unless an explicit grant names exactly that
    /// origin, and never above the policy's own maximum. Three bounds, all
    /// machine-readable, none inferred from content.
    pub fn permitted_trust_for(&self, source_kind: SourceKind, source_id: &str) -> TrustClass {
        let granted = self
            .trust_elevation_grants
            .iter()
            .filter(|grant| grant.source_kind == source_kind && grant.source_id == source_id)
            .map(|grant| grant.granted_trust_class)
            .max();

        let ceiling = granted.unwrap_or_else(|| source_kind.default_trust_ceiling());
        ceiling.min(self.max_trust_class)
    }

    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(MemorySecurityError::schema(format!(
                "memory policy `{}` declares schema version `{}`; only `{}` is supported",
                self.policy_id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.policy_id, "policy id")?;

        for field in &self.protected_fields {
            crate::canonical::assert_safe_identifier(field, "protected field name")?;
        }
        for grant in &self.trust_elevation_grants {
            crate::canonical::assert_safe_identifier(&grant.source_id, "grant source id")?;
            if grant.granted_trust_class.rank() > self.max_trust_class.rank() {
                return Err(MemorySecurityError::invalid(format!(
                    "policy `{}` grants `{}` above its own maximum `{}`",
                    self.policy_id,
                    grant.granted_trust_class.as_str(),
                    self.max_trust_class.as_str()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn valid_policy() -> MemoryPolicy {
        MemoryPolicy {
            schema_version: "1".to_owned(),
            policy_id: "policy-support-memory".to_owned(),
            title: Some("support desk memory policy".to_owned()),
            allowed_writers: PolicyDimension::only(["user-7", "agent-1"]),
            allowed_readers: PolicyDimension::only(["user-7", "agent-1"]),
            allowed_tenants: PolicyDimension::only(["tenant-a"]),
            allowed_namespaces: PolicyDimension::only(["ns-support"]),
            allowed_source_kinds: vec![
                SourceKind::UserInput,
                SourceKind::ToolOutput,
                SourceKind::SystemAuthored,
            ],
            max_trust_class: TrustClass::TrustedPolicy,
            allowed_objective_ids: PolicyDimension::only(["objective-summarize-ticket"]),
            protected_fields: vec!["recipient".to_owned(), "amount".to_owned()],
            trust_elevation_grants: Vec::new(),
        }
    }

    #[test]
    fn the_fixture_policy_validates() {
        valid_policy().validate().expect("valid");
    }

    #[test]
    fn an_omitted_dimension_permits_nothing() {
        // Fail-closed: forgetting a field must never widen a policy.
        let dimension = PolicyDimension::default();
        assert!(dimension.is_empty());
        assert!(!dimension.is_any());
        assert!(!dimension.permits("anything"));

        let decoded: MemoryPolicy = serde_json::from_value(serde_json::json!({
            "schema_version": "1",
            "policy_id": "policy-minimal",
            "max_trust_class": "UNTRUSTED"
        }))
        .expect("decodes");
        assert!(!decoded.permits_writer("user-7"));
        assert!(!decoded.permits_reader("user-7"));
        assert!(!decoded.permits_tenant("tenant-a"));
        assert!(!decoded.permits_namespace("ns-support"));
        assert!(!decoded.permits_objective("objective-anything"));
    }

    #[test]
    fn any_must_be_written_explicitly() {
        let any = PolicyDimension::Any;
        assert!(any.is_any());
        assert!(any.permits("anything at all"));
        assert!(any.values().is_empty());

        let json = serde_json::to_string(&any).expect("serializes");
        assert_eq!(json, r#"{"constraint":"ANY"}"#);
    }

    #[test]
    fn a_source_cannot_exceed_its_own_ceiling_without_a_grant() {
        let policy = valid_policy();
        // User input caps at CONSTRAINED however permissive the policy is.
        assert_eq!(
            policy.permitted_trust_for(SourceKind::UserInput, "turn-12"),
            TrustClass::Constrained
        );
        // System-authored content may reach policy trust.
        assert_eq!(
            policy.permitted_trust_for(SourceKind::SystemAuthored, "policy-doc-1"),
            TrustClass::TrustedPolicy
        );
    }

    #[test]
    fn an_explicit_grant_elevates_exactly_one_origin() {
        // A blanket grant over a whole source kind would re-open the boundary,
        // so a grant names the specific origin it applies to.
        let mut policy = valid_policy();
        policy.trust_elevation_grants.push(TrustElevationGrant {
            source_kind: SourceKind::ToolOutput,
            source_id: "tool-verified-directory".to_owned(),
            granted_trust_class: TrustClass::TrustedPolicy,
        });

        assert_eq!(
            policy.permitted_trust_for(SourceKind::ToolOutput, "tool-verified-directory"),
            TrustClass::TrustedPolicy
        );
        // A different origin of the same kind is unaffected.
        assert_eq!(
            policy.permitted_trust_for(SourceKind::ToolOutput, "tool-web-scrape"),
            TrustClass::Constrained
        );
        // A different kind with the same id is unaffected.
        assert_eq!(
            policy.permitted_trust_for(SourceKind::UserInput, "tool-verified-directory"),
            TrustClass::Constrained
        );
    }

    #[test]
    fn the_policy_maximum_caps_every_grant() {
        let mut policy = valid_policy();
        policy.max_trust_class = TrustClass::Constrained;
        policy.trust_elevation_grants.push(TrustElevationGrant {
            source_kind: SourceKind::SystemAuthored,
            source_id: "policy-doc-1".to_owned(),
            granted_trust_class: TrustClass::Constrained,
        });
        assert_eq!(
            policy.permitted_trust_for(SourceKind::SystemAuthored, "policy-doc-1"),
            TrustClass::Constrained
        );

        // A grant above the policy's own maximum is refused outright.
        policy.trust_elevation_grants[0].granted_trust_class = TrustClass::TrustedPolicy;
        let err = policy.validate().expect_err("must be refused");
        assert!(err.to_string().contains("above its own maximum"));
    }

    #[test]
    fn an_unset_source_kind_list_does_not_mean_nothing_is_allowed() {
        // "Unset" means unconstrained here, because constraining to nothing
        // would make the policy unusable rather than strict.
        let mut policy = valid_policy();
        policy.allowed_source_kinds.clear();
        for source in SourceKind::all() {
            assert!(policy.permits_source_kind(source), "{}", source.as_str());
        }

        let policy = valid_policy();
        assert!(policy.permits_source_kind(SourceKind::UserInput));
        assert!(!policy.permits_source_kind(SourceKind::ExternalContent));
    }

    #[test]
    fn protected_fields_are_matched_whole() {
        let policy = valid_policy();
        assert!(policy.is_protected_field("recipient"));
        assert!(policy.is_protected_field("amount"));
        // A prefix of a protected field is not itself protected.
        assert!(!policy.is_protected_field("recipient_display_name"));
        assert!(!policy.is_protected_field("recip"));
    }

    #[test]
    fn a_policy_can_carry_no_executable_or_remote_field() {
        for hostile in [
            serde_json::json!({"schema_version":"1","policy_id":"p","max_trust_class":"UNTRUSTED","callback":"handler"}),
            serde_json::json!({"schema_version":"1","policy_id":"p","max_trust_class":"UNTRUSTED","eval":"1+1"}),
            serde_json::json!({"schema_version":"1","policy_id":"p","max_trust_class":"UNTRUSTED","endpoint":"https://policy.example.invalid"}),
            serde_json::json!({"schema_version":"1","policy_id":"p","max_trust_class":"UNTRUSTED","connection_string":"redis://x"}),
        ] {
            assert!(serde_json::from_value::<MemoryPolicy>(hostile).is_err());
        }
    }

    #[test]
    fn a_future_schema_version_is_refused() {
        let mut policy = valid_policy();
        policy.schema_version = "2".to_owned();
        assert!(policy.validate().is_err());
    }
}
