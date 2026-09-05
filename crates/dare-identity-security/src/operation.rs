//! Canonical operations and the authorization-relevant projection.
//!
//! This is where Cycle 003 is reused rather than reimplemented. The projection
//! is built as a [`dare_coaz_integrity::CanonicalValue`] and digested by that
//! crate's canonicalization, so identity binding and COAZ authorization
//! integrity agree on what "the same operation" means. No second binding engine
//! exists.
//!
//! # Why the comparison is semantic
//!
//! An operation carries two argument maps. `authorization_relevant_arguments`
//! participate in the projection; `incidental_arguments` deliberately do not.
//! So a permit survives a changed trace id or page size, and does not survive a
//! changed resource, action, tenant or subject:
//!
//! ```text
//! authorized: subject=user-7 action=read resource=document-123 tenant=tenant-a
//! final:      subject=user-7 action=read resource=document-999 tenant=tenant-a
//!             -> different projection, so the earlier permit does not apply
//! ```
//!
//! That is the difference between comparing meaning and comparing bytes. Raw
//! JSON equality would flag the harmless change and could be defeated by
//! reordering keys; this cannot.

use std::collections::BTreeMap;

use dare_coaz_integrity::CanonicalValue;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{IdentitySecurityError, Result};

/// A structured operation. Observed, never dispatched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub operation_id: String,
    pub subject_id: String,
    pub action: String,
    pub resource_id: String,
    pub resource_type: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    /// Arguments that change what was authorized.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authorization_relevant_arguments: BTreeMap<String, String>,
    /// Arguments irrelevant to authorization: a trace id, a page size.
    ///
    /// Excluded from the projection on purpose. Including them would make every
    /// harmless difference invalidate a permit, and a check that fires on
    /// everything gets switched off.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub incidental_arguments: BTreeMap<String, String>,
}

/// The authorization-relevant projection of an operation.
///
/// Two operations with the same projection are the same operation as far as an
/// authorization decision is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationProjection {
    canonical: CanonicalValue,
    digest: String,
}

impl OperationProjection {
    /// The `sha256:<hex>` digest of the canonical projection.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The canonical form, for evidence and debugging.
    pub fn canonical(&self) -> &CanonicalValue {
        &self.canonical
    }
}

/// Which authorization-relevant field differs between two projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationField {
    Subject,
    Action,
    ResourceId,
    ResourceType,
    Tenant,
    Objective,
    ToolId,
    AuthorizationRelevantArguments,
}

impl OperationField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "SUBJECT",
            Self::Action => "ACTION",
            Self::ResourceId => "RESOURCE_ID",
            Self::ResourceType => "RESOURCE_TYPE",
            Self::Tenant => "TENANT",
            Self::Objective => "OBJECTIVE",
            Self::ToolId => "TOOL_ID",
            Self::AuthorizationRelevantArguments => "AUTHORIZATION_RELEVANT_ARGUMENTS",
        }
    }
}

/// One authorization-relevant difference between two operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDifference {
    pub field: OperationField,
    pub authorized: String,
    pub final_value: String,
}

impl Operation {
    /// Build the authorization-relevant projection.
    ///
    /// Only the fields an authorization decision actually depends on enter the
    /// canonical value, which is what makes the resulting digest a statement
    /// about meaning rather than about formatting.
    pub fn projection(&self) -> Result<OperationProjection> {
        let value = json!({
            "subject_id": self.subject_id,
            "action": self.action,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "tenant_id": self.tenant_id,
            "objective_id": self.objective_id,
            "tool_id": self.tool_id,
            "authorization_relevant_arguments": self.authorization_relevant_arguments,
        });

        let canonical = CanonicalValue::normalize(&value).map_err(|err| {
            IdentitySecurityError::invalid(format!(
                "operation `{}` could not be canonicalized: {err}",
                self.operation_id
            ))
        })?;
        // The bytes hashed and the hash itself are Cycle 003's; the `sha256:`
        // label is the DARE evidence convention every other cycle uses. Reuse
        // of the canonicalizer is the point, so nothing about the preimage
        // changes here.
        let digest = format!("sha256:{}", canonical.digest());

        Ok(OperationProjection { canonical, digest })
    }

    /// The projection digest, or an error if canonicalization fails.
    pub fn projection_digest(&self) -> Result<String> {
        Ok(self.projection()?.digest)
    }

    /// The policy key for this operation, as `<resource_type>.<action>`.
    pub fn key(&self) -> String {
        crate::authorization::AuthorizationPolicy::operation_key(&self.resource_type, &self.action)
    }

    /// Every authorization-relevant field in which `self` differs from `other`.
    ///
    /// A list rather than the first difference: an operation can be mutated on
    /// several axes at once, and naming only one would understate the change.
    pub fn authorization_differences(&self, other: &Self) -> Vec<OperationDifference> {
        let mut differences = Vec::new();

        let mut compare = |field: OperationField, authorized: &str, final_value: &str| {
            if authorized != final_value {
                differences.push(OperationDifference {
                    field,
                    authorized: authorized.to_owned(),
                    final_value: final_value.to_owned(),
                });
            }
        };

        compare(OperationField::Subject, &self.subject_id, &other.subject_id);
        compare(OperationField::Action, &self.action, &other.action);
        compare(
            OperationField::ResourceId,
            &self.resource_id,
            &other.resource_id,
        );
        compare(
            OperationField::ResourceType,
            &self.resource_type,
            &other.resource_type,
        );
        compare(OperationField::Tenant, &self.tenant_id, &other.tenant_id);
        compare(
            OperationField::Objective,
            self.objective_id.as_deref().unwrap_or(""),
            other.objective_id.as_deref().unwrap_or(""),
        );
        compare(
            OperationField::ToolId,
            self.tool_id.as_deref().unwrap_or(""),
            other.tool_id.as_deref().unwrap_or(""),
        );

        if self.authorization_relevant_arguments != other.authorization_relevant_arguments {
            differences.push(OperationDifference {
                field: OperationField::AuthorizationRelevantArguments,
                authorized: render_arguments(&self.authorization_relevant_arguments),
                final_value: render_arguments(&other.authorization_relevant_arguments),
            });
        }

        differences
    }

    /// Whether the two operations are the same as far as authorization goes.
    pub fn authorization_equivalent(&self, other: &Self) -> bool {
        self.authorization_differences(other).is_empty()
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<()> {
        for (label, value) in [
            ("operation_id", &self.operation_id),
            ("subject_id", &self.subject_id),
            ("action", &self.action),
            ("resource_id", &self.resource_id),
            ("resource_type", &self.resource_type),
            ("tenant_id", &self.tenant_id),
        ] {
            if value.trim().is_empty() {
                return Err(IdentitySecurityError::invalid(format!(
                    "operation `{}` has an empty {label}",
                    self.operation_id
                )));
            }
        }

        // An argument named in both maps would make the projection depend on
        // which map the reader consulted, so the split has to be a partition.
        for key in self.incidental_arguments.keys() {
            if self.authorization_relevant_arguments.contains_key(key) {
                return Err(IdentitySecurityError::invalid(format!(
                    "operation `{}` lists argument `{key}` as both authorization-relevant and \
                     incidental",
                    self.operation_id
                )));
            }
        }

        Ok(())
    }
}

fn render_arguments(arguments: &BTreeMap<String, String>) -> String {
    arguments
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<String>>()
        .join(",")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// One field mutation applied to an operation under test.
    type Mutation = Box<dyn Fn(&mut Operation)>;

    pub(crate) fn authorized_operation() -> Operation {
        serde_json::from_value(json!({
            "operation_id": "op-read-123",
            "subject_id": "user-7",
            "action": "read",
            "resource_id": "document-123",
            "resource_type": "document",
            "tenant_id": "tenant-a",
            "objective_id": "objective-summarize-ticket",
            "authorization_relevant_arguments": {"field_set": "summary"},
            "incidental_arguments": {"trace_id": "trace-001", "page_size": "50"}
        }))
        .expect("operation decodes")
    }

    #[test]
    fn a_representative_operation_validates_and_projects() {
        let operation = authorized_operation();
        operation.validate().expect("valid");
        let projection = operation.projection().expect("projects");
        assert!(projection.digest().starts_with("sha256:"));
        assert_eq!(projection.digest().len(), 71);
    }

    #[test]
    fn the_projection_is_stable_across_repeated_computation() {
        let operation = authorized_operation();
        assert_eq!(
            operation.projection_digest().expect("digest"),
            operation.projection_digest().expect("digest")
        );
    }

    #[test]
    fn an_incidental_argument_does_not_change_the_projection() {
        // The permit survives a changed trace id. A check that fired on this
        // would fire constantly, and a check that fires constantly gets
        // switched off.
        let authorized = authorized_operation();
        let mut later = authorized.clone();
        later
            .incidental_arguments
            .insert("trace_id".to_owned(), "trace-999".to_owned());
        later
            .incidental_arguments
            .insert("page_size".to_owned(), "10".to_owned());

        assert_eq!(
            authorized.projection_digest().expect("digest"),
            later.projection_digest().expect("digest")
        );
        assert!(authorized.authorization_equivalent(&later));
        assert!(authorized.authorization_differences(&later).is_empty());
    }

    #[test]
    fn the_operation_id_itself_is_not_part_of_the_projection() {
        // Two records of the same authorized operation are the same operation.
        let authorized = authorized_operation();
        let mut renamed = authorized.clone();
        renamed.operation_id = "op-recorded-again".to_owned();
        assert_eq!(
            authorized.projection_digest().expect("digest"),
            renamed.projection_digest().expect("digest")
        );
    }

    #[test]
    fn a_changed_resource_changes_the_projection() {
        // The example from the approval, verbatim.
        let authorized = authorized_operation();
        let mut mutated = authorized.clone();
        mutated.resource_id = "document-999".to_owned();

        assert_ne!(
            authorized.projection_digest().expect("digest"),
            mutated.projection_digest().expect("digest")
        );
        let differences = authorized.authorization_differences(&mutated);
        assert_eq!(differences.len(), 1);
        assert_eq!(differences[0].field, OperationField::ResourceId);
        assert_eq!(differences[0].authorized, "document-123");
        assert_eq!(differences[0].final_value, "document-999");
    }

    #[test]
    fn every_authorization_relevant_field_changes_the_projection() {
        let authorized = authorized_operation();
        let base = authorized.projection_digest().expect("digest");

        let mutations: Vec<(OperationField, Mutation)> = vec![
            (
                OperationField::Subject,
                Box::new(|op: &mut Operation| op.subject_id = "user-8".to_owned()),
            ),
            (
                OperationField::Action,
                Box::new(|op: &mut Operation| op.action = "delete".to_owned()),
            ),
            (
                OperationField::ResourceType,
                Box::new(|op: &mut Operation| op.resource_type = "ticket".to_owned()),
            ),
            (
                OperationField::Tenant,
                Box::new(|op: &mut Operation| op.tenant_id = "tenant-b".to_owned()),
            ),
            (
                OperationField::Objective,
                Box::new(|op: &mut Operation| op.objective_id = Some("objective-other".to_owned())),
            ),
            (
                OperationField::ToolId,
                Box::new(|op: &mut Operation| op.tool_id = Some("tool-x".to_owned())),
            ),
            (
                OperationField::AuthorizationRelevantArguments,
                Box::new(|op: &mut Operation| {
                    op.authorization_relevant_arguments
                        .insert("field_set".to_owned(), "everything".to_owned());
                }),
            ),
        ];

        for (field, mutate) in mutations {
            let mut mutated = authorized.clone();
            mutate(&mut mutated);
            assert_ne!(
                base,
                mutated.projection_digest().expect("digest"),
                "{} must change the projection",
                field.as_str()
            );
            let differences = authorized.authorization_differences(&mutated);
            assert!(
                differences
                    .iter()
                    .any(|difference| difference.field == field),
                "{} must be reported as a difference",
                field.as_str()
            );
        }
    }

    #[test]
    fn several_mutations_at_once_are_all_reported() {
        let authorized = authorized_operation();
        let mut mutated = authorized.clone();
        mutated.resource_id = "document-999".to_owned();
        mutated.action = "delete".to_owned();
        mutated.tenant_id = "tenant-b".to_owned();

        let fields: Vec<OperationField> = authorized
            .authorization_differences(&mutated)
            .into_iter()
            .map(|difference| difference.field)
            .collect();
        assert_eq!(
            fields,
            vec![
                OperationField::Action,
                OperationField::ResourceId,
                OperationField::Tenant
            ]
        );
    }

    #[test]
    fn the_projection_is_insensitive_to_key_order_in_the_source_json() {
        // Canonicalization is why this holds. A raw-byte comparison would treat
        // these two records as different operations.
        let one: Operation = serde_json::from_value(json!({
            "operation_id": "op-1", "subject_id": "user-7", "action": "read",
            "resource_id": "document-123", "resource_type": "document", "tenant_id": "tenant-a",
            "authorization_relevant_arguments": {"b": "2", "a": "1"}
        }))
        .expect("decodes");
        let other: Operation = serde_json::from_value(json!({
            "tenant_id": "tenant-a", "resource_type": "document", "resource_id": "document-123",
            "action": "read", "subject_id": "user-7", "operation_id": "op-1",
            "authorization_relevant_arguments": {"a": "1", "b": "2"}
        }))
        .expect("decodes");

        assert_eq!(
            one.projection_digest().expect("digest"),
            other.projection_digest().expect("digest")
        );
    }

    #[test]
    fn the_projection_reuses_the_cycle_003_canonicalizer() {
        // Not a second binding engine. The preimage and the hash are exactly
        // Cycle 003's; Cycle 015 only adds the `sha256:` label that the rest of
        // DARE evidence already uses.
        let operation = authorized_operation();
        let projection = operation.projection().expect("projects");
        assert_eq!(
            projection.digest(),
            format!("sha256:{}", projection.canonical().digest())
        );
        assert_eq!(projection.canonical().digest().len(), 64);
    }

    #[test]
    fn an_argument_cannot_be_both_relevant_and_incidental() {
        // Otherwise the projection would depend on which map a reader consulted.
        let mut operation = authorized_operation();
        operation
            .incidental_arguments
            .insert("field_set".to_owned(), "summary".to_owned());
        let err = operation.validate().expect_err("must be refused");
        assert!(err.to_string().contains("both authorization-relevant"));
    }

    #[test]
    fn an_operation_with_an_empty_required_field_is_refused() {
        for field in [
            "subject_id",
            "action",
            "resource_id",
            "resource_type",
            "tenant_id",
        ] {
            let mut operation = authorized_operation();
            match field {
                "subject_id" => operation.subject_id = "  ".to_owned(),
                "action" => operation.action = String::new(),
                "resource_id" => operation.resource_id = String::new(),
                "resource_type" => operation.resource_type = String::new(),
                _ => operation.tenant_id = String::new(),
            }
            assert!(
                operation.validate().is_err(),
                "empty {field} must be refused"
            );
        }
    }

    #[test]
    fn the_operation_key_is_resource_type_dot_action() {
        assert_eq!(authorized_operation().key(), "document.read");
    }

    #[test]
    fn an_operation_cannot_carry_a_credential_or_unknown_field() {
        let hostile = json!({
            "operation_id": "op-1", "subject_id": "user-7", "action": "read",
            "resource_id": "document-123", "resource_type": "document", "tenant_id": "tenant-a",
            "access_token": "eyJhbGciOi"
        });
        assert!(serde_json::from_value::<Operation>(hostile).is_err());
    }
}
