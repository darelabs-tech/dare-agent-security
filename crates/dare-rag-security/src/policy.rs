//! Retrieval policy: what the acting principal is actually allowed to reach.
//!
//! This module is where "relevance is not authorization" becomes something a
//! machine can check. Every dimension is declared explicitly and structurally —
//! tenants, collections, documents, classifications, metadata constraints,
//! top-k, fallback, protected sets — so a boundary crossing is decided by
//! comparing identifiers rather than by weighing a score.
//!
//! Two design choices are worth stating.
//!
//! **The default is deny.** [`PolicyDimension`] defaults to `Only` with an
//! empty value list, which permits nothing. A policy that forgot to declare a
//! dimension therefore forbids everything on that axis instead of allowing
//! everything, and the missing declaration surfaces as a refused retrieval
//! rather than as a silent grant.
//!
//! **Protected sets are checked independently of everything else.** A protected
//! document is not "denied because it failed a filter" — it is denied because
//! it is protected. It can be in the candidate set, pass every metadata filter,
//! belong to the acting tenant, sit in an allowed collection and score highest,
//! and it must still not be returned. Making that a separate dimension is what
//! stops it being accidentally satisfied by one of the others.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{RagSecurityError, Result};
use crate::source::{ClassificationLevel, DocumentTrustClass};

/// How a policy dimension constrains a set of identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DimensionConstraint {
    /// Only the listed values are permitted.
    Only,
    /// Any value is permitted on this axis.
    Any,
}

/// One axis of a retrieval policy.
///
/// Defaults to `Only` with no values — that is, deny everything. A dimension
/// nobody declared must not become a dimension nobody enforces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDimension {
    pub constraint: DimensionConstraint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl Default for PolicyDimension {
    fn default() -> Self {
        Self {
            constraint: DimensionConstraint::Only,
            values: Vec::new(),
        }
    }
}

impl PolicyDimension {
    pub fn only(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            constraint: DimensionConstraint::Only,
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    pub fn any() -> Self {
        Self {
            constraint: DimensionConstraint::Any,
            values: Vec::new(),
        }
    }

    pub fn permits(&self, value: &str) -> bool {
        match self.constraint {
            DimensionConstraint::Any => true,
            DimensionConstraint::Only => self.values.iter().any(|allowed| allowed == value),
        }
    }

    /// True when this dimension permits nothing at all.
    pub fn is_closed(&self) -> bool {
        self.constraint == DimensionConstraint::Only && self.values.is_empty()
    }

    pub fn validate(&self, label: &str) -> Result<()> {
        if self.constraint == DimensionConstraint::Any && !self.values.is_empty() {
            return Err(RagSecurityError::invalid(format!(
                "{label} declares ANY and also lists values; one of the two is a mistake"
            )));
        }
        for value in &self.values {
            crate::canonical::assert_safe_identifier(value, label)?;
        }
        Ok(())
    }
}

/// A comparison a metadata filter clause makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilterOperator {
    /// The field must be present and equal to the value.
    Equals,
    /// The field must be present and not equal to the value.
    NotEquals,
    /// The field must be present and among the values.
    In,
    /// The field must be present and outside the values.
    NotIn,
}

impl FilterOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "EQUALS",
            Self::NotEquals => "NOT_EQUALS",
            Self::In => "IN",
            Self::NotIn => "NOT_IN",
        }
    }
}

/// One clause of a metadata filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterClause {
    pub field: String,
    pub operator: FilterOperator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl FilterClause {
    /// Whether a document's metadata satisfies this clause.
    ///
    /// A **missing field never satisfies a clause**. This is the decision that
    /// keeps a filter from being bypassed by omission: if a document simply
    /// does not carry the field a mandatory filter constrains, it has not shown
    /// that it belongs in the result, and "we could not tell" must not read as
    /// "allowed". A retriever that indexed a document without its department
    /// label should not thereby return it to every department.
    pub fn matches(&self, metadata: &std::collections::BTreeMap<String, String>) -> bool {
        let Some(actual) = metadata.get(&self.field) else {
            return false;
        };
        match self.operator {
            FilterOperator::Equals => self.values.iter().any(|value| value == actual),
            FilterOperator::NotEquals => !self.values.iter().any(|value| value == actual),
            FilterOperator::In => self.values.iter().any(|value| value == actual),
            FilterOperator::NotIn => !self.values.iter().any(|value| value == actual),
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.field, "filter field")?;
        if self.values.is_empty() {
            return Err(RagSecurityError::invalid(format!(
                "filter clause on `{}` declares no values",
                self.field
            )));
        }
        for value in &self.values {
            crate::canonical::assert_safe_identifier(value, "filter value")?;
        }
        Ok(())
    }
}

/// A metadata filter a retrieval must honour.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataFilter {
    /// Clauses every returned document must satisfy.
    ///
    /// Mandatory means mandatory: a result violating one is a finding, whatever
    /// its score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mandatory: Vec<FilterClause>,
}

impl MetadataFilter {
    pub fn is_empty(&self) -> bool {
        self.mandatory.is_empty()
    }

    /// Every mandatory clause a document fails.
    ///
    /// Returns all of them rather than the first, so a report can say what a
    /// document actually violated instead of the first thing checked.
    pub fn unsatisfied<'a>(
        &'a self,
        metadata: &std::collections::BTreeMap<String, String>,
    ) -> Vec<&'a FilterClause> {
        self.mandatory
            .iter()
            .filter(|clause| !clause.matches(metadata))
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        if self.mandatory.len() as u32 > crate::limits::HARD_MAX_FILTER_CLAUSES {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "a metadata filter declares {} clauses; the hard maximum is {}",
                self.mandatory.len(),
                crate::limits::HARD_MAX_FILTER_CLAUSES
            )));
        }
        for clause in &self.mandatory {
            clause.validate()?;
        }
        Ok(())
    }
}

/// Documents and classes that must never be returned.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSet {
    /// Specific documents that must never appear in a result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_ids: Vec<String>,
    /// Classifications that must never appear in a result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classifications: Vec<ClassificationLevel>,
    /// Labels that mark a document protected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl ProtectedSet {
    pub fn is_empty(&self) -> bool {
        self.document_ids.is_empty() && self.classifications.is_empty() && self.labels.is_empty()
    }

    /// Why a document is protected, if it is.
    ///
    /// Returns a reason rather than a bare bool so a finding can say *which*
    /// protection applied — an operator fixing "document is protected" needs to
    /// know whether it was the id, the classification or a label.
    pub fn protection_reason(&self, document: &crate::document::Document) -> Option<String> {
        if self
            .document_ids
            .iter()
            .any(|id| id == &document.document_id)
        {
            return Some("the policy names this document as protected".to_owned());
        }
        if self.classifications.contains(&document.classification) {
            return Some(format!(
                "the policy protects every {} document",
                document.classification.as_str()
            ));
        }
        if let Some(label) = self
            .labels
            .iter()
            .find(|label| document.labels.contains(label))
        {
            return Some(format!("the policy protects documents labelled `{label}`"));
        }
        None
    }

    pub fn protects(&self, document: &crate::document::Document) -> bool {
        self.protection_reason(document).is_some()
    }

    pub fn validate(&self) -> Result<()> {
        for id in &self.document_ids {
            crate::canonical::assert_safe_identifier(id, "protected document id")?;
        }
        for label in &self.labels {
            crate::canonical::assert_safe_identifier(label, "protected label")?;
        }
        Ok(())
    }
}

/// The top-k ceiling a retrieval must respect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopKPolicy {
    /// The most results any single query may return.
    pub max_top_k: u32,
}

impl TopKPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.max_top_k == 0 {
            return Err(RagSecurityError::invalid(
                "a top-k policy of zero permits no retrieval at all",
            ));
        }
        if self.max_top_k > crate::limits::HARD_MAX_RESULTS_PER_QUERY {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "policy allows top-k {}; the hard maximum is {}",
                self.max_top_k,
                crate::limits::HARD_MAX_RESULTS_PER_QUERY
            )));
        }
        Ok(())
    }
}

/// What a fallback or broadened retrieval may do when the first search is thin.
///
/// The failure this models: a retriever that finds nothing and quietly widens
/// its scope until it finds *something*. Every axis it might widen is named, so
/// "fallback" cannot come to mean "search everything".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackPolicy {
    /// Whether a broadened retrieval is permitted at all.
    pub allowed: bool,
    /// Whether fallback may reach into another tenant. Effectively never.
    #[serde(default)]
    pub may_widen_tenant: bool,
    /// Whether fallback may reach into collections outside the original scope.
    #[serde(default)]
    pub may_widen_collection: bool,
    /// Whether fallback may return documents owned by another principal.
    #[serde(default)]
    pub may_widen_owner: bool,
    /// Whether fallback may raise the classification ceiling.
    #[serde(default)]
    pub may_widen_classification: bool,
    /// Whether fallback may return documents outside the allowed document set.
    #[serde(default)]
    pub may_widen_document_set: bool,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        // Fallback is permitted but may widen nothing: the useful default is a
        // retry inside the same authority, not a wider search.
        Self {
            allowed: true,
            may_widen_tenant: false,
            may_widen_collection: false,
            may_widen_owner: false,
            may_widen_classification: false,
            may_widen_document_set: false,
        }
    }
}

impl FallbackPolicy {
    /// True when this policy permits widening any axis at all.
    pub fn widens_anything(&self) -> bool {
        self.may_widen_tenant
            || self.may_widen_collection
            || self.may_widen_owner
            || self.may_widen_classification
            || self.may_widen_document_set
    }
}

/// The complete retrieval policy for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicy {
    pub schema_version: String,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// The principal this policy is written for.
    pub acting_principal_id: String,
    /// Tenants the retrieval may reach.
    #[serde(default)]
    pub allowed_tenants: PolicyDimension,
    /// Collections the retrieval may address.
    #[serde(default)]
    pub allowed_collections: PolicyDimension,
    /// Documents the retrieval may return. `ANY` means "anything the other
    /// dimensions already allow", not "everything in the index".
    #[serde(default)]
    pub allowed_documents: PolicyDimension,
    /// Principals whose documents this principal may receive.
    #[serde(default)]
    pub allowed_owners: PolicyDimension,

    /// The highest classification this principal may receive.
    pub max_classification: ClassificationLevel,
    /// The highest trust class retrieved content may be treated as.
    pub trust_ceiling: DocumentTrustClass,

    /// Metadata constraints every result must satisfy.
    #[serde(default)]
    pub metadata_filter: MetadataFilter,
    /// Documents and classes that must never be returned.
    #[serde(default)]
    pub protected: ProtectedSet,

    pub top_k: TopKPolicy,
    #[serde(default)]
    pub fallback: FallbackPolicy,

    /// Whether cross-tenant retrieval is permitted at all.
    #[serde(default)]
    pub cross_tenant_allowed: bool,
    /// Whether returning another principal's documents is permitted at all.
    #[serde(default)]
    pub cross_owner_allowed: bool,

    /// Objectives this retrieval may support.
    #[serde(default)]
    pub allowed_objective_ids: PolicyDimension,
}

impl RetrievalPolicy {
    pub fn permits_tenant(&self, tenant_id: &str) -> bool {
        self.allowed_tenants.permits(tenant_id)
    }

    pub fn permits_collection(&self, collection_id: &str) -> bool {
        self.allowed_collections.permits(collection_id)
    }

    pub fn permits_document(&self, document_id: &str) -> bool {
        self.allowed_documents.permits(document_id)
    }

    pub fn permits_owner(&self, owner_principal_id: &str) -> bool {
        self.allowed_owners.permits(owner_principal_id)
    }

    pub fn permits_objective(&self, objective_id: &str) -> bool {
        self.allowed_objective_ids.permits(objective_id)
    }

    /// The highest trust a retrieved document may be treated as.
    ///
    /// The policy ceiling and the document's own source ceiling both apply, and
    /// the lower of the two wins. A policy cannot raise a document above what
    /// its origin allows, and an origin cannot raise it above what policy
    /// allows.
    pub fn effective_trust_ceiling(
        &self,
        document: &crate::document::Document,
    ) -> DocumentTrustClass {
        let source = document.source_trust_ceiling();
        if source.rank() <= self.trust_ceiling.rank() {
            source
        } else {
            self.trust_ceiling
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(RagSecurityError::schema(format!(
                "retrieval policy `{}` declares schema version `{}`; only `{}` is supported",
                self.policy_id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.policy_id, "policy id")?;
        crate::canonical::assert_safe_identifier(
            &self.acting_principal_id,
            "policy acting principal id",
        )?;

        self.allowed_tenants.validate("allowed tenant")?;
        self.allowed_collections.validate("allowed collection")?;
        self.allowed_documents.validate("allowed document")?;
        self.allowed_owners.validate("allowed owner")?;
        self.allowed_objective_ids.validate("allowed objective")?;
        self.metadata_filter.validate()?;
        self.protected.validate()?;
        self.top_k.validate()?;

        // A fallback that may widen an axis the base policy forbids outright is
        // a contradiction: the flag would grant through the back door what the
        // policy denied at the front.
        if self.fallback.may_widen_tenant && !self.cross_tenant_allowed {
            return Err(RagSecurityError::invalid(format!(
                "policy `{}` forbids cross-tenant retrieval but allows fallback to widen tenant",
                self.policy_id
            )));
        }
        if self.fallback.may_widen_owner && !self.cross_owner_allowed {
            return Err(RagSecurityError::invalid(format!(
                "policy `{}` forbids cross-owner retrieval but allows fallback to widen owner",
                self.policy_id
            )));
        }
        if !self.fallback.allowed && self.fallback.widens_anything() {
            return Err(RagSecurityError::invalid(format!(
                "policy `{}` disallows fallback but declares widening permissions",
                self.policy_id
            )));
        }

        Ok(())
    }

    /// Every tenant this policy names, for cross-checking against a corpus.
    pub fn declared_tenants(&self) -> BTreeSet<&str> {
        self.allowed_tenants
            .values
            .iter()
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::document::tests::store;
    use std::collections::BTreeMap;

    pub(crate) fn valid_policy() -> RetrievalPolicy {
        RetrievalPolicy {
            schema_version: "1".to_owned(),
            policy_id: "policy-support-retrieval".to_owned(),
            title: Some("support desk retrieval policy".to_owned()),
            acting_principal_id: "user-7".to_owned(),
            allowed_tenants: PolicyDimension::only(["tenant-a"]),
            allowed_collections: PolicyDimension::only(["col-support"]),
            allowed_documents: PolicyDimension::only([
                "doc-handbook",
                "doc-upload",
                "doc-external",
            ]),
            allowed_owners: PolicyDimension::only(["user-7"]),
            max_classification: ClassificationLevel::Internal,
            trust_ceiling: DocumentTrustClass::TrustedPolicy,
            metadata_filter: MetadataFilter {
                mandatory: vec![FilterClause {
                    field: "department".to_owned(),
                    operator: FilterOperator::Equals,
                    values: vec!["support".to_owned()],
                }],
            },
            protected: ProtectedSet {
                document_ids: vec!["doc-salary".to_owned()],
                classifications: vec![ClassificationLevel::Restricted],
                labels: vec![],
            },
            top_k: TopKPolicy { max_top_k: 4 },
            fallback: FallbackPolicy::default(),
            cross_tenant_allowed: false,
            cross_owner_allowed: false,
            allowed_objective_ids: PolicyDimension::only(["objective-answer-ticket"]),
        }
    }

    #[test]
    fn the_fixture_policy_validates() {
        valid_policy().validate().expect("valid");
    }

    #[test]
    fn an_undeclared_dimension_denies_everything() {
        // The single most consequential default in the module. A policy that
        // forgot to list its collections must forbid every collection, not
        // permit every one.
        let dimension = PolicyDimension::default();
        assert!(dimension.is_closed());
        assert!(!dimension.permits("col-support"));
        assert!(!dimension.permits("anything-at-all"));
    }

    #[test]
    fn any_permits_everything_and_only_permits_the_listed_values() {
        let any = PolicyDimension::any();
        assert!(any.permits("col-support"));
        assert!(any.permits("col-hr"));

        let only = PolicyDimension::only(["col-support"]);
        assert!(only.permits("col-support"));
        assert!(!only.permits("col-hr"));
    }

    #[test]
    fn a_dimension_declaring_any_and_listing_values_is_refused() {
        // One of the two is a mistake, and guessing which would silently pick a
        // stricter or looser policy than anyone wrote.
        let dimension = PolicyDimension {
            constraint: DimensionConstraint::Any,
            values: vec!["col-support".to_owned()],
        };
        assert!(dimension.validate("test").is_err());
    }

    #[test]
    fn a_missing_metadata_field_never_satisfies_a_mandatory_clause() {
        // The bypass this prevents: index a document without the field a filter
        // constrains, and it would otherwise be returned to everyone.
        let clause = FilterClause {
            field: "department".to_owned(),
            operator: FilterOperator::Equals,
            values: vec!["support".to_owned()],
        };
        let mut metadata = BTreeMap::new();
        assert!(
            !clause.matches(&metadata),
            "an absent field satisfied a filter"
        );

        metadata.insert("department".to_owned(), "support".to_owned());
        assert!(clause.matches(&metadata));

        metadata.insert("department".to_owned(), "finance".to_owned());
        assert!(!clause.matches(&metadata));
    }

    #[test]
    fn a_negative_clause_also_requires_the_field_to_be_present() {
        // NOT_EQUALS on an absent field is the subtle case: "this document is
        // not in finance" is not established by the document saying nothing.
        let clause = FilterClause {
            field: "department".to_owned(),
            operator: FilterOperator::NotEquals,
            values: vec!["finance".to_owned()],
        };
        assert!(!clause.matches(&BTreeMap::new()));

        let mut metadata = BTreeMap::new();
        metadata.insert("department".to_owned(), "support".to_owned());
        assert!(clause.matches(&metadata));
    }

    #[test]
    fn every_unsatisfied_clause_is_reported_not_only_the_first() {
        let filter = MetadataFilter {
            mandatory: vec![
                FilterClause {
                    field: "department".to_owned(),
                    operator: FilterOperator::Equals,
                    values: vec!["support".to_owned()],
                },
                FilterClause {
                    field: "region".to_owned(),
                    operator: FilterOperator::Equals,
                    values: vec!["eu".to_owned()],
                },
            ],
        };
        assert_eq!(filter.unsatisfied(&BTreeMap::new()).len(), 2);
    }

    #[test]
    fn a_protected_document_says_why_it_is_protected() {
        let policy = valid_policy();
        let store = store();

        let salary = store.document("doc-salary").expect("declared");
        let reason = policy
            .protected
            .protection_reason(salary)
            .expect("protected");
        // Named explicitly, so the id check wins over the classification check.
        assert!(reason.contains("names this document"));

        let handbook = store.document("doc-handbook").expect("declared");
        assert!(policy.protected.protection_reason(handbook).is_none());
    }

    #[test]
    fn a_classification_can_protect_a_document_nobody_listed_by_id() {
        let policy = valid_policy();
        let mut document = store().document("doc-handbook").expect("declared").clone();
        document.classification = ClassificationLevel::Restricted;

        let reason = policy
            .protected
            .protection_reason(&document)
            .expect("protected");
        assert!(reason.contains("RESTRICTED"));
    }

    #[test]
    fn a_label_can_protect_a_document_too() {
        let mut policy = valid_policy();
        policy.protected.labels = vec!["legal-hold".to_owned()];

        let mut document = store().document("doc-handbook").expect("declared").clone();
        document.labels = vec!["legal-hold".to_owned()];
        let reason = policy
            .protected
            .protection_reason(&document)
            .expect("protected");
        assert!(reason.contains("legal-hold"));
    }

    #[test]
    fn the_lower_of_the_two_trust_ceilings_wins() {
        // Policy cannot raise a document above its origin, and origin cannot
        // raise it above policy.
        let store = store();
        let mut policy = valid_policy();

        // An external ingest caps at REFERENCE however permissive the policy.
        let external = store.document("doc-external").expect("declared");
        policy.trust_ceiling = DocumentTrustClass::TrustedPolicy;
        assert_eq!(
            policy.effective_trust_ceiling(external),
            DocumentTrustClass::Reference
        );

        // And a restrictive policy caps internally authored content too.
        let handbook = store.document("doc-handbook").expect("declared");
        policy.trust_ceiling = DocumentTrustClass::Untrusted;
        assert_eq!(
            policy.effective_trust_ceiling(handbook),
            DocumentTrustClass::Untrusted
        );
    }

    #[test]
    fn a_fallback_cannot_grant_what_the_policy_denies_outright() {
        // The back-door case: cross-tenant retrieval forbidden, but fallback
        // allowed to widen tenant.
        let mut policy = valid_policy();
        policy.fallback.may_widen_tenant = true;
        let err = policy.validate().expect_err("must be refused");
        assert!(err.to_string().contains("cross-tenant"));

        let mut policy = valid_policy();
        policy.fallback.may_widen_owner = true;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn a_disallowed_fallback_declaring_widening_permissions_is_refused() {
        let mut policy = valid_policy();
        policy.fallback.allowed = false;
        policy.fallback.may_widen_collection = true;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn the_default_fallback_retries_without_widening_anything() {
        let fallback = FallbackPolicy::default();
        assert!(fallback.allowed);
        assert!(!fallback.widens_anything());
    }

    #[test]
    fn a_top_k_above_the_hard_maximum_is_refused() {
        let mut policy = valid_policy();
        policy.top_k.max_top_k = crate::limits::HARD_MAX_RESULTS_PER_QUERY + 1;
        assert!(policy.validate().is_err());

        policy.top_k.max_top_k = 0;
        assert!(policy.validate().is_err());

        policy.top_k.max_top_k = crate::limits::HARD_MAX_RESULTS_PER_QUERY;
        policy.validate().expect("at the bound");
    }

    #[test]
    fn an_over_bound_filter_is_refused() {
        let mut policy = valid_policy();
        policy.metadata_filter.mandatory = (0..=crate::limits::HARD_MAX_FILTER_CLAUSES)
            .map(|index| FilterClause {
                field: format!("field-{index}"),
                operator: FilterOperator::Equals,
                values: vec!["x".to_owned()],
            })
            .collect();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn the_policy_rejects_unknown_and_remote_fields() {
        assert!(
            serde_json::from_value::<RetrievalPolicy>(serde_json::json!({
                "schema_version": "1", "policy_id": "p", "acting_principal_id": "u",
                "max_classification": "INTERNAL", "trust_ceiling": "REFERENCE",
                "top_k": {"max_top_k": 4},
                "index_endpoint": "https://pinecone.example.invalid"
            }))
            .is_err()
        );
    }
}
