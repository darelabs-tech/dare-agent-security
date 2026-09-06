//! Memory items, stores and their bindings.
//!
//! A memory item is declarative, synthetic and secret-free. It carries what is
//! needed to decide a boundary question — where it came from, who owns it,
//! which tenant and namespace it belongs to, how far it may be trusted, when it
//! is valid and what its content hashes to — and nothing that could reach a
//! real store.
//!
//! Content is optional on purpose. The engine reasons over `content_digest`;
//! raw text is present only when a fixture needs it to be legible, and it has
//! passed the hostile/credential sweep before it gets here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};
use crate::lifecycle::{LogicalTime, ValidityWindow};
use crate::source::{LifecycleState, SourceKind, TrustClass};

/// Where a memory item's content came from, as machine-readable metadata.
///
/// Provenance is the thing that must survive persistence. An item whose
/// provenance is absent cannot be reasoned about — not because absence proves
/// poisoning, but because nothing can be concluded either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_kind: SourceKind,
    /// Synthetic identifier of the specific origin, e.g. a turn or tool id.
    pub source_id: String,
    /// The principal whose action produced the content, when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_principal_id: Option<String>,
    /// Logical time the content was produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<LogicalTime>,
}

impl Provenance {
    /// True when the provenance is complete enough to reason about.
    ///
    /// Source kind alone is not enough: without an origin identifier, two
    /// different items from the same kind of source are indistinguishable, and
    /// substitution between them would be invisible.
    pub fn is_machine_readable(&self) -> bool {
        !self.source_id.trim().is_empty()
    }
}

/// One persisted memory item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryItem {
    pub memory_id: String,
    pub namespace_id: String,
    pub owner_principal_id: String,
    pub tenant_id: String,
    /// Absent provenance is representable on purpose: a fixture must be able to
    /// describe memory that lost it, which is the thing under test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    pub trust_class: TrustClass,
    /// Canonical digest of the item's content.
    pub content_digest: String,
    /// Bounded, sanitized fixture text. Optional; the engine reasons over the
    /// digest, never over this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_excerpt: Option<String>,
    pub created_at: LogicalTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<LogicalTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<LogicalTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<LogicalTime>,
    /// Monotonic version, incremented by an authorized update.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Descriptive labels. Holding a label is not authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

fn default_version() -> u32 {
    1
}

impl MemoryItem {
    /// The item's validity window as a half-open interval.
    pub fn validity(&self) -> ValidityWindow {
        ValidityWindow {
            valid_from: self.valid_from.unwrap_or(self.created_at),
            valid_until: self.expires_at,
        }
    }

    /// Lifecycle state at a logical instant.
    ///
    /// Revocation dominates expiry: an item revoked before it expired is
    /// reported as revoked, because that is the more specific fact and the one
    /// an operator needs.
    pub fn lifecycle_at(&self, now: LogicalTime) -> LifecycleState {
        if let Some(revoked_at) = self.revoked_at {
            if now >= revoked_at {
                return LifecycleState::Revoked;
            }
        }
        let window = self.validity();
        if now < window.valid_from {
            return LifecycleState::NotYetValid;
        }
        if let Some(until) = window.valid_until {
            if now >= until {
                return LifecycleState::Expired;
            }
        }
        LifecycleState::Valid
    }

    /// True when this item may be used at the given instant.
    pub fn is_usable_at(&self, now: LogicalTime) -> bool {
        self.lifecycle_at(now).is_usable()
    }

    /// True when provenance is present and machine-readable.
    pub fn has_machine_readable_provenance(&self) -> bool {
        self.provenance
            .as_ref()
            .is_some_and(Provenance::is_machine_readable)
    }

    /// The trust ceiling this item's source allows without a policy grant.
    ///
    /// `None` when provenance is absent: an item with no known source has no
    /// derivable ceiling, which is a different thing from having a low one.
    pub fn source_trust_ceiling(&self) -> Option<TrustClass> {
        self.provenance
            .as_ref()
            .map(|provenance| provenance.source_kind.default_trust_ceiling())
    }

    /// True when the item's declared trust exceeds what its source allows.
    ///
    /// False when provenance is absent — that is the provenance invariant's
    /// finding, not the trust invariant's, and each must report its own.
    pub fn exceeds_source_trust_ceiling(&self) -> bool {
        self.source_trust_ceiling()
            .is_some_and(|ceiling| self.trust_class.rank() > ceiling.rank())
    }

    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.memory_id, "memory id")?;
        crate::canonical::assert_safe_identifier(&self.namespace_id, "namespace id")?;
        crate::canonical::assert_safe_identifier(&self.owner_principal_id, "owner principal id")?;
        crate::canonical::assert_safe_identifier(&self.tenant_id, "tenant id")?;

        if !self.content_digest.starts_with("sha256:") {
            return Err(MemorySecurityError::invalid(format!(
                "memory item `{}` carries a content digest that is not a sha256 reference",
                self.memory_id
            )));
        }

        if let Some(provenance) = &self.provenance {
            crate::canonical::assert_safe_identifier(
                &provenance.source_id,
                "provenance source id",
            )?;
            if let Some(author) = &provenance.author_principal_id {
                crate::canonical::assert_safe_identifier(author, "provenance author id")?;
            }
        }

        if let Some(valid_from) = self.valid_from {
            if valid_from < self.created_at {
                return Err(MemorySecurityError::invalid(format!(
                    "memory item `{}` becomes valid before it was created",
                    self.memory_id
                )));
            }
        }
        if let Some(expires_at) = self.expires_at {
            let starts = self.valid_from.unwrap_or(self.created_at);
            if expires_at <= starts {
                return Err(MemorySecurityError::invalid(format!(
                    "memory item `{}` expires at or before it becomes valid",
                    self.memory_id
                )));
            }
        }
        if let Some(revoked_at) = self.revoked_at {
            if revoked_at < self.created_at {
                return Err(MemorySecurityError::invalid(format!(
                    "memory item `{}` was revoked before it was created",
                    self.memory_id
                )));
            }
        }
        if self.version == 0 {
            return Err(MemorySecurityError::invalid(format!(
                "memory item `{}` carries version 0; versions start at 1",
                self.memory_id
            )));
        }
        Ok(())
    }
}

/// A bounded snapshot of persisted memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStore {
    pub schema_version: String,
    pub store_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub items: Vec<MemoryItem>,
    /// Namespaces the store declares. An item in an undeclared namespace is
    /// refused rather than treated as belonging to a new one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
}

impl MemoryStore {
    pub fn get(&self, memory_id: &str) -> Option<&MemoryItem> {
        self.items.iter().find(|item| item.memory_id == memory_id)
    }

    /// Look one item up, refusing an unknown reference.
    ///
    /// An unknown id is a refusal rather than `None`: silently treating it as
    /// absent would evaluate a scenario against memory nobody declared.
    pub fn require(&self, memory_id: &str, context: &str) -> Result<&MemoryItem> {
        self.get(memory_id).ok_or_else(|| {
            MemorySecurityError::unknown_reference(format!(
                "{context} references memory `{memory_id}`, which the store does not declare"
            ))
        })
    }

    /// Every declared namespace, including those only implied by items.
    pub fn declared_namespaces(&self) -> BTreeSet<&str> {
        self.namespaces
            .iter()
            .map(String::as_str)
            .chain(self.items.iter().map(|item| item.namespace_id.as_str()))
            .collect()
    }

    /// Items grouped by the tenant that owns them.
    pub fn by_tenant(&self) -> BTreeMap<&str, Vec<&MemoryItem>> {
        let mut out: BTreeMap<&str, Vec<&MemoryItem>> = BTreeMap::new();
        for item in &self.items {
            out.entry(item.tenant_id.as_str()).or_default().push(item);
        }
        out
    }

    /// Structural checks: bounds, duplicates and namespace declarations.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(MemorySecurityError::schema(format!(
                "memory store `{}` declares schema version `{}`; only `{}` is supported",
                self.store_id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.store_id, "store id")?;

        if self.items.len() as u32 > crate::limits::HARD_MAX_MEMORY_ITEMS {
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "memory store `{}` declares {} items; the hard maximum is {}",
                self.store_id,
                self.items.len(),
                crate::limits::HARD_MAX_MEMORY_ITEMS
            )));
        }

        let mut seen = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !seen.insert(item.memory_id.as_str()) {
                return Err(MemorySecurityError::invalid(format!(
                    "memory store `{}` declares memory `{}` more than once",
                    self.store_id, item.memory_id
                )));
            }
        }

        for namespace in &self.namespaces {
            crate::canonical::assert_safe_identifier(namespace, "namespace id")?;
        }
        let namespaces = self.declared_namespaces();
        if namespaces.len() as u32 > crate::limits::HARD_MAX_NAMESPACES {
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "memory store `{}` spans {} namespaces; the hard maximum is {}",
                self.store_id,
                namespaces.len(),
                crate::limits::HARD_MAX_NAMESPACES
            )));
        }

        // When a store enumerates its namespaces, an item outside that list is
        // refused. A store that enumerates none is not making the claim.
        if !self.namespaces.is_empty() {
            for item in &self.items {
                if !self.namespaces.contains(&item.namespace_id) {
                    return Err(MemorySecurityError::unknown_reference(format!(
                        "memory `{}` lives in namespace `{}`, which store `{}` does not declare",
                        item.memory_id, item.namespace_id, self.store_id
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn item(memory_id: &str) -> MemoryItem {
        MemoryItem {
            memory_id: memory_id.to_owned(),
            namespace_id: "ns-support".to_owned(),
            owner_principal_id: "user-7".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            provenance: Some(Provenance {
                source_kind: SourceKind::UserInput,
                source_id: "turn-12".to_owned(),
                author_principal_id: Some("user-7".to_owned()),
                recorded_at: Some(100),
            }),
            trust_class: TrustClass::Constrained,
            content_digest: format!("sha256:{}", "a".repeat(64)),
            content_excerpt: None,
            created_at: 100,
            valid_from: None,
            expires_at: Some(200),
            revoked_at: None,
            version: 1,
            labels: Vec::new(),
        }
    }

    pub(crate) fn store() -> MemoryStore {
        MemoryStore {
            schema_version: "1".to_owned(),
            store_id: "store-support".to_owned(),
            title: Some("synthetic support memory".to_owned()),
            items: vec![item("mem-1")],
            namespaces: vec!["ns-support".to_owned()],
        }
    }

    #[test]
    fn a_valid_store_validates() {
        store().validate().expect("the fixture store is valid");
    }

    #[test]
    fn lifecycle_is_decided_on_logical_time_not_the_wall_clock() {
        let item = item("mem-1");
        assert_eq!(item.lifecycle_at(99), LifecycleState::NotYetValid);
        assert_eq!(item.lifecycle_at(100), LifecycleState::Valid);
        assert_eq!(item.lifecycle_at(199), LifecycleState::Valid);
        // Half-open: the expiry instant is already expired.
        assert_eq!(item.lifecycle_at(200), LifecycleState::Expired);
        assert_eq!(item.lifecycle_at(10_000), LifecycleState::Expired);

        assert!(item.is_usable_at(150));
        assert!(!item.is_usable_at(200));
    }

    #[test]
    fn revocation_dominates_expiry() {
        // An item revoked before it expired is reported as revoked: that is the
        // more specific fact, and the one an operator needs.
        let mut item = item("mem-1");
        item.revoked_at = Some(150);
        assert_eq!(item.lifecycle_at(149), LifecycleState::Valid);
        assert_eq!(item.lifecycle_at(150), LifecycleState::Revoked);
        assert_eq!(item.lifecycle_at(250), LifecycleState::Revoked);
    }

    #[test]
    fn an_item_with_no_expiry_stays_valid() {
        let mut item = item("mem-1");
        item.expires_at = None;
        assert_eq!(item.lifecycle_at(1_000_000), LifecycleState::Valid);
    }

    #[test]
    fn absent_provenance_is_representable_and_yields_no_derivable_ceiling() {
        // A fixture must be able to describe memory that lost provenance, and
        // "no known source" is different from "a low-trust source".
        let mut item = item("mem-1");
        item.provenance = None;
        assert!(!item.has_machine_readable_provenance());
        assert_eq!(item.source_trust_ceiling(), None);
        // The trust invariant reports nothing here; provenance is the finding.
        assert!(!item.exceeds_source_trust_ceiling());
    }

    #[test]
    fn provenance_without_an_origin_identifier_is_not_machine_readable() {
        // Two items from the same kind of source would be indistinguishable,
        // so substitution between them would be invisible.
        let mut item = item("mem-1");
        item.provenance.as_mut().expect("provenance").source_id = "   ".to_owned();
        assert!(!item.has_machine_readable_provenance());
    }

    #[test]
    fn trust_above_the_source_ceiling_is_detected() {
        let mut item = item("mem-1");
        // User input caps at CONSTRAINED.
        item.trust_class = TrustClass::Constrained;
        assert!(!item.exceeds_source_trust_ceiling());
        item.trust_class = TrustClass::TrustedPolicy;
        assert!(item.exceeds_source_trust_ceiling());

        // System-authored content may reach policy trust.
        item.provenance.as_mut().expect("provenance").source_kind = SourceKind::SystemAuthored;
        assert!(!item.exceeds_source_trust_ceiling());
    }

    #[test]
    fn an_impossible_validity_window_is_refused() {
        let mut item = item("mem-1");
        item.expires_at = Some(50);
        assert!(item.validate().is_err());

        let mut item = super::tests::item("mem-1");
        item.valid_from = Some(50);
        assert!(item.validate().is_err());

        let mut item = super::tests::item("mem-1");
        item.revoked_at = Some(10);
        assert!(item.validate().is_err());

        let mut item = super::tests::item("mem-1");
        item.version = 0;
        assert!(item.validate().is_err());
    }

    #[test]
    fn a_content_digest_must_be_a_sha256_reference() {
        let mut item = item("mem-1");
        item.content_digest = "trust-me".to_owned();
        let err = item.validate().expect_err("must be refused");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn a_duplicate_memory_id_is_refused() {
        let mut store = store();
        store.items.push(item("mem-1"));
        let err = store.validate().expect_err("must be refused");
        assert!(err.to_string().contains("more than once"));
    }

    #[test]
    fn an_item_outside_the_declared_namespaces_is_refused() {
        let mut store = store();
        store.items[0].namespace_id = "ns-elsewhere".to_owned();
        let err = store.validate().expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("ns-elsewhere"));

        // A store that enumerates no namespaces is not making the claim.
        let mut store = super::tests::store();
        store.namespaces.clear();
        store.items[0].namespace_id = "ns-elsewhere".to_owned();
        store.validate().expect("no enumeration, no claim");
    }

    #[test]
    fn the_item_and_namespace_bounds_are_refusals() {
        let mut store = store();
        let template = item("mem-x");
        for index in 0..=crate::limits::HARD_MAX_MEMORY_ITEMS {
            let mut extra = template.clone();
            extra.memory_id = format!("mem-{index}");
            store.items.push(extra);
        }
        let err = store.validate().expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::BudgetExhausted(_)));

        let mut store = super::tests::store();
        store.namespaces = (0..=crate::limits::HARD_MAX_NAMESPACES)
            .map(|index| format!("ns-{index}"))
            .collect();
        let err = store.validate().expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn an_unknown_memory_reference_is_refused_rather_than_treated_as_absent() {
        let store = store();
        let err = store
            .require("mem-nowhere", "a recall")
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("mem-nowhere"));
        assert!(store.get("mem-nowhere").is_none());
    }

    #[test]
    fn a_store_rejects_unknown_and_hostile_fields() {
        assert!(serde_json::from_value::<MemoryItem>(serde_json::json!({
            "memory_id": "mem-1", "namespace_id": "ns", "owner_principal_id": "user-7",
            "tenant_id": "tenant-a", "trust_class": "UNTRUSTED",
            "content_digest": "sha256:aa", "created_at": 1,
            "connection_string": "redis://localhost:6379"
        }))
        .is_err());
    }

    #[test]
    fn tenant_grouping_keeps_tenants_separate() {
        let mut store = store();
        let mut other = item("mem-2");
        other.tenant_id = "tenant-b".to_owned();
        other.namespace_id = "ns-support".to_owned();
        store.items.push(other);

        let grouped = store.by_tenant();
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["tenant-a"].len(), 1);
        assert_eq!(grouped["tenant-b"].len(), 1);
    }
}
