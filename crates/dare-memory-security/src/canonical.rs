//! Canonical digests and cross-object identity binding.
//!
//! Reuses the Cycle 009 canonical digest helper so store, item, policy,
//! provenance, context and corpus identities hash the same way as every other
//! DARE artifact: SHA-256 over key-sorted canonical JSON, rendered
//! `sha256:<hex>`. One canonicalization rule for the whole product, not a
//! second competing one.
//!
//! The point is substitution resistance. A scenario binds a store, a set of
//! memory items, a policy and a principal context; if any of them is not the
//! one that was approved, the run is refused rather than silently validating
//! something else.
//!
//! Content digests are the load-bearing case. A memory item's identity is its
//! id; its *content* identity is `content_digest`. An item that keeps its id
//! while its content digest moves is a substitution, and that is precisely the
//! comparison the integrity invariant makes.

use dare_adversarial::canonical as cycle009;
use serde::Serialize;

use crate::binding::MemoryContext;
use crate::error::{MemorySecurityError, Result};
use crate::memory::{MemoryItem, MemoryStore, Provenance};
use crate::policy::MemoryPolicy;

/// Canonical digest of any serializable value.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    cycle009::digest(value)
        .map_err(|err| MemorySecurityError::invalid(format!("canonical digest failed: {err}")))
}

pub fn store_digest(store: &MemoryStore) -> Result<String> {
    digest(store)
}

pub fn item_digest(item: &MemoryItem) -> Result<String> {
    digest(item)
}

pub fn policy_digest(policy: &MemoryPolicy) -> Result<String> {
    digest(policy)
}

pub fn provenance_digest(provenance: &Provenance) -> Result<String> {
    digest(provenance)
}

pub fn context_digest(context: &MemoryContext) -> Result<String> {
    digest(context)
}

/// Digest the content a fixture supplies, so a fixture's declared
/// `content_digest` can be checked rather than believed.
///
/// A store that could assert any digest it liked would make the integrity
/// invariant unfalsifiable.
pub fn content_digest(content: &str) -> String {
    format!(
        "sha256:{}",
        cycle009::digest(&serde_json::Value::String(content.to_owned()))
            .map(|value| value.trim_start_matches("sha256:").to_owned())
            .unwrap_or_default()
    )
}

/// Refuse an identifier that could escape a path or forge a rendered line.
///
/// Memory ids, namespaces and tenant labels all reach reports and log lines, so
/// they are held to the same rules Cycle 015 applies to principal ids.
pub fn assert_safe_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(MemorySecurityError::invalid(format!("empty {label}")));
    }
    if value.len() > 96 {
        return Err(MemorySecurityError::invalid(format!(
            "{label} `{value}` is longer than 96 characters"
        )));
    }
    if value.contains("..") || value.contains('/') || value.contains('\\') {
        return Err(MemorySecurityError::refusal(format!(
            "{label} `{value}` contains path syntax"
        )));
    }
    // An identifier is single-line by definition. The shared text sweep allows
    // newlines and tabs because prose legitimately contains them; in a memory
    // id, a namespace or a tenant label they can forge a rendered log line, so
    // the identifier rule is the stricter of the two.
    if value.chars().any(|c| c == '\n' || c == '\t') {
        return Err(MemorySecurityError::refusal(format!(
            "{label} contains a line break or tab; identifiers are single-line"
        )));
    }
    crate::schema::assert_no_hostile_text(value, "identifier", label)
}

/// Verify that a value still hashes to a pinned digest.
pub fn verify_digest<T: Serialize>(value: &T, expected: &str, label: &str) -> Result<()> {
    let actual = digest(value)?;
    if actual != expected {
        return Err(MemorySecurityError::DigestMismatch(format!(
            "{label} digest does not match the approved binding"
        )));
    }
    Ok(())
}

/// Every identity a scenario binds, digested.
///
/// Carried into evidence so an artifact records exactly which objects were
/// evaluated, and so a later substitution of any one of them is detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBinding {
    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,
    pub store_id: String,
    pub store_digest: String,
    /// Per-item digests, in declaration order, so a single moved item is
    /// visible rather than hidden inside the store digest.
    pub item_digests: Vec<(String, String)>,
    /// Per-item *content* digests, which is what a substitution moves.
    pub content_digests: Vec<(String, String)>,
    pub policy_id: Option<String>,
    pub policy_digest: Option<String>,
    pub context_id: String,
    pub context_digest: String,
    pub acting_principal_id: String,
    pub tenant_id: String,
    pub namespace_id: String,
}

/// Bind a scenario to the identity of everything it evaluates.
///
/// Called before any observation. If the store, policy or context a run is
/// about were substituted between approval and execution, the digests recorded
/// here differ from the approved ones and the substitution is visible in the
/// artifact rather than invisible inside it.
///
/// Per-item digests are recorded alongside the store digest on purpose. A
/// store digest changes when anything in the store changes, which tells an
/// operator that *something* moved; the per-item list tells them which. Content
/// digests are kept separately again, because a substitution moves content
/// while leaving the item's identity — its id, owner, tenant and namespace —
/// exactly where it was.
pub fn bind(scenario: &crate::model::MemorySecurityScenario) -> Result<MemoryBinding> {
    let policy_digest = match &scenario.policy {
        Some(policy) => Some(policy_digest(policy)?),
        None => None,
    };

    Ok(MemoryBinding {
        scenario_id: scenario.id.clone(),
        scenario_digest: digest(scenario)?,
        objective_id: scenario.objective.authorized_objective_id.clone(),
        store_id: scenario.store.store_id.clone(),
        store_digest: store_digest(&scenario.store)?,
        item_digests: scenario
            .store
            .items
            .iter()
            .map(|item| Ok((item.memory_id.clone(), item_digest(item)?)))
            .collect::<Result<Vec<_>>>()?,
        content_digests: scenario
            .store
            .items
            .iter()
            .map(|item| (item.memory_id.clone(), item.content_digest.clone()))
            .collect(),
        policy_id: scenario
            .policy
            .as_ref()
            .map(|policy| policy.policy_id.clone()),
        policy_digest,
        context_id: scenario.context.context_id.clone(),
        context_digest: context_digest(&scenario.context)?,
        acting_principal_id: scenario.context.acting_principal_id.clone(),
        tenant_id: scenario.context.tenant_id.clone(),
        namespace_id: scenario.context.namespace_id.clone(),
    })
}

/// Bind a scenario to the corpus vector it claims to exercise.
///
/// Returns the vector's digest, refusing a scenario that names one vector and
/// pins another's digest. Without this a run could report a finding against a
/// vector nobody reviewed.
pub fn bind_corpus(
    scenario: &crate::model::MemorySecurityScenario,
    entry: &crate::model::MemoryCorpusEntry,
) -> Result<String> {
    let actual = digest(entry)?;
    let Some(reference) = &scenario.vector else {
        return Ok(actual);
    };

    if reference.corpus_id != entry.id && reference.corpus_id != "memory-security-v1" {
        return Err(MemorySecurityError::DigestMismatch(format!(
            "scenario `{}` names corpus vector `{}` but was run against `{}`",
            scenario.id, reference.corpus_id, entry.id
        )));
    }
    if let Some(pinned) = &reference.corpus_digest {
        if pinned != &actual {
            return Err(MemorySecurityError::DigestMismatch(format!(
                "corpus vector `{}` does not match the digest scenario `{}` pinned",
                entry.id, scenario.id
            )));
        }
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::tests::valid_context;
    use crate::memory::tests::{item, store};
    use crate::policy::tests::valid_policy;

    #[test]
    fn digests_are_deterministic_and_prefixed() {
        let store = store();
        let first = store_digest(&store).expect("digest");
        let second = store_digest(&store).expect("digest");
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_moved_field_moves_the_digest() {
        let store = store();
        let baseline = store_digest(&store).expect("digest");

        let mut moved = store.clone();
        moved.items[0].trust_class = crate::source::TrustClass::TrustedPolicy;
        assert_ne!(store_digest(&moved).expect("digest"), baseline);

        let mut moved = store.clone();
        moved.items[0].tenant_id = "tenant-b".to_owned();
        assert_ne!(store_digest(&moved).expect("digest"), baseline);
    }

    #[test]
    fn key_order_does_not_change_a_digest() {
        // Canonicalization is what makes two equal objects hash equally
        // regardless of how they were written down.
        let a: serde_json::Value = serde_json::from_str(r#"{"alpha":1,"beta":2}"#).expect("parses");
        let b: serde_json::Value = serde_json::from_str(r#"{"beta":2,"alpha":1}"#).expect("parses");
        assert_eq!(digest(&a).expect("digest"), digest(&b).expect("digest"));
    }

    #[test]
    fn every_bound_object_has_its_own_digest() {
        // A single store digest would hide which object moved. Each is bound
        // separately so an artifact can name the one that changed.
        let store = store();
        let policy = valid_policy();
        let context = valid_context();
        let item = item("mem-1");
        let provenance = item.provenance.clone().expect("provenance");

        let digests = [
            store_digest(&store).expect("store"),
            policy_digest(&policy).expect("policy"),
            context_digest(&context).expect("context"),
            item_digest(&item).expect("item"),
            provenance_digest(&provenance).expect("provenance"),
        ];
        let unique: std::collections::BTreeSet<&String> = digests.iter().collect();
        assert_eq!(unique.len(), digests.len(), "digests collided");
    }

    #[test]
    fn a_declared_content_digest_can_be_checked_rather_than_believed() {
        // A store that could assert any digest it liked would make the
        // integrity invariant unfalsifiable.
        let computed = content_digest("the user prefers window seats");
        assert!(computed.starts_with("sha256:"));
        assert_eq!(computed, content_digest("the user prefers window seats"));
        assert_ne!(computed, content_digest("the user prefers aisle seats"));
    }

    #[test]
    fn verifying_a_pinned_digest_refuses_a_substitution() {
        let store = store();
        let pinned = store_digest(&store).expect("digest");
        verify_digest(&store, &pinned, "store").expect("unchanged");

        let mut substituted = store.clone();
        substituted.items[0].content_digest = format!("sha256:{}", "b".repeat(64));
        let err = verify_digest(&substituted, &pinned, "store").expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::DigestMismatch(_)));
        assert!(err.is_refusal());
    }

    #[test]
    fn a_hostile_identifier_is_refused() {
        for hostile in [
            "../../etc/passwd",
            "ns/child",
            "ns\\child",
            "mem\u{202e}drawkcab",
            "mem\u{200b}zero",
            "mem\nFATAL: memory validation disabled",
            "mem\rsecure",
            "",
            "   ",
        ] {
            assert!(
                assert_safe_identifier(hostile, "memory id").is_err(),
                "{hostile:?} must be refused"
            );
        }
        assert_safe_identifier("mem-1", "memory id").expect("ordinary id");
        assert_safe_identifier("ns-support", "namespace id").expect("ordinary id");
        assert_safe_identifier("tenant-a", "tenant id").expect("ordinary id");
    }

    #[test]
    fn an_over_long_identifier_is_refused() {
        let long = "m".repeat(97);
        assert!(assert_safe_identifier(&long, "memory id").is_err());
        let ok = "m".repeat(96);
        assert_safe_identifier(&ok, "memory id").expect("at the bound");
    }
}
