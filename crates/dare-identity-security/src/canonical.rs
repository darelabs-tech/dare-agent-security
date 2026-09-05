//! Canonical digests and cross-object identity binding.
//!
//! Reuses the Cycle 009 canonical digest helper so scenario, principal-set,
//! authority, delegation, resource, policy and corpus identities hash the same
//! way as every other DARE artifact: SHA-256 over key-sorted canonical JSON,
//! rendered `sha256:<hex>`.
//!
//! The point is substitution resistance. A scenario binds a principal set, a
//! set of authorities, a delegation chain, a resource context and a policy; if
//! any of them is not the one that was approved, the run is refused rather than
//! silently validating something else.
//!
//! Operation projections are digested by Cycle 003 instead, in
//! [`crate::operation`], because that is the digest an authorization decision
//! binds to. Two canonicalizers exist in DARE and each owns its own question;
//! this module never recomputes what Cycle 003 already answers.

use dare_adversarial::canonical as cycle009;
use serde::Serialize;

use crate::authority::Authority;
use crate::authorization::AuthorizationPolicy;
use crate::delegation::DelegationChain;
use crate::error::{IdentitySecurityError, Result};
use crate::principal::PrincipalSet;
use crate::resource::ResourceContext;

/// Canonical digest of any serializable value.
///
/// Delegates to the Cycle 009 helper: one canonicalization rule for the whole
/// product, not a second competing one.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    cycle009::digest(value)
        .map_err(|err| IdentitySecurityError::invalid(format!("canonical digest failed: {err}")))
}

pub fn principal_set_digest(set: &PrincipalSet) -> Result<String> {
    digest(set)
}

pub fn authority_digest(authority: &Authority) -> Result<String> {
    digest(authority)
}

pub fn delegation_chain_digest(chain: &DelegationChain) -> Result<String> {
    digest(chain)
}

pub fn resource_context_digest(resource: &ResourceContext) -> Result<String> {
    digest(resource)
}

pub fn policy_digest(policy: &AuthorizationPolicy) -> Result<String> {
    digest(policy)
}

/// Refuse an identifier that could escape a path or forge a rendered line.
pub fn assert_safe_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(IdentitySecurityError::invalid(format!("empty {label}")));
    }
    if value.len() > 96 {
        return Err(IdentitySecurityError::invalid(format!(
            "{label} `{value}` is longer than 96 characters"
        )));
    }
    if value.contains("..") || value.contains('/') || value.contains('\\') {
        return Err(IdentitySecurityError::refusal(format!(
            "{label} `{value}` contains path syntax"
        )));
    }
    crate::schema::assert_no_hostile_text(value, "identifier", label)
}

/// Verify that a value still hashes to a pinned digest.
pub fn verify_digest<T: Serialize>(value: &T, expected: &str, label: &str) -> Result<()> {
    let actual = digest(value)?;
    if actual != expected {
        return Err(IdentitySecurityError::DigestMismatch(format!(
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
pub struct IdentityBinding {
    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,
    pub principal_set_id: String,
    pub principal_set_digest: String,
    pub initiating_principal_id: String,
    pub effective_principal_id: String,
    pub agent_principal_id: Option<String>,
    pub delegated_subject_id: Option<String>,
    pub resource_owner_id: Option<String>,
    /// Per-authority digests, in declaration order.
    pub authority_digests: Vec<(String, String)>,
    pub delegation_chain_id: Option<String>,
    pub delegation_chain_digest: Option<String>,
    pub resource_context_digest: Option<String>,
    pub tenant_id: Option<String>,
    pub policy_id: Option<String>,
    pub policy_digest: Option<String>,
}

/// Bind a scenario to every object it evaluates.
///
/// Every identifier is checked before it is digested, so a hostile id cannot
/// travel into an artifact, and every referenced object is digested, so a later
/// substitution of any one of them is detectable rather than invisible.
pub fn bind(scenario: &crate::model::IdentitySecurityScenario) -> Result<IdentityBinding> {
    assert_safe_identifier(&scenario.id, "scenario id")?;
    assert_safe_identifier(&scenario.objective.id, "objective id")?;
    assert_safe_identifier(&scenario.principals.set_id, "principal set id")?;

    let bindings = &scenario.principals.bindings;
    for (label, id) in [
        (
            "initiating principal id",
            Some(&bindings.initiating_principal_id),
        ),
        (
            "effective principal id",
            Some(&bindings.effective_principal_id),
        ),
        ("agent principal id", bindings.agent_principal_id.as_ref()),
        (
            "delegated subject id",
            bindings.delegated_subject_id.as_ref(),
        ),
        ("resource owner id", bindings.resource_owner_id.as_ref()),
    ] {
        if let Some(id) = id {
            assert_safe_identifier(id, label)?;
        }
    }

    let mut authority_digests = Vec::with_capacity(scenario.authorities.len());
    for authority in &scenario.authorities {
        assert_safe_identifier(&authority.id, "authority id")?;
        authority_digests.push((authority.id.clone(), authority_digest(authority)?));
    }

    let (delegation_chain_id, delegation_chain_digest) = match &scenario.delegation {
        Some(chain) => {
            assert_safe_identifier(&chain.chain_id, "delegation chain id")?;
            (
                Some(chain.chain_id.clone()),
                Some(delegation_chain_digest(chain)?),
            )
        }
        None => (None, None),
    };

    let (resource_context_digest_value, tenant_id) = match &scenario.resource {
        Some(resource) => (
            Some(resource_context_digest(resource)?),
            Some(resource.tenant_id.clone()),
        ),
        None => (None, None),
    };

    let (policy_id, policy_digest_value) = match &scenario.policy {
        Some(policy) => {
            assert_safe_identifier(&policy.policy_id, "policy id")?;
            (Some(policy.policy_id.clone()), Some(policy_digest(policy)?))
        }
        None => (None, None),
    };

    Ok(IdentityBinding {
        scenario_id: scenario.id.clone(),
        scenario_digest: digest(scenario)?,
        objective_id: scenario.objective.id.clone(),
        principal_set_id: scenario.principals.set_id.clone(),
        principal_set_digest: principal_set_digest(&scenario.principals)?,
        initiating_principal_id: bindings.initiating_principal_id.clone(),
        effective_principal_id: bindings.effective_principal_id.clone(),
        agent_principal_id: bindings.agent_principal_id.clone(),
        delegated_subject_id: bindings.delegated_subject_id.clone(),
        resource_owner_id: bindings.resource_owner_id.clone(),
        authority_digests,
        delegation_chain_id,
        delegation_chain_digest,
        resource_context_digest: resource_context_digest_value,
        tenant_id,
        policy_id,
        policy_digest: policy_digest_value,
    })
}

/// Bind a scenario to the corpus vector it references.
///
/// A scenario that names a vector must be run against that vector. A different
/// entry, or one whose content no longer matches the pinned digest, is refused
/// rather than quietly evaluated in the named vector's place.
pub fn bind_corpus(
    scenario: &crate::model::IdentitySecurityScenario,
    entry: &crate::model::IdentityCorpusEntry,
) -> Result<String> {
    let Some(reference) = scenario.vector.as_ref() else {
        return Err(IdentitySecurityError::invalid(format!(
            "scenario `{}` references no corpus vector, so it cannot be bound to `{}`",
            scenario.id, entry.id
        )));
    };
    if reference.corpus_id != entry.id {
        return Err(IdentitySecurityError::DigestMismatch(format!(
            "scenario `{}` references vector `{}` but was given `{}`",
            scenario.id, reference.corpus_id, entry.id
        )));
    }
    let actual = digest(entry)?;
    if let Some(pinned) = &reference.corpus_digest {
        if pinned != &actual {
            return Err(IdentitySecurityError::DigestMismatch(format!(
                "corpus vector `{}` does not match the digest the scenario pinned",
                entry.id
            )));
        }
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityDimension;
    use crate::authorization::tests::valid_policy;
    use crate::delegation::tests::valid_chain;
    use crate::principal::tests::valid_principal_set;
    use crate::resource::tests::same_tenant_resource;

    #[test]
    fn digests_are_stable_and_prefixed() {
        let set = valid_principal_set();
        let first = principal_set_digest(&set).expect("digest");
        let second = principal_set_digest(&set).expect("digest");
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), 71);
    }

    #[test]
    fn every_bound_object_digests_independently() {
        let principals = principal_set_digest(&valid_principal_set()).expect("digest");
        let chain = delegation_chain_digest(&valid_chain()).expect("digest");
        let resource = resource_context_digest(&same_tenant_resource()).expect("digest");
        let policy = policy_digest(&valid_policy()).expect("digest");

        let all = [&principals, &chain, &resource, &policy];
        for (index, one) in all.iter().enumerate() {
            for other in all.iter().skip(index + 1) {
                assert_ne!(one, other, "distinct objects must digest distinctly");
            }
        }
    }

    #[test]
    fn a_changed_principal_binding_changes_the_digest() {
        // The substitution this exists to catch: swapping the effective
        // principal must not leave the recorded identity looking the same.
        let set = valid_principal_set();
        let before = principal_set_digest(&set).expect("digest");

        let mut substituted = set;
        substituted.bindings.effective_principal_id = "agent-1".to_owned();
        let after = principal_set_digest(&substituted).expect("digest");

        assert_ne!(before, after);
    }

    #[test]
    fn a_widened_authority_changes_the_digest() {
        let mut authority = Authority::empty("authority-x");
        authority.actions = AuthorityDimension::only(["read"]);
        let before = authority_digest(&authority).expect("digest");

        authority.actions = AuthorityDimension::only(["read", "delete"]);
        assert_ne!(before, authority_digest(&authority).expect("digest"));
    }

    #[test]
    fn a_pinned_digest_refuses_a_substituted_object() {
        let set = valid_principal_set();
        let pinned = principal_set_digest(&set).expect("digest");
        verify_digest(&set, &pinned, "principal set").expect("matches");

        let mut substituted = set;
        substituted.bindings.effective_principal_id = "svc-index".to_owned();
        let err = verify_digest(&substituted, &pinned, "principal set")
            .expect_err("substitution must be refused");
        assert!(err.is_refusal());
        assert!(matches!(err, IdentitySecurityError::DigestMismatch(_)));
    }

    #[test]
    fn a_digest_mismatch_message_names_no_content() {
        // An error is read by operators and written to logs. It should say what
        // failed without echoing the object that failed it.
        let set = valid_principal_set();
        let err = verify_digest(&set, "sha256:0000", "principal set").expect_err("mismatch");
        let text = err.to_string();
        assert!(text.contains("principal set"));
        assert!(!text.contains("user-7"));
        assert!(!text.contains("sha256:0000"));
    }

    #[test]
    fn identifiers_that_could_escape_a_path_are_refused() {
        for hostile in ["../etc/passwd", "a/b", "a\\b", "..", ""] {
            assert!(
                assert_safe_identifier(hostile, "scenario id").is_err(),
                "must refuse `{hostile}`"
            );
        }
        assert_safe_identifier("user-7", "principal id").expect("ordinary id is fine");
        assert_safe_identifier("objective-summarize-ticket", "objective id").expect("fine");
    }

    #[test]
    fn identifiers_that_render_as_another_identifier_are_refused() {
        // A right-to-left override makes `user-7` and something else display
        // identically, which in this cycle is a substitution vector rather than
        // a cosmetic problem.
        assert!(assert_safe_identifier("user\u{202e}7", "principal id").is_err());
        assert!(assert_safe_identifier("user\u{200b}7", "principal id").is_err());
    }

    #[test]
    fn an_over_long_identifier_is_refused() {
        assert!(assert_safe_identifier(&"a".repeat(97), "principal id").is_err());
        assert_safe_identifier(&"a".repeat(96), "principal id").expect("the boundary is allowed");
    }

    #[test]
    fn the_digest_matches_the_cycle_009_helper_exactly() {
        // One canonicalization rule for the whole product, not a second
        // competing one.
        let set = valid_principal_set();
        assert_eq!(
            principal_set_digest(&set).expect("digest"),
            cycle009::digest(&set).expect("cycle 009 digest")
        );
    }
}
