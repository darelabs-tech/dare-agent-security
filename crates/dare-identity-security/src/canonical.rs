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
