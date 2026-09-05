//! Provider-neutral authorization policy and typed decision records.
//!
//! A policy here is declarative set data, exactly like an authority: no rule
//! expression, no condition string, no callback. Nothing in this module calls a
//! policy decision point, issues an AuthZEN request or parses a token. The
//! Subject-Action-Resource-Context shape informed the modelling; resemblance to
//! that shape is not conformance with it, and the engine stays offline.
//!
//! A decision carries the digest of the operation it was made *about*. That
//! single field is what makes a permit bindable: an authorization is valid only
//! for the authorization-relevant semantics it actually covered, so a later
//! operation whose projection differs cannot inherit it.

use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityDimension, LogicalTime};
use crate::error::{IdentitySecurityError, Result};

/// The effect of an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionEffect {
    Permit,
    Deny,
}

impl DecisionEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "PERMIT",
            Self::Deny => "DENY",
        }
    }

    pub fn all() -> [Self; 2] {
        [Self::Permit, Self::Deny]
    }
}

/// A declarative authorization policy.
///
/// Every dimension follows the same fail-closed rule as an authority: omitted
/// means nothing is permitted, and `ANY` has to be written explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub subjects: AuthorityDimension,
    #[serde(default)]
    pub actions: AuthorityDimension,
    #[serde(default)]
    pub resource_types: AuthorityDimension,
    #[serde(default)]
    pub tenants: AuthorityDimension,
    #[serde(default)]
    pub purposes: AuthorityDimension,
    /// Operation keys the policy declares denied, as `<resource_type>.<action>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_operation_keys: Vec<String>,
}

/// One authorization decision about one canonical operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub effect: DecisionEffect,
    pub subject_id: String,
    /// Digest of the policy that produced this decision.
    pub policy_digest: String,
    /// Digest of the authorization-relevant projection this decision covered.
    ///
    /// The load-bearing field. A decision without it would be a permit for
    /// nothing in particular, which is how a stale permit gets reused.
    pub bound_operation_digest: String,
    /// Synthetic logical tick the decision was issued at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<LogicalTime>,
}

impl AuthorizationPolicy {
    /// The canonical key for an operation, as the policy names denials.
    pub fn operation_key(resource_type: &str, action: &str) -> String {
        format!("{resource_type}.{action}")
    }

    /// Whether the policy explicitly declares this operation denied.
    ///
    /// Exact membership over whole keys. A substring match would let
    /// `document.read` be denied by a rule about `document.read_all`.
    pub fn declares_denied(&self, resource_type: &str, action: &str) -> bool {
        let key = Self::operation_key(resource_type, action);
        self.denied_operation_keys.contains(&key)
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(IdentitySecurityError::refusal(format!(
                "authorization policy declares unsupported schema_version `{}`",
                self.schema_version
            )));
        }
        for key in &self.denied_operation_keys {
            if key.split('.').count() != 2 || key.starts_with('.') || key.ends_with('.') {
                return Err(IdentitySecurityError::invalid(format!(
                    "denied operation key `{key}` is not of the form <resource_type>.<action>"
                )));
            }
        }
        Ok(())
    }
}

impl AuthorizationDecision {
    /// Whether this decision covers a given operation projection digest.
    ///
    /// Digest equality, never "close enough". If the projection changed, the
    /// decision was about a different operation and must not be reused.
    pub fn covers(&self, operation_digest: &str) -> bool {
        self.bound_operation_digest == operation_digest
    }

    pub fn is_permit(&self) -> bool {
        self.effect == DecisionEffect::Permit
    }

    pub fn is_deny(&self) -> bool {
        self.effect == DecisionEffect::Deny
    }

    /// Structural validation of the fields a binding depends on.
    pub fn validate(&self) -> Result<()> {
        if self.decision_id.trim().is_empty() {
            return Err(IdentitySecurityError::invalid("empty decision id"));
        }
        if !self.bound_operation_digest.starts_with("sha256:") {
            // A decision that does not name what it decided about cannot bind
            // anything, and treating it as covering the current operation would
            // be exactly the stale-permit reuse this cycle detects.
            return Err(IdentitySecurityError::invalid(format!(
                "decision `{}` carries no sha256 bound-operation digest",
                self.decision_id
            )));
        }
        if !self.policy_digest.starts_with("sha256:") {
            return Err(IdentitySecurityError::invalid(format!(
                "decision `{}` carries no sha256 policy digest",
                self.decision_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn valid_policy_value() -> serde_json::Value {
        json!({
            "schema_version": "1",
            "policy_id": "policy-support-desk",
            "objective_id": "objective-summarize-ticket",
            "title": "read support documents in tenant A for the summarize purpose",
            "subjects": {"constraint": "ONLY", "values": ["user-7"]},
            "actions": {"constraint": "ONLY", "values": ["read", "list"]},
            "resource_types": {"constraint": "ONLY", "values": ["document"]},
            "tenants": {"constraint": "ONLY", "values": ["tenant-a"]},
            "purposes": {"constraint": "ONLY", "values": ["purpose-summarize"]},
            "denied_operation_keys": ["document.delete", "document.share"]
        })
    }

    pub(crate) fn valid_policy() -> AuthorizationPolicy {
        serde_json::from_value(valid_policy_value()).expect("policy decodes")
    }

    fn decision(effect: DecisionEffect, digest: &str) -> AuthorizationDecision {
        AuthorizationDecision {
            decision_id: "decision-1".to_owned(),
            effect,
            subject_id: "user-7".to_owned(),
            policy_digest: format!("sha256:{}", "a".repeat(64)),
            bound_operation_digest: digest.to_owned(),
            issued_at: Some(100),
        }
    }

    #[test]
    fn a_representative_policy_validates() {
        let policy = valid_policy();
        policy.validate().expect("valid");
        assert_eq!(policy.policy_id, "policy-support-desk");
        assert!(policy.actions.permits("read"));
        assert!(!policy.actions.permits("delete"));
    }

    #[test]
    fn a_denied_operation_key_is_matched_whole_never_by_substring() {
        // `document.read` must not be denied by a rule about `document.read_all`.
        let mut policy = valid_policy();
        policy.denied_operation_keys = vec!["document.read_all".to_owned()];

        assert!(policy.declares_denied("document", "read_all"));
        assert!(
            !policy.declares_denied("document", "read"),
            "a prefix of a denied key is not itself denied"
        );
    }

    #[test]
    fn declared_denials_are_exact_on_both_halves() {
        let policy = valid_policy();
        assert!(policy.declares_denied("document", "delete"));
        assert!(!policy.declares_denied("ticket", "delete"));
        assert!(!policy.declares_denied("document", "deleted"));
    }

    #[test]
    fn a_malformed_denied_key_is_refused() {
        for key in ["document", "document.", ".delete", "a.b.c", ""] {
            let mut policy = valid_policy();
            policy.denied_operation_keys = vec![key.to_owned()];
            assert!(policy.validate().is_err(), "must refuse `{key}`");
        }
    }

    #[test]
    fn an_omitted_policy_dimension_permits_nothing() {
        let policy: AuthorizationPolicy = serde_json::from_value(json!({
            "schema_version": "1",
            "policy_id": "policy-empty",
            "objective_id": "objective-none"
        }))
        .expect("decodes");
        assert!(policy.subjects.is_empty());
        assert!(policy.actions.is_empty());
        assert!(!policy.actions.permits("read"));
    }

    #[test]
    fn a_decision_binds_to_exactly_one_operation_projection() {
        let digest = format!("sha256:{}", "b".repeat(64));
        let permit = decision(DecisionEffect::Permit, &digest);
        permit.validate().expect("valid");

        assert!(permit.covers(&digest));
        assert!(
            !permit.covers(&format!("sha256:{}", "c".repeat(64))),
            "a different projection is a different operation"
        );
    }

    #[test]
    fn a_decision_without_a_bound_operation_digest_is_refused() {
        // Such a decision would be a permit for nothing in particular, and
        // treating it as covering the current operation is stale-permit reuse.
        let mut broken = decision(DecisionEffect::Permit, "");
        assert!(broken.validate().is_err());

        broken.bound_operation_digest = "not-a-digest".to_owned();
        assert!(broken.validate().is_err());
    }

    #[test]
    fn permit_and_deny_stay_distinct() {
        let digest = format!("sha256:{}", "d".repeat(64));
        let permit = decision(DecisionEffect::Permit, &digest);
        let deny = decision(DecisionEffect::Deny, &digest);

        assert!(permit.is_permit() && !permit.is_deny());
        assert!(deny.is_deny() && !deny.is_permit());
        assert_eq!(
            serde_json::to_value(DecisionEffect::Deny).expect("serializes"),
            json!("DENY")
        );
    }

    #[test]
    fn an_unknown_decision_effect_fails_closed() {
        // No default: an unrecognized effect must never decode as PERMIT.
        assert!(serde_json::from_str::<DecisionEffect>("\"ALLOW\"").is_err());
        assert!(serde_json::from_str::<DecisionEffect>("\"permit\"").is_err());
        assert!(serde_json::from_str::<DecisionEffect>("\"INDETERMINATE\"").is_err());
    }

    #[test]
    fn a_policy_carries_no_rule_expression_or_endpoint() {
        let encoded = serde_json::to_string(&valid_policy()).expect("serializes");
        for forbidden in [
            "condition",
            "expression",
            "rego",
            "cel",
            "pdp_url",
            "authzen_url",
            "endpoint",
        ] {
            assert!(!encoded.contains(forbidden), "policy declares {forbidden}");
        }
    }

    #[test]
    fn unknown_policy_and_decision_fields_fail_closed() {
        let mut value = valid_policy_value();
        value["pdp_url"] = json!("https://example.invalid/authzen");
        assert!(serde_json::from_value::<AuthorizationPolicy>(value).is_err());

        let hostile = json!({
            "decision_id": "d", "effect": "PERMIT", "subject_id": "s",
            "policy_digest": "sha256:x", "bound_operation_digest": "sha256:y",
            "access_token": "eyJhbGciOi"
        });
        assert!(serde_json::from_value::<AuthorizationDecision>(hostile).is_err());
    }

    #[test]
    fn an_unsupported_policy_version_is_refused() {
        let mut policy = valid_policy();
        policy.schema_version = "2".to_owned();
        assert!(policy.validate().expect_err("refused").is_refusal());
    }
}
