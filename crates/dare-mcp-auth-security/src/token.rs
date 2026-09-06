//! Synthetic token claims, resource and audience binding.
//!
//! There is no token here. There is a *projection* of one: an opaque synthetic
//! id, an issuer, a subject, an audience set, a scope set and a validity state
//! the deployment recorded. No raw bearer value, no refresh token, no
//! signature, no key.
//!
//! That is not a limitation working around a missing feature. Verifying a
//! signature requires fetching a key, which this cycle may not do, and the
//! question worth asking is a different one anyway. A token can be perfectly
//! signed by exactly the right authorization server and still authorize
//! nothing about the request it arrived on, because it was minted for another
//! resource. Signature validity is an input; **binding** is what is judged.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::protocol::SyntheticUri;
use crate::source::TokenValidityState;

/// A bounded projection of one access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenClaims {
    /// A synthetic identity for this token. Never the token itself.
    pub token_id: String,
    /// The issuer the token claims.
    pub issuer: SyntheticUri,
    /// The subject the token claims, where one is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The audiences the token names.
    #[serde(default)]
    pub audience: Vec<SyntheticUri>,
    /// The resources the token names, where the deployment records them
    /// separately from audience.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<SyntheticUri>,
    /// The scopes the token carries.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// What the deployment's own verification concluded.
    pub validity: TokenValidityState,
}

impl TokenClaims {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.token_id, "token id")?;
        if let Some(subject) = &self.subject {
            crate::canonical::assert_safe_identifier(subject, "token subject")?;
        }
        if self.audience.len() as u32 > crate::limits::HARD_MAX_AUDIENCES_PER_TOKEN {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "token `{}` names {} audiences; the hard maximum is {}",
                self.token_id,
                self.audience.len(),
                crate::limits::HARD_MAX_AUDIENCES_PER_TOKEN
            )));
        }
        if self.scopes.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "token `{}` carries too many scopes",
                self.token_id
            )));
        }
        let field_count = self.audience.len() + self.resources.len() + self.scopes.len();
        if field_count as u32 > crate::limits::HARD_MAX_CLAIM_FIELDS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "token `{}` carries {field_count} claim fields; the hard maximum is {}",
                self.token_id,
                crate::limits::HARD_MAX_CLAIM_FIELDS
            )));
        }
        for scope in &self.scopes {
            crate::canonical::assert_safe_identifier(scope, "token scope")?;
        }
        Ok(())
    }

    /// Whether this token names the given resource, on either claim.
    ///
    /// Audience and resource are checked together because deployments record
    /// the same fact in either field, and a token that names the resource in
    /// one but not the other is bound to it.
    pub fn names_resource(&self, resource: &SyntheticUri) -> bool {
        self.audience.contains(resource) || self.resources.contains(resource)
    }

    /// Whether validity evidence exists at all.
    pub fn has_validity_evidence(&self) -> bool {
        self.validity.is_positive_evidence()
    }

    pub fn scope_set(&self) -> BTreeSet<&str> {
        self.scopes.iter().map(String::as_str).collect()
    }
}

/// The token evidence a scenario declares, and what it is expected to be for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenContext {
    /// The token presented on the assessed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<TokenClaims>,
    /// The resource the request was actually for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<SyntheticUri>,
    /// Whether the deployment accepted the token for this request.
    #[serde(default)]
    pub accepted_by_resource: bool,
}

impl TokenContext {
    pub fn validate(&self) -> Result<()> {
        if let Some(token) = &self.presented {
            token.validate()?;
        }
        Ok(())
    }

    /// Whether the presented token is bound to the resource under test.
    ///
    /// `None` when there is nothing to compare. Notably this is **not**
    /// influenced by whether the token is valid: a rejected token that names
    /// the right resource is still bound to it, and an engine that folded the
    /// two together would report one finding where there are two independent
    /// questions.
    pub fn resource_binding_holds(&self) -> Option<bool> {
        let token = self.presented.as_ref()?;
        let target = self.target_resource.as_ref()?;
        Some(token.names_resource(target))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::tests::uri;

    pub(crate) fn token_context() -> TokenContext {
        TokenContext {
            presented: Some(TokenClaims {
                token_id: "tok-1".to_owned(),
                issuer: uri("as-primary"),
                subject: Some("user-7".to_owned()),
                audience: vec![uri("mcp-invoices")],
                resources: vec![],
                scopes: vec!["invoices.read".to_owned()],
                validity: TokenValidityState::Verified,
            }),
            target_resource: Some(uri("mcp-invoices")),
            accepted_by_resource: true,
        }
    }

    #[test]
    fn a_token_for_the_right_resource_binds() {
        let context = token_context();
        context.validate().expect("valid");
        assert_eq!(context.resource_binding_holds(), Some(true));
        assert!(context
            .presented
            .as_ref()
            .expect("present")
            .has_validity_evidence());
    }

    #[test]
    fn a_token_minted_for_another_resource_does_not_bind() {
        // The core of the cycle. This token is verified, correctly issued, and
        // authorizes nothing here.
        let mut context = token_context();
        context.presented.as_mut().expect("present").audience = vec![uri("mcp-payroll")];
        assert_eq!(context.resource_binding_holds(), Some(false));
        assert!(context
            .presented
            .as_ref()
            .expect("present")
            .has_validity_evidence());
    }

    #[test]
    fn the_resource_claim_binds_as_well_as_the_audience_claim() {
        // Deployments record the same fact in either field. Reading only one
        // would report a finding against a token that is correctly bound.
        let mut context = token_context();
        let token = context.presented.as_mut().expect("present");
        token.audience = vec![];
        token.resources = vec![uri("mcp-invoices")];
        assert_eq!(context.resource_binding_holds(), Some(true));
    }

    #[test]
    fn a_token_with_no_verification_evidence_is_not_evidence_either_way() {
        let mut context = token_context();
        context.presented.as_mut().expect("present").validity = TokenValidityState::Unknown;
        assert!(!context
            .presented
            .as_ref()
            .expect("present")
            .has_validity_evidence());
        // Binding is still answerable — the two questions are independent.
        assert_eq!(context.resource_binding_holds(), Some(true));
    }

    #[test]
    fn validity_and_binding_stay_independent_questions() {
        // A rejected token that names the right resource is still bound to it.
        // Folding the two together would report one finding where there are
        // two, and would hide whichever one the fold discarded.
        let mut context = token_context();
        context.presented.as_mut().expect("present").validity = TokenValidityState::Rejected;
        assert_eq!(context.resource_binding_holds(), Some(true));
        assert!(context
            .presented
            .as_ref()
            .expect("present")
            .has_validity_evidence());
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_raw_token() {
        for hostile in [
            serde_json::json!({
                "token_id": "tok-1", "issuer": "as-primary", "validity": "VERIFIED",
                "access_token": "eyJhbGciOiJIUzI1NiJ9.e30.sig"
            }),
            serde_json::json!({
                "token_id": "tok-1", "issuer": "as-primary", "validity": "VERIFIED",
                "refresh_token": "rt_live_abc"
            }),
            serde_json::json!({
                "token_id": "tok-1", "issuer": "as-primary", "validity": "VERIFIED",
                "authorization": "Bearer abcdefghijklmnop"
            }),
        ] {
            assert!(serde_json::from_value::<TokenClaims>(hostile).is_err());
        }
    }

    #[test]
    fn too_many_audiences_are_refused_rather_than_truncated() {
        let mut context = token_context();
        context.presented.as_mut().expect("present").audience = (0
            ..crate::limits::HARD_MAX_AUDIENCES_PER_TOKEN + 1)
            .map(|index| uri(&format!("aud-{index}")))
            .collect();
        let err = context.validate().expect_err("must be refused");
        assert!(matches!(err, McpAuthSecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn an_absent_token_is_nothing_to_compare() {
        let mut context = token_context();
        context.presented = None;
        assert_eq!(context.resource_binding_holds(), None);
    }
}
