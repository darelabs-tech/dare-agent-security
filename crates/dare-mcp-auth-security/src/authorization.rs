//! Authorization request and response correlation.
//!
//! The security question is not whether a response is well formed. It is
//! whether *this* response belongs to *that* request, and whether it came from
//! the authorization server the client selected for this resource.
//!
//! Issuer mix-up is the attack this module exists to make visible: a response
//! that is internally perfect, correctly signed, and issued by a server the
//! client never selected for the resource in front of it.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::protocol::SyntheticUri;

/// What the client asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequestContext {
    pub request_id: String,
    /// The authorization server the client selected.
    pub selected_issuer: SyntheticUri,
    /// The resource indicator the client requested a token for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_indicator: Option<SyntheticUri>,
    /// Scopes requested.
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    /// The correlation value the client generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The redirect URI the client asked the response to arrive at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<SyntheticUri>,
}

impl AuthorizationRequestContext {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.request_id, "authorization request id")?;
        if self.requested_scopes.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT {
            return Err(McpAuthSecurityError::BudgetExhausted(
                "authorization request declares too many scopes".to_owned(),
            ));
        }
        for scope in &self.requested_scopes {
            crate::canonical::assert_safe_identifier(scope, "requested scope")?;
        }
        if let Some(state) = &self.state {
            crate::canonical::assert_safe_identifier(state, "authorization state")?;
        }
        Ok(())
    }
}

/// What came back.
///
/// There is no authorization *code* field, deliberately. A code is a credential:
/// recording one would be storing a bearer secret, and this engine can answer
/// every question it needs to from the correlation values alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponseContext {
    /// The request this response claims to answer.
    pub request_id: String,
    /// The issuer the response identifies itself with.
    ///
    /// Optional because a response may omit it, and an absent issuer is a
    /// different situation from a wrong one: the first cannot be checked, the
    /// second is a finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_issuer: Option<SyntheticUri>,
    /// The correlation value the response carried back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The redirect URI the response was delivered to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<SyntheticUri>,
    /// Whether the client accepted this response and continued the flow.
    ///
    /// The difference between observing a mix-up and being fooled by one. A
    /// client that received a response from the wrong issuer and rejected it
    /// behaved correctly.
    #[serde(default)]
    pub accepted_by_client: bool,
}

impl AuthorizationResponseContext {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.request_id, "authorization response id")?;
        if let Some(state) = &self.state {
            crate::canonical::assert_safe_identifier(state, "authorization state")?;
        }
        Ok(())
    }
}

/// The full authorization exchange a scenario declares.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AuthorizationRequestContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AuthorizationResponseContext>,
}

impl AuthorizationContext {
    pub fn validate(&self) -> Result<()> {
        if let Some(request) = &self.request {
            request.validate()?;
        }
        if let Some(response) = &self.response {
            response.validate()?;
        }
        if let (Some(request), Some(response)) = (&self.request, &self.response) {
            if request.request_id != response.request_id {
                return Err(McpAuthSecurityError::invalid(
                    "authorization response answers a request the scenario did not declare",
                ));
            }
        }
        Ok(())
    }

    /// Whether the response issuer matches the selected authorization server.
    ///
    /// `None` when there is nothing to compare — no request, no response, or a
    /// response that carried no issuer. The evaluator turns that into missing
    /// coverage rather than agreement.
    pub fn issuer_correlation_holds(&self) -> Option<bool> {
        let request = self.request.as_ref()?;
        let response = self.response.as_ref()?;
        let issuer = response.response_issuer.as_ref()?;
        Some(issuer == &request.selected_issuer)
    }

    /// Whether the state value survived the round trip.
    pub fn state_correlation_holds(&self) -> Option<bool> {
        let request = self.request.as_ref()?;
        let response = self.response.as_ref()?;
        match (&request.state, &response.state) {
            (None, None) => None,
            (Some(sent), Some(returned)) => Some(sent == returned),
            // A state was sent and nothing came back, or one appeared that was
            // never sent. Both break the correlation.
            _ => Some(false),
        }
    }

    /// Whether the response arrived at the redirect URI the request named.
    pub fn redirect_correlation_holds(&self) -> Option<bool> {
        let request = self.request.as_ref()?;
        let response = self.response.as_ref()?;
        match (&request.redirect_uri, &response.redirect_uri) {
            (None, None) => None,
            (Some(requested), Some(delivered)) => Some(requested == delivered),
            _ => Some(false),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::tests::uri;

    pub(crate) fn authorization_context() -> AuthorizationContext {
        AuthorizationContext {
            request: Some(AuthorizationRequestContext {
                request_id: "auth-1".to_owned(),
                selected_issuer: uri("as-primary"),
                resource_indicator: Some(uri("mcp-invoices")),
                requested_scopes: vec!["invoices.read".to_owned()],
                state: Some("state-abc".to_owned()),
                redirect_uri: Some(uri("client-callback")),
            }),
            response: Some(AuthorizationResponseContext {
                request_id: "auth-1".to_owned(),
                response_issuer: Some(uri("as-primary")),
                state: Some("state-abc".to_owned()),
                redirect_uri: Some(uri("client-callback")),
                accepted_by_client: true,
            }),
        }
    }

    #[test]
    fn a_well_correlated_exchange_holds_on_every_axis() {
        let context = authorization_context();
        context.validate().expect("valid");
        assert_eq!(context.issuer_correlation_holds(), Some(true));
        assert_eq!(context.state_correlation_holds(), Some(true));
        assert_eq!(context.redirect_correlation_holds(), Some(true));
    }

    #[test]
    fn a_response_from_another_issuer_breaks_correlation() {
        // The mix-up. Everything else about this response is perfect.
        let mut context = authorization_context();
        context.response.as_mut().expect("present").response_issuer = Some(uri("as-attacker"));
        assert_eq!(context.issuer_correlation_holds(), Some(false));
        assert_eq!(context.state_correlation_holds(), Some(true));
    }

    #[test]
    fn a_substituted_state_breaks_correlation() {
        let mut context = authorization_context();
        context.response.as_mut().expect("present").state = Some("state-other".to_owned());
        assert_eq!(context.state_correlation_holds(), Some(false));
    }

    #[test]
    fn a_state_that_vanishes_or_appears_breaks_correlation() {
        // Both directions. A response that drops the state cannot be correlated
        // to its request, and one that invents a state was correlated to
        // something else.
        let mut dropped = authorization_context();
        dropped.response.as_mut().expect("present").state = None;
        assert_eq!(dropped.state_correlation_holds(), Some(false));

        let mut invented = authorization_context();
        invented.request.as_mut().expect("present").state = None;
        assert_eq!(invented.state_correlation_holds(), Some(false));
    }

    #[test]
    fn a_redirect_substitution_breaks_correlation() {
        let mut context = authorization_context();
        context.response.as_mut().expect("present").redirect_uri = Some(uri("attacker-callback"));
        assert_eq!(context.redirect_correlation_holds(), Some(false));
    }

    #[test]
    fn an_absent_issuer_is_nothing_to_compare_rather_than_agreement() {
        let mut context = authorization_context();
        context.response.as_mut().expect("present").response_issuer = None;
        assert_eq!(context.issuer_correlation_holds(), None);
    }

    #[test]
    fn a_response_answering_an_undeclared_request_is_refused() {
        let mut context = authorization_context();
        context.response.as_mut().expect("present").request_id = "auth-other".to_owned();
        assert!(context.validate().is_err());
    }

    #[test]
    fn the_model_has_no_field_for_an_authorization_code() {
        // A code is a bearer credential. The engine answers every question it
        // needs from correlation values, so there is nowhere to put one.
        let with_code = serde_json::json!({
            "request_id": "auth-1",
            "response_issuer": "as-primary",
            "authorization_code": "ac_live_abcdef",
            "accepted_by_client": true
        });
        assert!(serde_json::from_value::<AuthorizationResponseContext>(with_code).is_err());
    }

    #[test]
    fn whether_the_client_accepted_the_response_is_recorded_separately() {
        // Observing a mix-up and being fooled by one are different outcomes.
        let mut context = authorization_context();
        let response = context.response.as_mut().expect("present");
        response.response_issuer = Some(uri("as-attacker"));
        response.accepted_by_client = false;
        assert_eq!(context.issuer_correlation_holds(), Some(false));
        assert!(
            !context
                .response
                .as_ref()
                .expect("present")
                .accepted_by_client
        );
    }
}
