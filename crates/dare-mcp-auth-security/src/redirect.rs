//! Redirect URI integrity.
//!
//! A redirect URI is where an authorization response is delivered, which makes
//! it a place a code can be sent. Three values matter and they are three
//! different things: what the client **registered**, what it **requested**, and
//! where the response was **delivered**.
//!
//! Checking only two of them misses real attacks. Comparing requested against
//! delivered catches a response diverted in flight; comparing registered
//! against requested catches a client asking for a destination it was never
//! allowed to use. A flow can pass one and fail the other.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::protocol::SyntheticUri;

/// Recorded redirect evidence for one authorization flow.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectContext {
    /// Redirect URIs the client registration declares.
    #[serde(default)]
    pub registered: Vec<SyntheticUri>,
    /// The redirect URI the authorization request asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<SyntheticUri>,
    /// Where the authorization response was actually delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<SyntheticUri>,
}

impl RedirectContext {
    pub fn validate(&self) -> Result<()> {
        if self.registered.len() as u32 > crate::limits::HARD_MAX_REGISTRATION_REDIRECT_URIS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "registration declares {} redirect URIs; the hard maximum is {}",
                self.registered.len(),
                crate::limits::HARD_MAX_REGISTRATION_REDIRECT_URIS
            )));
        }
        Ok(())
    }

    /// Whether the requested redirect was one the client had registered.
    ///
    /// `None` when there is no registration to check against, which is a
    /// coverage gap rather than permission.
    pub fn requested_is_registered(&self) -> Option<bool> {
        let requested = self.requested.as_ref()?;
        if self.registered.is_empty() {
            return None;
        }
        Some(self.registered.contains(requested))
    }

    /// Whether the response arrived where the request asked it to.
    pub fn delivery_matches_request(&self) -> Option<bool> {
        let requested = self.requested.as_ref()?;
        let delivered = self.delivered.as_ref()?;
        Some(requested == delivered)
    }

    /// Whether every redirect check that could be made held.
    ///
    /// Deliberately not a single boolean over all three: a check that could not
    /// be made is absent from the result rather than counted as passing.
    pub fn integrity_holds(&self) -> Option<bool> {
        match (
            self.requested_is_registered(),
            self.delivery_matches_request(),
        ) {
            (None, None) => None,
            (left, right) => Some(left.unwrap_or(true) && right.unwrap_or(true)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::tests::uri;

    pub(crate) fn redirect_context() -> RedirectContext {
        RedirectContext {
            registered: vec![uri("client-callback"), uri("client-callback-alt")],
            requested: Some(uri("client-callback")),
            delivered: Some(uri("client-callback")),
        }
    }

    #[test]
    fn a_registered_and_undiverted_redirect_holds() {
        let context = redirect_context();
        context.validate().expect("valid");
        assert_eq!(context.requested_is_registered(), Some(true));
        assert_eq!(context.delivery_matches_request(), Some(true));
        assert_eq!(context.integrity_holds(), Some(true));
    }

    #[test]
    fn a_response_diverted_in_flight_is_caught() {
        let mut context = redirect_context();
        context.delivered = Some(uri("attacker-callback"));
        assert_eq!(context.delivery_matches_request(), Some(false));
        assert_eq!(context.integrity_holds(), Some(false));
    }

    #[test]
    fn a_client_requesting_an_unregistered_destination_is_caught() {
        // The other half. Delivery matches the request perfectly here; the
        // request itself was for somewhere the client never registered.
        let mut context = redirect_context();
        context.requested = Some(uri("attacker-callback"));
        context.delivered = Some(uri("attacker-callback"));
        assert_eq!(context.delivery_matches_request(), Some(true));
        assert_eq!(context.requested_is_registered(), Some(false));
        assert_eq!(context.integrity_holds(), Some(false));
    }

    #[test]
    fn no_registration_to_check_against_is_a_gap_not_permission() {
        let mut context = redirect_context();
        context.registered = vec![];
        assert_eq!(context.requested_is_registered(), None);
        // Delivery is still checkable, so integrity still answers.
        assert_eq!(context.integrity_holds(), Some(true));
    }

    #[test]
    fn nothing_observed_at_all_answers_nothing() {
        let context = RedirectContext::default();
        assert_eq!(context.integrity_holds(), None);
    }

    #[test]
    fn a_redirect_can_never_be_a_reachable_target() {
        let hostile = serde_json::json!({
            "registered": ["https://client.example/callback"],
            "requested": "https://client.example/callback"
        });
        assert!(serde_json::from_value::<RedirectContext>(hostile).is_err());
    }

    #[test]
    fn too_many_registered_redirects_are_refused() {
        let mut context = redirect_context();
        context.registered = (0..crate::limits::HARD_MAX_REGISTRATION_REDIRECT_URIS + 1)
            .map(|index| uri(&format!("cb-{index}")))
            .collect();
        assert!(matches!(
            context.validate().expect_err("refused"),
            McpAuthSecurityError::BudgetExhausted(_)
        ));
    }
}
