//! Client registration metadata trust.
//!
//! The question is never "does this document say the client is registered". Any
//! document can say that. The question is where the document came from, and
//! whether that provenance justifies believing what it says about a client
//! identifier and its redirect URIs.
//!
//! Cycle 018 performs no registration. It reads a recorded projection of one
//! and judges whether the deployment relied on it further than its provenance
//! supports.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::protocol::SyntheticUri;
use crate::source::RegistrationTrustClass;

/// Recorded client registration metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationContext {
    /// The client identifier the metadata asserts.
    pub client_id: String,
    /// Where the metadata came from.
    pub trust_class: RegistrationTrustClass,
    /// Redirect URIs the metadata asserts.
    #[serde(default)]
    pub redirect_uris: Vec<SyntheticUri>,
    /// Whether the deployment relied on this metadata to accept the client.
    ///
    /// The difference between recording an untrusted document and being fooled
    /// by one. A deployment that read untrusted metadata and refused to act on
    /// it did the right thing.
    #[serde(default)]
    pub relied_upon: bool,
}

impl RegistrationContext {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.client_id, "client id")?;
        if self.redirect_uris.len() as u32 > crate::limits::HARD_MAX_REGISTRATION_REDIRECT_URIS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "registration for `{}` declares {} redirect URIs; the hard maximum is {}",
                self.client_id,
                self.redirect_uris.len(),
                crate::limits::HARD_MAX_REGISTRATION_REDIRECT_URIS
            )));
        }
        Ok(())
    }

    /// Whether the deployment's reliance on this metadata is justified by its
    /// provenance.
    ///
    /// `None` when the metadata was recorded but not relied upon — nothing was
    /// trusted, so there is nothing to over-trust.
    pub fn trust_holds(&self) -> Option<bool> {
        if !self.relied_upon {
            return None;
        }
        Some(self.trust_class.is_trusted_provenance())
    }

    /// Whether the legacy dynamic-registration path was used.
    ///
    /// Not a violation. Current MCP guidance treats it as a compatibility
    /// route, and reporting it as a finding would be wrong about the
    /// specification. It is surfaced so an operator can see which route a
    /// deployment took.
    pub fn used_legacy_registration(&self) -> bool {
        matches!(
            self.trust_class,
            RegistrationTrustClass::DynamicRegistrationLegacy
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::tests::uri;

    pub(crate) fn registration_context() -> RegistrationContext {
        RegistrationContext {
            client_id: "client-public-01".to_owned(),
            trust_class: RegistrationTrustClass::PreRegistered,
            redirect_uris: vec![uri("client-callback")],
            relied_upon: true,
        }
    }

    #[test]
    fn pre_registered_metadata_may_be_relied_upon() {
        let context = registration_context();
        context.validate().expect("valid");
        assert_eq!(context.trust_holds(), Some(true));
        assert!(!context.used_legacy_registration());
    }

    #[test]
    fn a_client_metadata_document_may_be_relied_upon() {
        let mut context = registration_context();
        context.trust_class = RegistrationTrustClass::ClientMetadataDocument;
        assert_eq!(context.trust_holds(), Some(true));
    }

    #[test]
    fn untrusted_metadata_cannot_manufacture_a_client() {
        // The finding: a redirect URI accepted because an untrusted document
        // asserted it was registered.
        let mut context = registration_context();
        context.trust_class = RegistrationTrustClass::Untrusted;
        assert_eq!(context.trust_holds(), Some(false));
    }

    #[test]
    fn recording_untrusted_metadata_without_relying_on_it_is_not_a_finding() {
        // A deployment that read the document and refused to act on it did the
        // right thing, and reporting it would punish the correct behaviour.
        let mut context = registration_context();
        context.trust_class = RegistrationTrustClass::Untrusted;
        context.relied_upon = false;
        assert_eq!(context.trust_holds(), None);
    }

    #[test]
    fn the_legacy_dynamic_path_is_surfaced_but_not_a_violation() {
        // Current MCP guidance treats dynamic registration as a compatibility
        // route. Reporting it as a finding would be a finding against a
        // deployment doing something still permitted.
        let mut context = registration_context();
        context.trust_class = RegistrationTrustClass::DynamicRegistrationLegacy;
        assert_eq!(context.trust_holds(), Some(true));
        assert!(context.used_legacy_registration());
    }

    #[test]
    fn registration_cannot_name_a_reachable_redirect() {
        let hostile = serde_json::json!({
            "client_id": "client-public-01",
            "trust_class": "PRE_REGISTERED",
            "redirect_uris": ["https://client.example/cb"]
        });
        assert!(serde_json::from_value::<RegistrationContext>(hostile).is_err());
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_client_secret() {
        let hostile = serde_json::json!({
            "client_id": "client-public-01",
            "trust_class": "PRE_REGISTERED",
            "client_secret": "cs_live_abcdef"
        });
        assert!(serde_json::from_value::<RegistrationContext>(hostile).is_err());
    }

    #[test]
    fn an_unknown_trust_class_fails_closed() {
        // The permissive value is the natural default, which is why there is
        // none.
        let hostile = serde_json::json!({
            "client_id": "client-public-01",
            "trust_class": "PROBABLY_REGISTERED"
        });
        assert!(serde_json::from_value::<RegistrationContext>(hostile).is_err());
    }
}
