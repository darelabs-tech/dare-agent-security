//! Protected Resource Metadata and Authorization Server Metadata.
//!
//! Both are **evidence about** a thing, never trust in it. That is the whole
//! point of the module. Metadata says "this resource claims these authorization
//! servers are allowed to issue for it"; it does not make them allowed, and a
//! document that arrived from somewhere unverified says nothing at all.
//!
//! Nothing here is fetched. A real implementation resolves these documents over
//! the network; this engine reads a recorded, closed, non-fetchable projection
//! of what such a resolution produced.

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::protocol::SyntheticUri;
use crate::source::TrustClass;

/// Recorded Protected Resource Metadata for one protected resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourceMetadata {
    /// The resource this document describes.
    pub resource: SyntheticUri,
    /// The authorization server issuers this resource advertises.
    #[serde(default)]
    pub authorization_servers: Vec<SyntheticUri>,
    /// Scopes the resource advertises as supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// How much this document may be believed.
    pub trust: TrustClass,
}

impl ProtectedResourceMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.authorization_servers.len() as u32 > crate::limits::HARD_MAX_AUTHORIZATION_SERVERS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "protected resource metadata advertises {} authorization servers; the hard \
                 maximum is {}",
                self.authorization_servers.len(),
                crate::limits::HARD_MAX_AUTHORIZATION_SERVERS
            )));
        }
        if self.scopes_supported.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT {
            return Err(McpAuthSecurityError::BudgetExhausted(
                "protected resource metadata advertises too many scopes".to_owned(),
            ));
        }
        for scope in &self.scopes_supported {
            crate::canonical::assert_safe_identifier(scope, "advertised scope")?;
        }
        Ok(())
    }

    /// Whether this document advertises the given authorization server.
    pub fn advertises(&self, issuer: &SyntheticUri) -> bool {
        self.authorization_servers.contains(issuer)
    }
}

/// Recorded Authorization Server Metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerMetadata {
    /// The issuer identifier this document declares for itself.
    pub issuer: SyntheticUri,
    /// The authorization endpoint identity. Never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<SyntheticUri>,
    /// The token endpoint identity. Never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<SyntheticUri>,
    /// Code challenge methods the server advertises.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<crate::source::CodeChallengeMethod>,
    /// How much this document may be believed.
    pub trust: TrustClass,
}

impl AuthorizationServerMetadata {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// The resource context a request was actually assessed against.
///
/// Kept separate from the metadata document on purpose. The metadata says what
/// a resource claims; this says which resource the request in front of us was
/// for. Comparing the two is the Protected Resource Metadata invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContext {
    /// The protected resource under test.
    pub expected_resource: SyntheticUri,
    /// The Protected Resource Metadata recorded for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProtectedResourceMetadata>,
    /// Authorization-server metadata documents recorded for the flow.
    #[serde(default)]
    pub authorization_servers: Vec<AuthorizationServerMetadata>,
    /// The authorization server the client actually selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_authorization_server: Option<SyntheticUri>,
}

impl ResourceContext {
    pub fn validate(&self) -> Result<()> {
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        if self.authorization_servers.len() as u32 > crate::limits::HARD_MAX_METADATA_DOCUMENTS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scenario declares {} authorization-server metadata documents; the hard maximum \
                 is {}",
                self.authorization_servers.len(),
                crate::limits::HARD_MAX_METADATA_DOCUMENTS
            )));
        }
        for server in &self.authorization_servers {
            server.validate()?;
        }
        Ok(())
    }

    /// The metadata document for the selected authorization server.
    pub fn selected_metadata(&self) -> Option<&AuthorizationServerMetadata> {
        let selected = self.selected_authorization_server.as_ref()?;
        self.authorization_servers
            .iter()
            .find(|server| &server.issuer == selected)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::source::CodeChallengeMethod;

    pub(crate) fn uri(value: &str) -> SyntheticUri {
        SyntheticUri::new(value).expect("synthetic identifier")
    }

    pub(crate) fn resource_context() -> ResourceContext {
        ResourceContext {
            expected_resource: uri("mcp-invoices"),
            metadata: Some(ProtectedResourceMetadata {
                resource: uri("mcp-invoices"),
                authorization_servers: vec![uri("as-primary")],
                scopes_supported: vec!["invoices.read".to_owned(), "invoices.write".to_owned()],
                trust: TrustClass::Authenticated,
            }),
            authorization_servers: vec![AuthorizationServerMetadata {
                issuer: uri("as-primary"),
                authorization_endpoint: Some(uri("as-primary.authorize")),
                token_endpoint: Some(uri("as-primary.token")),
                code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
                trust: TrustClass::Authenticated,
            }],
            selected_authorization_server: Some(uri("as-primary")),
        }
    }

    #[test]
    fn the_fixture_context_validates() {
        resource_context().validate().expect("valid");
    }

    #[test]
    fn metadata_binds_the_resource_it_describes() {
        let context = resource_context();
        let metadata = context.metadata.as_ref().expect("present");
        assert_eq!(metadata.resource, context.expected_resource);
        assert!(metadata.advertises(&uri("as-primary")));
        assert!(!metadata.advertises(&uri("as-attacker")));
    }

    #[test]
    fn the_selected_server_resolves_to_its_own_metadata() {
        let context = resource_context();
        let selected = context.selected_metadata().expect("resolved");
        assert_eq!(selected.issuer, uri("as-primary"));
    }

    #[test]
    fn selecting_a_server_nobody_recorded_resolves_to_nothing() {
        // Not an error here — the evaluator turns it into a finding. What must
        // not happen is resolving to *some* metadata document and comparing
        // against the wrong one.
        let mut context = resource_context();
        context.selected_authorization_server = Some(uri("as-attacker"));
        assert!(context.selected_metadata().is_none());
    }

    #[test]
    fn metadata_cannot_name_a_reachable_endpoint() {
        let hostile = serde_json::json!({
            "issuer": "https://as.example.com",
            "code_challenge_methods_supported": ["S256"],
            "trust": "AUTHENTICATED"
        });
        assert!(serde_json::from_value::<AuthorizationServerMetadata>(hostile).is_err());
    }

    #[test]
    fn too_many_authorization_servers_are_refused_rather_than_truncated() {
        let mut context = resource_context();
        let metadata = context.metadata.as_mut().expect("present");
        metadata.authorization_servers = (0..crate::limits::HARD_MAX_AUTHORIZATION_SERVERS + 1)
            .map(|index| uri(&format!("as-{index}")))
            .collect();
        let err = context.validate().expect_err("must be refused");
        assert!(matches!(err, McpAuthSecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn a_metadata_document_records_how_much_it_may_be_believed() {
        // The field exists so an evaluator never has to assume. A document
        // whose provenance is self-reported cannot establish an issuer.
        let mut context = resource_context();
        context.metadata.as_mut().expect("present").trust = TrustClass::SelfReported;
        assert!(!context
            .metadata
            .as_ref()
            .expect("present")
            .trust
            .may_establish_identity());
    }
}
