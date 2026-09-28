//! Observed authorization metadata (Cycle 022, Review BQ-1).
//!
//! Cycle 018 reads protected-resource and authorization-server metadata only
//! from the scenario, and refuses URL-shaped values there so nothing in a
//! scenario can ever be fetched. A remote run (Cycle 022) observes real
//! metadata over its own gateway; this module turns that observation into a
//! scenario this engine can decide, without giving the engine any way to
//! reach a network.
//!
//! Every URL becomes an opaque identifier, `u-` and 16 hex characters of its
//! SHA-256. Equal URLs give equal identifiers, so every comparison the engine
//! makes (resource against expected resource, issuer against advertised
//! servers) sees the same structure it would see on the URLs themselves. The
//! derived scenario keeps only the observed metadata: every other context is
//! cleared, because the base scenario's tokens, flows and scopes are
//! synthetic and must never be decided as though a live target produced them.
//!
//! Observed metadata is recorded as `AUTHENTICATED` (Product Owner decision,
//! Cycle 022): each document arrived over verified TLS from the exact origin
//! the target's owner authorized, so its provenance is authenticated. Its
//! content is still what the server says about itself; the remote validator
//! reports that separately, and never presents this trust class as more than
//! origin authentication. With `SELF_REPORTED` every coherent server would
//! fail the resource and issuer invariants, which could then never tell a
//! secure server from a vulnerable one.

use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::metadata::{AuthorizationServerMetadata, ProtectedResourceMetadata, ResourceContext};
use crate::model::McpAuthScenario;
use crate::protocol::SyntheticUri;
use crate::source::{CodeChallengeMethod, TrustClass};

/// Authorization-server metadata as observed (RFC 8414 fields, as strings).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedAuthServer {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

/// Protected-resource metadata as observed (RFC 9728 fields, as strings).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedResourceContext {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub as_metadata: Vec<ObservedAuthServer>,
}

/// The opaque identifier of a URL: `u-` and 16 hex characters of SHA-256.
pub fn opaque_uri(url: &str) -> Result<SyntheticUri> {
    let hex = format!("{:x}", Sha256::digest(url.as_bytes()));
    SyntheticUri::new(format!("u-{}", &hex[..16]))
}

fn method(value: &str) -> Option<CodeChallengeMethod> {
    match value {
        "S256" => Some(CodeChallengeMethod::S256),
        "plain" => Some(CodeChallengeMethod::Plain),
        _ => None,
    }
}

/// `base` with its protected-resource context replaced by `observed`, every
/// other context cleared, one trial, and no lab reference behaviour.
/// `expected_resource` is the resource URL the validator expects (the MCP
/// endpoint the authorization names).
pub fn scenario_with_observed_resource(
    base: &McpAuthScenario,
    observed: Option<&ObservedResourceContext>,
    expected_resource: &str,
) -> Result<McpAuthScenario> {
    let metadata = match observed {
        Some(observed) => Some(ProtectedResourceMetadata {
            resource: opaque_uri(&observed.resource)?,
            authorization_servers: observed
                .authorization_servers
                .iter()
                .map(|s| opaque_uri(s))
                .collect::<Result<_>>()?,
            scopes_supported: observed.scopes_supported.clone(),
            trust: TrustClass::Authenticated,
        }),
        None => None,
    };
    let authorization_servers = observed
        .map(|o| {
            o.as_metadata
                .iter()
                .map(|server| {
                    Ok(AuthorizationServerMetadata {
                        issuer: opaque_uri(&server.issuer)?,
                        authorization_endpoint: server
                            .authorization_endpoint
                            .as_deref()
                            .map(opaque_uri)
                            .transpose()?,
                        token_endpoint: server
                            .token_endpoint
                            .as_deref()
                            .map(opaque_uri)
                            .transpose()?,
                        code_challenge_methods_supported: server
                            .code_challenge_methods_supported
                            .iter()
                            .filter_map(|m| method(m))
                            .collect(),
                        trust: TrustClass::Authenticated,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let selected = authorization_servers.first().map(|s| s.issuer.clone());
    let mut derived = base.clone();
    derived.protected_resource = ResourceContext {
        expected_resource: opaque_uri(expected_resource)?,
        metadata,
        authorization_servers,
        selected_authorization_server: selected,
    };
    derived.authorization_flow = Default::default();
    derived.tokens = Default::default();
    derived.flow = Default::default();
    derived.scope = Default::default();
    derived.registration = None;
    derived.credential_flow = Default::default();
    derived.identity_metadata = Default::default();
    derived.final_operation = Default::default();
    derived.lab = None;
    derived.trials.count = 1;
    derived.validate()?;
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> McpAuthScenario {
        let corpus_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scenarios");
        let raw = std::fs::read(corpus_root.join("mcp-auth-lab-001.json")).expect("scenario");
        serde_json::from_slice(&raw).expect("parses")
    }

    #[test]
    fn opaque_identifiers_preserve_equality_and_are_not_fetchable() {
        let a = opaque_uri("https://mcp.example.test/mcp").unwrap();
        assert_eq!(a, opaque_uri("https://mcp.example.test/mcp").unwrap());
        assert_ne!(a, opaque_uri("https://mcp.example.test/other").unwrap());
        assert!(a.as_str().starts_with("u-") && a.as_str().len() == 18);
        assert!(!a.as_str().contains("://"));
    }

    #[test]
    fn the_derived_scenario_keeps_only_observed_metadata() {
        let observed = ObservedResourceContext {
            resource: "https://mcp.example.test/mcp".into(),
            authorization_servers: vec!["https://as.example.test".into()],
            scopes_supported: vec!["tools.read".into()],
            as_metadata: vec![ObservedAuthServer {
                issuer: "https://as.example.test".into(),
                code_challenge_methods_supported: vec!["S256".into(), "unknown".into()],
                ..Default::default()
            }],
        };
        let derived = scenario_with_observed_resource(
            &base(),
            Some(&observed),
            "https://mcp.example.test/mcp",
        )
        .unwrap();
        let pr = &derived.protected_resource;
        assert_eq!(
            pr.expected_resource,
            pr.metadata.as_ref().unwrap().resource,
            "same URL, same id"
        );
        assert_eq!(
            pr.metadata.as_ref().unwrap().trust,
            TrustClass::Authenticated
        );
        assert!(pr
            .metadata
            .as_ref()
            .unwrap()
            .advertises(&pr.authorization_servers[0].issuer));
        assert_eq!(
            pr.authorization_servers[0].code_challenge_methods_supported,
            vec![CodeChallengeMethod::S256]
        );
        assert_eq!(pr.authorization_servers[0].trust, TrustClass::Authenticated);
        assert!(derived.lab.is_none() && derived.registration.is_none());
        assert_eq!(derived.tokens, Default::default());
        assert_eq!(derived.trials.count, 1);
    }

    #[test]
    fn a_resource_that_differs_from_the_expected_one_stays_different() {
        let observed = ObservedResourceContext {
            resource: "https://attacker.example.test/mcp".into(),
            ..Default::default()
        };
        let derived = scenario_with_observed_resource(
            &base(),
            Some(&observed),
            "https://mcp.example.test/mcp",
        )
        .unwrap();
        assert_ne!(
            derived.protected_resource.expected_resource,
            derived.protected_resource.metadata.unwrap().resource
        );
    }

    #[test]
    fn no_observation_means_no_metadata() {
        let derived =
            scenario_with_observed_resource(&base(), None, "https://mcp.example.test/mcp").unwrap();
        assert!(derived.protected_resource.metadata.is_none());
        assert!(derived.protected_resource.authorization_servers.is_empty());
    }
}
