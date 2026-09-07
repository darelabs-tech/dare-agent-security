//! Self-reported MCP identity metadata, and the boundary around it.
//!
//! `clientInfo` and `serverInfo` are the protocol's way of saying "here is what
//! I call myself". They are useful — inventory, correlation, version-dependent
//! behaviour — and they are not identity. Anything can claim any name.
//!
//! Authoritative principal, tenant and delegation semantics belong to Cycle 015
//! and are re-exported here rather than redefined. The one thing this module
//! adds is the boundary: a check that nothing self-reported was promoted into
//! the authority position.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::source::TrustClass;

/// Principal kinds, re-exported from Cycle 015.
///
/// Not redefined. Two identity models that must agree and are edited in
/// different crates eventually disagree, and the disagreement would be about
/// who is allowed to do what.
pub use dare_identity_security::PrincipalKind;

/// What the peer said about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReportedMetadata {
    /// The name the peer reports.
    pub name: String,
    /// The version the peer reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The title the peer reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl SelfReportedMetadata {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.name, "self-reported name")?;
        for (value, label) in [
            (&self.version, "self-reported version"),
            (&self.title, "self-reported title"),
        ] {
            if let Some(value) = value {
                crate::canonical::assert_safe_identifier(value, label)?;
            }
        }
        Ok(())
    }

    /// Always [`TrustClass::SelfReported`].
    ///
    /// A method rather than a field so a fixture cannot declare its own
    /// `clientInfo` authenticated. The trust class of self-description is a
    /// property of what it *is*, not of what the document claims.
    pub fn trust(&self) -> TrustClass {
        TrustClass::SelfReported
    }
}

/// The authoritative principal a request ran under, where one was established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePrincipal {
    pub principal_id: String,
    /// Reused verbatim from Cycle 015.
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// How this principal was established.
    pub trust: TrustClass,
}

impl AuthoritativePrincipal {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.principal_id, "principal id")?;
        if let Some(tenant) = &self.tenant_id {
            crate::canonical::assert_safe_identifier(tenant, "tenant id")?;
        }
        Ok(())
    }
}

/// Identity evidence for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityContext {
    /// What the client said about itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<SelfReportedMetadata>,
    /// What the server said about itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_info: Option<SelfReportedMetadata>,
    /// The principal the deployment actually acted under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acting_principal: Option<AuthoritativePrincipal>,
    /// Whether the deployment derived the acting principal from self-reported
    /// metadata.
    ///
    /// The violation, stated as a fact rather than inferred. Inferring it would
    /// mean guessing from a name collision, and a client legitimately named
    /// after its principal is not a finding.
    #[serde(default)]
    pub principal_derived_from_self_report: bool,
}

impl IdentityContext {
    pub fn validate(&self) -> Result<()> {
        for info in [&self.client_info, &self.server_info].into_iter().flatten() {
            info.validate()?;
        }
        if let Some(principal) = &self.acting_principal {
            principal.validate()?;
        }
        Ok(())
    }

    /// Whether the self-reported boundary held.
    ///
    /// `None` when there is no self-description to have crossed it. Two ways to
    /// fail: the deployment says outright that it derived the principal from
    /// self-report, or it recorded an acting principal whose own trust class is
    /// self-reported — which is the same mistake wearing a different label.
    pub fn boundary_holds(&self) -> Option<bool> {
        if self.client_info.is_none() && self.server_info.is_none() {
            return None;
        }
        if self.principal_derived_from_self_report {
            return Some(false);
        }
        match &self.acting_principal {
            Some(principal) => Some(principal.trust.may_establish_identity()),
            // Self-description observed and no principal claimed from it. The
            // boundary held precisely because nothing was promoted.
            None => Some(true),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn identity_context() -> IdentityContext {
        IdentityContext {
            client_info: Some(SelfReportedMetadata {
                name: "acme-mcp-client".to_owned(),
                version: Some("1.4.2".to_owned()),
                title: Some("Acme Client".to_owned()),
            }),
            server_info: Some(SelfReportedMetadata {
                name: "invoices-mcp-server".to_owned(),
                version: Some("2.0.0".to_owned()),
                title: None,
            }),
            acting_principal: Some(AuthoritativePrincipal {
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: Some("tenant-a".to_owned()),
                trust: TrustClass::Authenticated,
            }),
            principal_derived_from_self_report: false,
        }
    }

    #[test]
    fn an_authenticated_principal_alongside_self_description_holds() {
        let context = identity_context();
        context.validate().expect("valid");
        assert_eq!(context.boundary_holds(), Some(true));
    }

    #[test]
    fn deriving_the_principal_from_self_report_fails_the_boundary() {
        let mut context = identity_context();
        context.principal_derived_from_self_report = true;
        assert_eq!(context.boundary_holds(), Some(false));
    }

    #[test]
    fn a_principal_whose_own_trust_is_self_reported_fails_too() {
        // The same mistake wearing a different label. A deployment that did not
        // set the flag but recorded a self-reported principal has still
        // promoted self-description to authority.
        let mut context = identity_context();
        context.acting_principal.as_mut().expect("present").trust = TrustClass::SelfReported;
        assert_eq!(context.boundary_holds(), Some(false));
    }

    #[test]
    fn a_declared_principal_is_not_enough_either() {
        let mut context = identity_context();
        context.acting_principal.as_mut().expect("present").trust = TrustClass::Declared;
        assert_eq!(context.boundary_holds(), Some(false));
    }

    #[test]
    fn self_description_with_no_principal_claimed_from_it_holds() {
        // The boundary held precisely because nothing was promoted.
        let mut context = identity_context();
        context.acting_principal = None;
        assert_eq!(context.boundary_holds(), Some(true));
    }

    #[test]
    fn no_self_description_answers_nothing() {
        let mut context = identity_context();
        context.client_info = None;
        context.server_info = None;
        assert_eq!(context.boundary_holds(), None);
    }

    #[test]
    fn self_reported_metadata_cannot_declare_itself_authenticated() {
        // Trust is a property of what the evidence is, not of what the document
        // says about itself. There is no field to set.
        let context = identity_context();
        let info = context.client_info.as_ref().expect("present");
        assert_eq!(info.trust(), TrustClass::SelfReported);
        assert!(!info.trust().may_establish_identity());

        let hostile = serde_json::json!({ "name": "acme", "trust": "AUTHENTICATED" });
        assert!(serde_json::from_value::<SelfReportedMetadata>(hostile).is_err());
    }

    #[test]
    fn principal_kinds_come_from_cycle_015() {
        // Re-exported, not redefined. Two identity models that must agree and
        // live in different crates eventually disagree about who may do what.
        let kinds = [
            PrincipalKind::Human,
            PrincipalKind::Agent,
            PrincipalKind::Workload,
            PrincipalKind::Service,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).expect("serializes");
            let back: PrincipalKind = serde_json::from_str(&json).expect("round trips");
            assert_eq!(back, kind);
        }
        // And this crate adds none of its own.
        assert!(serde_json::from_str::<PrincipalKind>("\"MCP_CLIENT\"").is_err());
    }
}
