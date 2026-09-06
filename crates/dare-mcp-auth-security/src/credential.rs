//! Inbound and upstream credential separation.
//!
//! A credential presented *to* an MCP server is not a credential *for* whatever
//! that server calls next. Forwarding one is the confused-deputy shape of this
//! surface: the upstream service sees a valid token and has no way to know it
//! was minted for somebody else's audience.
//!
//! Nothing here stores a secret. Credentials are compared as synthetic
//! identities and digests, which is enough to answer the only question that
//! matters — *is the thing going out the same thing that came in* — without
//! keeping anything worth stealing.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::source::CredentialClass;

/// One credential, as a projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    /// Synthetic identity for this credential. Never the credential.
    pub credential_id: String,
    /// What the credential is for.
    pub class: CredentialClass,
    /// Digest of the underlying material, where the deployment recorded one.
    ///
    /// Two credentials with the same digest are the same credential. This is
    /// how reuse is detected without either value being stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material_digest: Option<String>,
}

impl CredentialRef {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.credential_id, "credential id")?;
        if let Some(digest) = &self.material_digest {
            crate::canonical::assert_digest_shape(digest, "credential material digest")?;
        }
        Ok(())
    }

    /// Whether this and another projection denote the same credential.
    ///
    /// Digest first, because it is the stronger signal: two ids can differ
    /// while naming the same material, which is exactly what a forwarding bug
    /// looks like after a rename.
    pub fn is_same_credential_as(&self, other: &Self) -> bool {
        match (&self.material_digest, &other.material_digest) {
            (Some(left), Some(right)) => left == right,
            _ => self.credential_id == other.credential_id,
        }
    }
}

/// The credential flow a scenario declares.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContext {
    /// What the client presented to the MCP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<CredentialRef>,
    /// What the MCP server presented upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<CredentialRef>,
    /// Whether a recorded exchange or delegation produced the upstream
    /// credential from the inbound one.
    ///
    /// This is what makes a legitimate relationship distinguishable from
    /// passthrough. An exchange is a deliberate act with its own authorization;
    /// forwarding is the absence of one.
    #[serde(default)]
    pub exchange_recorded: bool,
    /// Whether the deployment's policy permits an exchange here.
    #[serde(default)]
    pub exchange_permitted: bool,
}

impl CredentialContext {
    pub fn validate(&self) -> Result<()> {
        if let Some(inbound) = &self.inbound {
            inbound.validate()?;
        }
        if let Some(upstream) = &self.upstream {
            upstream.validate()?;
        }
        Ok(())
    }

    /// Whether the inbound credential stayed separate from the upstream one.
    ///
    /// `None` when either side was not observed: a run that never saw an
    /// upstream call has nothing to say about forwarding, and saying "separate"
    /// would be claiming a control that was never exercised.
    ///
    /// The same credential appearing on both sides is separation failing —
    /// *unless* an exchange was recorded and policy permits it, which is a
    /// deliberate, authorized relationship rather than passthrough.
    pub fn separation_holds(&self) -> Option<bool> {
        let inbound = self.inbound.as_ref()?;
        let upstream = self.upstream.as_ref()?;

        if !inbound.is_same_credential_as(upstream) {
            return Some(true);
        }
        Some(self.exchange_recorded && self.exchange_permitted)
    }

    /// Whether the same credential material appears on both sides at all.
    ///
    /// Reported separately from the verdict so an artifact can distinguish
    /// "forwarded" from "forwarded but authorized".
    pub fn credential_reused(&self) -> Option<bool> {
        let inbound = self.inbound.as_ref()?;
        let upstream = self.upstream.as_ref()?;
        Some(inbound.is_same_credential_as(upstream))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn inbound() -> CredentialRef {
        CredentialRef {
            credential_id: "cred-inbound".to_owned(),
            class: CredentialClass::InboundMcp,
            material_digest: Some(crate::canonical::digest_bytes(b"inbound-material")),
        }
    }

    pub(crate) fn credential_context() -> CredentialContext {
        CredentialContext {
            inbound: Some(inbound()),
            upstream: Some(CredentialRef {
                credential_id: "cred-upstream".to_owned(),
                class: CredentialClass::UpstreamService,
                material_digest: Some(crate::canonical::digest_bytes(b"upstream-material")),
            }),
            exchange_recorded: false,
            exchange_permitted: false,
        }
    }

    #[test]
    fn distinct_credentials_stay_separate() {
        let context = credential_context();
        context.validate().expect("valid");
        assert_eq!(context.separation_holds(), Some(true));
        assert_eq!(context.credential_reused(), Some(false));
    }

    #[test]
    fn forwarding_the_inbound_credential_upstream_fails_separation() {
        // The confused deputy. The upstream service sees a valid token and has
        // no way to know it was minted for somebody else.
        let mut context = credential_context();
        context.upstream = Some(CredentialRef {
            credential_id: "cred-upstream".to_owned(),
            class: CredentialClass::UpstreamService,
            material_digest: inbound().material_digest,
        });
        assert_eq!(context.credential_reused(), Some(true));
        assert_eq!(context.separation_holds(), Some(false));
    }

    #[test]
    fn a_rename_does_not_hide_forwarding() {
        // Two ids differ while naming the same material. Comparing ids alone
        // would call this separation.
        let mut context = credential_context();
        context.upstream = Some(CredentialRef {
            credential_id: "totally-different-name".to_owned(),
            class: CredentialClass::UpstreamService,
            material_digest: inbound().material_digest,
        });
        assert_eq!(context.separation_holds(), Some(false));
    }

    #[test]
    fn an_authorized_exchange_is_not_forwarding() {
        // An exchange is a deliberate act with its own authorization.
        // Forwarding is the absence of one.
        let mut context = credential_context();
        context.upstream = Some(CredentialRef {
            credential_id: "cred-exchanged".to_owned(),
            class: CredentialClass::ExchangedDelegated,
            material_digest: inbound().material_digest,
        });
        context.exchange_recorded = true;
        context.exchange_permitted = true;
        assert_eq!(context.credential_reused(), Some(true));
        assert_eq!(context.separation_holds(), Some(true));
    }

    #[test]
    fn an_exchange_policy_does_not_permit_forwards_alone() {
        // Recording an exchange that policy does not permit is still a finding,
        // and so is claiming policy permits one that was never recorded.
        let mut context = credential_context();
        context.upstream = Some(CredentialRef {
            credential_id: "cred-upstream".to_owned(),
            class: CredentialClass::UpstreamService,
            material_digest: inbound().material_digest,
        });

        context.exchange_recorded = true;
        context.exchange_permitted = false;
        assert_eq!(context.separation_holds(), Some(false));

        context.exchange_recorded = false;
        context.exchange_permitted = true;
        assert_eq!(context.separation_holds(), Some(false));
    }

    #[test]
    fn an_unobserved_upstream_call_answers_nothing() {
        // Saying "separate" here would claim a control that was never
        // exercised.
        let mut context = credential_context();
        context.upstream = None;
        assert_eq!(context.separation_holds(), None);
        assert_eq!(context.credential_reused(), None);
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_secret() {
        for hostile in [
            serde_json::json!({
                "credential_id": "cred-inbound", "class": "INBOUND_MCP",
                "bearer": "Bearer abcdefghijklmnopqrst"
            }),
            serde_json::json!({
                "credential_id": "cred-inbound", "class": "INBOUND_MCP",
                "value": "eyJhbGciOiJIUzI1NiJ9.e30.sig"
            }),
        ] {
            assert!(serde_json::from_value::<CredentialRef>(hostile).is_err());
        }
    }

    #[test]
    fn a_digest_field_must_actually_be_a_digest() {
        let mut context = credential_context();
        context.inbound.as_mut().expect("present").material_digest = Some("nope".to_owned());
        assert!(context.validate().is_err());
    }
}
