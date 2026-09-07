//! PKCE challenge and verifier binding.
//!
//! PKCE exists so that an intercepted authorization code is useless without the
//! secret that started the flow. Two things can go wrong and they are different
//! findings: the binding can be **absent** where it was required, and it can be
//! **downgraded** to a method that binds nothing.
//!
//! No verifier value is stored. The verifier is a secret; what the engine needs
//! is whether the challenge presented at the authorization request corresponds
//! to the verifier presented at the token request, and a digest answers that
//! without keeping either.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::source::CodeChallengeMethod;

/// Recorded PKCE evidence for one authorization flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PkceContext {
    /// Whether the scenario declares PKCE with S256 as required here.
    ///
    /// Declared rather than inferred: whether a public client must use PKCE is
    /// a property of the deployment and the client type, and guessing it would
    /// produce findings against confidential clients that never needed it.
    #[serde(default)]
    pub s256_required: bool,
    /// The method actually used.
    pub method: CodeChallengeMethod,
    /// Digest of the challenge sent with the authorization request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_digest: Option<String>,
    /// Digest of the verifier presented at the token request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_digest: Option<String>,
}

impl PkceContext {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.challenge_digest, "pkce challenge digest"),
            (&self.verifier_digest, "pkce verifier digest"),
        ] {
            if let Some(value) = value {
                crate::canonical::assert_digest_shape(value, label)?;
            }
        }
        Ok(())
    }

    /// Whether the declared requirement was met by the method used.
    ///
    /// `None` when nothing was required — there is no finding in a flow that
    /// never needed PKCE, and reporting one would be noise.
    pub fn method_requirement_holds(&self) -> Option<bool> {
        if !self.s256_required {
            return None;
        }
        Some(self.method.satisfies_s256_requirement())
    }

    /// Whether the challenge and the verifier correspond.
    ///
    /// `None` when either side is missing. A flow that recorded a challenge and
    /// no verifier has not been observed all the way through, which is a
    /// coverage gap rather than a violation.
    pub fn binding_holds(&self) -> Option<bool> {
        let challenge = self.challenge_digest.as_ref()?;
        let verifier = self.verifier_digest.as_ref()?;
        Some(challenge == verifier)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn pkce_context() -> PkceContext {
        let bound = crate::canonical::digest_bytes(b"synthetic-verifier-material");
        PkceContext {
            s256_required: true,
            method: CodeChallengeMethod::S256,
            challenge_digest: Some(bound.clone()),
            verifier_digest: Some(bound),
        }
    }

    #[test]
    fn a_bound_s256_flow_holds() {
        let context = pkce_context();
        context.validate().expect("valid");
        assert_eq!(context.method_requirement_holds(), Some(true));
        assert_eq!(context.binding_holds(), Some(true));
    }

    #[test]
    fn a_downgrade_to_plain_fails_the_requirement() {
        // Plain is not a weaker binding, it is none: the verifier travels with
        // the challenge and an interceptor has both.
        let mut context = pkce_context();
        context.method = CodeChallengeMethod::Plain;
        assert_eq!(context.method_requirement_holds(), Some(false));
    }

    #[test]
    fn removing_pkce_entirely_fails_the_requirement() {
        let mut context = pkce_context();
        context.method = CodeChallengeMethod::None;
        assert_eq!(context.method_requirement_holds(), Some(false));
    }

    #[test]
    fn a_verifier_that_does_not_match_its_challenge_breaks_the_binding() {
        let mut context = pkce_context();
        context.verifier_digest = Some(crate::canonical::digest_bytes(b"other-material"));
        assert_eq!(context.binding_holds(), Some(false));
    }

    #[test]
    fn a_flow_that_never_required_pkce_produces_no_finding() {
        // A confidential client that used no PKCE is not a violation, and an
        // engine that reported one would be wrong about the specification.
        let mut context = pkce_context();
        context.s256_required = false;
        context.method = CodeChallengeMethod::None;
        assert_eq!(context.method_requirement_holds(), None);
    }

    #[test]
    fn a_half_observed_flow_is_a_gap_rather_than_a_violation() {
        let mut context = pkce_context();
        context.verifier_digest = None;
        assert_eq!(context.binding_holds(), None);
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_raw_verifier() {
        let hostile = serde_json::json!({
            "s256_required": true,
            "method": "S256",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        });
        assert!(serde_json::from_value::<PkceContext>(hostile).is_err());
    }

    #[test]
    fn a_digest_field_must_actually_be_a_digest() {
        let mut context = pkce_context();
        context.challenge_digest = Some("not-a-digest".to_owned());
        assert!(context.validate().is_err());
    }
}
