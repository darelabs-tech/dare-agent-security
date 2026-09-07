//! Closed taxonomies.
//!
//! Every enum here fails closed: an unknown wire token is a deserialization
//! error, not a default. That matters more in an authorization engine than
//! almost anywhere else, because the natural default for an unreadable value is
//! the permissive one. A registration whose trust class could not be parsed is
//! exactly the registration that must not be treated as pre-registered, and a
//! token whose validity state could not be read is exactly the token that must
//! not be assumed valid.

use serde::{Deserialize, Serialize};

/// The six reporting surfaces, kept separate so one never inherits another's
/// result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    /// Protocol revision and request routing bound to the JSON-RPC operation.
    ProtocolBinding,
    /// Protected Resource Metadata and authorization-server/issuer boundaries.
    ResourceAuthorization,
    /// Token validity evidence and resource/audience binding.
    TokenBinding,
    /// PKCE, redirect URI and state correlation.
    FlowIntegrity,
    /// Scope challenge, step-up and client-registration trust.
    ScopeAndRegistration,
    /// Credential separation, self-reported identity and final-operation binding.
    CredentialAndIdentity,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolBinding => "PROTOCOL_BINDING",
            Self::ResourceAuthorization => "RESOURCE_AUTHORIZATION",
            Self::TokenBinding => "TOKEN_BINDING",
            Self::FlowIntegrity => "FLOW_INTEGRITY",
            Self::ScopeAndRegistration => "SCOPE_AND_REGISTRATION",
            Self::CredentialAndIdentity => "CREDENTIAL_AND_IDENTITY",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::ProtocolBinding,
            Self::ResourceAuthorization,
            Self::TokenBinding,
            Self::FlowIntegrity,
            Self::ScopeAndRegistration,
            Self::CredentialAndIdentity,
        ]
    }
}

/// How much authority a piece of recorded evidence may carry on its own.
///
/// Ordered, so "promotion" is an integer comparison rather than a judgement
/// call. Nothing self-reported may ever reach [`TrustClass::Authenticated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustClass {
    /// Asserted by the subject about itself. `clientInfo`, `serverInfo`, a
    /// title, a version string. Inventory data and nothing more.
    SelfReported,
    /// Recorded from a source the deployment configured but which carries no
    /// cryptographic proof in this evidence model.
    Declared,
    /// Backed by evidence the deployment treats as authenticated.
    Authenticated,
}

impl TrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfReported => "SELF_REPORTED",
            Self::Declared => "DECLARED",
            Self::Authenticated => "AUTHENTICATED",
        }
    }

    /// Whether this class may establish a principal, tenant, subject or scope.
    ///
    /// Only [`TrustClass::Authenticated`] may. This is the whole content of the
    /// self-reported metadata boundary, expressed once so every caller agrees.
    pub fn may_establish_identity(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

/// Where a piece of authorization evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSourceKind {
    /// A locally recorded synthetic fixture.
    SyntheticFixture,
    /// A sanitized recorded trace.
    RecordedTrace,
    /// Declared by the scenario as approved ground truth.
    ApprovedScenario,
}

impl EvidenceSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticFixture => "SYNTHETIC_FIXTURE",
            Self::RecordedTrace => "RECORDED_TRACE",
            Self::ApprovedScenario => "APPROVED_SCENARIO",
        }
    }
}

/// The MCP protocol revision a scenario declares.
///
/// Deliberately closed at three values. `Unsupported` is a value rather than a
/// parse failure because a scenario may legitimately *describe* a server
/// offering an unsupported revision; what must not happen is that description
/// being evaluated as though it were current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolRevisionClass {
    /// The current wire revision, as Cycle 002 defines it.
    Current,
    /// The one isolated legacy revision Cycle 002 recognises.
    Legacy,
    /// Anything else. Fails closed.
    Unsupported,
}

impl ProtocolRevisionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::Legacy => "LEGACY",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    /// Classify a revision string against the Cycle 002 constants.
    ///
    /// The comparison uses the imported constants rather than literals, so this
    /// crate cannot disagree with Cycle 002 about what "current" means.
    pub fn classify(revision: &str) -> Self {
        if revision == crate::CURRENT_WIRE_REVISION {
            Self::Current
        } else if revision == crate::LEGACY_WIRE_REVISION {
            Self::Legacy
        } else {
            Self::Unsupported
        }
    }

    /// Whether the modern authorization surface applies to this revision.
    ///
    /// Only the current revision carries it. Evaluating the 2026 authorization
    /// invariants against a legacy or unknown revision would report findings
    /// about controls that revision never claimed to have.
    pub fn carries_modern_auth_surface(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// Validity state of a token, as declared by fixture evidence.
///
/// This is deliberately an enum and not a computation. Cycle 018 verifies no
/// signature and fetches no key; a deployment's own verification result is an
/// input, and what this engine judges is the binding *around* it. `Unknown`
/// exists so a scenario can state that verification evidence is absent, which
/// is a real and common situation and must produce `INCONCLUSIVE` rather than a
/// guess in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TokenValidityState {
    /// The deployment recorded a successful verification.
    Verified,
    /// The deployment recorded a failed verification.
    Rejected,
    /// The token is past its recorded validity window.
    Expired,
    /// No verification evidence exists.
    Unknown,
}

impl TokenValidityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this state is positive evidence of validity.
    ///
    /// `Unknown` is not. A token whose verification nobody recorded is not a
    /// valid token and is not an invalid one either — it is a token about which
    /// the run has nothing to say.
    ///
    /// Note what this answers and what it does not. "Evidence exists" is a
    /// question about the *run*; whether the token may be relied on is a
    /// question about the *token*, and it is [`may_be_accepted`] that answers
    /// it. Conflating the two is how a REJECTED token becomes acceptable for
    /// having been examined.
    ///
    /// [`may_be_accepted`]: Self::may_be_accepted
    pub fn is_positive_evidence(self) -> bool {
        matches!(self, Self::Verified | Self::Rejected | Self::Expired)
    }

    /// Whether a token in this state may be relied on for authorization.
    ///
    /// **Only `Verified`.** The other three are each a different reason not to
    /// rely on it, and none of them becomes weaker for being recorded:
    ///
    /// - `Rejected` — the deployment's own verifier said no;
    /// - `Expired` — it is outside the window it was issued for;
    /// - `Unknown` — nobody checked, so accepting it is a decision made on no
    ///   evidence.
    ///
    /// An engine that treated `is_positive_evidence` as sufficient would answer
    /// "was this examined?" while appearing to answer "may this be used?", and
    /// a rejected token that was examined and then accepted would pass.
    pub fn may_be_accepted(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Why a token in this state may not be relied on.
    ///
    /// `None` for `Verified`. Phrased as the reason rather than the state so a
    /// finding reads as a sentence about what happened.
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            Self::Verified => None,
            Self::Rejected => Some("the deployment's own verification rejected it"),
            Self::Expired => Some("it is past the validity window it was issued for"),
            Self::Unknown => Some("no verification of it was ever recorded"),
        }
    }
}

/// Where client registration metadata came from, and therefore how much it may
/// be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationTrustClass {
    /// Registered out of band with the authorization server.
    PreRegistered,
    /// A client metadata document the deployment resolved and trusts.
    ClientMetadataDocument,
    /// Dynamic client registration. A compatibility path in current MCP
    /// guidance, recorded as such rather than treated as equivalent trust.
    DynamicRegistrationLegacy,
    /// Provenance unknown. Fails closed: this may not establish a redirect URI
    /// or a client identifier.
    Untrusted,
}

impl RegistrationTrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreRegistered => "PRE_REGISTERED",
            Self::ClientMetadataDocument => "CLIENT_METADATA_DOCUMENT",
            Self::DynamicRegistrationLegacy => "DYNAMIC_REGISTRATION_LEGACY",
            Self::Untrusted => "UNTRUSTED",
        }
    }

    /// Whether registration metadata from this source may be relied on to
    /// establish a redirect URI or client identifier.
    ///
    /// The legacy dynamic path is deliberately included: current MCP guidance
    /// treats it as a compatibility route rather than a prohibited one, and
    /// recording it as untrusted would report a finding against a deployment
    /// doing something the specification still permits. What it is *not* is
    /// equivalent to pre-registration, which is why the class survives into the
    /// artifact instead of collapsing into a boolean.
    pub fn is_trusted_provenance(self) -> bool {
        matches!(
            self,
            Self::PreRegistered | Self::ClientMetadataDocument | Self::DynamicRegistrationLegacy
        )
    }
}

/// What a credential is for.
///
/// The separation invariant is a comparison between an inbound credential and
/// an upstream one; the class is what makes "the same credential appearing on
/// both sides" a detectable event rather than a coincidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialClass {
    /// Presented by a client to the MCP server.
    InboundMcp,
    /// Used by the MCP server when calling something else.
    UpstreamService,
    /// Obtained through an explicit, recorded exchange or delegation.
    ExchangedDelegated,
}

impl CredentialClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InboundMcp => "INBOUND_MCP",
            Self::UpstreamService => "UPSTREAM_SERVICE",
            Self::ExchangedDelegated => "EXCHANGED_DELEGATED",
        }
    }
}

/// The PKCE code challenge method a flow used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeChallengeMethod {
    /// SHA-256. The method a modern public client is expected to use.
    S256,
    /// The verifier sent unhashed. A downgrade wherever S256 is required.
    Plain,
    /// No PKCE at all.
    None,
}

impl CodeChallengeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
            Self::Plain => "PLAIN",
            Self::None => "NONE",
        }
    }

    /// Whether this method satisfies a requirement for S256.
    ///
    /// Only S256 does. `Plain` is a downgrade rather than a weaker-but-present
    /// control: it offers no binding at all against an intercepted code.
    pub fn satisfies_s256_requirement(self) -> bool {
        matches!(self, Self::S256)
    }
}

/// How a run observed its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessErrorKind {
    /// The adapter itself failed.
    AdapterFailure,
    /// The scenario could not be staged.
    StagingFailure,
    /// A Cycle 009 control stopped the run.
    KillSwitchTriggered,
    /// A budget was exhausted mid-run.
    BudgetExhausted,
}

impl HarnessErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdapterFailure => "ADAPTER_FAILURE",
            Self::StagingFailure => "STAGING_FAILURE",
            Self::KillSwitchTriggered => "KILL_SWITCH_TRIGGERED",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
        }
    }
}

/// Whether a corpus entry describes an attack or a benign control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    McpAuthAttack,
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::McpAuthAttack => "MCP_AUTH_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn round_trip<T>(value: T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        serde_json::from_str(&serde_json::to_string(&value).expect("serializes"))
            .expect("round trips")
    }

    #[test]
    fn every_taxonomy_is_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = ScenarioClass::all()
            .iter()
            .map(|class| class.as_str())
            .collect();
        assert_eq!(names.len(), 6);

        for value in [
            TrustClass::SelfReported,
            TrustClass::Declared,
            TrustClass::Authenticated,
        ] {
            assert_eq!(round_trip(value), value);
        }
    }

    #[test]
    fn an_unknown_token_fails_closed_rather_than_defaulting() {
        // The permissive value is the natural default, which is exactly why
        // there must not be one. A registration whose class could not be read
        // must not become PRE_REGISTERED.
        assert!(serde_json::from_str::<RegistrationTrustClass>("\"SUPER_TRUSTED\"").is_err());
        assert!(serde_json::from_str::<TokenValidityState>("\"PROBABLY_FINE\"").is_err());
        assert!(serde_json::from_str::<TrustClass>("\"MOSTLY_AUTHENTICATED\"").is_err());
        assert!(serde_json::from_str::<CodeChallengeMethod>("\"S512\"").is_err());
        assert!(serde_json::from_str::<CredentialClass>("\"SOMETHING\"").is_err());
        assert!(serde_json::from_str::<ProtocolRevisionClass>("\"FUTURE\"").is_err());
    }

    #[test]
    fn the_wire_tokens_are_screaming_snake_case_and_stable() {
        assert_eq!(
            serde_json::to_string(&TrustClass::SelfReported).unwrap(),
            "\"SELF_REPORTED\""
        );
        assert_eq!(
            serde_json::to_string(&RegistrationTrustClass::DynamicRegistrationLegacy).unwrap(),
            "\"DYNAMIC_REGISTRATION_LEGACY\""
        );
        assert_eq!(
            serde_json::to_string(&CodeChallengeMethod::S256).unwrap(),
            "\"S256\""
        );
    }

    #[test]
    fn only_authenticated_evidence_may_establish_identity() {
        // The self-reported metadata boundary, in one line. `clientInfo` is
        // SELF_REPORTED and can never reach the level that establishes a
        // principal.
        assert!(!TrustClass::SelfReported.may_establish_identity());
        assert!(!TrustClass::Declared.may_establish_identity());
        assert!(TrustClass::Authenticated.may_establish_identity());
    }

    #[test]
    fn trust_is_ordered_so_promotion_is_arithmetic() {
        assert!(TrustClass::SelfReported < TrustClass::Declared);
        assert!(TrustClass::Declared < TrustClass::Authenticated);
    }

    #[test]
    fn revision_classification_follows_cycle_002_rather_than_a_literal() {
        assert_eq!(
            ProtocolRevisionClass::classify(crate::CURRENT_WIRE_REVISION),
            ProtocolRevisionClass::Current
        );
        assert_eq!(
            ProtocolRevisionClass::classify(crate::LEGACY_WIRE_REVISION),
            ProtocolRevisionClass::Legacy
        );
        for unknown in ["2025-01-01", "2027-12-31", "", "latest", "2026-07-27"] {
            assert_eq!(
                ProtocolRevisionClass::classify(unknown),
                ProtocolRevisionClass::Unsupported,
                "`{unknown}` was not treated as unsupported"
            );
        }
    }

    #[test]
    fn only_the_current_revision_carries_the_modern_auth_surface() {
        // Evaluating the 2026 authorization invariants against a legacy server
        // would report findings about controls that revision never claimed.
        assert!(ProtocolRevisionClass::Current.carries_modern_auth_surface());
        assert!(!ProtocolRevisionClass::Legacy.carries_modern_auth_surface());
        assert!(!ProtocolRevisionClass::Unsupported.carries_modern_auth_surface());
    }

    #[test]
    fn an_unverified_token_is_not_evidence_in_either_direction() {
        // The distinction that makes INCONCLUSIVE possible. A token nobody
        // verified is not valid and is not invalid.
        assert!(!TokenValidityState::Unknown.is_positive_evidence());
        assert!(TokenValidityState::Verified.is_positive_evidence());
        assert!(TokenValidityState::Rejected.is_positive_evidence());
        assert!(TokenValidityState::Expired.is_positive_evidence());
    }

    #[test]
    fn untrusted_registration_is_the_only_class_that_cannot_establish_a_client() {
        // The legacy dynamic path is a compatibility route in current MCP
        // guidance, not a prohibited one. Reporting it as untrusted would be a
        // finding against a deployment doing something still permitted; the
        // class survives into the artifact so a reader can see which route was
        // used.
        assert!(RegistrationTrustClass::PreRegistered.is_trusted_provenance());
        assert!(RegistrationTrustClass::ClientMetadataDocument.is_trusted_provenance());
        assert!(RegistrationTrustClass::DynamicRegistrationLegacy.is_trusted_provenance());
        assert!(!RegistrationTrustClass::Untrusted.is_trusted_provenance());
    }

    #[test]
    fn plain_pkce_does_not_satisfy_a_requirement_for_s256() {
        // Plain is not a weaker control, it is the absence of one: the verifier
        // travels with the challenge and binds nothing against interception.
        assert!(CodeChallengeMethod::S256.satisfies_s256_requirement());
        assert!(!CodeChallengeMethod::Plain.satisfies_s256_requirement());
        assert!(!CodeChallengeMethod::None.satisfies_s256_requirement());
    }
}
