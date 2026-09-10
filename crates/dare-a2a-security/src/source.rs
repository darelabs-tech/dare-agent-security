//! The closed taxonomies.
//!
//! Every enum here fails to decode on an unknown value. That is the point: an
//! Agent Card is somebody else's document, and guessing which familiar value an
//! unfamiliar one meant is how a peer with an unreadable security scheme ends
//! up in the graph with its requirements unasked.

use serde::{Deserialize, Serialize};

/// Where a piece of evidence came from.
///
/// The asymmetry this cycle rests on lives here: only a local approval source
/// may establish that something was *approved*. A peer's own Agent Card can say
/// anything about itself, and saying it does not make it so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    /// A discovery document supplied by, or describing, the peer.
    AgentCard,
    /// A captured request/response/task trace.
    CapturedTrace,
    /// A verification another verifier performed and recorded.
    RecordedVerification,
    /// The local policy manifest the deployment controls.
    LocalPolicy,
    /// A locally recorded delegation or authority grant.
    LocalDelegationRecord,
    /// A fixture the harness staged.
    SyntheticFixture,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentCard => "AGENT_CARD",
            Self::CapturedTrace => "CAPTURED_TRACE",
            Self::RecordedVerification => "RECORDED_VERIFICATION",
            Self::LocalPolicy => "LOCAL_POLICY",
            Self::LocalDelegationRecord => "LOCAL_DELEGATION_RECORD",
            Self::SyntheticFixture => "SYNTHETIC_FIXTURE",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::AgentCard,
            Self::CapturedTrace,
            Self::RecordedVerification,
            Self::LocalPolicy,
            Self::LocalDelegationRecord,
            Self::SyntheticFixture,
        ]
    }

    /// Whether evidence from this source may establish that something was
    /// **approved**.
    ///
    /// Only the two local sources. A card describing its own provider as
    /// trusted is a claim by the thing being judged, and an engine that
    /// accepted it would be asking the peer whether the peer is allowed.
    pub fn may_establish_approval(self) -> bool {
        matches!(self, Self::LocalPolicy | Self::LocalDelegationRecord)
    }
}

/// What a verification concluded, as recorded by whoever performed it.
///
/// Four values, and the split between the last two is the one Cycle 018 paid
/// for. "A verification was attempted and could not conclude" and "no
/// verification was recorded at all" are different situations, and neither may
/// become a PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    /// A verification was performed and succeeded.
    Valid,
    /// A verification was performed and failed.
    Invalid,
    /// A verification was performed and could not conclude.
    Indeterminate,
    /// No verification was recorded.
    Unrecorded,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Indeterminate => "INDETERMINATE",
            Self::Unrecorded => "UNRECORDED",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::Valid,
            Self::Invalid,
            Self::Indeterminate,
            Self::Unrecorded,
        ]
    }

    /// Whether a verification happened at all, whatever it concluded.
    ///
    /// Distinct from [`Self::may_satisfy_positive_evidence`]. "Was it checked?"
    /// decides between a gap and a finding; "did it pass?" decides the finding.
    pub fn is_recorded_evidence(self) -> bool {
        matches!(self, Self::Valid | Self::Invalid | Self::Indeterminate)
    }

    /// Whether this status may satisfy a positive PASS condition.
    ///
    /// Only `VALID`. An `INDETERMINATE` result is a verifier saying it could
    /// not tell, and an engine that accepted it would be converting somebody
    /// else's uncertainty into its own confidence.
    pub fn may_satisfy_positive_evidence(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Whether this status is concrete evidence of a failure.
    pub fn is_concrete_failure(self) -> bool {
        matches!(self, Self::Invalid)
    }
}

/// Whether one identity dimension bound to what local policy approved.
///
/// Four answers, because `Option<bool>` only had three and the missing one is
/// exactly where a false `PASS` gets in: "policy named no expectation" and
/// "policy expected a value the evidence never carried" both arrived as `None`,
/// and treating the second as the first is absence read as agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingCheck {
    /// Local policy pinned nothing for this dimension.
    NotExpected,
    /// Policy pinned a value and the evidence did not carry one to compare.
    Unproven,
    /// Compared and equal.
    Matches,
    /// Compared and different.
    Differs,
}

impl BindingCheck {
    /// Compare an observed value with what policy pinned.
    pub fn compare(observed: Option<&str>, expected: Option<&str>) -> Self {
        match (observed, expected) {
            (_, None) => Self::NotExpected,
            (None, Some(_)) => Self::Unproven,
            (Some(observed), Some(expected)) => {
                if observed == expected {
                    Self::Matches
                } else {
                    Self::Differs
                }
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotExpected => "NOT_EXPECTED",
            Self::Unproven => "UNPROVEN",
            Self::Matches => "MATCHES",
            Self::Differs => "DIFFERS",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::NotExpected,
            Self::Unproven,
            Self::Matches,
            Self::Differs,
        ]
    }

    /// Whether an **optional** dimension may contribute to a positive result.
    ///
    /// `NotExpected` may: a policy that pinned nothing has nothing to
    /// contradict. `Unproven` may not, which is the whole point of the type.
    pub fn may_satisfy_positive_evidence(self) -> bool {
        matches!(self, Self::Matches | Self::NotExpected)
    }

    /// Whether a **required** dimension was actually established.
    ///
    /// Stricter than [`Self::may_satisfy_positive_evidence`]: for a binding the
    /// DESIGN requires, a policy that pinned nothing leaves the question
    /// unanswered rather than agreed.
    pub fn is_proven(self) -> bool {
        matches!(self, Self::Matches)
    }

    /// Whether this is concrete evidence of a substitution.
    pub fn is_concrete_failure(self) -> bool {
        matches!(self, Self::Differs)
    }
}

/// The kind of identity a claim names.
///
/// Kept apart because substituting one for another is the failure. A service
/// account that authenticated is not the user on whose behalf it claims to act,
/// and a card's provider is neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityKind {
    /// The logical agent, as the local policy names it.
    LogicalAgent,
    /// The provider named by an Agent Card.
    CardProvider,
    /// The host or interface that answered.
    EndpointIdentity,
    /// The principal an authentication established.
    AuthenticatedPrincipal,
    /// The subject a delegation names as the one being acted for.
    DelegatedSubject,
    /// The tenant the exchange claims to belong to.
    Tenant,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LogicalAgent => "LOGICAL_AGENT",
            Self::CardProvider => "CARD_PROVIDER",
            Self::EndpointIdentity => "ENDPOINT_IDENTITY",
            Self::AuthenticatedPrincipal => "AUTHENTICATED_PRINCIPAL",
            Self::DelegatedSubject => "DELEGATED_SUBJECT",
            Self::Tenant => "TENANT",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::LogicalAgent,
            Self::CardProvider,
            Self::EndpointIdentity,
            Self::AuthenticatedPrincipal,
            Self::DelegatedSubject,
            Self::Tenant,
        ]
    }

    /// Whether an identity of this kind can be the actor a decision is made
    /// about.
    ///
    /// An endpoint identity cannot: it answers which host replied, and no
    /// authorization question has "a host" as its subject.
    pub fn may_be_an_authorization_subject(self) -> bool {
        matches!(
            self,
            Self::AuthenticatedPrincipal | Self::DelegatedSubject | Self::LogicalAgent
        )
    }
}

/// A declared A2A security scheme class.
///
/// Closed, with no catch-all. A card declaring a scheme this engine cannot
/// read is a card whose requirements cannot be checked, and admitting it under
/// an `OTHER` bucket would let the requirement pass unexamined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecuritySchemeKind {
    ApiKey,
    HttpBearer,
    HttpBasic,
    // Spelled the way the specifications spell them. The derive's
    // `SCREAMING_SNAKE_CASE` rename produces `O_AUTH2_CLIENT_CREDENTIALS` and
    // `OPEN_ID_CONNECT`, which no real document carries — and a wire spelling
    // that disagrees with `as_str` means a document readable by only half the
    // engine.
    #[serde(rename = "OAUTH2_CLIENT_CREDENTIALS")]
    OAuth2ClientCredentials,
    #[serde(rename = "OAUTH2_AUTHORIZATION_CODE")]
    OAuth2AuthorizationCode,
    #[serde(rename = "OPENID_CONNECT")]
    OpenIdConnect,
    MutualTls,
    SignedRequest,
}

impl SecuritySchemeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "API_KEY",
            Self::HttpBearer => "HTTP_BEARER",
            Self::HttpBasic => "HTTP_BASIC",
            Self::OAuth2ClientCredentials => "OAUTH2_CLIENT_CREDENTIALS",
            Self::OAuth2AuthorizationCode => "OAUTH2_AUTHORIZATION_CODE",
            Self::OpenIdConnect => "OPENID_CONNECT",
            Self::MutualTls => "MUTUAL_TLS",
            Self::SignedRequest => "SIGNED_REQUEST",
        }
    }

    pub fn all() -> [Self; 8] {
        [
            Self::ApiKey,
            Self::HttpBearer,
            Self::HttpBasic,
            Self::OAuth2ClientCredentials,
            Self::OAuth2AuthorizationCode,
            Self::OpenIdConnect,
            Self::MutualTls,
            Self::SignedRequest,
        ]
    }

    /// Whether this scheme can carry a delegated end-user subject.
    ///
    /// Client credentials cannot: the flow authenticates a service to a
    /// service, and there is no user in it. A deployment relying on it to carry
    /// "acting for Alice" is relying on something the flow never established.
    pub fn may_carry_delegated_subject(self) -> bool {
        matches!(
            self,
            Self::OAuth2AuthorizationCode | Self::OpenIdConnect | Self::SignedRequest
        )
    }
}

/// The transport an exchange used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportKind {
    /// Spelled as A2A 1.0.0 spells it, rather than as the derive would.
    ///
    /// The default `SCREAMING_SNAKE_CASE` rename produces `JSON_RPC`, which is
    /// not the token any real document carries. Leaving the two spellings to
    /// diverge would mean `as_str` and the wire format disagreeing — and a
    /// document written with either one being readable by only half the engine.
    #[serde(rename = "JSONRPC")]
    JsonRpc,
    Grpc,
    HttpJson,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonRpc => "JSONRPC",
            Self::Grpc => "GRPC",
            Self::HttpJson => "HTTP_JSON",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::JsonRpc, Self::Grpc, Self::HttpJson]
    }
}

/// Who produced a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageRole {
    /// The local agent sent it.
    LocalAgent,
    /// A remote peer sent it.
    RemotePeer,
}

impl MessageRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalAgent => "LOCAL_AGENT",
            Self::RemotePeer => "REMOTE_PEER",
        }
    }

    /// Whether content in this role is peer-controlled.
    ///
    /// The whole message-authority boundary turns on this: peer-controlled
    /// content is data, however well authenticated it is.
    pub fn is_peer_controlled(self) -> bool {
        matches!(self, Self::RemotePeer)
    }
}

/// How a data label constrains disclosure.
///
/// Ordered from least to most restrictive, so a widening is a comparison
/// rather than a table somebody must keep consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataSensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Restricted => "RESTRICTED",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::Public,
            Self::Internal,
            Self::Confidential,
            Self::Restricted,
        ]
    }
}

/// Whether an operation changes state, and therefore whether repeating it is
/// safe.
///
/// The distinction the replay boundary rests on. Repeating a read is a
/// performance question; repeating a transfer is a second transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationEffect {
    /// Reads only. Repeating changes nothing.
    ReadOnly,
    /// Changes state, and the operation is defined to be idempotent.
    IdempotentStateChange,
    /// Changes state, and repeating it repeats the change.
    NonIdempotentStateChange,
}

impl OperationEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "READ_ONLY",
            Self::IdempotentStateChange => "IDEMPOTENT_STATE_CHANGE",
            Self::NonIdempotentStateChange => "NON_IDEMPOTENT_STATE_CHANGE",
        }
    }

    pub fn all() -> [Self; 3] {
        [
            Self::ReadOnly,
            Self::IdempotentStateChange,
            Self::NonIdempotentStateChange,
        ]
    }

    /// Whether repeating this operation needs deciding evidence before it can
    /// be called safe.
    ///
    /// A read does not. An idempotent change does not *by definition* — but
    /// the definition is a claim, and whose claim it is decides whether it
    /// counts, which is a question for the evaluator rather than this enum.
    pub fn requires_replay_evidence(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// What a corpus fixture stages.
///
/// A behaviour, never a verdict. `TASK_SUBSTITUTED` says the task id changed
/// under the exchange; it does not say the run should FAIL, and the evaluator
/// remains the only thing that decides that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    Compliant,
    CardSubstituted,
    CardSignatureInvalid,
    CardSignatureUnrecorded,
    ProviderMismatch,
    PeerIdentityMismatch,
    AudienceMismatch,
    AuthenticationInvalid,
    AuthenticationUnrecorded,
    AuthenticationIndeterminate,
    LogicalAgentSubstituted,
    DelegatedIdentitySubstituted,
    SecuritySchemeUnsatisfied,
    SecuritySchemeUnverified,
    SkillNotAuthorized,
    MessageSignatureInvalid,
    MessageSignatureMissing,
    MessageSignatureIndeterminate,
    PeerContentTreatedAsInstruction,
    TaskSubstituted,
    ContextSubstituted,
    PrincipalMismatch,
    DelegationAmplified,
    DelegationChainBroken,
    CrossTenantAccess,
    TenantClaimUnverified,
    DataScopeWidened,
    UnapprovedDestination,
    ReplayWithoutEvidence,
    DuplicateNonIdempotentAction,
    IdempotencyProven,
    ProtocolDowngraded,
    ProtocolVersionUnsupported,
    InterfaceNotApproved,
    ExtensionUndeclared,
    ExtensionUnapproved,
    RequiredExtensionUnknown,
    PushDestinationUnapproved,
    PushScopeWidened,
    MultipleIndependentViolations,
    NoRelevantObservation,
    HarnessFailure,
}

impl ReferenceBehavior {
    /// Whether this behaviour is legitimate activity rather than a crossing.
    ///
    /// Controls matter as much as attacks: a surface with only attack fixtures
    /// lets an over-strict engine look perfect while failing every legitimate
    /// exchange on that surface.
    pub fn is_legitimate(self) -> bool {
        matches!(self, Self::Compliant | Self::IdempotencyProven)
    }

    pub fn all() -> [Self; 42] {
        [
            Self::Compliant,
            Self::CardSubstituted,
            Self::CardSignatureInvalid,
            Self::CardSignatureUnrecorded,
            Self::ProviderMismatch,
            Self::PeerIdentityMismatch,
            Self::AudienceMismatch,
            Self::AuthenticationInvalid,
            Self::AuthenticationUnrecorded,
            Self::AuthenticationIndeterminate,
            Self::LogicalAgentSubstituted,
            Self::DelegatedIdentitySubstituted,
            Self::SecuritySchemeUnsatisfied,
            Self::SecuritySchemeUnverified,
            Self::SkillNotAuthorized,
            Self::MessageSignatureInvalid,
            Self::MessageSignatureMissing,
            Self::MessageSignatureIndeterminate,
            Self::PeerContentTreatedAsInstruction,
            Self::TaskSubstituted,
            Self::ContextSubstituted,
            Self::PrincipalMismatch,
            Self::DelegationAmplified,
            Self::DelegationChainBroken,
            Self::CrossTenantAccess,
            Self::TenantClaimUnverified,
            Self::DataScopeWidened,
            Self::UnapprovedDestination,
            Self::ReplayWithoutEvidence,
            Self::DuplicateNonIdempotentAction,
            Self::IdempotencyProven,
            Self::ProtocolDowngraded,
            Self::ProtocolVersionUnsupported,
            Self::InterfaceNotApproved,
            Self::ExtensionUndeclared,
            Self::ExtensionUnapproved,
            Self::RequiredExtensionUnknown,
            Self::PushDestinationUnapproved,
            Self::PushScopeWidened,
            Self::MultipleIndependentViolations,
            Self::NoRelevantObservation,
            Self::HarnessFailure,
        ]
    }
}

/// The surface a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    DiscoveryBinding,
    PeerIdentity,
    MessageAuthenticity,
    SecurityRequirement,
    SkillAuthorization,
    MessageAuthority,
    TaskContextBinding,
    AuthorityPropagation,
    TenantBoundary,
    DataScope,
    ReplayBoundary,
    ProtocolNegotiation,
    ExtensionTrust,
    PushNotification,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiscoveryBinding => "DISCOVERY_BINDING",
            Self::PeerIdentity => "PEER_IDENTITY",
            Self::MessageAuthenticity => "MESSAGE_AUTHENTICITY",
            Self::SecurityRequirement => "SECURITY_REQUIREMENT",
            Self::SkillAuthorization => "SKILL_AUTHORIZATION",
            Self::MessageAuthority => "MESSAGE_AUTHORITY",
            Self::TaskContextBinding => "TASK_CONTEXT_BINDING",
            Self::AuthorityPropagation => "AUTHORITY_PROPAGATION",
            Self::TenantBoundary => "TENANT_BOUNDARY",
            Self::DataScope => "DATA_SCOPE",
            Self::ReplayBoundary => "REPLAY_BOUNDARY",
            Self::ProtocolNegotiation => "PROTOCOL_NEGOTIATION",
            Self::ExtensionTrust => "EXTENSION_TRUST",
            Self::PushNotification => "PUSH_NOTIFICATION",
        }
    }

    pub fn all() -> [Self; 14] {
        [
            Self::DiscoveryBinding,
            Self::PeerIdentity,
            Self::MessageAuthenticity,
            Self::SecurityRequirement,
            Self::SkillAuthorization,
            Self::MessageAuthority,
            Self::TaskContextBinding,
            Self::AuthorityPropagation,
            Self::TenantBoundary,
            Self::DataScope,
            Self::ReplayBoundary,
            Self::ProtocolNegotiation,
            Self::ExtensionTrust,
            Self::PushNotification,
        ]
    }
}

/// How a run obtained its evidence.
///
/// Four modes, and there is no fifth. Every one of them reads local files or
/// locally constructed structures: a remote mode would need a transport this
/// crate does not declare, and adding the variant would be the first half of
/// adding the capability.
///
/// `REPLAY` means *re-evaluating a capture*. It does not mean re-sending it,
/// and nothing in this crate could.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum A2aMode {
    Static,
    Replay,
    Simulated,
    LocalSynthetic,
}

impl A2aMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "STATIC",
            Self::Replay => "REPLAY",
            Self::Simulated => "SIMULATED",
            Self::LocalSynthetic => "LOCAL_SYNTHETIC",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::Static,
            Self::Replay,
            Self::Simulated,
            Self::LocalSynthetic,
        ]
    }
}

/// Why a harness could not observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessErrorKind {
    AdapterFailure,
    DocumentRefused,
    BudgetExhausted,
}

impl HarnessErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdapterFailure => "ADAPTER_FAILURE",
            Self::DocumentRefused => "DOCUMENT_REFUSED",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_taxonomy_is_closed_and_uniquely_named() {
        let sources: BTreeSet<&str> = EvidenceSource::all().iter().map(|s| s.as_str()).collect();
        assert_eq!(sources.len(), 6);
        let statuses: BTreeSet<&str> = VerificationStatus::all()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(statuses.len(), 4);
        let identities: BTreeSet<&str> = IdentityKind::all().iter().map(|k| k.as_str()).collect();
        assert_eq!(identities.len(), 6);
        let schemes: BTreeSet<&str> = SecuritySchemeKind::all()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(schemes.len(), 8);
        let classes: BTreeSet<&str> = ScenarioClass::all().iter().map(|c| c.as_str()).collect();
        assert_eq!(classes.len(), 14);
        let behaviors: BTreeSet<ReferenceBehavior> =
            ReferenceBehavior::all().iter().copied().collect();
        assert_eq!(behaviors.len(), 42);
    }

    #[test]
    fn an_unknown_wire_value_fails_closed_rather_than_defaulting() {
        // The reason these are enums. An Agent Card is somebody else's
        // document, and guessing which familiar value an unfamiliar one meant
        // is how a peer with an unreadable security scheme ends up in the graph
        // with its requirements unasked.
        assert!(serde_json::from_str::<SecuritySchemeKind>("\"PROBABLY_OAUTH\"").is_err());
        assert!(serde_json::from_str::<VerificationStatus>("\"MOSTLY_VALID\"").is_err());
        assert!(serde_json::from_str::<IdentityKind>("\"SOME_IDENTITY\"").is_err());
        assert!(serde_json::from_str::<A2aMode>("\"REMOTE\"").is_err());
        assert!(serde_json::from_str::<TransportKind>("\"SMTP\"").is_err());
    }

    #[test]
    fn there_are_exactly_four_modes_and_none_of_them_is_remote() {
        assert_eq!(A2aMode::all().len(), 4);
        let names: Vec<&str> = A2aMode::all().iter().map(|mode| mode.as_str()).collect();
        assert_eq!(names, ["STATIC", "REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"]);
        for hostile in ["\"LIVE\"", "\"REMOTE\"", "\"NETWORK\"", "\"PROBE\""] {
            assert!(
                serde_json::from_str::<A2aMode>(hostile).is_err(),
                "{hostile} decoded as a mode"
            );
        }
    }

    #[test]
    fn only_a_local_source_may_establish_approval() {
        // A card describing its own provider as trusted is a claim by the thing
        // being judged. An engine that accepted it would be asking the peer
        // whether the peer is allowed.
        assert!(EvidenceSource::LocalPolicy.may_establish_approval());
        assert!(EvidenceSource::LocalDelegationRecord.may_establish_approval());
        for source in [
            EvidenceSource::AgentCard,
            EvidenceSource::CapturedTrace,
            EvidenceSource::RecordedVerification,
            EvidenceSource::SyntheticFixture,
        ] {
            assert!(
                !source.may_establish_approval(),
                "{} could approve something",
                source.as_str()
            );
        }
    }

    #[test]
    fn a_recorded_verification_is_not_the_same_as_a_favourable_one() {
        // The Cycle 018 lesson, in this cycle's vocabulary. "Was it checked?"
        // decides between a gap and a finding; "did it pass?" decides the
        // finding.
        assert!(VerificationStatus::Indeterminate.is_recorded_evidence());
        assert!(!VerificationStatus::Indeterminate.may_satisfy_positive_evidence());
        assert!(VerificationStatus::Invalid.is_recorded_evidence());
        assert!(!VerificationStatus::Invalid.may_satisfy_positive_evidence());
        assert!(!VerificationStatus::Unrecorded.is_recorded_evidence());
        assert!(!VerificationStatus::Unrecorded.may_satisfy_positive_evidence());
    }

    #[test]
    fn only_valid_may_satisfy_positive_evidence_and_only_invalid_is_a_finding() {
        for status in VerificationStatus::all() {
            assert_eq!(
                status.may_satisfy_positive_evidence(),
                status == VerificationStatus::Valid,
                "{}",
                status.as_str()
            );
            assert_eq!(
                status.is_concrete_failure(),
                status == VerificationStatus::Invalid,
                "{}",
                status.as_str()
            );
        }
    }

    #[test]
    fn an_endpoint_identity_is_never_an_authorization_subject() {
        // TLS server identity answers which host replied. No authorization
        // question has "a host" as its subject.
        assert!(!IdentityKind::EndpointIdentity.may_be_an_authorization_subject());
        assert!(!IdentityKind::CardProvider.may_be_an_authorization_subject());
        assert!(IdentityKind::AuthenticatedPrincipal.may_be_an_authorization_subject());
        assert!(IdentityKind::DelegatedSubject.may_be_an_authorization_subject());
    }

    #[test]
    fn client_credentials_cannot_carry_a_delegated_subject() {
        // The flow authenticates a service to a service. A deployment relying
        // on it to carry "acting for Alice" is relying on something the flow
        // never established.
        assert!(!SecuritySchemeKind::OAuth2ClientCredentials.may_carry_delegated_subject());
        assert!(!SecuritySchemeKind::ApiKey.may_carry_delegated_subject());
        assert!(!SecuritySchemeKind::MutualTls.may_carry_delegated_subject());
        assert!(SecuritySchemeKind::OAuth2AuthorizationCode.may_carry_delegated_subject());
        assert!(SecuritySchemeKind::OpenIdConnect.may_carry_delegated_subject());
    }

    #[test]
    fn every_taxonomy_is_spelled_the_same_way_on_the_wire_and_in_prose() {
        // `as_str` feeds reports; the serde representation feeds documents. If
        // the two disagree, a document written with one spelling is readable by
        // only half the engine.
        //
        // This is not hypothetical: the derive's `SCREAMING_SNAKE_CASE` turns
        // `JsonRpc` into `JSON_RPC` and `OAuth2AuthorizationCode` into
        // `O_AUTH2_AUTHORIZATION_CODE`, neither of which any real A2A document
        // carries. Both were caught here, and this test covers the whole class
        // rather than the two instances.
        macro_rules! assert_spellings_agree {
            ($type:ty, $values:expr) => {
                for value in $values {
                    let wire = serde_json::to_string(&value).expect("serializes");
                    assert_eq!(
                        wire.trim_matches('"'),
                        value.as_str(),
                        "{:?} is spelled two ways",
                        value
                    );
                    let round_trip: $type = serde_json::from_str(&wire).expect("round-trips");
                    assert_eq!(round_trip, value);
                }
            };
        }

        assert_spellings_agree!(TransportKind, TransportKind::all());
        assert_spellings_agree!(SecuritySchemeKind, SecuritySchemeKind::all());
        assert_spellings_agree!(EvidenceSource, EvidenceSource::all());
        assert_spellings_agree!(VerificationStatus, VerificationStatus::all());
        assert_spellings_agree!(IdentityKind, IdentityKind::all());
        assert_spellings_agree!(DataSensitivity, DataSensitivity::all());
        assert_spellings_agree!(OperationEffect, OperationEffect::all());
        assert_spellings_agree!(ScenarioClass, ScenarioClass::all());
        assert_spellings_agree!(A2aMode, A2aMode::all());
    }

    #[test]
    fn peer_content_is_recognisable_as_peer_controlled() {
        assert!(MessageRole::RemotePeer.is_peer_controlled());
        assert!(!MessageRole::LocalAgent.is_peer_controlled());
    }

    #[test]
    fn data_sensitivity_is_ordered_so_widening_is_a_comparison() {
        assert!(DataSensitivity::Public < DataSensitivity::Internal);
        assert!(DataSensitivity::Internal < DataSensitivity::Confidential);
        assert!(DataSensitivity::Confidential < DataSensitivity::Restricted);
    }

    #[test]
    fn only_a_read_is_safe_to_repeat_without_evidence() {
        // Repeating a read is a performance question. Repeating a transfer is a
        // second transfer.
        assert!(!OperationEffect::ReadOnly.requires_replay_evidence());
        assert!(OperationEffect::IdempotentStateChange.requires_replay_evidence());
        assert!(OperationEffect::NonIdempotentStateChange.requires_replay_evidence());
    }

    #[test]
    fn a_reference_behaviour_is_a_behaviour_and_never_a_verdict() {
        // `MULTIPLE_INDEPENDENT_VIOLATIONS` says an exchange crosses several
        // boundaries. It does not say the run should FAIL, and the evaluator
        // remains the only thing that decides that.
        let rendered =
            serde_json::to_string(&ReferenceBehavior::all().to_vec()).expect("serializes");
        // Whole-word comparison. `HARNESS_FAILURE` contains `FAIL` as a
        // substring and is not the verdict FAIL — the same false positive that
        // cost Cycle 013 a red build when `SECURE` matched inside
        // `INSECURE_INTER_AGENT_COMMUNICATION`.
        let words: Vec<&str> = rendered
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|word| !word.is_empty())
            .collect();
        for verdict in ["PASS", "FAIL", "INCONCLUSIVE", "SECURE", "VULNERABLE"] {
            assert!(
                !words.contains(&verdict),
                "a reference behaviour names the verdict `{verdict}`"
            );
        }
    }

    #[test]
    fn the_behaviour_set_carries_legitimate_activity_too() {
        // A corpus of attacks alone lets an over-strict engine look perfect.
        let legitimate: Vec<ReferenceBehavior> = ReferenceBehavior::all()
            .into_iter()
            .filter(|behavior| behavior.is_legitimate())
            .collect();
        assert!(!legitimate.is_empty());
        assert!(legitimate.contains(&ReferenceBehavior::Compliant));
        assert!(legitimate.contains(&ReferenceBehavior::IdempotencyProven));
    }

    #[test]
    fn the_wire_tokens_are_screaming_snake_case_and_stable() {
        for token in EvidenceSource::all().iter().map(|s| s.as_str()) {
            assert_eq!(token, token.to_uppercase());
        }
        for token in ScenarioClass::all().iter().map(|c| c.as_str()) {
            assert_eq!(token, token.to_uppercase());
        }
    }
}
