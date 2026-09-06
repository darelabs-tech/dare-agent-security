//! Closed taxonomies for the identity-security engine.
//!
//! Every enum here is closed and fails closed. An unknown value is refused at
//! the serde boundary rather than degraded to a default, because a default in
//! this domain would be a silent grant: an unrecognized principal kind treated
//! as `HUMAN`, or an unrecognized delegation kind treated as `ON_BEHALF_OF`,
//! would hand authority to something the scenario never described.
//!
//! The taxonomies are also kept *separate*. Principal binding, delegation,
//! privilege, tenant/resource and authorization binding are five distinct
//! surfaces, and a family from one may never stand in for a family from
//! another — reports separate them, so the types do too.

use serde::{Deserialize, Serialize};

use crate::error::{IdentitySecurityError, Result};

/// Which of the five identity surfaces a scenario exercises.
///
/// Reports render these separately and never merge them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    PrincipalBinding,
    Delegation,
    Privilege,
    TenantResource,
    AuthorizationBinding,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalBinding => "PRINCIPAL_BINDING",
            Self::Delegation => "DELEGATION",
            Self::Privilege => "PRIVILEGE",
            Self::TenantResource => "TENANT_RESOURCE",
            Self::AuthorizationBinding => "AUTHORIZATION_BINDING",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::PrincipalBinding,
            Self::Delegation,
            Self::Privilege,
            Self::TenantResource,
            Self::AuthorizationBinding,
        ]
    }
}

/// Closed set of principal kinds.
///
/// These stay distinct throughout the engine. Collapsing `SERVICE` into
/// `HUMAN`, or treating an `AGENT` as its user, is the substitution most of
/// this cycle exists to detect — so the type system refuses to blur them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalKind {
    /// A person. The only kind that can originate authority in this model.
    Human,
    /// An agent acting for some other principal. Never an authority source.
    Agent,
    /// A workload identity: a process, job or compute context.
    Workload,
    /// A service identity, typically holding broad technical capability.
    Service,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "HUMAN",
            Self::Agent => "AGENT",
            Self::Workload => "WORKLOAD",
            Self::Service => "SERVICE",
        }
    }

    pub fn all() -> [Self; 4] {
        [Self::Human, Self::Agent, Self::Workload, Self::Service]
    }

    /// Whether a principal of this kind can originate authority on its own.
    ///
    /// Only a human can. An agent, workload or service principal holds
    /// authority only where a human delegated it, which is the whole content of
    /// "credential availability is not delegated authority": a `SERVICE`
    /// principal with broad capability is still not a source of authority for a
    /// user's operation.
    pub fn originates_authority(self) -> bool {
        matches!(self, Self::Human)
    }

    /// Whether a principal of this kind typically carries runtime credentials
    /// whose capability exceeds any single user's delegated authority.
    pub fn is_technical_identity(self) -> bool {
        matches!(self, Self::Workload | Self::Service)
    }
}

/// The role a principal plays in one scenario.
///
/// These are roles, not kinds: the same `HUMAN` principal can be both the
/// initiating principal and the resource owner. Keeping them separate is what
/// makes "the agent acted as itself rather than for the user" expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalRole {
    /// Who started the request. The authority source.
    Initiating,
    /// Whose authority the operation is actually being performed under.
    Effective,
    /// The agent mediating the request.
    Agent,
    /// The subject a delegation was granted for.
    DelegatedSubject,
    /// Who owns the resource being acted on.
    ResourceOwner,
}

impl PrincipalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiating => "INITIATING",
            Self::Effective => "EFFECTIVE",
            Self::Agent => "AGENT",
            Self::DelegatedSubject => "DELEGATED_SUBJECT",
            Self::ResourceOwner => "RESOURCE_OWNER",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::Initiating,
            Self::Effective,
            Self::Agent,
            Self::DelegatedSubject,
            Self::ResourceOwner,
        ]
    }
}

/// Closed set of delegation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationKind {
    /// A principal acts on behalf of another, carrying that subject forward.
    OnBehalfOf,
    /// One agent hands a task to another agent.
    AgentHandoff,
    /// A service identity is used to carry out a delegated task.
    ServiceDelegation,
}

impl DelegationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnBehalfOf => "ON_BEHALF_OF",
            Self::AgentHandoff => "AGENT_HANDOFF",
            Self::ServiceDelegation => "SERVICE_DELEGATION",
        }
    }

    pub fn all() -> [Self; 3] {
        [
            Self::OnBehalfOf,
            Self::AgentHandoff,
            Self::ServiceDelegation,
        ]
    }

    /// Whether this kind must carry a delegated subject forward unchanged.
    ///
    /// `ON_BEHALF_OF` exists precisely to preserve a subject; an edge of that
    /// kind that changes the subject has lost the thing it was for.
    pub fn preserves_delegated_subject(self) -> bool {
        matches!(self, Self::OnBehalfOf)
    }
}

/// Where identity and authorization observations came from.
///
/// There is deliberately no `LIVE_IDP`, `OAUTH_SERVER`, `REMOTE_PDP` or
/// `AUTHZEN_ENDPOINT` variant: Cycle 015 observes local, synthetic and replayed
/// context only, and a source that cannot be named cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentitySourceKind {
    /// Identity context declared by the target application.
    DeclaredIdentityContext,
    /// A delegation assertion captured locally as declarative metadata.
    DelegationAssertion,
    /// An authorization decision record captured locally.
    AuthorizationDecisionRecord,
    /// An identity/authority context authored for the synthetic lab.
    SyntheticIdentityContext,
    /// A sanitized local replay trace.
    ReplayTrace,
}

impl IdentitySourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredIdentityContext => "DECLARED_IDENTITY_CONTEXT",
            Self::DelegationAssertion => "DELEGATION_ASSERTION",
            Self::AuthorizationDecisionRecord => "AUTHORIZATION_DECISION_RECORD",
            Self::SyntheticIdentityContext => "SYNTHETIC_IDENTITY_CONTEXT",
            Self::ReplayTrace => "REPLAY_TRACE",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::DeclaredIdentityContext,
            Self::DelegationAssertion,
            Self::AuthorizationDecisionRecord,
            Self::SyntheticIdentityContext,
            Self::ReplayTrace,
        ]
    }

    /// No identity source is authoritative on its own.
    ///
    /// A delegation assertion asserts; it does not thereby grant. Authority
    /// comes from the approved ceiling the scenario declares, and every source
    /// here is untrusted input to be checked against it.
    pub fn is_authoritative(self) -> bool {
        false
    }
}

/// Trust level attached to a source of identity context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustLevel {
    Trusted,
    Untrusted,
    Mixed,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Mixed => "MIXED",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Trusted, Self::Untrusted, Self::Mixed]
    }
}

/// What a corpus entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    /// A vector that should produce a deterministic violation.
    IdentityAttack,
    /// A control that should produce no violation at all.
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentityAttack => "IDENTITY_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }

    pub fn all() -> [Self; 2] {
        [Self::IdentityAttack, Self::BenignControl]
    }
}

/// Parse a closed enum from an operator-supplied token, failing closed.
///
/// Used where a token arrives outside serde (a CLI flag, a manifest field).
/// The error names what was rejected without echoing it into a verdict.
pub fn parse_closed<T: Copy>(
    token: &str,
    candidates: &[(T, &'static str)],
    label: &str,
) -> Result<T> {
    candidates
        .iter()
        .find(|(_, name)| *name == token)
        .map(|(value, _)| *value)
        .ok_or_else(|| {
            let known: Vec<&str> = candidates.iter().map(|(_, name)| *name).collect();
            IdentitySecurityError::refusal(format!(
                "unknown {label} `{token}`; the closed set is {known:?}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn wire_tokens_round_trip_for_every_variant() {
        for kind in PrincipalKind::all() {
            let encoded = serde_json::to_value(kind).expect("serializes");
            assert_eq!(encoded, serde_json::json!(kind.as_str()));
            let decoded: PrincipalKind = serde_json::from_value(encoded).expect("round trips");
            assert_eq!(decoded, kind);
        }
        for role in PrincipalRole::all() {
            assert_eq!(
                serde_json::to_value(role).expect("serializes"),
                serde_json::json!(role.as_str())
            );
        }
        for kind in DelegationKind::all() {
            assert_eq!(
                serde_json::to_value(kind).expect("serializes"),
                serde_json::json!(kind.as_str())
            );
        }
        for source in IdentitySourceKind::all() {
            assert_eq!(
                serde_json::to_value(source).expect("serializes"),
                serde_json::json!(source.as_str())
            );
        }
        for class in ScenarioClass::all() {
            assert_eq!(
                serde_json::to_value(class).expect("serializes"),
                serde_json::json!(class.as_str())
            );
        }
    }

    #[test]
    fn unknown_and_miscased_values_fail_closed() {
        // A default here would be a silent grant, so there is none.
        assert!(serde_json::from_str::<PrincipalKind>("\"ROBOT\"").is_err());
        assert!(serde_json::from_str::<PrincipalKind>("\"human\"").is_err());
        assert!(serde_json::from_str::<DelegationKind>("\"IMPERSONATION\"").is_err());
        assert!(serde_json::from_str::<DelegationKind>("\"on_behalf_of\"").is_err());
        assert!(serde_json::from_str::<PrincipalRole>("\"SUPERUSER\"").is_err());
        assert!(serde_json::from_str::<IdentitySourceKind>("\"LIVE_IDP\"").is_err());
        assert!(serde_json::from_str::<TrustLevel>("\"SEMI_TRUSTED\"").is_err());
        assert!(serde_json::from_str::<CorpusClass>("\"MAYBE\"").is_err());
        assert!(serde_json::from_str::<ScenarioClass>("\"IDENTITY\"").is_err());
    }

    #[test]
    fn no_source_kind_can_name_a_live_provider() {
        // Not "does not use one" — cannot name one.
        let names: BTreeSet<&str> = IdentitySourceKind::all()
            .into_iter()
            .map(IdentitySourceKind::as_str)
            .collect();
        for forbidden in [
            "LIVE_IDP",
            "OAUTH_SERVER",
            "OIDC_PROVIDER",
            "REMOTE_PDP",
            "AUTHZEN_ENDPOINT",
            "LIVE_MCP_SERVER",
            "TOKEN_INTROSPECTION",
        ] {
            assert!(!names.contains(forbidden), "{forbidden} must not exist");
        }
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn no_identity_source_is_authoritative_on_its_own() {
        // A delegation assertion asserts; it does not grant. Authority comes
        // from the approved ceiling, and every source is untrusted input.
        for source in IdentitySourceKind::all() {
            assert!(
                !source.is_authoritative(),
                "{} must not be authoritative",
                source.as_str()
            );
        }
    }

    #[test]
    fn only_a_human_principal_originates_authority() {
        assert!(PrincipalKind::Human.originates_authority());
        for kind in [
            PrincipalKind::Agent,
            PrincipalKind::Workload,
            PrincipalKind::Service,
        ] {
            assert!(
                !kind.originates_authority(),
                "{} must not originate authority",
                kind.as_str()
            );
        }
    }

    #[test]
    fn technical_identities_are_identified_as_such() {
        // These are the kinds whose runtime credentials typically exceed any
        // single user's delegated authority, which is what makes the confused
        // deputy possible.
        assert!(PrincipalKind::Service.is_technical_identity());
        assert!(PrincipalKind::Workload.is_technical_identity());
        assert!(!PrincipalKind::Human.is_technical_identity());
        assert!(!PrincipalKind::Agent.is_technical_identity());
    }

    #[test]
    fn on_behalf_of_is_the_kind_that_must_preserve_a_subject() {
        assert!(DelegationKind::OnBehalfOf.preserves_delegated_subject());
        assert!(!DelegationKind::AgentHandoff.preserves_delegated_subject());
        assert!(!DelegationKind::ServiceDelegation.preserves_delegated_subject());
    }

    #[test]
    fn the_five_scenario_classes_match_the_five_reporting_surfaces() {
        let names: Vec<&str> = ScenarioClass::all()
            .into_iter()
            .map(ScenarioClass::as_str)
            .collect();
        assert_eq!(
            names,
            [
                "PRINCIPAL_BINDING",
                "DELEGATION",
                "PRIVILEGE",
                "TENANT_RESOURCE",
                "AUTHORIZATION_BINDING"
            ]
        );
    }

    #[test]
    fn principal_kinds_and_roles_are_different_vocabularies() {
        // A role is not a kind. If these overlapped, "the AGENT principal" and
        // "the principal in the agent role" would become indistinguishable, and
        // the substitution this cycle detects lives exactly in that gap.
        let kinds: BTreeSet<&str> = PrincipalKind::all()
            .into_iter()
            .map(PrincipalKind::as_str)
            .collect();
        let roles: BTreeSet<&str> = PrincipalRole::all()
            .into_iter()
            .map(PrincipalRole::as_str)
            .collect();
        // AGENT is deliberately in both vocabularies; nothing else is.
        let shared: Vec<&&str> = kinds.intersection(&roles).collect();
        assert_eq!(shared, [&"AGENT"]);
    }

    #[test]
    fn parse_closed_refuses_an_unknown_token_and_names_the_closed_set() {
        let candidates: Vec<(PrincipalKind, &'static str)> = PrincipalKind::all()
            .into_iter()
            .map(|kind| (kind, kind.as_str()))
            .collect();
        assert_eq!(
            parse_closed("SERVICE", &candidates, "principal kind").expect("known"),
            PrincipalKind::Service
        );

        let err = parse_closed("ROOT", &candidates, "principal kind").expect_err("unknown");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("ROOT"));
        assert!(err.to_string().contains("HUMAN"));
    }
}
