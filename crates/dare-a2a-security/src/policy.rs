//! The local policy, and the asymmetry it creates.
//!
//! Every other document this engine reads describes **what a peer is**. This is
//! the only one that describes **what was approved**, and that asymmetry is the
//! entire trust model.
//!
//! ```text
//! external agent listed != trusted peer
//! declared security scheme != successful authentication
//! tenant routing value != proof of tenant authorization
//! ```
//!
//! An Agent Card can say a peer is provided by Acme; it cannot say Acme was
//! approved. A message can carry `tenant: tenant-a`; that is a routing value the
//! sender chose. Approval lives here, in a file the deployment controls.
//!
//! # What a policy may not do
//!
//! It may not declare a verdict, an expected finding, or anything shaped like
//! one. The evaluator is the only verdict authority, and a policy that could
//! state an outcome would reduce the engine to agreeing with whoever wrote the
//! policy — which is the failure the whole paired-fixture discipline exists to
//! prevent.
//!
//! The refusal is structural rather than a check: there is no field for it, and
//! `deny_unknown_fields` means adding one fails to decode.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{A2aSecurityError, Result};
use crate::source::{DataSensitivity, SecuritySchemeKind, TransportKind};

/// What the deployment approved about one peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPeer {
    pub peer_id: String,
    /// The logical agent the deployment approved for this peer.
    ///
    /// Required before I02 may report a positive binding. A peer naming its own
    /// logical agent proves nothing: "the peer said it is X" is not "X is who
    /// we approved for this role".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_logical_agent: Option<String>,
    /// The provider the deployment expects the card to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_provider: Option<String>,
    /// The card digest the deployment pinned, if it pinned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_card_digest: Option<String>,
    /// The audience an authentication for this peer must name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_audience: Option<String>,
    /// Interface URLs the deployment approved. Compared as strings; never
    /// contacted.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_interfaces: BTreeSet<String>,
    /// Security scheme kinds the deployment accepts for this peer.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_scheme_kinds: BTreeSet<SecuritySchemeKind>,
    /// Signer key ids the deployment approved for this peer's card.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_signers: BTreeSet<String>,
    /// Whether an authentication for this peer must establish a delegated
    /// subject rather than only a service principal.
    ///
    /// Defaults to `false` so legitimate service-to-service authentication is
    /// not failed for lacking a user it was never meant to carry. Set it where
    /// the deployment expects the peer to act *for* somebody, and a service
    /// principal can no longer quietly stand in for that somebody.
    #[serde(default)]
    pub requires_delegated_identity: bool,
}

impl ApprovedPeer {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.peer_id, "an approved peer id")?;
        if let Some(provider) = &self.expected_provider {
            assert_safe_identifier(provider, "an expected provider")?;
        }
        if let Some(digest) = &self.expected_card_digest {
            crate::canonical::assert_digest_shape(digest, "an expected card digest")?;
        }
        if let Some(audience) = &self.expected_audience {
            assert_safe_identifier(audience, "an expected audience")?;
        }
        if let Some(agent) = &self.expected_logical_agent {
            assert_safe_identifier(agent, "an expected logical agent")?;
        }
        for signer in &self.approved_signers {
            assert_safe_identifier(signer, "an approved signer")?;
        }
        Ok(())
    }
}

/// Which principals may invoke which skills on which peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillGrant {
    pub peer_id: String,
    pub skill_id: String,
    /// Subjects allowed to invoke it. A subject is a principal or a delegated
    /// user — never an endpoint and never a card provider.
    pub allowed_subjects: BTreeSet<String>,
}

impl SkillGrant {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.peer_id, "a skill grant peer id")?;
        assert_safe_identifier(&self.skill_id, "a granted skill id")?;
        if self.allowed_subjects.is_empty() {
            return Err(A2aSecurityError::invalid(format!(
                "skill grant `{}`/`{}` allows nobody; an empty grant is indistinguishable from \
                 no grant and reads as one",
                self.peer_id, self.skill_id
            )));
        }
        for subject in &self.allowed_subjects {
            assert_safe_identifier(subject, "an allowed subject")?;
        }
        Ok(())
    }
}

/// Which subjects belong to which tenant.
///
/// The deployment's answer to "who is actually in this tenant", against which a
/// message's tenant *claim* is checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPolicy {
    /// Subject → tenant. A subject absent here has no proven tenant, which is a
    /// gap rather than membership of the tenant it claimed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subject_tenants: BTreeMap<String, String>,
    /// Peers a tenant may communicate with.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tenant_peers: BTreeMap<String, BTreeSet<String>>,
}

impl TenantPolicy {
    pub fn validate(&self) -> Result<()> {
        for (subject, tenant) in &self.subject_tenants {
            assert_safe_identifier(subject, "a tenant policy subject")?;
            assert_safe_identifier(tenant, "a tenant policy tenant")?;
        }
        for (tenant, peers) in &self.tenant_peers {
            assert_safe_identifier(tenant, "a tenant")?;
            for peer in peers {
                assert_safe_identifier(peer, "a tenant peer")?;
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The tenant a subject actually belongs to, according to the deployment.
    ///
    /// `None` means the policy says nothing about this subject — a gap, and
    /// deliberately not "the tenant they claimed".
    pub fn tenant_of(&self, subject: &str) -> Option<&str> {
        self.subject_tenants.get(subject).map(String::as_str)
    }

    /// Whether a tenant is allowed to talk to a peer at all.
    ///
    /// `None` when the policy lists no peers for the tenant, which is a gap.
    /// An empty list would be universal denial, and denying everything makes
    /// every exchange a finding — indistinguishable from a broken engine.
    pub fn tenant_may_reach(&self, tenant: &str, peer_id: &str) -> Option<bool> {
        self.tenant_peers
            .get(tenant)
            .map(|peers| peers.contains(peer_id))
    }
}

/// What may be disclosed to whom.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataScopePolicy {
    /// The most sensitive label each peer may receive.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_max_sensitivity: BTreeMap<String, DataSensitivity>,
    /// Destinations approved for onward disclosure. Compared as strings.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_destinations: BTreeSet<String>,
}

impl DataScopePolicy {
    pub fn validate(&self) -> Result<()> {
        for peer in self.peer_max_sensitivity.keys() {
            assert_safe_identifier(peer, "a data scope peer")?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The ceiling for a peer, or `None` when policy says nothing.
    pub fn ceiling_for(&self, peer_id: &str) -> Option<DataSensitivity> {
        self.peer_max_sensitivity.get(peer_id).copied()
    }
}

/// Which operations are safe to repeat, and under what evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPolicy {
    /// Skills the deployment declares idempotent, so a repeat is safe.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub idempotent_skills: BTreeSet<String>,
    /// Whether a repeated state-changing operation requires an idempotency key.
    #[serde(default)]
    pub requires_idempotency_key: bool,
}

impl ReplayPolicy {
    pub fn validate(&self) -> Result<()> {
        for skill in &self.idempotent_skills {
            assert_safe_identifier(skill, "an idempotent skill")?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Which protocol versions and interfaces may be used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_versions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_transports: BTreeSet<TransportKind>,
    /// The lowest version the deployment will accept.
    ///
    /// Separate from the approved set because a downgrade *within* the approved
    /// set is still a downgrade, and an operator wants to know which of the two
    /// happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<String>,
}

impl ProtocolPolicy {
    pub fn validate(&self) -> Result<()> {
        for version in &self.approved_versions {
            assert_safe_identifier(version, "an approved protocol version")?;
        }
        if let Some(minimum) = &self.minimum_version {
            assert_safe_identifier(minimum, "a minimum protocol version")?;
            if !self.approved_versions.is_empty() && !self.approved_versions.contains(minimum) {
                return Err(A2aSecurityError::invalid(
                    "the minimum protocol version is not in the approved set; a floor outside \
                     the set is a floor nothing can stand on"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Which extensions may be used, and which may bear authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_extensions: BTreeSet<String>,
    /// Extensions the deployment allows to affect authorization or identity.
    ///
    /// A separate, smaller set on purpose: approving an extension to *run* is
    /// not approving it to *decide*.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub authority_bearing_extensions: BTreeSet<String>,
}

impl ExtensionPolicy {
    pub fn validate(&self) -> Result<()> {
        for extension in &self.approved_extensions {
            assert_safe_identifier(extension, "an approved extension")?;
        }
        for extension in &self.authority_bearing_extensions {
            assert_safe_identifier(extension, "an authority-bearing extension")?;
            if !self.approved_extensions.contains(extension) {
                return Err(A2aSecurityError::invalid(format!(
                    "extension `{extension}` may bear authority but is not approved at all; \
                     approving something to decide without approving it to run is a gap in the \
                     policy rather than a stricter policy"
                )));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Where push notifications may be sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationPolicy {
    /// Callback destinations the deployment approved. Compared as strings and
    /// never contacted.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_destinations: BTreeSet<String>,
    /// The most sensitive label a push notification may carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity: Option<DataSensitivity>,
}

impl PushNotificationPolicy {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// The local A2A policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aPolicy {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_peers: BTreeSet<ApprovedPeer>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub skill_grants: BTreeSet<SkillGrant>,
    #[serde(default, skip_serializing_if = "TenantPolicy::is_empty")]
    pub tenant_policy: TenantPolicy,
    #[serde(default, skip_serializing_if = "DataScopePolicy::is_empty")]
    pub data_scope_policy: DataScopePolicy,
    #[serde(default, skip_serializing_if = "ReplayPolicy::is_empty")]
    pub replay_policy: ReplayPolicy,
    #[serde(default, skip_serializing_if = "ProtocolPolicy::is_empty")]
    pub protocol_policy: ProtocolPolicy,
    #[serde(default, skip_serializing_if = "ExtensionPolicy::is_empty")]
    pub extension_policy: ExtensionPolicy,
    #[serde(default, skip_serializing_if = "PushNotificationPolicy::is_empty")]
    pub push_notification_policy: PushNotificationPolicy,
}

impl A2aPolicy {
    pub fn validate(&self) -> Result<()> {
        if !self.schema_version.is_empty() && self.schema_version != "1" {
            return Err(A2aSecurityError::schema(format!(
                "policy schema version `{}` is not supported; guessing what an unknown version \
                 meant is how an approved expectation quietly changes",
                self.schema_version
            )));
        }
        if let Some(id) = &self.policy_id {
            assert_safe_identifier(id, "a policy id")?;
        }
        for peer in &self.approved_peers {
            peer.validate()?;
        }
        for grant in &self.skill_grants {
            grant.validate()?;
        }
        self.tenant_policy.validate()?;
        self.data_scope_policy.validate()?;
        self.replay_policy.validate()?;
        self.protocol_policy.validate()?;
        self.extension_policy.validate()?;
        self.push_notification_policy.validate()?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub fn approved_peer(&self, peer_id: &str) -> Option<&ApprovedPeer> {
        self.approved_peers
            .iter()
            .find(|peer| peer.peer_id == peer_id)
    }

    /// Whether a subject may invoke a skill on a peer.
    ///
    /// Three answers. `None` means no grant exists for that peer and skill at
    /// all, which is a gap — and deliberately not a denial, because an absent
    /// policy is the absence of a decision rather than a decision to refuse.
    pub fn skill_allows(&self, peer_id: &str, skill_id: &str, subject: &str) -> Option<bool> {
        self.skill_grants
            .iter()
            .find(|grant| grant.peer_id == peer_id && grant.skill_id == skill_id)
            .map(|grant| grant.allowed_subjects.contains(subject))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn policy() -> A2aPolicy {
        A2aPolicy {
            schema_version: "1".to_owned(),
            policy_id: Some("policy-1".to_owned()),
            approved_peers: BTreeSet::from([ApprovedPeer {
                peer_id: "planner".to_owned(),
                expected_logical_agent: Some("planner".to_owned()),
                expected_provider: Some("acme".to_owned()),
                expected_card_digest: None,
                expected_audience: Some("local-orchestrator".to_owned()),
                approved_interfaces: BTreeSet::from(["https://peer.example/a2a".to_owned()]),
                approved_scheme_kinds: BTreeSet::from([
                    SecuritySchemeKind::OAuth2AuthorizationCode,
                ]),
                approved_signers: BTreeSet::from(["key-1".to_owned()]),
                requires_delegated_identity: true,
            }]),
            skill_grants: BTreeSet::from([SkillGrant {
                peer_id: "planner".to_owned(),
                skill_id: "summarize".to_owned(),
                allowed_subjects: BTreeSet::from(["user-alice".to_owned()]),
            }]),
            tenant_policy: TenantPolicy {
                subject_tenants: BTreeMap::from([("user-alice".to_owned(), "tenant-a".to_owned())]),
                tenant_peers: BTreeMap::from([(
                    "tenant-a".to_owned(),
                    BTreeSet::from(["planner".to_owned()]),
                )]),
            },
            data_scope_policy: DataScopePolicy {
                peer_max_sensitivity: BTreeMap::from([(
                    "planner".to_owned(),
                    DataSensitivity::Internal,
                )]),
                approved_destinations: BTreeSet::from(["https://callback.example/hook".to_owned()]),
            },
            replay_policy: ReplayPolicy {
                idempotent_skills: BTreeSet::from(["summarize".to_owned()]),
                requires_idempotency_key: true,
            },
            protocol_policy: ProtocolPolicy {
                approved_versions: BTreeSet::from(["1.0.0".to_owned()]),
                approved_transports: BTreeSet::from([TransportKind::JsonRpc]),
                minimum_version: Some("1.0.0".to_owned()),
            },
            extension_policy: ExtensionPolicy {
                approved_extensions: BTreeSet::from(["ext-trace".to_owned()]),
                authority_bearing_extensions: BTreeSet::new(),
            },
            push_notification_policy: PushNotificationPolicy {
                approved_destinations: BTreeSet::from(["https://callback.example/hook".to_owned()]),
                max_sensitivity: Some(DataSensitivity::Internal),
            },
        }
    }

    #[test]
    fn the_fixture_policy_validates() {
        policy().validate().expect("valid");
    }

    #[test]
    fn a_policy_cannot_declare_a_verdict() {
        // Structural rather than checked: there is no field, and
        // `deny_unknown_fields` means adding one fails to decode. A policy that
        // could state an outcome would reduce the engine to agreeing with
        // whoever wrote the policy.
        for hostile in [
            serde_json::json!({ "schema_version": "1", "expected_verdict": "PASS" }),
            serde_json::json!({ "schema_version": "1", "is_secure": true }),
            serde_json::json!({ "schema_version": "1", "expected_findings": [] }),
            serde_json::json!({ "schema_version": "1", "should_fail": false }),
        ] {
            assert!(
                serde_json::from_value::<A2aPolicy>(hostile).is_err(),
                "a policy declared its own outcome"
            );
        }
    }

    #[test]
    fn an_unsupported_policy_version_is_refused_rather_than_guessed() {
        let mut policy = policy();
        policy.schema_version = "2".to_owned();
        assert!(policy.validate().expect_err("refused").is_refusal());
    }

    #[test]
    fn an_absent_grant_is_a_gap_and_not_a_denial() {
        // An absent policy is the absence of a decision, not a decision to
        // refuse. Denying everything would make every exchange a finding.
        let policy = policy();
        assert_eq!(
            policy.skill_allows("planner", "summarize", "user-alice"),
            Some(true)
        );
        assert_eq!(
            policy.skill_allows("planner", "summarize", "user-mallory"),
            Some(false)
        );
        assert_eq!(
            policy.skill_allows("planner", "transfer-funds", "user-alice"),
            None
        );
        assert_eq!(
            policy.skill_allows("other-peer", "summarize", "user-alice"),
            None
        );
    }

    #[test]
    fn an_empty_grant_is_refused_rather_than_stored() {
        // A grant allowing nobody is indistinguishable from no grant and reads
        // as one, so it would be a denial wearing an approval's clothes.
        let grant = SkillGrant {
            peer_id: "planner".to_owned(),
            skill_id: "summarize".to_owned(),
            allowed_subjects: BTreeSet::new(),
        };
        assert!(grant.validate().is_err());
    }

    #[test]
    fn a_subject_the_tenant_policy_does_not_know_has_no_proven_tenant() {
        // Deliberately not "the tenant they claimed". A routing value is what
        // the sender chose.
        let policy = policy();
        assert_eq!(
            policy.tenant_policy.tenant_of("user-alice"),
            Some("tenant-a")
        );
        assert_eq!(policy.tenant_policy.tenant_of("user-mallory"), None);
    }

    #[test]
    fn a_tenant_with_no_listed_peers_is_a_gap_rather_than_universal_denial() {
        let policy = policy();
        assert_eq!(
            policy.tenant_policy.tenant_may_reach("tenant-a", "planner"),
            Some(true)
        );
        assert_eq!(
            policy.tenant_policy.tenant_may_reach("tenant-a", "other"),
            Some(false)
        );
        assert_eq!(
            policy
                .tenant_policy
                .tenant_may_reach("tenant-unknown", "planner"),
            None
        );
    }

    #[test]
    fn an_extension_may_not_bear_authority_without_being_approved_at_all() {
        // Approving something to decide without approving it to run is a gap in
        // the policy rather than a stricter policy.
        let mut hostile = policy();
        hostile
            .extension_policy
            .authority_bearing_extensions
            .insert("ext-unapproved".to_owned());
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn a_minimum_version_outside_the_approved_set_is_refused() {
        // A floor outside the set is a floor nothing can stand on.
        let mut hostile = policy();
        hostile.protocol_policy.minimum_version = Some("0.9.0".to_owned());
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn approving_a_skill_to_run_is_separate_from_approving_an_extension_to_decide() {
        // Two sets, and the second is a subset of the first by construction.
        let policy = policy();
        assert!(policy
            .extension_policy
            .approved_extensions
            .contains("ext-trace"));
        assert!(policy
            .extension_policy
            .authority_bearing_extensions
            .is_empty());
    }

    #[test]
    fn a_hostile_identifier_in_the_policy_is_refused() {
        let mut hostile = policy();
        hostile
            .tenant_policy
            .subject_tenants
            .insert("user\u{202E}alice".to_owned(), "tenant-a".to_owned());
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn policy_collections_are_order_independent() {
        // The policy is part of the binding, so two equivalent policies must
        // digest identically or a reordering would read as a change.
        let mut left = policy();
        left.data_scope_policy.approved_destinations =
            BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()]);
        let mut right = policy();
        right.data_scope_policy.approved_destinations =
            BTreeSet::from(["c".to_owned(), "a".to_owned(), "b".to_owned()]);
        assert_eq!(
            crate::canonical::digest(&left).unwrap(),
            crate::canonical::digest(&right).unwrap()
        );
    }
}
