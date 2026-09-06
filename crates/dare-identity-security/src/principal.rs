//! Principals and the role bindings that keep them distinct.
//!
//! A principal is declarative metadata: an identifier, a kind, an optional
//! tenant, capability labels and a reference to an authority ceiling. It is
//! never a token, a credential or anything a secret could hide inside.
//!
//! The roles are the point of this module. A scenario names, separately:
//!
//! - the **initiating** principal — who started the request, and the only
//!   source of authority;
//! - the **effective** principal — whose authority the operation actually runs
//!   under;
//! - the **agent** principal — the mediator;
//! - the **delegated subject** — who a delegation was granted for;
//! - the **resource owner** — who owns what is being acted on.
//!
//! Collapsing any two of these is how an agent ends up acting as itself while
//! appearing to act for a user, so the model refuses to let them share a field.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{IdentitySecurityError, Result};
use crate::source::{PrincipalKind, PrincipalRole};

/// One principal in a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_label: Option<String>,
    /// The tenant this principal belongs to, when it belongs to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Capability labels. Descriptive only: holding a label is not authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// The authority ceiling this principal holds, by reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ceiling_id: Option<String>,
}

/// Which principal plays which role in this scenario.
///
/// Initiating and effective are required: a scenario that cannot say who
/// started a request and whose authority it runs under cannot be evaluated at
/// all, and defaulting either one would invent the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBindings {
    pub initiating_principal_id: String,
    pub effective_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_owner_id: Option<String>,
}

/// A versioned, bounded set of principals plus their role bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSet {
    pub schema_version: String,
    pub set_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub principals: Vec<Principal>,
    pub bindings: PrincipalBindings,
}

impl PrincipalSet {
    /// Look one principal up by id.
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.principals.iter().find(|principal| principal.id == id)
    }

    /// Look one principal up, refusing an unknown reference.
    ///
    /// An unknown id is a refusal rather than `None`: treating it as absent
    /// would silently evaluate a scenario against a principal nobody declared.
    pub fn require(&self, id: &str, context: &str) -> Result<&Principal> {
        self.get(id).ok_or_else(|| {
            IdentitySecurityError::unknown_reference(format!(
                "{context} references principal `{id}`, which the principal set does not declare"
            ))
        })
    }

    /// The principal filling a role, when the scenario names one.
    pub fn principal_for(&self, role: PrincipalRole) -> Option<&Principal> {
        let id = match role {
            PrincipalRole::Initiating => Some(&self.bindings.initiating_principal_id),
            PrincipalRole::Effective => Some(&self.bindings.effective_principal_id),
            PrincipalRole::Agent => self.bindings.agent_principal_id.as_ref(),
            PrincipalRole::DelegatedSubject => self.bindings.delegated_subject_id.as_ref(),
            PrincipalRole::ResourceOwner => self.bindings.resource_owner_id.as_ref(),
        }?;
        self.get(id)
    }

    /// The id filling a role, when the scenario names one.
    pub fn id_for(&self, role: PrincipalRole) -> Option<&str> {
        match role {
            PrincipalRole::Initiating => Some(self.bindings.initiating_principal_id.as_str()),
            PrincipalRole::Effective => Some(self.bindings.effective_principal_id.as_str()),
            PrincipalRole::Agent => self.bindings.agent_principal_id.as_deref(),
            PrincipalRole::DelegatedSubject => self.bindings.delegated_subject_id.as_deref(),
            PrincipalRole::ResourceOwner => self.bindings.resource_owner_id.as_deref(),
        }
    }

    /// Every role this scenario actually binds, in a stable order.
    pub fn bound_roles(&self) -> BTreeMap<PrincipalRole, String> {
        let mut bound = BTreeMap::new();
        for role in PrincipalRole::all() {
            if let Some(id) = self.id_for(role) {
                bound.insert(role, id.to_owned());
            }
        }
        bound
    }

    /// Validate structural integrity: bounds, uniqueness and references.
    ///
    /// Runs before anything is evaluated, so a malformed set never reaches an
    /// invariant that would have to guess what it meant.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(IdentitySecurityError::refusal(format!(
                "principal set declares unsupported schema_version `{}`",
                self.schema_version
            )));
        }

        if self.principals.is_empty() {
            return Err(IdentitySecurityError::invalid(
                "a principal set must declare at least one principal",
            ));
        }
        if self.principals.len() as u32 > crate::limits::HARD_MAX_PRINCIPALS {
            return Err(IdentitySecurityError::refusal(format!(
                "principal set declares {} principals, above the hard maximum {}",
                self.principals.len(),
                crate::limits::HARD_MAX_PRINCIPALS
            )));
        }

        let mut seen = BTreeSet::new();
        for principal in &self.principals {
            if principal.id.trim().is_empty() {
                return Err(IdentitySecurityError::invalid("empty principal id"));
            }
            if !seen.insert(principal.id.as_str()) {
                // Two principals sharing an id makes every reference to it
                // ambiguous, and an ambiguous principal reference is exactly
                // the confusion this cycle is meant to detect.
                return Err(IdentitySecurityError::invalid(format!(
                    "duplicate principal id `{}`",
                    principal.id
                )));
            }
        }

        // Every bound role must name a declared principal.
        for role in PrincipalRole::all() {
            if let Some(id) = self.id_for(role) {
                self.require(id, &format!("the {} role", role.as_str()))?;
            }
        }

        Ok(())
    }

    /// Whether the effective principal is the initiating principal.
    ///
    /// Equality of identifiers, never of kinds or labels: two different
    /// principals of the same kind are still two different principals.
    pub fn effective_matches_initiating(&self) -> bool {
        self.bindings.effective_principal_id == self.bindings.initiating_principal_id
    }

    /// Whether the effective principal is the agent itself.
    ///
    /// True here means the agent is acting as itself. That is only legitimate
    /// where the agent genuinely holds the authority in its own right, which
    /// the authority evaluators decide separately.
    pub fn effective_is_agent(&self) -> bool {
        self.bindings
            .agent_principal_id
            .as_ref()
            .is_some_and(|agent| agent == &self.bindings.effective_principal_id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn valid_principal_set_value() -> serde_json::Value {
        json!({
            "schema_version": "1",
            "set_id": "principals-support-desk",
            "title": "a human, the agent acting for them, and a broad service identity",
            "principals": [
                {
                    "id": "user-7",
                    "kind": "HUMAN",
                    "display_label": "support operator",
                    "tenant_id": "tenant-a",
                    "roles": ["support.reader"],
                    "authority_ceiling_id": "authority-user-read"
                },
                {
                    "id": "agent-1",
                    "kind": "AGENT",
                    "tenant_id": "tenant-a",
                    "roles": ["assistant"],
                    "authority_ceiling_id": "authority-agent-none"
                },
                {
                    "id": "svc-index",
                    "kind": "SERVICE",
                    "tenant_id": "tenant-a",
                    "roles": ["index.admin"],
                    "authority_ceiling_id": "authority-service-admin"
                }
            ],
            "bindings": {
                "initiating_principal_id": "user-7",
                "effective_principal_id": "user-7",
                "agent_principal_id": "agent-1",
                "delegated_subject_id": "user-7",
                "resource_owner_id": "user-7"
            }
        })
    }

    pub(crate) fn valid_principal_set() -> PrincipalSet {
        serde_json::from_value(valid_principal_set_value()).expect("principal set decodes")
    }

    #[test]
    fn a_representative_set_validates() {
        let set = valid_principal_set();
        set.validate().expect("valid");
        assert_eq!(set.principals.len(), 3);
        assert!(set.effective_matches_initiating());
        assert!(!set.effective_is_agent());
    }

    #[test]
    fn the_four_principal_kinds_stay_distinct() {
        let set = valid_principal_set();
        assert_eq!(
            set.require("user-7", "test").expect("present").kind,
            PrincipalKind::Human
        );
        assert_eq!(
            set.require("agent-1", "test").expect("present").kind,
            PrincipalKind::Agent
        );
        assert_eq!(
            set.require("svc-index", "test").expect("present").kind,
            PrincipalKind::Service
        );
        // And a kind is never inferred from a role label.
        assert!(set
            .require("svc-index", "test")
            .expect("present")
            .roles
            .contains(&"index.admin".to_owned()));
        assert!(!set
            .require("svc-index", "test")
            .expect("present")
            .kind
            .originates_authority());
    }

    #[test]
    fn every_role_is_addressable_separately() {
        let set = valid_principal_set();
        assert_eq!(set.id_for(PrincipalRole::Initiating), Some("user-7"));
        assert_eq!(set.id_for(PrincipalRole::Effective), Some("user-7"));
        assert_eq!(set.id_for(PrincipalRole::Agent), Some("agent-1"));
        assert_eq!(set.id_for(PrincipalRole::DelegatedSubject), Some("user-7"));
        assert_eq!(set.id_for(PrincipalRole::ResourceOwner), Some("user-7"));
        assert_eq!(set.bound_roles().len(), 5);
    }

    #[test]
    fn one_principal_may_fill_several_roles_without_the_roles_merging() {
        // user-7 is initiating, effective, delegated subject and resource
        // owner. That is ordinary, and the roles stay separately addressable so
        // a later substitution of just one of them is still visible.
        let set = valid_principal_set();
        let bound = set.bound_roles();
        assert_eq!(bound[&PrincipalRole::Initiating], "user-7");
        assert_eq!(bound[&PrincipalRole::ResourceOwner], "user-7");
        assert_ne!(
            bound[&PrincipalRole::Agent],
            bound[&PrincipalRole::Initiating]
        );
    }

    #[test]
    fn a_substituted_effective_principal_is_visible() {
        let mut set = valid_principal_set();
        set.bindings.effective_principal_id = "agent-1".to_owned();
        set.validate().expect("still structurally valid");

        assert!(!set.effective_matches_initiating());
        assert!(
            set.effective_is_agent(),
            "the agent is now acting as itself rather than for the user"
        );
    }

    #[test]
    fn an_unknown_principal_reference_is_a_refusal() {
        let mut set = valid_principal_set();
        set.bindings.delegated_subject_id = Some("ghost".to_owned());
        let err = set
            .validate()
            .expect_err("unknown reference must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn a_duplicate_principal_id_fails_closed() {
        // Two principals sharing an id makes every reference ambiguous.
        let mut set = valid_principal_set();
        let mut clone = set.principals[0].clone();
        clone.kind = PrincipalKind::Service;
        set.principals.push(clone);
        let err = set.validate().expect_err("duplicate id must be refused");
        assert!(err.to_string().contains("duplicate principal id"));
    }

    #[test]
    fn the_principal_bound_is_enforced_and_not_clamped() {
        let mut set = valid_principal_set();
        let template = set.principals[0].clone();
        for index in 0..20 {
            let mut principal = template.clone();
            principal.id = format!("filler-{index}");
            set.principals.push(principal);
        }
        let err = set.validate().expect_err("over-limit set must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("above the hard maximum 16"));
    }

    #[test]
    fn exactly_the_maximum_number_of_principals_is_allowed() {
        let mut set = valid_principal_set();
        let template = set.principals[0].clone();
        while (set.principals.len() as u32) < crate::limits::HARD_MAX_PRINCIPALS {
            let mut principal = template.clone();
            principal.id = format!("filler-{}", set.principals.len());
            set.principals.push(principal);
        }
        assert_eq!(set.principals.len(), 16);
        set.validate().expect("the boundary itself is allowed");
    }

    #[test]
    fn an_empty_principal_set_is_refused() {
        let mut set = valid_principal_set();
        set.principals.clear();
        assert!(set.validate().is_err());
    }

    #[test]
    fn initiating_and_effective_are_required_not_defaulted() {
        // Defaulting either would invent the answer to the question the
        // principal invariants ask.
        let mut value = valid_principal_set_value();
        value["bindings"]
            .as_object_mut()
            .expect("object")
            .remove("effective_principal_id");
        assert!(serde_json::from_value::<PrincipalSet>(value).is_err());

        let mut value = valid_principal_set_value();
        value["bindings"]
            .as_object_mut()
            .expect("object")
            .remove("initiating_principal_id");
        assert!(serde_json::from_value::<PrincipalSet>(value).is_err());
    }

    #[test]
    fn a_principal_cannot_carry_a_credential_or_executable_field() {
        for hostile in [
            json!({"id": "user-7", "kind": "HUMAN", "token": "eyJhbGciOi"}),
            json!({"id": "user-7", "kind": "HUMAN", "bearer": "abc"}),
            json!({"id": "user-7", "kind": "HUMAN", "client_secret": "s3cret"}),
            json!({"id": "user-7", "kind": "HUMAN", "private_key": "-----BEGIN"}),
            json!({"id": "user-7", "kind": "HUMAN", "callback": "http://x"}),
            json!({"id": "user-7", "kind": "HUMAN", "shell": "id"}),
        ] {
            assert!(
                serde_json::from_value::<Principal>(hostile.clone()).is_err(),
                "must refuse: {hostile}"
            );
        }
    }

    #[test]
    fn an_unsupported_schema_version_is_refused() {
        let mut set = valid_principal_set();
        set.schema_version = "2".to_owned();
        let err = set.validate().expect_err("unsupported version");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_role_that_names_nothing_stays_unbound_rather_than_defaulting() {
        // An optional role left out is genuinely absent. It must not silently
        // fall back to the initiating principal, which would manufacture a
        // delegated subject that the scenario never claimed.
        let mut value = valid_principal_set_value();
        value["bindings"]
            .as_object_mut()
            .expect("object")
            .remove("delegated_subject_id");
        let set: PrincipalSet = serde_json::from_value(value).expect("decodes");
        set.validate().expect("valid");

        assert_eq!(set.id_for(PrincipalRole::DelegatedSubject), None);
        assert_eq!(set.bound_roles().len(), 4);
    }
}
