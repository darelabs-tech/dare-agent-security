//! The fourteen invariants, the scenarios that stage them, and the property
//! mapping.
//!
//! # Fourteen, and exactly fourteen
//!
//! `DESIGN.md` fixes the list I01–I14. A fifteenth added during execution would
//! change what the cycle claims to have proved without anyone reviewing the
//! claim, and `the_registry_holds_exactly_the_fourteen_approved_invariants`
//! fails if the count moves.
//!
//! # Why several invariants share a property
//!
//! Twelve properties carry fourteen invariants. `MESSAGE_AUTHENTICITY` covers
//! both I03 (the signature binds this message) and I04 (the mechanism used
//! satisfied an approved requirement), because both are what a reader of that
//! property came to ask. `AUTHORITY_PROPAGATION` covers I06 and I08 for the
//! same reason: content becoming instruction and authority widening across a
//! hop are two ways the same boundary fails.
//!
//! Splitting them into fourteen properties would make the registry describe the
//! engine's internals rather than the risk.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{A2aSecurityError, Result};
use crate::source::{A2aMode, ReferenceBehavior, ScenarioClass};

/// The risk family every property in this cycle belongs to.
///
/// Frozen by Cycle 012. This cycle adds properties to it and creates no second
/// family.
pub const RISK_FAMILY: &str = "INSECURE_INTER_AGENT_COMMUNICATION";

/// The property namespace. There is deliberately no top-level `A2A.*`.
pub const PROPERTY_PREFIX: &str = "AGENT.A2A.";

/// One deterministic invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum A2aInvariant {
    /// I01. The card in hand is the card policy approved.
    DiscoveryBindingPreserved,
    /// I02. The authenticated party is the intended agent, audience and tenant.
    PeerIdentityBound,
    /// I03. Authentication evidence binds the exact message received.
    MessageAuthenticityEstablished,
    /// I04. The mechanism used satisfies an approved requirement.
    SecurityRequirementSatisfied,
    /// I05. The effective subject may invoke the skill that was invoked.
    SkillAuthorized,
    /// I06. Peer-controlled content stayed data.
    MessageAuthorityBoundaryPreserved,
    /// I07. Task, context and initiating principal stayed the same.
    TaskContextBindingPreserved,
    /// I08. Authority held or narrowed across every hop.
    AuthorityPropagationBounded,
    /// I09. The exchange stayed inside the approved tenant.
    TenantBoundaryPreserved,
    /// I10. Disclosure stayed inside what policy allowed.
    DataScopeBoundaryPreserved,
    /// I11. A repeated action was proven safe to repeat.
    ReplayBoundaryPreserved,
    /// I12. The version and interface used were ones policy permits.
    ProtocolNegotiationIntegrityPreserved,
    /// I13. Extensions in use were declared, approved and non-authoritative.
    ExtensionTrustBoundaryPreserved,
    /// I14. A callback configuration discloses no further than approved.
    PushNotificationBoundaryPreserved,
}

impl A2aInvariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiscoveryBindingPreserved => "DISCOVERY_BINDING_PRESERVED",
            Self::PeerIdentityBound => "PEER_IDENTITY_BOUND",
            Self::MessageAuthenticityEstablished => "MESSAGE_AUTHENTICITY_ESTABLISHED",
            Self::SecurityRequirementSatisfied => "SECURITY_REQUIREMENT_SATISFIED",
            Self::SkillAuthorized => "SKILL_AUTHORIZED",
            Self::MessageAuthorityBoundaryPreserved => "MESSAGE_AUTHORITY_BOUNDARY_PRESERVED",
            Self::TaskContextBindingPreserved => "TASK_CONTEXT_BINDING_PRESERVED",
            Self::AuthorityPropagationBounded => "AUTHORITY_PROPAGATION_BOUNDED",
            Self::TenantBoundaryPreserved => "TENANT_BOUNDARY_PRESERVED",
            Self::DataScopeBoundaryPreserved => "DATA_SCOPE_BOUNDARY_PRESERVED",
            Self::ReplayBoundaryPreserved => "REPLAY_BOUNDARY_PRESERVED",
            Self::ProtocolNegotiationIntegrityPreserved => {
                "PROTOCOL_NEGOTIATION_INTEGRITY_PRESERVED"
            }
            Self::ExtensionTrustBoundaryPreserved => "EXTENSION_TRUST_BOUNDARY_PRESERVED",
            Self::PushNotificationBoundaryPreserved => "PUSH_NOTIFICATION_BOUNDARY_PRESERVED",
        }
    }

    /// The approved identifier, I01 through I14.
    pub fn design_id(self) -> &'static str {
        match self {
            Self::DiscoveryBindingPreserved => "I01",
            Self::PeerIdentityBound => "I02",
            Self::MessageAuthenticityEstablished => "I03",
            Self::SecurityRequirementSatisfied => "I04",
            Self::SkillAuthorized => "I05",
            Self::MessageAuthorityBoundaryPreserved => "I06",
            Self::TaskContextBindingPreserved => "I07",
            Self::AuthorityPropagationBounded => "I08",
            Self::TenantBoundaryPreserved => "I09",
            Self::DataScopeBoundaryPreserved => "I10",
            Self::ReplayBoundaryPreserved => "I11",
            Self::ProtocolNegotiationIntegrityPreserved => "I12",
            Self::ExtensionTrustBoundaryPreserved => "I13",
            Self::PushNotificationBoundaryPreserved => "I14",
        }
    }

    /// The fourteen, in the order `DESIGN.md` fixes them.
    pub fn all() -> [Self; 14] {
        [
            Self::DiscoveryBindingPreserved,
            Self::PeerIdentityBound,
            Self::MessageAuthenticityEstablished,
            Self::SecurityRequirementSatisfied,
            Self::SkillAuthorized,
            Self::MessageAuthorityBoundaryPreserved,
            Self::TaskContextBindingPreserved,
            Self::AuthorityPropagationBounded,
            Self::TenantBoundaryPreserved,
            Self::DataScopeBoundaryPreserved,
            Self::ReplayBoundaryPreserved,
            Self::ProtocolNegotiationIntegrityPreserved,
            Self::ExtensionTrustBoundaryPreserved,
            Self::PushNotificationBoundaryPreserved,
        ]
    }

    /// The registry property this invariant reports under.
    pub fn property_id(self) -> &'static str {
        match self {
            Self::DiscoveryBindingPreserved => "AGENT.A2A.DISCOVERY_TRUST_BOUNDARY",
            Self::PeerIdentityBound => "AGENT.A2A.PEER_IDENTITY_BINDING",
            Self::MessageAuthenticityEstablished | Self::SecurityRequirementSatisfied => {
                "AGENT.A2A.MESSAGE_AUTHENTICITY"
            }
            Self::SkillAuthorized => "AGENT.A2A.SKILL_AUTHORIZATION",
            Self::MessageAuthorityBoundaryPreserved | Self::AuthorityPropagationBounded => {
                "AGENT.A2A.AUTHORITY_PROPAGATION"
            }
            Self::TaskContextBindingPreserved => "AGENT.A2A.MESSAGE_CONTEXT_BINDING",
            Self::TenantBoundaryPreserved => "AGENT.A2A.TENANT_BOUNDARY",
            Self::DataScopeBoundaryPreserved => "AGENT.A2A.DATA_SCOPE_BOUNDARY",
            Self::ReplayBoundaryPreserved => "AGENT.A2A.REPLAY_BOUNDARY",
            Self::ProtocolNegotiationIntegrityPreserved => {
                "AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY"
            }
            Self::ExtensionTrustBoundaryPreserved => "AGENT.A2A.EXTENSION_TRUST_BOUNDARY",
            Self::PushNotificationBoundaryPreserved => "AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY",
        }
    }

    /// The surface this invariant belongs to.
    pub fn scenario_class(self) -> ScenarioClass {
        match self {
            Self::DiscoveryBindingPreserved => ScenarioClass::DiscoveryBinding,
            Self::PeerIdentityBound => ScenarioClass::PeerIdentity,
            Self::MessageAuthenticityEstablished => ScenarioClass::MessageAuthenticity,
            Self::SecurityRequirementSatisfied => ScenarioClass::SecurityRequirement,
            Self::SkillAuthorized => ScenarioClass::SkillAuthorization,
            Self::MessageAuthorityBoundaryPreserved => ScenarioClass::MessageAuthority,
            Self::TaskContextBindingPreserved => ScenarioClass::TaskContextBinding,
            Self::AuthorityPropagationBounded => ScenarioClass::AuthorityPropagation,
            Self::TenantBoundaryPreserved => ScenarioClass::TenantBoundary,
            Self::DataScopeBoundaryPreserved => ScenarioClass::DataScope,
            Self::ReplayBoundaryPreserved => ScenarioClass::ReplayBoundary,
            Self::ProtocolNegotiationIntegrityPreserved => ScenarioClass::ProtocolNegotiation,
            Self::ExtensionTrustBoundaryPreserved => ScenarioClass::ExtensionTrust,
            Self::PushNotificationBoundaryPreserved => ScenarioClass::PushNotification,
        }
    }

    /// The twelve distinct properties the fourteen invariants report under.
    pub fn properties() -> BTreeSet<&'static str> {
        Self::all()
            .iter()
            .map(|invariant| invariant.property_id())
            .collect()
    }
}

/// A local scenario that stages evidence for evaluation.
///
/// Note what it cannot say. There is no `expected_verdict`, no
/// `expected_findings`, no `is_secure`, no `should_fail` and no evaluator
/// override — the evaluator is the only verdict authority, and a scenario able
/// to state an outcome would turn every paired fixture into a test of the
/// fixture author.
///
/// There is also no executable hook: no command, no script path, no callback,
/// and no endpoint. A scenario describes local evidence; it runs nothing and
/// reaches nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aScenario {
    pub scenario_id: String,
    pub class: ScenarioClass,
    pub mode: A2aMode,
    /// The invariant this scenario is built to exercise.
    ///
    /// A coverage selector, never a verdict. Every applicable invariant is
    /// still evaluated, and a concrete failure of another one is retained.
    pub primary_invariant: A2aInvariant,
    /// Local evidence files this scenario reads, relative to the corpus root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_files: Vec<String>,
    /// How a staged fixture should behave, where one is staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_behavior: Option<ReferenceBehavior>,
    /// What the scenario is for, in operator terms.
    pub description: String,
}

impl A2aScenario {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.scenario_id, "scenario id")?;
        if self.description.trim().is_empty() {
            return Err(A2aSecurityError::invalid(format!(
                "scenario `{}` has no description; a fixture nobody can explain is a fixture \
                 nobody can review",
                self.scenario_id
            )));
        }
        for file in &self.evidence_files {
            assert_safe_identifier(file, "evidence file")?;
        }
        Ok(())
    }

    pub fn is_synthetic(&self) -> bool {
        self.mode == A2aMode::LocalSynthetic
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn scenario(id: &str, invariant: A2aInvariant) -> A2aScenario {
        A2aScenario {
            scenario_id: id.to_owned(),
            class: invariant.scenario_class(),
            mode: A2aMode::Simulated,
            primary_invariant: invariant,
            evidence_files: Vec::new(),
            reference_behavior: None,
            description: "a fixture".to_owned(),
        }
    }

    #[test]
    fn the_registry_holds_exactly_the_fourteen_approved_invariants() {
        // `DESIGN.md` fixes I01 through I14. A fifteenth added during execution
        // would change what the cycle claims to have proved without anyone
        // reviewing the claim.
        assert_eq!(A2aInvariant::all().len(), 14);
        let names: BTreeSet<&str> = A2aInvariant::all()
            .iter()
            .map(|invariant| invariant.as_str())
            .collect();
        assert_eq!(names.len(), 14, "two invariants share a name");

        let design_ids: Vec<&str> = A2aInvariant::all()
            .iter()
            .map(|invariant| invariant.design_id())
            .collect();
        assert_eq!(
            design_ids,
            [
                "I01", "I02", "I03", "I04", "I05", "I06", "I07", "I08", "I09", "I10", "I11", "I12",
                "I13", "I14"
            ]
        );
    }

    #[test]
    fn every_invariant_maps_into_the_frozen_namespace() {
        // Cycle 012 owns the namespace. A parallel top-level `A2A.*` would give
        // a reader two places to look for one risk.
        for invariant in A2aInvariant::all() {
            assert!(
                invariant.property_id().starts_with(PROPERTY_PREFIX),
                "{} left the frozen namespace",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn fourteen_invariants_report_under_twelve_properties() {
        // Two pairs share deliberately. `MESSAGE_AUTHENTICITY` covers both the
        // signature binding and whether the mechanism satisfied a requirement;
        // `AUTHORITY_PROPAGATION` covers both content becoming instruction and
        // authority widening across a hop. Splitting them would make the
        // registry describe the engine's internals rather than the risk.
        assert_eq!(A2aInvariant::properties().len(), 12);
    }

    #[test]
    fn the_two_inherited_properties_carry_two_invariants_each() {
        let authenticity: Vec<&str> = A2aInvariant::all()
            .iter()
            .filter(|invariant| invariant.property_id() == "AGENT.A2A.MESSAGE_AUTHENTICITY")
            .map(|invariant| invariant.design_id())
            .collect();
        assert_eq!(authenticity, ["I03", "I04"]);

        let authority: Vec<&str> = A2aInvariant::all()
            .iter()
            .filter(|invariant| invariant.property_id() == "AGENT.A2A.AUTHORITY_PROPAGATION")
            .map(|invariant| invariant.design_id())
            .collect();
        assert_eq!(authority, ["I06", "I08"]);
    }

    #[test]
    fn every_scenario_class_has_exactly_one_invariant_as_its_primary_surface() {
        // A surface with no invariant behind it would be a heading in a report
        // with nothing under it.
        let classes: BTreeSet<&str> = A2aInvariant::all()
            .iter()
            .map(|invariant| invariant.scenario_class().as_str())
            .collect();
        assert_eq!(classes.len(), ScenarioClass::all().len());
    }

    #[test]
    fn an_unknown_invariant_fails_to_decode() {
        assert!(serde_json::from_str::<A2aInvariant>("\"SOMETHING_NEW\"").is_err());
    }

    #[test]
    fn a_scenario_cannot_declare_a_verdict_or_reach_anything() {
        // The corpus authority boundary, structural rather than checked. The
        // last three matter as much as the first four: a fixture that could
        // name a command or an endpoint would be an execution or network hook
        // wearing a corpus entry's clothes.
        for hostile in [
            serde_json::json!({ "expected_verdict": "FAIL" }),
            serde_json::json!({ "expected_findings": [] }),
            serde_json::json!({ "is_secure": false }),
            serde_json::json!({ "should_fail": true }),
            serde_json::json!({ "evaluator_override": "SKIP" }),
            serde_json::json!({ "command": "cargo run" }),
            serde_json::json!({ "endpoint": "https://peer.example" }),
            serde_json::json!({ "fetch_card": true }),
        ] {
            let mut value =
                serde_json::to_value(scenario("a2a-lab-001", A2aInvariant::PeerIdentityBound))
                    .expect("serializes");
            let object = value.as_object_mut().expect("an object");
            for (key, extra) in hostile.as_object().expect("an object") {
                object.insert(key.clone(), extra.clone());
            }
            assert!(
                serde_json::from_value::<A2aScenario>(value).is_err(),
                "a scenario carrying {hostile} decoded"
            );
        }
    }

    #[test]
    fn the_primary_invariant_is_a_coverage_selector_and_not_a_verdict() {
        let scenario = scenario("a2a-lab-001", A2aInvariant::PeerIdentityBound);
        let rendered = serde_json::to_string(&scenario).expect("serializes");
        for absent in ["verdict", "expected", "secure", "finding"] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "a scenario carries a `{absent}` field"
            );
        }
    }

    #[test]
    fn a_scenario_without_a_description_is_refused() {
        // A fixture nobody can explain is a fixture nobody can review, and a
        // corpus of them proves only that the engine agrees with itself.
        let mut nameless = scenario("a2a-lab-001", A2aInvariant::TenantBoundaryPreserved);
        nameless.description = "   ".to_owned();
        assert!(nameless.validate().is_err());
    }

    #[test]
    fn a_path_shaped_evidence_reference_is_refused() {
        let mut hostile = scenario("a2a-lab-001", A2aInvariant::TenantBoundaryPreserved);
        hostile.evidence_files = vec!["../../etc/passwd".to_owned()];
        assert!(hostile.validate().is_err());
    }
}
