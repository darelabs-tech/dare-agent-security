//! Closed source, trust, lifecycle and scenario vocabulary.
//!
//! Every taxonomy here is a closed set. An unknown value fails to decode rather
//! than degrading to a default, because a memory item whose source or trust
//! class could not be read is exactly the item that must not be assumed benign.
//!
//! The rule the whole cycle turns on lives in this module's types: a
//! [`SourceKind`] is *not* an authority. Where content came from constrains how
//! far it may be trusted; it never elevates it. Trust is assigned by policy and
//! is never inferred from what the content says about itself.

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};

/// Where a memory item's content originally came from.
///
/// Closed on purpose. A source Cycle 016 cannot name is a source it cannot
/// reason about, and defaulting it to something familiar would be a guess
/// presented as a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceKind {
    /// Content the user typed or supplied.
    UserInput,
    /// Content returned by a tool call.
    ToolOutput,
    /// Content ingested from outside the system.
    ExternalContent,
    /// Content authored by the system itself under policy.
    SystemAuthored,
    /// Content the agent produced.
    AgentGenerated,
    /// Context imported from another session or store.
    ImportedContext,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserInput => "USER_INPUT",
            Self::ToolOutput => "TOOL_OUTPUT",
            Self::ExternalContent => "EXTERNAL_CONTENT",
            Self::SystemAuthored => "SYSTEM_AUTHORED",
            Self::AgentGenerated => "AGENT_GENERATED",
            Self::ImportedContext => "IMPORTED_CONTEXT",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::UserInput,
            Self::ToolOutput,
            Self::ExternalContent,
            Self::SystemAuthored,
            Self::AgentGenerated,
            Self::ImportedContext,
        ]
    }

    /// The highest trust class this source may reach *without* an explicit
    /// policy grant.
    ///
    /// Only `SYSTEM_AUTHORED` content is policy-authoritative by default;
    /// everything else caps at `CONSTRAINED` however trustworthy it looks. This
    /// is the ceiling a write is checked against, not a promise about content.
    pub fn default_trust_ceiling(self) -> TrustClass {
        match self {
            Self::SystemAuthored => TrustClass::TrustedPolicy,
            // Imported context is a store-to-store copy: it arrives with
            // whatever the exporting side claimed, which is not evidence.
            Self::UserInput
            | Self::ToolOutput
            | Self::ExternalContent
            | Self::AgentGenerated
            | Self::ImportedContext => TrustClass::Constrained,
        }
    }

    /// True when content from this source must be treated as
    /// attacker-influenceable.
    pub fn is_externally_influenceable(self) -> bool {
        matches!(
            self,
            Self::UserInput | Self::ToolOutput | Self::ExternalContent | Self::ImportedContext
        )
    }

    /// True when this source can, by itself, carry policy authority.
    ///
    /// Exactly one source can, and even then only when policy also allows it.
    pub fn may_be_policy_authoritative(self) -> bool {
        matches!(self, Self::SystemAuthored)
    }
}

/// How far a memory item may be trusted once persisted.
///
/// Ordered: `Untrusted < Constrained < TrustedPolicy`. The ordering is what
/// makes "promotion" a comparison rather than a judgement call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustClass {
    /// Data. May be stored and recalled; may not shape a protected decision.
    Untrusted,
    /// Data usable within an explicitly authorized objective and nothing wider.
    Constrained,
    /// Policy-authoritative memory.
    TrustedPolicy,
}

impl TrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "UNTRUSTED",
            Self::Constrained => "CONSTRAINED",
            Self::TrustedPolicy => "TRUSTED_POLICY",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Untrusted, Self::Constrained, Self::TrustedPolicy]
    }

    /// Rank, so promotion is a numeric comparison rather than a judgement.
    pub fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Constrained => 1,
            Self::TrustedPolicy => 2,
        }
    }

    /// True when moving from `self` to `other` raises trust.
    ///
    /// Lowering trust is always allowed; raising it requires an explicit,
    /// machine-readable policy grant, which is checked elsewhere.
    pub fn is_promotion_to(self, other: Self) -> bool {
        other.rank() > self.rank()
    }

    /// True when this class may influence a protected decision at all.
    pub fn may_influence_protected_decision(self) -> bool {
        matches!(self, Self::TrustedPolicy)
    }
}

/// Lifecycle state of a memory item at a given logical time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    /// Created but not yet inside its validity window.
    NotYetValid,
    /// Inside its validity window and not revoked.
    Valid,
    /// Past its expiry.
    Expired,
    /// Explicitly revoked, regardless of expiry.
    Revoked,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Valid => "VALID",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
        }
    }

    pub fn all() -> [Self; 4] {
        [Self::NotYetValid, Self::Valid, Self::Expired, Self::Revoked]
    }

    /// True when memory in this state may be used at all.
    ///
    /// Exactly one state is usable. The other three are each usable-looking in
    /// a different way, which is why they are named separately rather than
    /// collapsed into `!valid`.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Which memory-security surface a scenario exercises.
///
/// Surfaces are reported separately and never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    Provenance,
    TrustBoundary,
    TenantPrincipal,
    Lifecycle,
    DecisionInfluence,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provenance => "PROVENANCE",
            Self::TrustBoundary => "TRUST_BOUNDARY",
            Self::TenantPrincipal => "TENANT_PRINCIPAL",
            Self::Lifecycle => "LIFECYCLE",
            Self::DecisionInfluence => "DECISION_INFLUENCE",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::Provenance,
            Self::TrustBoundary,
            Self::TenantPrincipal,
            Self::Lifecycle,
            Self::DecisionInfluence,
        ]
    }
}

/// Closed memory-poisoning family taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PoisoningFamily {
    ProvenanceLoss,
    TrustPromotion,
    MemoryOverwriteSubstitution,
    CrossPrincipalRecall,
    CrossTenantRecall,
    CrossNamespaceRecall,
    StaleMemoryUse,
    RevokedMemoryUse,
    PoisonedRecallToObjective,
    PoisonedRecallToToolSelection,
    PoisonedRecallToArgument,
    PoisonedRecallToProtectedField,
}

impl PoisoningFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProvenanceLoss => "PROVENANCE_LOSS",
            Self::TrustPromotion => "TRUST_PROMOTION",
            Self::MemoryOverwriteSubstitution => "MEMORY_OVERWRITE_SUBSTITUTION",
            Self::CrossPrincipalRecall => "CROSS_PRINCIPAL_RECALL",
            Self::CrossTenantRecall => "CROSS_TENANT_RECALL",
            Self::CrossNamespaceRecall => "CROSS_NAMESPACE_RECALL",
            Self::StaleMemoryUse => "STALE_MEMORY_USE",
            Self::RevokedMemoryUse => "REVOKED_MEMORY_USE",
            Self::PoisonedRecallToObjective => "POISONED_RECALL_TO_OBJECTIVE",
            Self::PoisonedRecallToToolSelection => "POISONED_RECALL_TO_TOOL_SELECTION",
            Self::PoisonedRecallToArgument => "POISONED_RECALL_TO_ARGUMENT",
            Self::PoisonedRecallToProtectedField => "POISONED_RECALL_TO_PROTECTED_FIELD",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::ProvenanceLoss,
            Self::TrustPromotion,
            Self::MemoryOverwriteSubstitution,
            Self::CrossPrincipalRecall,
            Self::CrossTenantRecall,
            Self::CrossNamespaceRecall,
            Self::StaleMemoryUse,
            Self::RevokedMemoryUse,
            Self::PoisonedRecallToObjective,
            Self::PoisonedRecallToToolSelection,
            Self::PoisonedRecallToArgument,
            Self::PoisonedRecallToProtectedField,
        ]
    }

    /// Which reporting surface this family belongs to.
    pub fn surface(self) -> ScenarioClass {
        match self {
            Self::ProvenanceLoss => ScenarioClass::Provenance,
            Self::TrustPromotion => ScenarioClass::TrustBoundary,
            Self::MemoryOverwriteSubstitution => ScenarioClass::TrustBoundary,
            Self::CrossPrincipalRecall | Self::CrossTenantRecall | Self::CrossNamespaceRecall => {
                ScenarioClass::TenantPrincipal
            }
            Self::StaleMemoryUse | Self::RevokedMemoryUse => ScenarioClass::Lifecycle,
            Self::PoisonedRecallToObjective
            | Self::PoisonedRecallToToolSelection
            | Self::PoisonedRecallToArgument
            | Self::PoisonedRecallToProtectedField => ScenarioClass::DecisionInfluence,
        }
    }
}

/// Where a scenario's observations came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemorySourceKind {
    /// A memory store snapshot authored for the synthetic lab.
    SyntheticMemoryStore,
    /// A sanitized local replay trace.
    ReplayTrace,
    /// A declared memory policy captured locally.
    DeclaredMemoryPolicy,
}

impl MemorySourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticMemoryStore => "SYNTHETIC_MEMORY_STORE",
            Self::ReplayTrace => "REPLAY_TRACE",
            Self::DeclaredMemoryPolicy => "DECLARED_MEMORY_POLICY",
        }
    }

    pub fn all() -> [Self; 3] {
        [
            Self::SyntheticMemoryStore,
            Self::ReplayTrace,
            Self::DeclaredMemoryPolicy,
        ]
    }

    /// No source is authoritative about its own security.
    ///
    /// Always false, and a test pins it: a store that declares itself clean is
    /// making a claim, not supplying evidence.
    pub fn is_authoritative(self) -> bool {
        false
    }
}

/// Declared trust of the channel a scenario's memory arrived through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Whether a corpus entry is an attack vector or a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    /// A vector that should produce a deterministic violation.
    MemoryAttack,
    /// A control that should produce no violation at all.
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryAttack => "MEMORY_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }

    pub fn all() -> [Self; 2] {
        [Self::MemoryAttack, Self::BenignControl]
    }
}

/// Parse a closed-enum token, failing closed on anything unknown.
pub fn parse_closed<T: serde::de::DeserializeOwned>(token: &str, label: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(token.to_owned()))
        .map_err(|_| MemorySecurityError::invalid(format!("`{token}` is not a known {label}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_taxonomy_is_closed_and_uniquely_named() {
        assert_eq!(SourceKind::all().len(), 6);
        assert_eq!(TrustClass::all().len(), 3);
        assert_eq!(LifecycleState::all().len(), 4);
        assert_eq!(ScenarioClass::all().len(), 5);
        assert_eq!(PoisoningFamily::all().len(), 12);
        assert_eq!(MemorySourceKind::all().len(), 3);
        assert_eq!(TrustLevel::all().len(), 3);
        assert_eq!(CorpusClass::all().len(), 2);

        for token in ["MEMORY_TELEPORT", "unknown", "", "user_input"] {
            assert!(
                parse_closed::<SourceKind>(token, "source kind").is_err(),
                "{token}"
            );
            assert!(
                parse_closed::<TrustClass>(token, "trust class").is_err(),
                "{token}"
            );
            assert!(
                parse_closed::<LifecycleState>(token, "lifecycle state").is_err(),
                "{token}"
            );
        }
        assert_eq!(
            parse_closed::<SourceKind>("USER_INPUT", "source kind").expect("known"),
            SourceKind::UserInput
        );
    }

    #[test]
    fn only_system_authored_content_can_carry_policy_authority() {
        // This is the cycle's thesis in one assertion: where content came from
        // constrains how far it may be trusted, and only one source may be
        // policy-authoritative at all.
        for source in SourceKind::all() {
            let authoritative = source.may_be_policy_authoritative();
            assert_eq!(
                authoritative,
                source == SourceKind::SystemAuthored,
                "{}",
                source.as_str()
            );
            assert_eq!(
                source.default_trust_ceiling(),
                if authoritative {
                    TrustClass::TrustedPolicy
                } else {
                    TrustClass::Constrained
                },
                "{}",
                source.as_str()
            );
        }
    }

    #[test]
    fn imported_context_is_treated_as_externally_influenceable() {
        // A store-to-store copy arrives with whatever the exporting side
        // claimed about it, which is not evidence.
        assert!(SourceKind::ImportedContext.is_externally_influenceable());
        assert!(SourceKind::UserInput.is_externally_influenceable());
        assert!(SourceKind::ToolOutput.is_externally_influenceable());
        assert!(SourceKind::ExternalContent.is_externally_influenceable());
        assert!(!SourceKind::SystemAuthored.is_externally_influenceable());
        // Agent-generated content is not externally influenceable by itself,
        // but it is still capped below policy authority.
        assert!(!SourceKind::AgentGenerated.is_externally_influenceable());
        assert_eq!(
            SourceKind::AgentGenerated.default_trust_ceiling(),
            TrustClass::Constrained
        );
    }

    #[test]
    fn trust_is_ordered_so_promotion_is_a_comparison() {
        assert!(TrustClass::Untrusted.rank() < TrustClass::Constrained.rank());
        assert!(TrustClass::Constrained.rank() < TrustClass::TrustedPolicy.rank());

        assert!(TrustClass::Untrusted.is_promotion_to(TrustClass::Constrained));
        assert!(TrustClass::Untrusted.is_promotion_to(TrustClass::TrustedPolicy));
        assert!(TrustClass::Constrained.is_promotion_to(TrustClass::TrustedPolicy));

        // Same-level and downward moves are never promotions.
        for class in TrustClass::all() {
            assert!(!class.is_promotion_to(class), "{}", class.as_str());
        }
        assert!(!TrustClass::TrustedPolicy.is_promotion_to(TrustClass::Untrusted));
        assert!(!TrustClass::Constrained.is_promotion_to(TrustClass::Untrusted));
    }

    #[test]
    fn only_policy_trusted_memory_may_shape_a_protected_decision() {
        assert!(TrustClass::TrustedPolicy.may_influence_protected_decision());
        assert!(!TrustClass::Constrained.may_influence_protected_decision());
        assert!(!TrustClass::Untrusted.may_influence_protected_decision());
    }

    #[test]
    fn exactly_one_lifecycle_state_is_usable() {
        let usable: Vec<&str> = LifecycleState::all()
            .into_iter()
            .filter(|state| state.is_usable())
            .map(LifecycleState::as_str)
            .collect();
        assert_eq!(usable, vec!["VALID"]);
    }

    #[test]
    fn the_three_unusable_lifecycle_states_stay_distinguishable() {
        // "Not yet valid", "expired" and "revoked" are different findings even
        // though all three block use; collapsing them would lose which one a
        // run actually observed.
        let mut names: Vec<&str> = LifecycleState::all()
            .into_iter()
            .filter(|state| !state.is_usable())
            .map(LifecycleState::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["EXPIRED", "NOT_YET_VALID", "REVOKED"]);
    }

    #[test]
    fn every_poisoning_family_maps_to_exactly_one_surface() {
        use std::collections::BTreeMap;
        let mut by_surface: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for family in PoisoningFamily::all() {
            by_surface
                .entry(family.surface().as_str())
                .or_default()
                .push(family.as_str());
        }
        // All five surfaces are reachable from the family taxonomy; a surface
        // no family maps to could never be exercised.
        assert_eq!(by_surface.len(), 5);
        for surface in ScenarioClass::all() {
            assert!(
                by_surface.contains_key(surface.as_str()),
                "{} is unreachable",
                surface.as_str()
            );
        }
    }

    #[test]
    fn no_observation_source_is_authoritative_about_its_own_security() {
        for source in MemorySourceKind::all() {
            assert!(!source.is_authoritative(), "{}", source.as_str());
        }
    }

    #[test]
    fn every_enum_round_trips_through_its_wire_form() {
        for source in SourceKind::all() {
            let wire = serde_json::to_string(&source).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", source.as_str()));
            assert_eq!(
                serde_json::from_str::<SourceKind>(&wire).expect("round-trips"),
                source
            );
        }
        for class in TrustClass::all() {
            let wire = serde_json::to_string(&class).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", class.as_str()));
        }
        for state in LifecycleState::all() {
            let wire = serde_json::to_string(&state).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", state.as_str()));
        }
        for family in PoisoningFamily::all() {
            let wire = serde_json::to_string(&family).expect("serializes");
            assert_eq!(wire, format!("\"{}\"", family.as_str()));
        }
    }
}
