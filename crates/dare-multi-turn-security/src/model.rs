//! The closed vocabulary shared by graphs, observations, invariants and results.
//!
//! Every enum here is closed and serializes in `SCREAMING_SNAKE_CASE`. A value
//! outside it cannot be deserialized, so a transcript or graph cannot introduce
//! a class the evaluator has no rule for.

use serde::{Deserialize, Serialize};

/// How a run obtains the target's responses. Every mode is local and offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessMode {
    Replay,
    Simulated,
    LocalSynthetic,
}

impl HarnessMode {
    /// SIMULATED and LOCAL_SYNTHETIC results are labelled synthetic.
    pub fn is_synthetic(self) -> bool {
        !matches!(self, Self::Replay)
    }
}

/// The channel a turn arrives through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TurnRole {
    User,
    Tool,
    Retrieved,
    Memory,
    Approval,
}

/// The closed classification of one target response.
///
/// A class only selects the next strategy node. Verdicts are decided from the
/// normalized facts of each turn, never from the class alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationClass {
    Refused,
    Complied,
    Partial,
    Deflected,
    AuthorityAccepted,
    ActionRequested,
    ActionExecuted,
    Unclassifiable,
}

impl ObservationClass {
    pub const ALL: [Self; 8] = [
        Self::Refused,
        Self::Complied,
        Self::Partial,
        Self::Deflected,
        Self::AuthorityAccepted,
        Self::ActionRequested,
        Self::ActionExecuted,
        Self::Unclassifiable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "REFUSED",
            Self::Complied => "COMPLIED",
            Self::Partial => "PARTIAL",
            Self::Deflected => "DEFLECTED",
            Self::AuthorityAccepted => "AUTHORITY_ACCEPTED",
            Self::ActionRequested => "ACTION_REQUESTED",
            Self::ActionExecuted => "ACTION_EXECUTED",
            Self::Unclassifiable => "UNCLASSIFIABLE",
        }
    }
}

/// Authority, ordered: `None < Read < Write < Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityLevel {
    None,
    Read,
    Write,
    Admin,
}

/// How much of a request the target fulfilled, as the adapter recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Fulfillment {
    Full,
    Partial,
    NoFulfillment,
}

/// A policy decision the target recorded for a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allow,
    Deny,
}

/// The cross-turn invariants. I08 (strategy integrity) is a runner guarantee
/// with no property and is deliberately not a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MultiTurnInvariant {
    #[serde(rename = "I01_REFUSAL_PERSISTENCE")]
    I01RefusalPersistence,
    #[serde(rename = "I02_CUMULATIVE_INTENT")]
    I02CumulativeIntent,
    #[serde(rename = "I03_CLAIMED_AUTHORITY")]
    I03ClaimedAuthority,
    #[serde(rename = "I04_DELAYED_INSTRUCTION")]
    I04DelayedInstruction,
    #[serde(rename = "I05_APPROVAL_CONTINUITY")]
    I05ApprovalContinuity,
    #[serde(rename = "I06_OBJECTIVE_STABILITY")]
    I06ObjectiveStability,
    #[serde(rename = "I07_CONVERSATION_ISOLATION")]
    I07ConversationIsolation,
}

impl MultiTurnInvariant {
    pub const ALL: [Self; 7] = [
        Self::I01RefusalPersistence,
        Self::I02CumulativeIntent,
        Self::I03ClaimedAuthority,
        Self::I04DelayedInstruction,
        Self::I05ApprovalContinuity,
        Self::I06ObjectiveStability,
        Self::I07ConversationIsolation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::I01RefusalPersistence => "I01_REFUSAL_PERSISTENCE",
            Self::I02CumulativeIntent => "I02_CUMULATIVE_INTENT",
            Self::I03ClaimedAuthority => "I03_CLAIMED_AUTHORITY",
            Self::I04DelayedInstruction => "I04_DELAYED_INSTRUCTION",
            Self::I05ApprovalContinuity => "I05_APPROVAL_CONTINUITY",
            Self::I06ObjectiveStability => "I06_OBJECTIVE_STABILITY",
            Self::I07ConversationIsolation => "I07_CONVERSATION_ISOLATION",
        }
    }

    /// The registry property each invariant decides (Blueprint §4.3).
    pub fn property_id(self) -> &'static str {
        match self {
            Self::I01RefusalPersistence => "AGENT.GOAL.REFUSAL_PERSISTENCE",
            Self::I02CumulativeIntent => "AGENT.GOAL.CUMULATIVE_INTENT_BOUNDARY",
            Self::I03ClaimedAuthority => "AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY",
            Self::I04DelayedInstruction => "AGENT.GOAL.DELAYED_INSTRUCTION_BOUNDARY",
            Self::I05ApprovalContinuity => "AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY",
            Self::I06ObjectiveStability => "AGENT.GOAL.OBJECTIVE_STABILITY",
            Self::I07ConversationIsolation => "AGENT.MEMORY.CONVERSATION_ISOLATION",
        }
    }
}

/// Why a conversation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopReason {
    TerminalReached,
    FirstFail,
    BudgetExhausted,
    HarnessError,
    Unclassifiable,
    NoTransition,
    StrategyFault,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_ordered_from_none_to_admin() {
        use AuthorityLevel::*;
        assert!(None < Read && Read < Write && Write < Admin);
    }

    #[test]
    fn serialized_names_match_the_schemas() {
        for class in ObservationClass::ALL {
            assert_eq!(serde_json::to_value(class).expect("json"), class.as_str());
        }
        for invariant in MultiTurnInvariant::ALL {
            assert_eq!(
                serde_json::to_value(invariant).expect("json"),
                invariant.as_str()
            );
        }
        let scenario: serde_json::Value =
            serde_json::from_str(crate::schema::SCENARIO_SCHEMA_V1_JSON).expect("json");
        let schema_invariants = scenario["properties"]["invariant"]["enum"]
            .as_array()
            .expect("enum")
            .clone();
        let ours: Vec<serde_json::Value> = MultiTurnInvariant::ALL
            .iter()
            .map(|i| i.as_str().into())
            .collect();
        assert_eq!(schema_invariants, ours);
    }

    #[test]
    fn every_invariant_maps_to_a_distinct_property_in_an_existing_family() {
        let families = [
            "AGENT.GOAL.",
            "AGENT.IDENTITY.",
            "AGENT.HUMAN_APPROVAL.",
            "AGENT.MEMORY.",
        ];
        let mut seen = std::collections::BTreeSet::new();
        for invariant in MultiTurnInvariant::ALL {
            let id = invariant.property_id();
            assert!(families.iter().any(|f| id.starts_with(f)), "{id}");
            assert!(
                !id.contains("MULTI_TURN"),
                "no new namespace (DESIGN §13 Q1)"
            );
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn only_replay_is_not_synthetic() {
        assert!(!HarnessMode::Replay.is_synthetic());
        assert!(HarnessMode::Simulated.is_synthetic());
        assert!(HarnessMode::LocalSynthetic.is_synthetic());
    }
}
