//! Closed source-trust and injection-family vocabulary.
//!
//! Direct and indirect injection are modeled as distinct source boundaries, not
//! as a single "prompt injection" bucket. Vector classes deferred to later
//! cycles — tool description/output poisoning, RAG retrieval poisoning and
//! agent-to-agent injection — have no representation here and cannot be
//! silently folded into a Cycle 013 result.

use serde::{Deserialize, Serialize};

/// Where injected content entered the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceKind {
    /// User-controlled prompt channel.
    UserPrompt,
    /// Text extracted from an ingested document.
    DocumentText,
    /// HTML the agent consumed as data.
    HtmlContent,
    /// Content read through an MCP resource.
    McpResourceContent,
    /// Any other explicitly untrusted external content channel.
    GenericExternalContent,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPrompt => "USER_PROMPT",
            Self::DocumentText => "DOCUMENT_TEXT",
            Self::HtmlContent => "HTML_CONTENT",
            Self::McpResourceContent => "MCP_RESOURCE_CONTENT",
            Self::GenericExternalContent => "GENERIC_EXTERNAL_CONTENT",
        }
    }

    /// The injection direction this source boundary represents.
    pub fn direction(self) -> InjectionDirection {
        match self {
            Self::UserPrompt => InjectionDirection::Direct,
            Self::DocumentText
            | Self::HtmlContent
            | Self::McpResourceContent
            | Self::GenericExternalContent => InjectionDirection::Indirect,
        }
    }

    /// Security property this source boundary is validated against.
    pub fn boundary_property(self) -> &'static str {
        match self.direction() {
            InjectionDirection::Direct => "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
            InjectionDirection::Indirect => "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
        }
    }

    /// Applicability predicate that must hold for this source to be testable.
    pub fn required_predicate(self) -> &'static str {
        match self.direction() {
            InjectionDirection::Direct => "user_prompt_present",
            InjectionDirection::Indirect => "untrusted_external_content_present",
        }
    }
}

/// Direct and indirect are reported separately and never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InjectionDirection {
    Direct,
    Indirect,
}

impl InjectionDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "DIRECT",
            Self::Indirect => "INDIRECT",
        }
    }
}

/// Declared trust level of the content channel.
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

    /// True when content from this channel must be treated as attacker-controlled.
    pub fn is_attacker_controlled(self) -> bool {
        matches!(self, Self::Untrusted | Self::Mixed)
    }
}

/// Closed injection-family taxonomy for Cycle 013.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InjectionFamily {
    DirectGoalOverride,
    DirectSystemInstructionOverride,
    DirectRoleConfusion,
    DirectProtectedDataRequest,
    DirectUnauthorizedActionRequest,
    DirectInstructionSmuggling,
    IndirectGoalOverride,
    IndirectSystemInstructionOverride,
    IndirectProtectedDataRequest,
    IndirectUnauthorizedActionRequest,
    IndirectHiddenInstruction,
    IndirectCrossContentInstruction,
}

impl InjectionFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectGoalOverride => "DIRECT_GOAL_OVERRIDE",
            Self::DirectSystemInstructionOverride => "DIRECT_SYSTEM_INSTRUCTION_OVERRIDE",
            Self::DirectRoleConfusion => "DIRECT_ROLE_CONFUSION",
            Self::DirectProtectedDataRequest => "DIRECT_PROTECTED_DATA_REQUEST",
            Self::DirectUnauthorizedActionRequest => "DIRECT_UNAUTHORIZED_ACTION_REQUEST",
            Self::DirectInstructionSmuggling => "DIRECT_INSTRUCTION_SMUGGLING",
            Self::IndirectGoalOverride => "INDIRECT_GOAL_OVERRIDE",
            Self::IndirectSystemInstructionOverride => "INDIRECT_SYSTEM_INSTRUCTION_OVERRIDE",
            Self::IndirectProtectedDataRequest => "INDIRECT_PROTECTED_DATA_REQUEST",
            Self::IndirectUnauthorizedActionRequest => "INDIRECT_UNAUTHORIZED_ACTION_REQUEST",
            Self::IndirectHiddenInstruction => "INDIRECT_HIDDEN_INSTRUCTION",
            Self::IndirectCrossContentInstruction => "INDIRECT_CROSS_CONTENT_INSTRUCTION",
        }
    }

    pub fn direction(self) -> InjectionDirection {
        match self {
            Self::DirectGoalOverride
            | Self::DirectSystemInstructionOverride
            | Self::DirectRoleConfusion
            | Self::DirectProtectedDataRequest
            | Self::DirectUnauthorizedActionRequest
            | Self::DirectInstructionSmuggling => InjectionDirection::Direct,
            Self::IndirectGoalOverride
            | Self::IndirectSystemInstructionOverride
            | Self::IndirectProtectedDataRequest
            | Self::IndirectUnauthorizedActionRequest
            | Self::IndirectHiddenInstruction
            | Self::IndirectCrossContentInstruction => InjectionDirection::Indirect,
        }
    }

    /// Every family, in stable declaration order.
    pub fn all() -> [Self; 12] {
        [
            Self::DirectGoalOverride,
            Self::DirectSystemInstructionOverride,
            Self::DirectRoleConfusion,
            Self::DirectProtectedDataRequest,
            Self::DirectUnauthorizedActionRequest,
            Self::DirectInstructionSmuggling,
            Self::IndirectGoalOverride,
            Self::IndirectSystemInstructionOverride,
            Self::IndirectProtectedDataRequest,
            Self::IndirectUnauthorizedActionRequest,
            Self::IndirectHiddenInstruction,
            Self::IndirectCrossContentInstruction,
        ]
    }
}

/// Corpus entry class. Benign controls are first-class so false positives are
/// testable rather than assumed absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    DirectAttack,
    IndirectAttack,
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectAttack => "DIRECT_ATTACK",
            Self::IndirectAttack => "INDIRECT_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }

    /// A benign control must never be counted as a tested attack vector.
    pub fn is_attack(self) -> bool {
        matches!(self, Self::DirectAttack | Self::IndirectAttack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_tokens_round_trip_for_every_variant() {
        for family in InjectionFamily::all() {
            let wire = serde_json::to_value(family).unwrap();
            assert_eq!(wire, json!(family.as_str()));
            let back: InjectionFamily = serde_json::from_value(wire).unwrap();
            assert_eq!(back, family);
        }
        for source in [
            SourceKind::UserPrompt,
            SourceKind::DocumentText,
            SourceKind::HtmlContent,
            SourceKind::McpResourceContent,
            SourceKind::GenericExternalContent,
        ] {
            assert_eq!(
                serde_json::to_value(source).unwrap(),
                json!(source.as_str())
            );
        }
        for trust in [
            TrustLevel::Trusted,
            TrustLevel::Untrusted,
            TrustLevel::Mixed,
        ] {
            assert_eq!(serde_json::to_value(trust).unwrap(), json!(trust.as_str()));
        }
    }

    #[test]
    fn direct_and_indirect_boundaries_stay_distinct() {
        assert_eq!(
            SourceKind::UserPrompt.direction(),
            InjectionDirection::Direct
        );
        for source in [
            SourceKind::DocumentText,
            SourceKind::HtmlContent,
            SourceKind::McpResourceContent,
            SourceKind::GenericExternalContent,
        ] {
            assert_eq!(source.direction(), InjectionDirection::Indirect);
        }

        assert_eq!(
            SourceKind::UserPrompt.boundary_property(),
            "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY"
        );
        assert_eq!(
            SourceKind::DocumentText.boundary_property(),
            "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY"
        );
        assert_ne!(
            SourceKind::UserPrompt.boundary_property(),
            SourceKind::HtmlContent.boundary_property()
        );
    }

    #[test]
    fn family_direction_agrees_with_its_name() {
        for family in InjectionFamily::all() {
            let expected = if family.as_str().starts_with("DIRECT_") {
                InjectionDirection::Direct
            } else {
                InjectionDirection::Indirect
            };
            assert_eq!(family.direction(), expected, "{}", family.as_str());
        }
        assert_eq!(
            InjectionFamily::all()
                .iter()
                .filter(|f| f.direction() == InjectionDirection::Direct)
                .count(),
            6
        );
        assert_eq!(
            InjectionFamily::all()
                .iter()
                .filter(|f| f.direction() == InjectionDirection::Indirect)
                .count(),
            6
        );
    }

    #[test]
    fn source_predicate_matches_the_boundary() {
        assert_eq!(
            SourceKind::UserPrompt.required_predicate(),
            "user_prompt_present"
        );
        assert_eq!(
            SourceKind::McpResourceContent.required_predicate(),
            "untrusted_external_content_present"
        );
    }

    #[test]
    fn deferred_cycle_vector_classes_have_no_representation() {
        // Cycle 014 tool poisoning, Cycle 016 memory poisoning, Cycle 017 RAG
        // poisoning and Cycle 020 A2A injection must not decode into a Cycle 013
        // family or source. Nothing here may silently absorb them.
        for token in [
            "\"TOOL_DESCRIPTION_POISONING\"",
            "\"TOOL_OUTPUT_POISONING\"",
            "\"DIRECT_TOOL_POISONING\"",
            "\"INDIRECT_RAG_POISONING\"",
            "\"MEMORY_POISONING\"",
            "\"A2A_MESSAGE_INJECTION\"",
        ] {
            assert!(serde_json::from_str::<InjectionFamily>(token).is_err());
        }
        for token in [
            "\"TOOL_DESCRIPTION\"",
            "\"TOOL_OUTPUT\"",
            "\"RAG_RETRIEVAL_CONTENT\"",
            "\"AGENT_MESSAGE\"",
            "\"MEMORY_RECORD\"",
        ] {
            assert!(serde_json::from_str::<SourceKind>(token).is_err());
        }
    }

    #[test]
    fn unknown_and_miscased_values_fail_closed() {
        assert!(serde_json::from_str::<InjectionFamily>("\"direct_goal_override\"").is_err());
        assert!(serde_json::from_str::<SourceKind>("\"user_prompt\"").is_err());
        assert!(serde_json::from_str::<TrustLevel>("\"UNKNOWN\"").is_err());
        assert!(serde_json::from_str::<TrustLevel>("null").is_err());
        assert!(serde_json::from_str::<CorpusClass>("\"HOSTILE\"").is_err());
        assert!(serde_json::from_str::<SourceKind>("\"\"").is_err());
    }

    #[test]
    fn trust_levels_treat_mixed_as_attacker_controlled() {
        assert!(TrustLevel::Untrusted.is_attacker_controlled());
        assert!(
            TrustLevel::Mixed.is_attacker_controlled(),
            "MIXED must fail closed toward untrusted"
        );
        assert!(!TrustLevel::Trusted.is_attacker_controlled());
    }

    #[test]
    fn benign_controls_are_not_counted_as_attacks() {
        assert!(CorpusClass::DirectAttack.is_attack());
        assert!(CorpusClass::IndirectAttack.is_attack());
        assert!(!CorpusClass::BenignControl.is_attack());
    }

    #[test]
    fn family_list_is_complete_and_unique() {
        let all = InjectionFamily::all();
        let unique: std::collections::HashSet<&str> =
            all.iter().map(|family| family.as_str()).collect();
        assert_eq!(unique.len(), all.len());
        assert_eq!(all.len(), 12);
    }
}
