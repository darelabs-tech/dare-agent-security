//! Closed tool-security taxonomies.
//!
//! Tool poisoning (a corrupted tool surface) and tool misuse (an outcome) are
//! modeled as separate scenario classes with separate family enums, so a result
//! can never conflate "the tool description was manipulated" with "the agent
//! used a tool it should not have".
//!
//! Concepts deferred to later cycles — identity/privilege (015), memory (016),
//! RAG (017), supply chain (019), A2A (020) — have no representation here and
//! cannot be decoded into a Cycle 014 result.

use serde::{Deserialize, Serialize};

/// Which security dimension a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioClass {
    /// The tool surface itself is manipulated.
    Poisoning,
    /// A legitimate tool is used outside the approved objective and policy.
    Misuse,
}

impl ScenarioClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Poisoning => "POISONING",
            Self::Misuse => "MISUSE",
        }
    }

    /// Reporting label. Poisoning and misuse are always reported separately.
    pub fn reporting_dimension(self) -> &'static str {
        match self {
            Self::Poisoning => "TOOL_POISONING",
            Self::Misuse => "TOOL_MISUSE",
        }
    }
}

/// Closed tool-poisoning taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PoisoningFamily {
    ToolDescriptionInstructionPoisoning,
    ToolDescriptionCapabilityMisrepresentation,
    ToolSchemaParameterPoisoning,
    ToolAnnotationTrustPoisoning,
    ToolOutputInstructionPoisoning,
    ToolOutputDataTrustPoisoning,
    ToolMetadataSubstitution,
    ToolMetadataHiddenInstruction,
}

impl PoisoningFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolDescriptionInstructionPoisoning => "TOOL_DESCRIPTION_INSTRUCTION_POISONING",
            Self::ToolDescriptionCapabilityMisrepresentation => {
                "TOOL_DESCRIPTION_CAPABILITY_MISREPRESENTATION"
            }
            Self::ToolSchemaParameterPoisoning => "TOOL_SCHEMA_PARAMETER_POISONING",
            Self::ToolAnnotationTrustPoisoning => "TOOL_ANNOTATION_TRUST_POISONING",
            Self::ToolOutputInstructionPoisoning => "TOOL_OUTPUT_INSTRUCTION_POISONING",
            Self::ToolOutputDataTrustPoisoning => "TOOL_OUTPUT_DATA_TRUST_POISONING",
            Self::ToolMetadataSubstitution => "TOOL_METADATA_SUBSTITUTION",
            Self::ToolMetadataHiddenInstruction => "TOOL_METADATA_HIDDEN_INSTRUCTION",
        }
    }

    pub fn all() -> [Self; 8] {
        [
            Self::ToolDescriptionInstructionPoisoning,
            Self::ToolDescriptionCapabilityMisrepresentation,
            Self::ToolSchemaParameterPoisoning,
            Self::ToolAnnotationTrustPoisoning,
            Self::ToolOutputInstructionPoisoning,
            Self::ToolOutputDataTrustPoisoning,
            Self::ToolMetadataSubstitution,
            Self::ToolMetadataHiddenInstruction,
        ]
    }

    /// Which part of the tool surface this family corrupts.
    pub fn surface_area(self) -> ToolSurfaceArea {
        match self {
            Self::ToolDescriptionInstructionPoisoning
            | Self::ToolDescriptionCapabilityMisrepresentation => ToolSurfaceArea::Description,
            Self::ToolSchemaParameterPoisoning => ToolSurfaceArea::InputSchema,
            Self::ToolAnnotationTrustPoisoning => ToolSurfaceArea::Annotations,
            Self::ToolOutputInstructionPoisoning | Self::ToolOutputDataTrustPoisoning => {
                ToolSurfaceArea::Output
            }
            Self::ToolMetadataSubstitution | Self::ToolMetadataHiddenInstruction => {
                ToolSurfaceArea::Metadata
            }
        }
    }
}

/// Part of the tool surface a poisoning family targets. Reported separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolSurfaceArea {
    Description,
    InputSchema,
    Annotations,
    Metadata,
    Output,
}

impl ToolSurfaceArea {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Description => "DESCRIPTION",
            Self::InputSchema => "INPUT_SCHEMA",
            Self::Annotations => "ANNOTATIONS",
            Self::Metadata => "METADATA",
            Self::Output => "OUTPUT",
        }
    }
}

/// Closed tool-misuse taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MisuseFamily {
    UnintendedToolSelection,
    ObjectiveToolMismatch,
    ArgumentSubstitution,
    DangerousArgumentRequest,
    ParameterPollution,
    ExcessiveInvocation,
    UnexpectedToolChain,
    ChainDepthViolation,
    OutputToActionEscalation,
    PolicyToolMismatch,
}

impl MisuseFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnintendedToolSelection => "UNINTENDED_TOOL_SELECTION",
            Self::ObjectiveToolMismatch => "OBJECTIVE_TOOL_MISMATCH",
            Self::ArgumentSubstitution => "ARGUMENT_SUBSTITUTION",
            Self::DangerousArgumentRequest => "DANGEROUS_ARGUMENT_REQUEST",
            Self::ParameterPollution => "PARAMETER_POLLUTION",
            Self::ExcessiveInvocation => "EXCESSIVE_INVOCATION",
            Self::UnexpectedToolChain => "UNEXPECTED_TOOL_CHAIN",
            Self::ChainDepthViolation => "CHAIN_DEPTH_VIOLATION",
            Self::OutputToActionEscalation => "OUTPUT_TO_ACTION_ESCALATION",
            Self::PolicyToolMismatch => "POLICY_TOOL_MISMATCH",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::UnintendedToolSelection,
            Self::ObjectiveToolMismatch,
            Self::ArgumentSubstitution,
            Self::DangerousArgumentRequest,
            Self::ParameterPollution,
            Self::ExcessiveInvocation,
            Self::UnexpectedToolChain,
            Self::ChainDepthViolation,
            Self::OutputToActionEscalation,
            Self::PolicyToolMismatch,
        ]
    }

    /// Which misuse surface this family exercises. Reported separately.
    pub fn misuse_surface(self) -> MisuseSurface {
        match self {
            Self::UnintendedToolSelection
            | Self::ObjectiveToolMismatch
            | Self::PolicyToolMismatch => MisuseSurface::Selection,
            Self::ArgumentSubstitution
            | Self::DangerousArgumentRequest
            | Self::ParameterPollution => MisuseSurface::Arguments,
            Self::UnexpectedToolChain | Self::ChainDepthViolation => MisuseSurface::Chain,
            Self::ExcessiveInvocation => MisuseSurface::Invocation,
            Self::OutputToActionEscalation => MisuseSurface::OutputEscalation,
        }
    }
}

/// Misuse surface, reported separately so coverage is legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MisuseSurface {
    Selection,
    Arguments,
    Chain,
    Invocation,
    OutputEscalation,
}

impl MisuseSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selection => "SELECTION",
            Self::Arguments => "ARGUMENTS",
            Self::Chain => "CHAIN",
            Self::Invocation => "INVOCATION",
            Self::OutputEscalation => "OUTPUT_ESCALATION",
        }
    }
}

/// Where tool-surface data came from.
///
/// There is deliberately no `LIVE_MCP_SERVER` or `REMOTE_PROVIDER` variant:
/// Cycle 014 observes local, synthetic and replayed surfaces only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolSourceKind {
    /// Tool metadata declared by the target application.
    DeclaredToolMetadata,
    /// Tool metadata as it would appear over MCP, captured locally.
    McpToolMetadata,
    /// Content returned by a tool.
    ToolOutput,
    /// A tool surface authored for the synthetic lab.
    SyntheticToolSurface,
    /// A sanitized local replay trace.
    ReplayTrace,
}

impl ToolSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredToolMetadata => "DECLARED_TOOL_METADATA",
            Self::McpToolMetadata => "MCP_TOOL_METADATA",
            Self::ToolOutput => "TOOL_OUTPUT",
            Self::SyntheticToolSurface => "SYNTHETIC_TOOL_SURFACE",
            Self::ReplayTrace => "REPLAY_TRACE",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::DeclaredToolMetadata,
            Self::McpToolMetadata,
            Self::ToolOutput,
            Self::SyntheticToolSurface,
            Self::ReplayTrace,
        ]
    }

    /// True when this source carries data the agent may treat as authority only
    /// after policy validation. Every Cycle 014 source is of this kind: none of
    /// them is authoritative on its own.
    pub fn is_authoritative(self) -> bool {
        false
    }
}

/// Declared trust level of a tool surface.
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

    /// True when content from this surface must be treated as attacker-controlled.
    ///
    /// `MIXED` fails closed toward untrusted.
    pub fn is_attacker_controlled(self) -> bool {
        matches!(self, Self::Untrusted | Self::Mixed)
    }
}

/// Corpus entry class. Benign controls are first-class so false positives are
/// testable rather than assumed absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorpusClass {
    PoisoningAttack,
    MisuseAttack,
    BenignControl,
}

impl CorpusClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoisoningAttack => "POISONING_ATTACK",
            Self::MisuseAttack => "MISUSE_ATTACK",
            Self::BenignControl => "BENIGN_CONTROL",
        }
    }

    /// A benign control is never counted as a tested attack vector.
    pub fn is_attack(self) -> bool {
        matches!(self, Self::PoisoningAttack | Self::MisuseAttack)
    }

    /// The scenario class this corpus class exercises, when it is an attack.
    pub fn scenario_class(self) -> Option<ScenarioClass> {
        match self {
            Self::PoisoningAttack => Some(ScenarioClass::Poisoning),
            Self::MisuseAttack => Some(ScenarioClass::Misuse),
            Self::BenignControl => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_tokens_round_trip_for_every_variant() {
        for family in PoisoningFamily::all() {
            let wire = serde_json::to_value(family).unwrap();
            assert_eq!(wire, json!(family.as_str()));
            assert_eq!(
                serde_json::from_value::<PoisoningFamily>(wire).unwrap(),
                family
            );
        }
        for family in MisuseFamily::all() {
            let wire = serde_json::to_value(family).unwrap();
            assert_eq!(wire, json!(family.as_str()));
            assert_eq!(
                serde_json::from_value::<MisuseFamily>(wire).unwrap(),
                family
            );
        }
        for source in ToolSourceKind::all() {
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
    fn poisoning_and_misuse_stay_separate_dimensions() {
        assert_eq!(
            ScenarioClass::Poisoning.reporting_dimension(),
            "TOOL_POISONING"
        );
        assert_eq!(ScenarioClass::Misuse.reporting_dimension(), "TOOL_MISUSE");
        assert_ne!(
            ScenarioClass::Poisoning.reporting_dimension(),
            ScenarioClass::Misuse.reporting_dimension()
        );

        // A poisoning family cannot decode as a misuse family, or vice versa.
        for family in PoisoningFamily::all() {
            let token = format!("\"{}\"", family.as_str());
            assert!(serde_json::from_str::<MisuseFamily>(&token).is_err());
        }
        for family in MisuseFamily::all() {
            let token = format!("\"{}\"", family.as_str());
            assert!(serde_json::from_str::<PoisoningFamily>(&token).is_err());
        }
    }

    #[test]
    fn poisoning_families_cover_every_surface_area() {
        let areas: std::collections::HashSet<ToolSurfaceArea> = PoisoningFamily::all()
            .iter()
            .map(|family| family.surface_area())
            .collect();
        assert_eq!(areas.len(), 5);
        assert_eq!(PoisoningFamily::all().len(), 8);
    }

    #[test]
    fn misuse_families_cover_every_misuse_surface() {
        let surfaces: std::collections::HashSet<MisuseSurface> = MisuseFamily::all()
            .iter()
            .map(|family| family.misuse_surface())
            .collect();
        assert_eq!(surfaces.len(), 5);
        assert_eq!(MisuseFamily::all().len(), 10);
    }

    #[test]
    fn no_source_kind_can_represent_a_live_or_remote_tool() {
        assert_eq!(ToolSourceKind::all().len(), 5);
        for token in [
            "\"LIVE_MCP_SERVER\"",
            "\"REMOTE_MCP\"",
            "\"REMOTE_PROVIDER\"",
            "\"HTTP_ENDPOINT\"",
            "\"PRODUCTION_TOOL\"",
            "\"LIVE_TOOL\"",
        ] {
            assert!(
                serde_json::from_str::<ToolSourceKind>(token).is_err(),
                "{token} must not be a selectable source"
            );
        }
    }

    #[test]
    fn no_tool_source_is_authoritative_on_its_own() {
        // This is the whole point of AGENT.TOOL.METADATA_TRUST_BOUNDARY: a tool
        // declaring something about itself never makes it policy.
        for source in ToolSourceKind::all() {
            assert!(!source.is_authoritative(), "{}", source.as_str());
        }
    }

    #[test]
    fn deferred_cycle_concepts_have_no_representation() {
        for token in [
            "\"CREDENTIAL_INHERITANCE\"",
            "\"PRIVILEGE_ESCALATION\"",
            "\"MEMORY_POISONING\"",
            "\"RAG_RETRIEVAL_POISONING\"",
            "\"SUPPLY_CHAIN_TAMPERING\"",
            "\"A2A_DELEGATION\"",
            "\"ARBITRARY_CODE_EXECUTION\"",
        ] {
            assert!(serde_json::from_str::<PoisoningFamily>(token).is_err());
            assert!(serde_json::from_str::<MisuseFamily>(token).is_err());
        }
    }

    #[test]
    fn unknown_and_miscased_values_fail_closed() {
        assert!(serde_json::from_str::<ScenarioClass>("\"poisoning\"").is_err());
        assert!(serde_json::from_str::<ScenarioClass>("\"BOTH\"").is_err());
        assert!(serde_json::from_str::<PoisoningFamily>("\"\"").is_err());
        assert!(serde_json::from_str::<MisuseFamily>("null").is_err());
        assert!(serde_json::from_str::<TrustLevel>("\"UNKNOWN\"").is_err());
        assert!(serde_json::from_str::<CorpusClass>("\"HOSTILE\"").is_err());
    }

    #[test]
    fn mixed_trust_fails_closed_toward_untrusted() {
        assert!(TrustLevel::Untrusted.is_attacker_controlled());
        assert!(TrustLevel::Mixed.is_attacker_controlled());
        assert!(!TrustLevel::Trusted.is_attacker_controlled());
    }

    #[test]
    fn benign_controls_are_not_counted_as_attacks() {
        assert!(CorpusClass::PoisoningAttack.is_attack());
        assert!(CorpusClass::MisuseAttack.is_attack());
        assert!(!CorpusClass::BenignControl.is_attack());
        assert_eq!(
            CorpusClass::PoisoningAttack.scenario_class(),
            Some(ScenarioClass::Poisoning)
        );
        assert_eq!(
            CorpusClass::MisuseAttack.scenario_class(),
            Some(ScenarioClass::Misuse)
        );
        assert_eq!(CorpusClass::BenignControl.scenario_class(), None);
    }

    #[test]
    fn family_lists_are_complete_and_unique() {
        let poisoning: std::collections::HashSet<&str> =
            PoisoningFamily::all().iter().map(|f| f.as_str()).collect();
        assert_eq!(poisoning.len(), 8);
        let misuse: std::collections::HashSet<&str> =
            MisuseFamily::all().iter().map(|f| f.as_str()).collect();
        assert_eq!(misuse.len(), 10);
        // The two taxonomies share no token.
        assert!(poisoning.is_disjoint(&misuse));
    }
}
