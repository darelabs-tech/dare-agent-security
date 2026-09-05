//! Typed prompt-injection data contracts.
//!
//! Every struct is `deny_unknown_fields`. Typed decoding happens only after
//! JSON Schema validation and the hostile-field sweep, so these types are the
//! second, independent gate rather than the first.

use serde::{Deserialize, Serialize};

use crate::source::{CorpusClass, InjectionFamily, SourceKind, TrustLevel};

/// Security invariant an evaluator decides deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvariantType {
    /// The authorized goal identifier did not change.
    AuthorizedGoalUnchanged,
    /// No protected synthetic canary was disclosed.
    ForbiddenCanaryNotDisclosed,
    /// No structured action outside the approved set was requested.
    UnauthorizedActionNotRequested,
    /// No protected field was emitted.
    ProtectedFieldNotEmitted,
    /// A policy DENY decision was not bypassed.
    PolicyDenyNotBypassed,
    /// The expected output schema was preserved.
    ExpectedSchemaPreserved,
}

impl InvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizedGoalUnchanged => "AUTHORIZED_GOAL_UNCHANGED",
            Self::ForbiddenCanaryNotDisclosed => "FORBIDDEN_CANARY_NOT_DISCLOSED",
            Self::UnauthorizedActionNotRequested => "UNAUTHORIZED_ACTION_NOT_REQUESTED",
            Self::ProtectedFieldNotEmitted => "PROTECTED_FIELD_NOT_EMITTED",
            Self::PolicyDenyNotBypassed => "POLICY_DENY_NOT_BYPASSED",
            Self::ExpectedSchemaPreserved => "EXPECTED_SCHEMA_PRESERVED",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::AuthorizedGoalUnchanged,
            Self::ForbiddenCanaryNotDisclosed,
            Self::UnauthorizedActionNotRequested,
            Self::ProtectedFieldNotEmitted,
            Self::PolicyDenyNotBypassed,
            Self::ExpectedSchemaPreserved,
        ]
    }
}

/// Security property the scenario validates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BoundaryProperty {
    #[serde(rename = "AGENT.GOAL.INSTRUCTION_INTEGRITY")]
    InstructionIntegrity,
    #[serde(rename = "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY")]
    UserInputInstructionBoundary,
    #[serde(rename = "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY")]
    ExternalContentInstructionBoundary,
}

impl BoundaryProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstructionIntegrity => "AGENT.GOAL.INSTRUCTION_INTEGRITY",
            Self::UserInputInstructionBoundary => "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
            Self::ExternalContentInstructionBoundary => {
                "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY"
            }
        }
    }
}

/// Content trust boundary the injected material crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBoundary {
    pub kind: SourceKind,
    pub trust: TrustLevel,
}

/// The authorized task the agent is supposed to be performing.
///
/// This is the security ground truth a scenario is measured against. It is
/// inline rather than referenced by path so that it is covered by the scenario
/// digest and cannot be substituted after approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Objective {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub authorized_goal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_canaries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_schema_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_policy_decisions: Vec<String>,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorRef {
    pub corpus_id: String,
    /// Optional binding. When present it must match the loaded corpus entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// The invariant under test. `expected` is always true by schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    #[serde(rename = "type")]
    pub type_: InvariantType,
    pub expected: bool,
}

/// Requested trial policy. Values are clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialSpec {
    pub count: u32,
    #[serde(default = "default_stop_on_first_fail")]
    pub stop_on_first_fail: bool,
}

fn default_stop_on_first_fail() -> bool {
    crate::limits::STOP_ON_FIRST_FAIL
}

/// Requested safety envelope. Values are clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetySpec {
    pub local_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_output_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
}

/// Standards attribution. Never an endorsement or an equivalence claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// Synthetic-lab metadata for SIMULATED and LOCAL_SYNTHETIC modes.
///
/// This block declares how the *reference agent* behaves so the corpus can be
/// exercised offline. It deliberately carries no expected verdict: the engine
/// must never be able to read the answer it is supposed to compute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabSpec {
    pub reference_behavior: crate::simulated::ReferenceBehavior,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub per_trial: std::collections::BTreeMap<String, crate::simulated::ReferenceBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_filler_bytes: Option<usize>,
}

impl LabSpec {
    /// Build the simulation profile this lab spec describes.
    pub fn profile(&self) -> crate::simulated::SimulationProfile {
        let mut profile = crate::simulated::SimulationProfile {
            behavior: self.reference_behavior,
            per_trial: std::collections::BTreeMap::new(),
            output_filler_bytes: self.output_filler_bytes,
        };
        for (index, behavior) in &self.per_trial {
            if let Ok(index) = index.parse::<u32>() {
                profile.per_trial.insert(index, *behavior);
            }
        }
        profile
    }
}

/// A complete, versioned prompt-injection scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionScenario {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub family: InjectionFamily,
    pub property: BoundaryProperty,
    pub source: SourceBoundary,
    pub objective: Objective,
    pub vector: VectorRef,
    pub invariant: InvariantSpec,
    pub trials: TrialSpec,
    pub safety: SafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<LabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<StandardRef>,
}

/// How corpus content is encoded. Descriptive only; never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentEncoding {
    PlainText,
    Html,
    Markdown,
    JsonText,
}

/// Inert fixture content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusContent {
    pub encoding: ContentEncoding,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_note: Option<String>,
}

/// Corpus provenance. Synthetic origin only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusProvenance {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub created_at: String,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One corpus vector or benign control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEntry {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: CorpusClass,
    pub family: InjectionFamily,
    pub source_kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustLevel>,
    pub property: BoundaryProperty,
    pub preconditions: Vec<String>,
    pub content: CorpusContent,
    pub expected_invariant: InvariantType,
    pub safety_class: String,
    pub standards: Vec<StandardRef>,
    pub provenance: CorpusProvenance,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scenario_round_trips_through_the_typed_layer() {
        let value = crate::schema::tests::valid_scenario();
        let scenario: PromptInjectionScenario = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(scenario.id, "PI-LAB-001");
        assert_eq!(scenario.family, InjectionFamily::DirectGoalOverride);
        assert_eq!(scenario.source.kind, SourceKind::UserPrompt);
        assert_eq!(scenario.source.trust, TrustLevel::Untrusted);
        assert_eq!(
            scenario.property,
            BoundaryProperty::UserInputInstructionBoundary
        );
        assert_eq!(
            scenario.invariant.type_,
            InvariantType::AuthorizedGoalUnchanged
        );
        assert!(scenario.safety.local_only);

        let back = serde_json::to_value(&scenario).unwrap();
        let again: PromptInjectionScenario = serde_json::from_value(back).unwrap();
        assert_eq!(again, scenario);
    }

    #[test]
    fn corpus_entry_round_trips_through_the_typed_layer() {
        let value = crate::corpus::tests::direct_entry();
        let entry: CorpusEntry = serde_json::from_value(value).unwrap();
        assert_eq!(entry.class, CorpusClass::DirectAttack);
        assert_eq!(entry.source_kind, SourceKind::UserPrompt);
        assert_eq!(entry.content.encoding, ContentEncoding::PlainText);
        assert_eq!(entry.safety_class, "SYNTHETIC_NOOP");

        let back = serde_json::to_value(&entry).unwrap();
        let again: CorpusEntry = serde_json::from_value(back).unwrap();
        assert_eq!(again, entry);
    }

    #[test]
    fn typed_layer_rejects_unknown_fields_independently_of_the_schema() {
        let mut value = crate::schema::tests::valid_scenario();
        value["adaptive_escalation"] = json!(true);
        assert!(serde_json::from_value::<PromptInjectionScenario>(value).is_err());

        let mut value = crate::corpus::tests::direct_entry();
        value["content"]["interpreter"] = json!("python");
        assert!(serde_json::from_value::<CorpusEntry>(value).is_err());
    }

    #[test]
    fn invariant_wire_tokens_are_stable_and_closed() {
        for invariant in InvariantType::all() {
            assert_eq!(
                serde_json::to_value(invariant).unwrap(),
                json!(invariant.as_str())
            );
        }
        assert_eq!(InvariantType::all().len(), 6);
        assert!(serde_json::from_str::<InvariantType>("\"LLM_JUDGEMENT\"").is_err());
        assert!(serde_json::from_str::<InvariantType>("\"MODEL_REFUSED\"").is_err());
        assert!(serde_json::from_str::<InvariantType>("\"looks_safe\"").is_err());
    }

    #[test]
    fn boundary_property_accepts_only_the_three_cycle_013_properties() {
        for property in [
            BoundaryProperty::InstructionIntegrity,
            BoundaryProperty::UserInputInstructionBoundary,
            BoundaryProperty::ExternalContentInstructionBoundary,
        ] {
            assert_eq!(
                serde_json::to_value(property).unwrap(),
                json!(property.as_str())
            );
        }
        assert!(
            serde_json::from_str::<BoundaryProperty>("\"AGENT.TOOL.OUTPUT_TRUST_BOUNDARY\"")
                .is_err()
        );
        assert!(serde_json::from_str::<BoundaryProperty>("\"AGENT.RAG.CONTENT\"").is_err());
    }

    #[test]
    fn content_encoding_is_descriptive_and_closed() {
        assert!(serde_json::from_str::<ContentEncoding>("\"EXECUTABLE\"").is_err());
        assert!(serde_json::from_str::<ContentEncoding>("\"SHELL\"").is_err());
        assert_eq!(
            serde_json::to_value(ContentEncoding::JsonText).unwrap(),
            json!("JSON_TEXT")
        );
    }

    #[test]
    fn stop_on_first_fail_defaults_to_the_approved_value() {
        let trials: TrialSpec = serde_json::from_value(json!({"count": 3})).unwrap();
        assert_eq!(trials.stop_on_first_fail, crate::limits::STOP_ON_FIRST_FAIL);
        assert!(trials.stop_on_first_fail);
    }

    #[test]
    fn objective_omits_empty_collections_for_stable_digests() {
        let objective = Objective {
            id: "objective-minimal".to_owned(),
            description: None,
            authorized_goal_id: "goal-minimal".to_owned(),
            authorized_actions: Vec::new(),
            protected_canaries: Vec::new(),
            protected_fields: Vec::new(),
            expected_schema_fields: Vec::new(),
            denied_policy_decisions: Vec::new(),
        };
        let value = serde_json::to_value(&objective).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 2, "empty collections must not be serialized");
        assert!(object.contains_key("id"));
        assert!(object.contains_key("authorized_goal_id"));
    }
}
