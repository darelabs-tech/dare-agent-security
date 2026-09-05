//! Typed tool-security data contracts.
//!
//! Every struct is `deny_unknown_fields`. Typed decoding happens only after
//! JSON Schema validation and the hostile-field sweep, so these types are the
//! second, independent gate rather than the first.

use serde::{Deserialize, Serialize};

use crate::source::{MisuseFamily, PoisoningFamily, ScenarioClass, ToolSourceKind, TrustLevel};

/// Security invariant a deterministic evaluator decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolInvariantType {
    /// Tool-declared metadata never becomes authority.
    ToolMetadataNotAuthoritative,
    /// Only tools in the approved set are selected or requested.
    ApprovedToolOnly,
    /// Tool selection stays bound to the authorized objective.
    ToolSelectionBoundToObjective,
    /// Arguments preserve the approved intent.
    ToolArgumentsPreserveApprovedIntent,
    /// No forbidden dangerous operation is requested.
    DangerousArgumentNotRequested,
    /// Tool output is data, never instruction.
    ToolOutputNotReinterpretedAsAuthority,
    /// Chain members stay inside the approved set.
    ChainWithinApprovedSet,
    /// Chain depth stays inside the approved bound.
    ChainDepthWithinBound,
    /// Invocation count stays inside the approved bound.
    InvocationCountWithinBound,
    /// An observed policy denial is not bypassed.
    PolicyDenyNotBypassed,
}

impl ToolInvariantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolMetadataNotAuthoritative => "TOOL_METADATA_NOT_AUTHORITATIVE",
            Self::ApprovedToolOnly => "APPROVED_TOOL_ONLY",
            Self::ToolSelectionBoundToObjective => "TOOL_SELECTION_BOUND_TO_OBJECTIVE",
            Self::ToolArgumentsPreserveApprovedIntent => "TOOL_ARGUMENTS_PRESERVE_APPROVED_INTENT",
            Self::DangerousArgumentNotRequested => "DANGEROUS_ARGUMENT_NOT_REQUESTED",
            Self::ToolOutputNotReinterpretedAsAuthority => {
                "TOOL_OUTPUT_NOT_REINTERPRETED_AS_AUTHORITY"
            }
            Self::ChainWithinApprovedSet => "CHAIN_WITHIN_APPROVED_SET",
            Self::ChainDepthWithinBound => "CHAIN_DEPTH_WITHIN_BOUND",
            Self::InvocationCountWithinBound => "INVOCATION_COUNT_WITHIN_BOUND",
            Self::PolicyDenyNotBypassed => "POLICY_DENY_NOT_BYPASSED",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::ToolMetadataNotAuthoritative,
            Self::ApprovedToolOnly,
            Self::ToolSelectionBoundToObjective,
            Self::ToolArgumentsPreserveApprovedIntent,
            Self::DangerousArgumentNotRequested,
            Self::ToolOutputNotReinterpretedAsAuthority,
            Self::ChainWithinApprovedSet,
            Self::ChainDepthWithinBound,
            Self::InvocationCountWithinBound,
            Self::PolicyDenyNotBypassed,
        ]
    }
}

/// Security property the scenario validates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolBoundaryProperty {
    #[serde(rename = "AGENT.TOOL.AUTHORIZATION_BOUNDARY")]
    AuthorizationBoundary,
    #[serde(rename = "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY")]
    OutputTrustBoundary,
    #[serde(rename = "AGENT.TOOL.METADATA_TRUST_BOUNDARY")]
    MetadataTrustBoundary,
    #[serde(rename = "AGENT.TOOL.SELECTION_INTENT_BINDING")]
    SelectionIntentBinding,
    #[serde(rename = "AGENT.TOOL.ARGUMENT_INTEGRITY")]
    ArgumentIntegrity,
    #[serde(rename = "AGENT.TOOL.CHAIN_BOUNDARY")]
    ChainBoundary,
}

impl ToolBoundaryProperty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationBoundary => "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
            Self::OutputTrustBoundary => "AGENT.TOOL.OUTPUT_TRUST_BOUNDARY",
            Self::MetadataTrustBoundary => "AGENT.TOOL.METADATA_TRUST_BOUNDARY",
            Self::SelectionIntentBinding => "AGENT.TOOL.SELECTION_INTENT_BINDING",
            Self::ArgumentIntegrity => "AGENT.TOOL.ARGUMENT_INTEGRITY",
            Self::ChainBoundary => "AGENT.TOOL.CHAIN_BOUNDARY",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::AuthorizationBoundary,
            Self::OutputTrustBoundary,
            Self::MetadataTrustBoundary,
            Self::SelectionIntentBinding,
            Self::ArgumentIntegrity,
            Self::ChainBoundary,
        ]
    }
}

/// Family, kept in one field but decoded into the correct closed taxonomy.
///
/// Serializes as a bare token so a scenario cannot claim a poisoning family for
/// a misuse class or vice versa without the cross-field check catching it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolFamily {
    Poisoning(PoisoningFamily),
    Misuse(MisuseFamily),
}

impl ToolFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Poisoning(family) => family.as_str(),
            Self::Misuse(family) => family.as_str(),
        }
    }

    /// The scenario class this family belongs to.
    pub fn class(self) -> ScenarioClass {
        match self {
            Self::Poisoning(_) => ScenarioClass::Poisoning,
            Self::Misuse(_) => ScenarioClass::Misuse,
        }
    }
}

/// Declared operation class for a tool or a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationClass {
    Read,
    Search,
    Summarize,
    Write,
    Delete,
    Send,
    Payment,
    ExternalFetch,
    PrivilegeChange,
}

impl OperationClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Search => "SEARCH",
            Self::Summarize => "SUMMARIZE",
            Self::Write => "WRITE",
            Self::Delete => "DELETE",
            Self::Send => "SEND",
            Self::Payment => "PAYMENT",
            Self::ExternalFetch => "EXTERNAL_FETCH",
            Self::PrivilegeChange => "PRIVILEGE_CHANGE",
        }
    }

    pub fn all() -> [Self; 9] {
        [
            Self::Read,
            Self::Search,
            Self::Summarize,
            Self::Write,
            Self::Delete,
            Self::Send,
            Self::Payment,
            Self::ExternalFetch,
            Self::PrivilegeChange,
        ]
    }

    /// True when this class can change state or leave the system.
    ///
    /// Cycle 014 observes such requests as structured data and never dispatches
    /// them. This classification exists to reason about the request, not to
    /// gate an execution path — because there is no execution path.
    pub fn is_state_changing_or_egress(self) -> bool {
        matches!(
            self,
            Self::Write
                | Self::Delete
                | Self::Send
                | Self::Payment
                | Self::ExternalFetch
                | Self::PrivilegeChange
        )
    }
}

/// Declared meaning of a tool parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticClass {
    Identifier,
    Query,
    Content,
    Path,
    Recipient,
    Amount,
    Scope,
    Flag,
    Opaque,
}

/// Declared parameter type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
}

/// One declared tool parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: ParameterType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_class: Option<SemanticClass>,
}

/// Declared input schema for a tool. Inert; never compiled or executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInputSchema {
    pub parameters: Vec<ToolParameter>,
}

/// Declared behavioral annotations.
///
/// A tool asserting `read_only_hint` does not make it read-only. These are
/// claims to be checked against policy, not facts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Declared sensitivity of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeclaredSensitivity {
    Low,
    Medium,
    High,
}

/// Declared security metadata for a tool. Untrusted, like the description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_operation_class: Option<OperationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_sensitivity: Option<DeclaredSensitivity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_requires_approval: Option<bool>,
}

/// One tool as observed on the surface under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    pub tool_id: String,
    pub tool_name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<ToolInputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_metadata: Option<ToolSecurityMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Approved canonical digest. A mismatch is refused before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// The observed tool surface under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceSnapshot {
    pub schema_version: String,
    pub surface_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub source_kind: ToolSourceKind,
    pub trust: TrustLevel,
    pub tools: Vec<ToolEntry>,
}

impl ToolSurfaceSnapshot {
    pub fn get(&self, tool_id: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|tool| tool.tool_id == tool_id)
    }
}

/// Typed constraint on one approved argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// One approved tool within the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedTool {
    pub tool_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_operation_classes: Vec<OperationClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_arguments: Vec<ApprovedArgument>,
}

/// Approved chain membership, order and depth.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_chain_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_order: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chain_depth: Option<u32>,
}

/// Approved invocation bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_requests: Option<u32>,
}

/// The authoritative approved tool policy.
///
/// This is the authority untrusted tool metadata must never override. It is
/// declarative data: there is no expression language and no executable rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedToolPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub approved_tools: Vec<ApprovedTool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_operation_classes: Vec<OperationClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_argument_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_policy: Option<ChainPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_policy: Option<InvocationPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_policy_decisions: Vec<String>,
}

impl ApprovedToolPolicy {
    pub fn approved_tool(&self, tool_id: &str) -> Option<&ApprovedTool> {
        self.approved_tools
            .iter()
            .find(|tool| tool.tool_id == tool_id)
    }

    /// Exact membership check. A tool absent from the policy is unapproved;
    /// absence of a rule is never permission.
    pub fn is_approved(&self, tool_id: &str) -> bool {
        self.approved_tool(tool_id).is_some()
    }
}

/// The authorized task a run is measured against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObjective {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub authorized_goal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_canaries: Vec<String>,
}

/// Source boundary of the tool surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSourceBoundary {
    pub kind: ToolSourceKind,
    pub trust: TrustLevel,
}

/// Reference to the corpus vector a scenario exercises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolVectorRef {
    pub corpus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_digest: Option<String>,
}

/// The invariant under test. `expected` is always true by schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInvariantSpec {
    #[serde(rename = "type")]
    pub type_: ToolInvariantType,
    pub expected: bool,
}

/// Requested trial policy. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTrialSpec {
    pub count: u32,
    #[serde(default = "default_stop_on_first_fail")]
    pub stop_on_first_fail: bool,
}

fn default_stop_on_first_fail() -> bool {
    crate::limits::STOP_ON_FIRST_FAIL
}

/// Requested safety envelope. Clamped against the hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSafetySpec {
    pub local_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tool_requests_per_trial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_tool_requests: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chain_depth: Option<u32>,
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
pub struct ToolStandardRef {
    pub source: String,
    pub reference: String,
    pub status: String,
}

/// How the reference agent behaves in synthetic modes.
///
/// This is fixture metadata, not an answer key: it describes *behavior*, and
/// the evaluator still computes the verdict from the resulting observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceBehavior {
    /// Stays within policy on every channel.
    Compliant,
    /// Treats a poisoned tool description/schema/annotation as authority.
    MetadataTreatedAsAuthority,
    /// Selects a tool outside the approved set.
    UnapprovedToolSelected,
    /// Selects an approved tool that does not serve the authorized objective.
    ObjectiveMismatchedSelection,
    /// Substitutes or pollutes arguments.
    ArgumentsSubstituted,
    /// Requests a forbidden dangerous operation.
    DangerousArgumentRequested,
    /// Treats tool output as instruction and acts on it.
    OutputTreatedAsAuthority,
    /// Adds a chain member outside the approved set.
    UnapprovedChainMember,
    /// Exceeds the approved chain depth.
    ChainDepthExceeded,
    /// Exceeds the approved invocation bound.
    ExcessiveInvocation,
    /// Requests an operation a policy decision denied.
    PolicyDenyBypassed,
    /// Violates several invariants at once, independently.
    MultipleIndependentViolations,
    /// Produces nothing decidable on the relevant channel.
    NoRelevantObservation,
    /// The harness itself failed.
    HarnessFailure,
}

impl ReferenceBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::MetadataTreatedAsAuthority => "METADATA_TREATED_AS_AUTHORITY",
            Self::UnapprovedToolSelected => "UNAPPROVED_TOOL_SELECTED",
            Self::ObjectiveMismatchedSelection => "OBJECTIVE_MISMATCHED_SELECTION",
            Self::ArgumentsSubstituted => "ARGUMENTS_SUBSTITUTED",
            Self::DangerousArgumentRequested => "DANGEROUS_ARGUMENT_REQUESTED",
            Self::OutputTreatedAsAuthority => "OUTPUT_TREATED_AS_AUTHORITY",
            Self::UnapprovedChainMember => "UNAPPROVED_CHAIN_MEMBER",
            Self::ChainDepthExceeded => "CHAIN_DEPTH_EXCEEDED",
            Self::ExcessiveInvocation => "EXCESSIVE_INVOCATION",
            Self::PolicyDenyBypassed => "POLICY_DENY_BYPASSED",
            Self::MultipleIndependentViolations => "MULTIPLE_INDEPENDENT_VIOLATIONS",
            Self::NoRelevantObservation => "NO_RELEVANT_OBSERVATION",
            Self::HarnessFailure => "HARNESS_FAILURE",
        }
    }
}

/// Synthetic-lab metadata. Carries no expected verdict, deliberately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLabSpec {
    pub reference_behavior: ReferenceBehavior,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub per_trial: std::collections::BTreeMap<String, ReferenceBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_filler_bytes: Option<usize>,
}

impl ToolLabSpec {
    /// Behavior for one trial index, falling back to the default.
    pub fn behavior_for(&self, trial_index: u32) -> ReferenceBehavior {
        self.per_trial
            .get(&trial_index.to_string())
            .copied()
            .unwrap_or(self.reference_behavior)
    }
}

/// A complete, versioned tool-security scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityScenario {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub class: ScenarioClass,
    pub family: ToolFamily,
    pub property: ToolBoundaryProperty,
    pub source: ToolSourceBoundary,
    pub objective: ToolObjective,
    pub policy: ApprovedToolPolicy,
    pub tool_surface: ToolSurfaceSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<ToolVectorRef>,
    pub invariant: ToolInvariantSpec,
    pub trials: ToolTrialSpec,
    pub safety: ToolSafetySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab: Option<ToolLabSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<ToolStandardRef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scenario_round_trips_through_the_typed_layer() {
        let value = crate::schema::tests::valid_scenario();
        let scenario: ToolSecurityScenario = serde_json::from_value(value).unwrap();
        assert_eq!(scenario.id, "TOOL-LAB-001");
        assert_eq!(scenario.class, ScenarioClass::Poisoning);
        assert_eq!(scenario.family.class(), ScenarioClass::Poisoning);
        assert_eq!(
            scenario.property,
            ToolBoundaryProperty::MetadataTrustBoundary
        );
        assert!(scenario.safety.local_only);
        assert_eq!(scenario.policy.approved_tools.len(), 2);
        assert_eq!(scenario.tool_surface.tools.len(), 2);

        let back = serde_json::to_value(&scenario).unwrap();
        let again: ToolSecurityScenario = serde_json::from_value(back).unwrap();
        assert_eq!(again, scenario);
    }

    #[test]
    fn typed_layer_rejects_unknown_fields_independently_of_the_schema() {
        let mut value = crate::schema::tests::valid_scenario();
        value["autonomous_escalation"] = json!(true);
        assert!(serde_json::from_value::<ToolSecurityScenario>(value).is_err());

        let mut value = crate::schema::tests::valid_scenario();
        value["policy"]["rule_expression"] = json!("tool == 'x'");
        assert!(serde_json::from_value::<ToolSecurityScenario>(value).is_err());

        let mut value = crate::schema::tests::valid_scenario();
        value["tool_surface"]["tools"][0]["interpreter"] = json!("python");
        assert!(serde_json::from_value::<ToolSecurityScenario>(value).is_err());
    }

    #[test]
    fn invariant_wire_tokens_are_stable_and_closed() {
        for invariant in ToolInvariantType::all() {
            assert_eq!(
                serde_json::to_value(invariant).unwrap(),
                json!(invariant.as_str())
            );
        }
        assert_eq!(ToolInvariantType::all().len(), 10);
        assert!(serde_json::from_str::<ToolInvariantType>("\"LLM_JUDGEMENT\"").is_err());
        assert!(serde_json::from_str::<ToolInvariantType>("\"SEEMS_SAFE\"").is_err());
        assert!(serde_json::from_str::<ToolInvariantType>("\"approved_tool_only\"").is_err());
    }

    #[test]
    fn boundary_property_accepts_only_the_six_tool_properties() {
        for property in ToolBoundaryProperty::all() {
            assert_eq!(
                serde_json::to_value(property).unwrap(),
                json!(property.as_str())
            );
        }
        assert_eq!(ToolBoundaryProperty::all().len(), 6);
        assert!(serde_json::from_str::<ToolBoundaryProperty>(
            "\"AGENT.GOAL.INSTRUCTION_INTEGRITY\""
        )
        .is_err());
        assert!(serde_json::from_str::<ToolBoundaryProperty>(
            "\"AGENT.IDENTITY.DELEGATION_INTEGRITY\""
        )
        .is_err());
    }

    #[test]
    fn family_decodes_into_the_correct_taxonomy() {
        let poisoning: ToolFamily =
            serde_json::from_str("\"TOOL_SCHEMA_PARAMETER_POISONING\"").unwrap();
        assert_eq!(poisoning.class(), ScenarioClass::Poisoning);

        let misuse: ToolFamily = serde_json::from_str("\"DANGEROUS_ARGUMENT_REQUEST\"").unwrap();
        assert_eq!(misuse.class(), ScenarioClass::Misuse);

        assert!(serde_json::from_str::<ToolFamily>("\"CREDENTIAL_INHERITANCE\"").is_err());
    }

    #[test]
    fn state_changing_operation_classes_are_identified() {
        for class in [
            OperationClass::Write,
            OperationClass::Delete,
            OperationClass::Send,
            OperationClass::Payment,
            OperationClass::ExternalFetch,
            OperationClass::PrivilegeChange,
        ] {
            assert!(class.is_state_changing_or_egress(), "{}", class.as_str());
        }
        for class in [
            OperationClass::Read,
            OperationClass::Search,
            OperationClass::Summarize,
        ] {
            assert!(!class.is_state_changing_or_egress(), "{}", class.as_str());
        }
        assert_eq!(OperationClass::all().len(), 9);
    }

    #[test]
    fn policy_membership_is_exact_and_absence_is_not_permission() {
        let scenario: ToolSecurityScenario =
            serde_json::from_value(crate::schema::tests::valid_scenario()).unwrap();
        assert!(scenario.policy.is_approved("ticket_search"));
        assert!(scenario.policy.is_approved("ticket_summarize"));

        // A tool nobody approved is unapproved, not implicitly allowed.
        assert!(!scenario.policy.is_approved("ticket_delete"));
        assert!(!scenario.policy.is_approved("ticket_searc"));
        assert!(!scenario.policy.is_approved("ticket_search_all"));
        assert!(scenario.policy.approved_tool("unknown_tool").is_none());
    }

    #[test]
    fn tool_annotations_are_claims_not_facts() {
        let scenario: ToolSecurityScenario =
            serde_json::from_value(crate::schema::tests::valid_scenario()).unwrap();
        let tool = scenario.tool_surface.get("ticket_search").expect("tool");
        // The surface claims read-only. That claim is data; policy decides.
        assert_eq!(
            tool.annotations.as_ref().and_then(|a| a.read_only_hint),
            Some(true)
        );
        assert!(!scenario.tool_surface.source_kind.is_authoritative());
    }

    #[test]
    fn reference_behavior_is_behavior_not_a_verdict() {
        // Every variant names what the agent (or harness) does, never what the
        // result is. Compared as whole tokens: HARNESS_FAILURE describes a
        // broken run, and matching it on the substring "FAIL" would be exactly
        // the imprecise-assertion mistake this project already paid for once.
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::MetadataTreatedAsAuthority,
            ReferenceBehavior::UnapprovedToolSelected,
            ReferenceBehavior::ObjectiveMismatchedSelection,
            ReferenceBehavior::ArgumentsSubstituted,
            ReferenceBehavior::DangerousArgumentRequested,
            ReferenceBehavior::OutputTreatedAsAuthority,
            ReferenceBehavior::UnapprovedChainMember,
            ReferenceBehavior::ChainDepthExceeded,
            ReferenceBehavior::ExcessiveInvocation,
            ReferenceBehavior::PolicyDenyBypassed,
            ReferenceBehavior::MultipleIndependentViolations,
            ReferenceBehavior::NoRelevantObservation,
            ReferenceBehavior::HarnessFailure,
        ] {
            let token = behavior.as_str();
            for verdict in ["PASS", "FAIL", "INCONCLUSIVE", "ERROR"] {
                assert_ne!(token, verdict, "{token} must not be a verdict token");
            }
            // Nor may a behavior decode as a verdict.
            assert!(serde_json::from_str::<crate::Verdict>(&format!("\"{token}\"")).is_err());
        }
    }

    #[test]
    fn lab_per_trial_overrides_fall_back_to_the_default() {
        let mut per_trial = std::collections::BTreeMap::new();
        per_trial.insert("1".to_owned(), ReferenceBehavior::UnapprovedToolSelected);
        let lab = ToolLabSpec {
            reference_behavior: ReferenceBehavior::Compliant,
            per_trial,
            output_filler_bytes: None,
        };
        assert_eq!(lab.behavior_for(0), ReferenceBehavior::Compliant);
        assert_eq!(
            lab.behavior_for(1),
            ReferenceBehavior::UnapprovedToolSelected
        );
        assert_eq!(lab.behavior_for(2), ReferenceBehavior::Compliant);
    }

    #[test]
    fn stop_on_first_fail_defaults_to_the_approved_value() {
        let trials: ToolTrialSpec = serde_json::from_value(json!({"count": 3})).unwrap();
        assert_eq!(trials.stop_on_first_fail, crate::limits::STOP_ON_FIRST_FAIL);
        assert!(trials.stop_on_first_fail);
    }
}
