//! Typed assessment facts. No arbitrary expressions.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Stdio,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentFacts {
    pub tools_count: u32,
    pub resources_count: u32,
    pub prompts_count: u32,
    pub transport: TransportKind,
    pub authorization_present: bool,
    /// ROE: when false, dynamic-only properties become BLOCKED (never NOT_APPLICABLE).
    pub dynamic_authorization_allowed: bool,
    pub execution_integrity_supported: bool,
    pub confused_deputy_supported: bool,
    #[serde(default)]
    pub agent_present: bool,
    #[serde(default)]
    pub memory_present: bool,
    #[serde(default)]
    pub rag_present: bool,
    #[serde(default)]
    pub multi_agent_present: bool,
    #[serde(default)]
    pub code_execution_present: bool,
    #[serde(default)]
    pub human_approval_present: bool,
    #[serde(default)]
    pub delegated_identity_present: bool,
    #[serde(default)]
    pub external_components_present: bool,
    #[serde(default)]
    pub stateful_agent_present: bool,
    #[serde(default)]
    pub runtime_dynamic_allowed: bool,
    /// Cycle 013: the target ingests user-controlled prompt content.
    #[serde(default)]
    pub user_prompt_present: bool,
    /// Cycle 013: the target ingests untrusted external content as data.
    #[serde(default)]
    pub untrusted_external_content_present: bool,
    #[serde(default)]
    pub out_of_scope_property_ids: Vec<String>,
}

impl AssessmentFacts {
    pub fn tools_present(&self) -> bool {
        self.tools_count > 0
    }
    pub fn resources_present(&self) -> bool {
        self.resources_count > 0
    }
    pub fn prompts_present(&self) -> bool {
        self.prompts_count > 0
    }
}
