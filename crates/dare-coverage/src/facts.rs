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
