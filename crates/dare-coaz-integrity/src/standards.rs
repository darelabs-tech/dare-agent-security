//! Versioned standards snapshot metadata for Cycle 003 vectors and results.

use serde::{Deserialize, Serialize};

/// Lifecycle status of a referenced standard or upstream item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StandardStatus {
    /// Published normative specification.
    Normative,
    /// Working draft not yet final.
    Draft,
    /// Open upstream proposal/issue, not normative text.
    OpenProposal,
}

/// Machine-readable reference to a standards document, section or upstream issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardReference {
    pub family: String,
    pub document: String,
    pub version: String,
    pub status: StandardStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_issue: Option<String>,
}

impl StandardReference {
    pub fn stable_id(&self) -> String {
        let section = self.section.as_deref().unwrap_or("");
        let issue = self.upstream_issue.as_deref().unwrap_or("");
        format!(
            "{}|{}|{}|{:?}|{}|{}",
            self.family, self.document, self.version, self.status, section, issue
        )
    }
}

/// Cycle 003 executable scope note carried alongside standards metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableScopeNote {
    pub mcp_method_scope: String,
    pub lifecycle_skew_note: String,
}

/// Full standards snapshot embedded in vectors and results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardsSnapshot {
    pub schema_version: String,
    pub references: Vec<StandardReference>,
    pub executable_scope: ExecutableScopeNote,
}

/// JSON fixture identifier for offline validation.
pub const STANDARDS_SNAPSHOT_FIXTURE_ID: &str = "cycle003-standards-v1";

/// Returns the canonical Cycle 003 standards snapshot.
pub fn cycle003_standards_snapshot() -> StandardsSnapshot {
    StandardsSnapshot {
        schema_version: "1.0.0".to_owned(),
        references: vec![
            StandardReference {
                family: "OpenID AuthZEN".to_owned(),
                document: "Authorization API".to_owned(),
                version: "1.0".to_owned(),
                status: StandardStatus::Normative,
                section: None,
                upstream_issue: None,
            },
            StandardReference {
                family: "COAZ".to_owned(),
                document: "Framework".to_owned(),
                version: "1.0 Draft 1".to_owned(),
                status: StandardStatus::Draft,
                section: None,
                upstream_issue: None,
            },
            StandardReference {
                family: "COAZ-MCP".to_owned(),
                document: "Binding".to_owned(),
                version: "1.0 Draft 1".to_owned(),
                status: StandardStatus::Draft,
                section: Some("Â§9 PEP Behavior".to_owned()),
                upstream_issue: None,
            },
            StandardReference {
                family: "COAZ-MCP".to_owned(),
                document: "Binding".to_owned(),
                version: "1.0 Draft 1".to_owned(),
                status: StandardStatus::Draft,
                section: Some("Â§11.5 Mapping Integrity".to_owned()),
                upstream_issue: None,
            },
            StandardReference {
                family: "OpenID AuthZEN".to_owned(),
                document: "COAZ-MCP authorization-to-execution binding".to_owned(),
                version: "proposal".to_owned(),
                status: StandardStatus::OpenProposal,
                section: None,
                upstream_issue: Some("openid/authzen#603".to_owned()),
            },
            StandardReference {
                family: "MCP".to_owned(),
                document: "Model Context Protocol".to_owned(),
                version: "2026-07-28".to_owned(),
                status: StandardStatus::Normative,
                section: Some("tools/call semantics".to_owned()),
                upstream_issue: None,
            },
        ],
        executable_scope: ExecutableScopeNote {
            mcp_method_scope: "tools/call".to_owned(),
            lifecycle_skew_note: "COAZ-MCP Draft 1 lifecycle examples may differ from MCP 2026-07-28; Cycle 003 vectors execute only tools/call against the repository MCP revision.".to_owned(),
        },
    }
}

/// Required stable identifiers asserted by the task-001 fixture test.
pub fn required_reference_keys() -> [&'static str; 6] {
    [
        "OpenID AuthZEN|Authorization API|1.0",
        "COAZ|Framework|1.0 Draft 1",
        "COAZ-MCP|Binding|1.0 Draft 1|Â§9 PEP Behavior",
        "COAZ-MCP|Binding|1.0 Draft 1|Â§11.5 Mapping Integrity",
        "openid/authzen#603",
        "MCP|Model Context Protocol|2026-07-28|tools/call semantics",
    ]
}

pub fn reference_key(reference: &StandardReference) -> String {
    match (&reference.section, &reference.upstream_issue) {
        (Some(section), _) => format!(
            "{}|{}|{}|{}",
            reference.family, reference.document, reference.version, section
        ),
        (None, Some(issue)) => issue.clone(),
        (None, None) => format!(
            "{}|{}|{}",
            reference.family, reference.document, reference.version
        ),
    }
}
