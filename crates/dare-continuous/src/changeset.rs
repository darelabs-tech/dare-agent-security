use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeType {
    SourceCodeChanged,
    InventoryChanged,
    CapabilityAdded,
    CapabilityRemoved,
    CapabilityChanged,
    AuthorizationChanged,
    CredentialChanged,
    TenantModelChanged,
    DependencyChanged,
    ProfileChanged,
    PropertyRegistryChanged,
    PolicyChanged,
    RoeChanged,
    GraphChanged,
    ValidationChanged,
    RuntimeEvidenceChanged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeFact {
    #[serde(rename = "type")]
    pub change_type: ChangeType,
    pub source: String,
    pub entity: String,
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityChangeSet {
    pub schema_version: String,
    pub baseline_state: String,
    pub candidate_state: String,
    pub changes: Vec<ChangeFact>,
}
