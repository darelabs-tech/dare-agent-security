use std::collections::BTreeSet;

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationMode {
    #[default]
    PlanOnly,
    Simulated,
    LocalSynthetic,
    AuthorizedDynamic,
}

impl ValidationMode {
    pub fn is_dynamic(self) -> bool {
        self == Self::AuthorizedDynamic
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofClass {
    ReadOnly,
    SyntheticNoop,
    DryRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSpec {
    pub objective: String,
    pub minimum_safe_condition: String,
    pub proof_class: ProofClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationPlan {
    pub schema_version: String,
    pub id: String,
    pub target_id: String,
    pub target_version: String,
    pub environment: String,
    pub attack_path_id: String,
    pub attack_path_digest: String,
    pub property_id: String,
    pub mode: ValidationMode,
    pub proof: ProofSpec,
    #[serde(default)]
    pub roe_id: Option<String>,
    #[serde(default)]
    pub roe_digest: Option<String>,
    pub vector_id: String,
    pub vector_digest: String,
    pub budget_id: String,
    pub budget_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpectedDecision {
    Allow,
    Deny,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KillTrigger {
    UnexpectedState,
    UnexpectedEgress,
    UnexpectedTarget,
    UnexpectedIdentity,
    SecretDetected,
    TargetInstability,
    EvidenceFailure,
    OperatorStop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorStep {
    pub method: String,
    pub capability: String,
    pub arguments: Value,
    pub safety_class: ProofClass,
    pub synthetic_observation: ExpectedDecision,
    #[serde(default)]
    pub bytes_read: u64,
    #[serde(default)]
    pub bytes_written: u64,
    #[serde(default)]
    pub state_changes: u32,
    #[serde(default)]
    pub external_egress_bytes: u64,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub trigger: Option<KillTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestVector {
    pub schema_version: String,
    pub id: String,
    pub mode: ValidationMode,
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub steps: Vec<VectorStep>,
    pub expected_secure: ExpectedDecision,
    pub expected_vulnerable: ExpectedDecision,
    pub stop_on_first_proof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBudget {
    pub schema_version: String,
    pub id: String,
    pub max_operations: u32,
    pub max_duration_seconds: u64,
    pub max_state_changes: u32,
    pub max_bytes_read: u64,
    pub max_bytes_written: u64,
    pub max_external_egress_bytes: u64,
    pub max_retries: u32,
    pub max_chain_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoeDocument {
    pub schema_version: String,
    pub id: String,
    pub target_id: String,
    pub environment: String,
    pub allowed_capabilities: Vec<String>,
    pub allowed_identities: Vec<String>,
    pub allowed_categories: Vec<String>,
    pub allowed_data_classes: Vec<String>,
    pub prohibited_operations: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub allow_state_changes: bool,
    pub allow_external_egress: bool,
    pub local_only: bool,
    pub approved_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreconditionsContext {
    #[serde(default)]
    pub satisfied: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationBundle {
    pub plan: ValidationPlan,
    pub vector: TestVector,
    pub budget: ExecutionBudget,
    #[serde(default)]
    pub roe: Option<RoeDocument>,
    #[serde(default)]
    pub preconditions: PreconditionsContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultStatus {
    Planned,
    Completed,
    Blocked,
    Stopped,
    Killed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepOutcome {
    pub index: usize,
    pub capability: String,
    pub decision: ExecutionDecision,
    pub observed: ExpectedDecision,
    pub simulated: bool,
    pub evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationEvidence {
    pub id: String,
    pub event: String,
    pub plan_digest: String,
    pub vector_digest: String,
    pub path_digest: String,
    pub verdict: Verdict,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
    pub plan_id: String,
    pub vector_id: String,
    pub property_id: String,
    pub mode: ValidationMode,
    pub status: ResultStatus,
    pub verdict: Option<Verdict>,
    pub plan_digest: String,
    pub vector_digest: String,
    pub budget_digest: String,
    pub attack_path_digest: String,
    pub operations: u32,
    pub outcomes: Vec<StepOutcome>,
    pub evidence: Vec<ValidationEvidence>,
    #[serde(default)]
    pub reason: Option<String>,
}
