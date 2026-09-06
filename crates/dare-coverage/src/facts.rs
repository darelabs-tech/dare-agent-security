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
    /// Cycle 014: the target exposes tool description/schema/annotation metadata.
    #[serde(default)]
    pub tool_metadata_present: bool,
    /// Cycle 014: the target consumes tool output.
    #[serde(default)]
    pub tool_output_present: bool,
    /// Cycle 014: the target composes tools into chains.
    #[serde(default)]
    pub tool_chaining_present: bool,
    /// Cycle 015: the target distinguishes an initiating from an effective principal.
    #[serde(default)]
    pub principal_context_present: bool,
    /// Cycle 015: the target produces authorization decisions bound to operations.
    #[serde(default)]
    pub authorization_decision_present: bool,
    /// Cycle 015: the target scopes resources by tenant.
    #[serde(default)]
    pub tenant_context_present: bool,
    /// Cycle 015: the target records a resource owner distinct from the caller.
    #[serde(default)]
    pub resource_owner_context_present: bool,
    /// Cycle 016: memory items carry machine-readable source/provenance.
    #[serde(default)]
    pub memory_provenance_present: bool,
    /// Cycle 016: the target recalls persisted memory into later decisions.
    #[serde(default)]
    pub memory_recall_present: bool,
    /// Cycle 016: memory items carry expiry/revocation lifecycle metadata.
    #[serde(default)]
    pub memory_lifecycle_present: bool,
    /// Cycle 016: memory is partitioned into namespaces.
    #[serde(default)]
    pub memory_namespace_present: bool,
    /// Cycle 017: a retrieval trace (query, candidates, results) is observable.
    #[serde(default)]
    pub retrieval_trace_present: bool,
    /// Cycle 017: the target declares a machine-readable retrieval policy.
    #[serde(default)]
    pub retrieval_policy_present: bool,
    /// Cycle 017: documents carry an access-control list or allowed-document set.
    #[serde(default)]
    pub document_acl_present: bool,
    /// Cycle 017: retrieved chunks carry document and source provenance.
    #[serde(default)]
    pub retrieval_provenance_present: bool,
    /// Cycle 017: retrieval runs under a tenant context distinct from others.
    #[serde(default)]
    pub retrieval_tenant_context_present: bool,
    /// Cycle 018: the target speaks the current MCP protocol revision.
    #[serde(default)]
    pub mcp_current_protocol_present: bool,
    /// Cycle 018: the target is reachable over the HTTP transport, where the
    /// modern MCP authorization surface lives at all.
    #[serde(default)]
    pub mcp_http_transport_present: bool,
    /// Cycle 018: the target participates in an MCP authorization flow.
    #[serde(default)]
    pub mcp_auth_flow_present: bool,
    /// Cycle 018: the target reports `clientInfo` / `serverInfo` self-description.
    #[serde(default)]
    pub mcp_identity_metadata_present: bool,
    /// Cycle 018: Protected Resource Metadata is observable for the resource.
    #[serde(default)]
    pub protected_resource_metadata_present: bool,
    /// Cycle 018: authorization-server metadata is observable.
    #[serde(default)]
    pub authorization_server_metadata_present: bool,
    /// Cycle 018: token claims are projected into evidence.
    #[serde(default)]
    pub token_claims_present: bool,
    /// Cycle 018: PKCE challenge/verifier binding is observable.
    #[serde(default)]
    pub pkce_context_present: bool,
    /// Cycle 018: an insufficient-scope challenge is observable.
    #[serde(default)]
    pub scope_challenge_present: bool,
    /// Cycle 018: client registration metadata is observable.
    #[serde(default)]
    pub client_registration_present: bool,
    /// Cycle 018: the target forwards or exchanges credentials to an upstream.
    #[serde(default)]
    pub credential_forwarding_present: bool,
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
