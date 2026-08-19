//! Version-aware MCP client adapter.
//!
//! SDK, lifecycle, and transport details stay behind project-owned types.
//! Public signatures in this module do not expose `rmcp` types.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;

use crate::policy::{DiscoveryMethod, PolicyProfile};

#[path = "adapter_error.rs"]
mod adapter_error;
#[path = "adapter_http.rs"]
mod adapter_http;
#[path = "adapter_session.rs"]
mod adapter_session;
#[path = "adapter_stdio.rs"]
mod adapter_stdio;

pub use adapter_error::{AdapterError, TimeoutPhase};
pub use adapter_http::{HttpTransportConfig, DEFAULT_MAX_RESPONSE_BYTES};
pub use adapter_session::{CURRENT_WIRE_REVISION, LEGACY_WIRE_REVISION};
pub use adapter_stdio::StdioLaunch;

use adapter_session::{profile_from_revision, wire_revision_for, RmcpSession, SharedPolicyGate};

/// MCP lifecycle selected for a [`PolicyProfile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryLifecycleMode {
    /// MCP `2026-07-28`: `server/discover`. Does not send `notifications/initialized`.
    Discover,
    /// MCP `2024-11-05`: `initialize` + `notifications/initialized`.
    Initialize,
}

/// Crate-owned server identity observed during discovery/initialize.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ServerSnapshot {
    /// Server name, when declared.
    pub name: String,
    /// Server version, when declared.
    pub version: Option<String>,
    /// Optional human title.
    pub title: Option<String>,
    /// Negotiated or selected protocol revision (`YYYY-MM-DD`).
    pub protocol_revision: String,
}

/// Crate-owned tool catalog entry. Never executed.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ToolSnapshot {
    /// Tool name.
    pub name: String,
    /// Optional title.
    pub title: Option<String>,
    /// Optional description (untrusted).
    pub description: Option<String>,
    /// Advertised input schema object, when present. Never executed as a validator.
    pub input_schema: Option<serde_json::Map<String, serde_json::Value>>,
    /// Self-reported annotation hints, when present.
    pub annotations: Option<crate::inventory::ToolAnnotations>,
}

/// Crate-owned resource catalog entry. Content is never read.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ResourceSnapshot {
    /// Resource URI.
    pub uri: String,
    /// Optional name.
    pub name: Option<String>,
    /// Optional description (untrusted).
    pub description: Option<String>,
}

/// Crate-owned resource template. Templates are not expanded.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ResourceTemplateSnapshot {
    /// URI template.
    pub uri_template: String,
    /// Optional name.
    pub name: Option<String>,
    /// Optional description (untrusted).
    pub description: Option<String>,
}

/// Crate-owned prompt catalog entry. Bodies are never fetched.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PromptSnapshot {
    /// Prompt name.
    pub name: String,
    /// Optional title.
    pub title: Option<String>,
    /// Optional description (untrusted).
    pub description: Option<String>,
}

/// Project-owned MCP discovery client. Implementations must not leak SDK types.
#[async_trait]
pub trait McpDiscoveryClient {
    /// Discover or return the server identity snapshot.
    async fn discover_server(&mut self) -> Result<ServerSnapshot, AdapterError>;
    /// List tools (`tools/list`).
    async fn list_tools(&mut self) -> Result<Vec<ToolSnapshot>, AdapterError>;
    /// List resources (`resources/list`).
    async fn list_resources(&mut self) -> Result<Vec<ResourceSnapshot>, AdapterError>;
    /// List resource templates (`resources/templates/list`).
    async fn list_resource_templates(
        &mut self,
    ) -> Result<Vec<ResourceTemplateSnapshot>, AdapterError>;
    /// List prompts (`prompts/list`).
    async fn list_prompts(&mut self) -> Result<Vec<PromptSnapshot>, AdapterError>;
}

/// Explicit discovery target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryTargetKind {
    /// Local child process. `program` is the executable; `args` is argv.
    Stdio {
        /// Executable path or name.
        program: String,
        /// Argument vector (not a shell string).
        args: Vec<String>,
    },
    /// Streamable HTTP URL. Must be explicit `https`.
    Http {
        /// Operator-supplied URL (validated; credentials are refused).
        url: String,
    },
}

/// Bounded timeouts for connect, request, and overall operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryTimeouts {
    /// Connect / handshake timeout.
    pub connect: Duration,
    /// Per-request timeout.
    pub request: Duration,
    /// Overall operation timeout wrapping each public call.
    pub overall: Duration,
}

impl DiscoveryTimeouts {
    /// Safe default timeouts.
    pub const fn new() -> Self {
        Self {
            connect: Duration::from_secs(5),
            request: Duration::from_secs(15),
            overall: Duration::from_secs(30),
        }
    }
}

impl Default for DiscoveryTimeouts {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for a discovery session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryTargetSpec {
    /// Explicit stdio or HTTP target.
    pub target: DiscoveryTargetKind,
    /// Bounded timeouts.
    pub timeouts: DiscoveryTimeouts,
    /// Passive policy profile / lifecycle selector.
    pub policy_profile: PolicyProfile,
    /// Maximum serialized list/discover payload size.
    pub max_response_bytes: usize,
    /// TEST ONLY. When true, cleartext `http://` loopback URLs are accepted.
    ///
    /// Production constructors ([`Self::http`], CLI `--url`) leave this `false`.
    /// Do not enable in production binaries: TLS remains required by default.
    pub http_loopback_tests: bool,
}

impl DiscoveryTargetSpec {
    /// stdio target with current MCP profile and default bounds.
    pub fn stdio(
        program: impl Into<String>,
        args: impl Into<Vec<String>>,
    ) -> Result<Self, AdapterError> {
        let launch = StdioLaunch::new(program, args)?;
        Ok(Self {
            target: DiscoveryTargetKind::Stdio {
                program: launch.program().to_owned(),
                args: launch.args().to_vec(),
            },
            timeouts: DiscoveryTimeouts::new(),
            policy_profile: PolicyProfile::Current2026_07_28,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            http_loopback_tests: false,
        })
    }

    /// HTTPS Streamable HTTP target with current MCP profile and default bounds.
    pub fn http(url: impl AsRef<str>) -> Result<Self, AdapterError> {
        let sanitized = HttpTransportConfig::new().validate_url(url.as_ref())?;
        Ok(Self {
            target: DiscoveryTargetKind::Http { url: sanitized },
            timeouts: DiscoveryTimeouts::new(),
            policy_profile: PolicyProfile::Current2026_07_28,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            http_loopback_tests: false,
        })
    }

    /// TEST ONLY. Cleartext Streamable HTTP to loopback (`127.0.0.1` / `localhost` / `::1`).
    ///
    /// Production [`Self::http`] remains HTTPS-only. This constructor exists so
    /// Cycle 002 E2E can exercise Streamable HTTP without shipping TLS-off
    /// defaults.
    pub fn http_loopback_for_tests(url: impl AsRef<str>) -> Result<Self, AdapterError> {
        let sanitized =
            HttpTransportConfig::loopback_http_for_tests().validate_url(url.as_ref())?;
        Ok(Self {
            target: DiscoveryTargetKind::Http { url: sanitized },
            timeouts: DiscoveryTimeouts::new(),
            policy_profile: PolicyProfile::Current2026_07_28,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            http_loopback_tests: true,
        })
    }

    /// Select the passive policy profile (and therefore the lifecycle).
    pub fn with_profile(mut self, profile: PolicyProfile) -> Self {
        self.policy_profile = profile;
        self
    }

    /// Select a protocol revision string. Unsupported revisions fail closed.
    pub fn with_revision(self, revision: &str) -> Result<Self, AdapterError> {
        let profile = profile_from_revision(revision)?;
        Ok(self.with_profile(profile))
    }

    /// Replace timeout budget.
    pub fn with_timeouts(mut self, timeouts: DiscoveryTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Replace the serialized response size bound.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, AdapterError> {
        if max_response_bytes == 0 {
            return Err(AdapterError::invalid_target("max-response-bytes"));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Lifecycle mode implied by the selected profile.
    pub fn lifecycle_mode(&self) -> DiscoveryLifecycleMode {
        lifecycle_mode_for(self.policy_profile)
    }
}

/// Lifecycle corresponding to a policy profile.
pub const fn lifecycle_mode_for(profile: PolicyProfile) -> DiscoveryLifecycleMode {
    match profile {
        PolicyProfile::Current2026_07_28 => DiscoveryLifecycleMode::Discover,
        PolicyProfile::Legacy2024_11_05 => DiscoveryLifecycleMode::Initialize,
    }
}

/// Wire methods the adapter will authorize for `profile` (lifecycle + lists).
pub fn planned_outbound_methods(profile: PolicyProfile) -> Vec<&'static str> {
    let mut methods = Vec::from(lifecycle_methods(profile));
    methods.extend_from_slice(ENUMERATION_METHODS);
    methods
}

/// Lifecycle methods authorized before handshake.
pub const fn lifecycle_methods(profile: PolicyProfile) -> &'static [&'static str] {
    match profile {
        PolicyProfile::Current2026_07_28 => &["server/discover"],
        PolicyProfile::Legacy2024_11_05 => &["initialize", "notifications/initialized"],
    }
}

/// Enumeration methods authorized by both profiles.
pub const ENUMERATION_METHODS: &[&str] = &[
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];

/// Live discovery client wrapping the official SDK behind crate-owned types.
pub struct DiscoveryClient {
    profile: PolicyProfile,
    timeouts: DiscoveryTimeouts,
    gate: SharedPolicyGate,
    session: RmcpSession,
}

impl DiscoveryClient {
    /// Connect to `spec` using the selected lifecycle and policy profile.
    pub async fn connect(spec: DiscoveryTargetSpec) -> Result<Self, AdapterError> {
        let gate = SharedPolicyGate::new(spec.policy_profile);
        let session = tokio::time::timeout(
            spec.timeouts.overall,
            RmcpSession::connect(&spec, gate.clone()),
        )
        .await
        .map_err(|_| AdapterError::Timeout {
            phase: TimeoutPhase::Overall,
        })??;
        Ok(Self {
            profile: spec.policy_profile,
            timeouts: spec.timeouts,
            gate,
            session,
        })
    }

    /// Methods authorized by [`crate::policy::PolicyGuardedTransport`] for this session.
    pub fn authorized_methods(&self) -> Vec<String> {
        self.gate.authorized_methods()
    }

    /// Selected policy profile.
    pub fn profile(&self) -> PolicyProfile {
        self.profile
    }

    /// Selected/negotiated protocol revision recorded on the server snapshot.
    pub fn protocol_revision(&self) -> &str {
        self.session.protocol_revision()
    }

    /// One `tools/list` page. Cursor is forwarded as opaque metadata.
    pub async fn list_tools_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ToolSnapshot>, Option<String>), AdapterError> {
        let limit = self.timeouts.overall;
        with_overall_timeout(limit, async {
            self.gate.authorize(DiscoveryMethod::ToolsList.as_str())?;
            self.session.list_tools_page(cursor).await
        })
        .await
    }

    /// One `resources/list` page. Resource contents are never fetched.
    pub async fn list_resources_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ResourceSnapshot>, Option<String>), AdapterError> {
        let limit = self.timeouts.overall;
        with_overall_timeout(limit, async {
            self.gate
                .authorize(DiscoveryMethod::ResourcesList.as_str())?;
            self.session.list_resources_page(cursor).await
        })
        .await
    }

    /// One `resources/templates/list` page. Templates are not expanded.
    pub async fn list_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ResourceTemplateSnapshot>, Option<String>), AdapterError> {
        let limit = self.timeouts.overall;
        with_overall_timeout(limit, async {
            self.gate
                .authorize(DiscoveryMethod::ResourceTemplatesList.as_str())?;
            self.session.list_resource_templates_page(cursor).await
        })
        .await
    }

    /// One `prompts/list` page. Prompt bodies are never fetched.
    pub async fn list_prompts_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<PromptSnapshot>, Option<String>), AdapterError> {
        let limit = self.timeouts.overall;
        with_overall_timeout(limit, async {
            self.gate.authorize(DiscoveryMethod::PromptsList.as_str())?;
            self.session.list_prompts_page(cursor).await
        })
        .await
    }
}

async fn with_overall_timeout<T, F>(limit: Duration, fut: F) -> Result<T, AdapterError>
where
    F: Future<Output = Result<T, AdapterError>>,
{
    match tokio::time::timeout(limit, fut).await {
        Ok(result) => result,
        Err(_) => Err(AdapterError::Timeout {
            phase: TimeoutPhase::Overall,
        }),
    }
}

#[async_trait]
impl McpDiscoveryClient for DiscoveryClient {
    async fn discover_server(&mut self) -> Result<ServerSnapshot, AdapterError> {
        let limit = self.timeouts.overall;
        with_overall_timeout(limit, async {
            match self.profile {
                PolicyProfile::Current2026_07_28 => {
                    self.gate
                        .authorize(DiscoveryMethod::ServerDiscover.as_str())?;
                }
                PolicyProfile::Legacy2024_11_05 => {}
            }
            Ok(self.session.server_snapshot())
        })
        .await
    }

    async fn list_tools(&mut self) -> Result<Vec<ToolSnapshot>, AdapterError> {
        self.list_tools_page(None)
            .await
            .map(|(items, _next_cursor)| items)
    }

    async fn list_resources(&mut self) -> Result<Vec<ResourceSnapshot>, AdapterError> {
        self.list_resources_page(None)
            .await
            .map(|(items, _next_cursor)| items)
    }

    async fn list_resource_templates(
        &mut self,
    ) -> Result<Vec<ResourceTemplateSnapshot>, AdapterError> {
        self.list_resource_templates_page(None)
            .await
            .map(|(items, _next_cursor)| items)
    }

    async fn list_prompts(&mut self) -> Result<Vec<PromptSnapshot>, AdapterError> {
        self.list_prompts_page(None)
            .await
            .map(|(items, _next_cursor)| items)
    }
}

/// Wire revision documented for a policy profile.
pub fn documented_wire_revision(profile: PolicyProfile) -> &'static str {
    wire_revision_for(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_methods_are_subset_of_allowlist() {
        for profile in [
            PolicyProfile::Current2026_07_28,
            PolicyProfile::Legacy2024_11_05,
        ] {
            let allow = PolicyProfile::allowlisted_methods(profile);
            for method in planned_outbound_methods(profile) {
                assert!(
                    allow.contains(&method),
                    "{method} requested by adapter is not allowlisted for {profile:?}"
                );
            }
        }
    }

    #[test]
    fn current_lifecycle_is_discover() {
        assert_eq!(
            lifecycle_mode_for(PolicyProfile::Current2026_07_28),
            DiscoveryLifecycleMode::Discover
        );
        assert_eq!(
            lifecycle_methods(PolicyProfile::Current2026_07_28),
            &["server/discover"]
        );
    }

    #[test]
    fn legacy_lifecycle_is_initialize() {
        assert_eq!(
            lifecycle_mode_for(PolicyProfile::Legacy2024_11_05),
            DiscoveryLifecycleMode::Initialize
        );
        assert_eq!(
            lifecycle_methods(PolicyProfile::Legacy2024_11_05),
            &["initialize", "notifications/initialized"]
        );
    }
}
