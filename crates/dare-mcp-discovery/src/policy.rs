//! Central allowlist guard for every outbound MCP discovery request.
//!
//! Discovery is passive by construction: only explicitly listed JSON-RPC
//! methods may reach transport. There is no denylist; unknown methods are
//! refused. `ping` is not allowlisted — it is not required for MCP
//! `2026-07-28` `server/discover` nor for the supported `2024-11-05`
//! handshake (`initialize` + `notifications/initialized`).

#[path = "policy_error.rs"]
mod policy_error;
#[path = "policy_transport.rs"]
mod policy_transport;

pub use policy_error::{PolicyError, PolicyRefusal, RefusalReason};
pub use policy_transport::{OutboundTransport, PolicyGuardedTransport};

/// MCP JSON-RPC methods that may be passive under some supported profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// MCP `2026-07-28` `server/discover`.
    ServerDiscover,
    /// `tools/list`.
    ToolsList,
    /// `resources/list`.
    ResourcesList,
    /// `resources/templates/list`.
    ResourceTemplatesList,
    /// `prompts/list`.
    PromptsList,
    /// Legacy MCP `2024-11-05` `initialize`.
    LegacyInitialize,
    /// Legacy MCP `2024-11-05` `notifications/initialized`.
    LegacyInitialized,
}

impl DiscoveryMethod {
    /// Wire JSON-RPC method name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerDiscover => "server/discover",
            Self::ToolsList => "tools/list",
            Self::ResourcesList => "resources/list",
            Self::ResourceTemplatesList => "resources/templates/list",
            Self::PromptsList => "prompts/list",
            Self::LegacyInitialize => "initialize",
            Self::LegacyInitialized => "notifications/initialized",
        }
    }

    /// Parse a wire method name into a known passive method.
    pub fn from_wire(method: &str) -> Option<Self> {
        match method {
            "server/discover" => Some(Self::ServerDiscover),
            "tools/list" => Some(Self::ToolsList),
            "resources/list" => Some(Self::ResourcesList),
            "resources/templates/list" => Some(Self::ResourceTemplatesList),
            "prompts/list" => Some(Self::PromptsList),
            "initialize" => Some(Self::LegacyInitialize),
            "notifications/initialized" => Some(Self::LegacyInitialized),
            _ => None,
        }
    }
}

/// Explicit protocol revision that selects the passive allowlist.
///
/// `Legacy2024_11_05` is the single pre-2026 compatibility path supported by
/// this crate (Blueprint §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyProfile {
    /// MCP revision `2026-07-28` (current, first-class).
    Current2026_07_28,
    /// MCP revision `2024-11-05` (explicit legacy lifecycle).
    Legacy2024_11_05,
}

impl PolicyProfile {
    /// Allowlisted wire methods for this revision. Allowlist only.
    pub const fn allowlisted_methods(self) -> &'static [&'static str] {
        match self {
            Self::Current2026_07_28 => &[
                "server/discover",
                "tools/list",
                "resources/list",
                "resources/templates/list",
                "prompts/list",
            ],
            Self::Legacy2024_11_05 => &[
                "initialize",
                "notifications/initialized",
                "tools/list",
                "resources/list",
                "resources/templates/list",
                "prompts/list",
            ],
        }
    }

    /// True when `method` is an exact allowlist member for this profile.
    pub fn allows(self, method: &str) -> bool {
        self.allowlisted_methods().contains(&method)
    }
}

/// Authorizes outbound MCP methods before they reach transport.
pub trait PassivePolicy {
    /// Allowlist check. Unknown and non-allowlisted methods return
    /// [`PolicyRefusal`].
    fn authorize(&self, method: &str) -> Result<(), PolicyRefusal>;
}

/// Default allowlist policy for a [`PolicyProfile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultPolicy {
    profile: PolicyProfile,
}

impl DefaultPolicy {
    /// Policy for an explicit protocol profile.
    pub const fn new(profile: PolicyProfile) -> Self {
        Self { profile }
    }

    /// MCP `2026-07-28` allowlist (`server/discover` + list methods).
    pub const fn current() -> Self {
        Self::new(PolicyProfile::Current2026_07_28)
    }

    /// MCP `2024-11-05` allowlist (legacy initialize handshake + list methods).
    pub const fn legacy() -> Self {
        Self::new(PolicyProfile::Legacy2024_11_05)
    }

    /// Active profile.
    pub const fn profile(&self) -> PolicyProfile {
        self.profile
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::current()
    }
}

impl PassivePolicy for DefaultPolicy {
    fn authorize(&self, method: &str) -> Result<(), PolicyRefusal> {
        if method.is_empty() {
            return Err(PolicyRefusal::new(method, RefusalReason::EmptyMethod));
        }
        if self.profile.allows(method) {
            Ok(())
        } else {
            Err(PolicyRefusal::new(
                method,
                RefusalReason::MethodNotAllowlisted,
            ))
        }
    }
}
