//! Closed protocol and method vocabulary (BLUEPRINT §5.4).
//!
//! There is no method with a side effect on the target: no `tools/call`, no
//! subscription, no sampling, no task cancellation and no push-notification
//! configuration. A method that is not in this enum cannot be planned,
//! authorized or sent.

pub mod a2a;
pub mod conversation;
pub mod mcp;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protocol {
    A2a,
    Mcp,
    DareConversation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Where a method's request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The authorization's `endpoints` path for the method's protocol.
    Endpoint,
    /// A fixed well-known path on the planned origin.
    WellKnown(&'static str),
}

pub const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
pub const AUTH_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// Every well-known path a request may use.
pub const WELL_KNOWN_PATHS: [&str; 3] = [
    AGENT_CARD_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    AUTH_SERVER_METADATA_PATH,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Method {
    A2aAgentCardGet,
    A2aMessageSend,
    A2aTasksGet,
    McpInitialize,
    /// `notifications/initialized`: the notification the streamable HTTP
    /// transport requires after `initialize`. It carries no data and has no
    /// effect on the target beyond completing the handshake.
    McpInitialized,
    McpToolsList,
    McpResourcesList,
    McpPromptsList,
    McpResourcesRead,
    McpPromptsGet,
    McpProtectedResourceMetadataGet,
    McpAuthServerMetadataGet,
    DareConversationTurn,
}

impl Method {
    pub const ALL: [Method; 13] = [
        Self::A2aAgentCardGet,
        Self::A2aMessageSend,
        Self::A2aTasksGet,
        Self::McpInitialize,
        Self::McpInitialized,
        Self::McpToolsList,
        Self::McpResourcesList,
        Self::McpPromptsList,
        Self::McpResourcesRead,
        Self::McpPromptsGet,
        Self::McpProtectedResourceMetadataGet,
        Self::McpAuthServerMetadataGet,
        Self::DareConversationTurn,
    ];

    pub fn protocol(self) -> Protocol {
        match self {
            Self::A2aAgentCardGet | Self::A2aMessageSend | Self::A2aTasksGet => Protocol::A2a,
            Self::DareConversationTurn => Protocol::DareConversation,
            _ => Protocol::Mcp,
        }
    }

    pub fn http_method(self) -> HttpMethod {
        match self {
            Self::A2aAgentCardGet
            | Self::McpProtectedResourceMetadataGet
            | Self::McpAuthServerMetadataGet => HttpMethod::Get,
            _ => HttpMethod::Post,
        }
    }

    pub fn target(self) -> Target {
        match self {
            Self::A2aAgentCardGet => Target::WellKnown(AGENT_CARD_PATH),
            Self::McpProtectedResourceMetadataGet => {
                Target::WellKnown(PROTECTED_RESOURCE_METADATA_PATH)
            }
            Self::McpAuthServerMetadataGet => Target::WellKnown(AUTH_SERVER_METADATA_PATH),
            _ => Target::Endpoint,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A2aAgentCardGet => "A2A_AGENT_CARD_GET",
            Self::A2aMessageSend => "A2A_MESSAGE_SEND",
            Self::A2aTasksGet => "A2A_TASKS_GET",
            Self::McpInitialize => "MCP_INITIALIZE",
            Self::McpInitialized => "MCP_INITIALIZED",
            Self::McpToolsList => "MCP_TOOLS_LIST",
            Self::McpResourcesList => "MCP_RESOURCES_LIST",
            Self::McpPromptsList => "MCP_PROMPTS_LIST",
            Self::McpResourcesRead => "MCP_RESOURCES_READ",
            Self::McpPromptsGet => "MCP_PROMPTS_GET",
            Self::McpProtectedResourceMetadataGet => "MCP_PROTECTED_RESOURCE_METADATA_GET",
            Self::McpAuthServerMetadataGet => "MCP_AUTH_SERVER_METADATA_GET",
            Self::DareConversationTurn => "DARE_CONVERSATION_TURN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_enum_has_no_side_effecting_method() {
        // The spellings of every side-effecting operation the protocols have.
        // None may appear as a method, in any casing.
        let forbidden = [
            "CALL",
            "SUBSCRIBE",
            "SAMPLING",
            "CANCEL",
            "PUSH",
            "DELETE",
            "WRITE",
            "SET",
            "COMPLETE",
        ];
        for method in Method::ALL {
            for word in forbidden {
                assert!(
                    !method.as_str().split('_').any(|part| part == word),
                    "{} looks side-effecting",
                    method.as_str()
                );
            }
        }
    }

    #[test]
    fn serde_names_match_as_str() {
        for method in Method::ALL {
            assert_eq!(serde_json::to_value(method).unwrap(), method.as_str());
        }
        assert_eq!(
            serde_json::to_value(Protocol::DareConversation).unwrap(),
            "DARE_CONVERSATION"
        );
        assert_eq!(serde_json::to_value(Protocol::A2a).unwrap(), "A2A");
    }

    #[test]
    fn every_get_is_a_well_known_path_and_every_post_an_endpoint() {
        for method in Method::ALL {
            match (method.http_method(), method.target()) {
                (HttpMethod::Get, Target::WellKnown(path)) => {
                    assert!(WELL_KNOWN_PATHS.contains(&path))
                }
                (HttpMethod::Post, Target::Endpoint) => {}
                other => panic!("{method:?}: {other:?}"),
            }
        }
    }
}
