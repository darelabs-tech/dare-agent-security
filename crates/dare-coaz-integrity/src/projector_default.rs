//! Default `tools/call` authorization projector for Cycle 003 vectors.

use crate::projector::{
    build_authzen_request, build_trusted_inputs, finalize_projection, mapping_identity,
    parse_tools_call, AuthorizationProjector, ProjectionError,
};
use crate::result::AuthorizationProjection;
use crate::vector::{McpOperation, TrustedAuthorizationContext};

/// Default COAZ-MCP-style mapping where method and tool identity drive authorization shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefaultToolsCallProjector;

impl DefaultToolsCallProjector {
    pub const FIXTURE_ID: &'static str = "default-tools-call";
    pub const MAPPING_KIND: &'static str = "default";
}

impl AuthorizationProjector for DefaultToolsCallProjector {
    fn fixture_id(&self) -> &'static str {
        Self::FIXTURE_ID
    }

    fn project(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
    ) -> Result<AuthorizationProjection, ProjectionError> {
        let (tool_name, arguments) = parse_tools_call(operation)?;
        let trusted_inputs = build_trusted_inputs(trusted)?;
        let authzen_request = build_authzen_request(trusted.subject_id.as_str(), tool_name);

        finalize_projection(
            mapping_identity(Self::MAPPING_KIND, Self::FIXTURE_ID, None)?,
            arguments.clone(),
            trusted_inputs,
            authzen_request,
        )
    }
}
