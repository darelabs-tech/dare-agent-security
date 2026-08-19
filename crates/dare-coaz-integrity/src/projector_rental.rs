//! Declared `rental.quote` authorization projector with explicit mapped arguments.

use serde_json::{json, Value};

use crate::projector::{
    build_declared_authzen_request, build_trusted_inputs, finalize_projection, mapping_identity,
    parse_tools_call, require_string_field, AuthorizationProjector, ProjectionError,
};
use crate::result::AuthorizationProjection;
use crate::vector::{McpOperation, TrustedAuthorizationContext};

/// Declared mapping where selected tool arguments and trusted agent context are binding-relevant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RentalQuoteProjector;

impl RentalQuoteProjector {
    pub const FIXTURE_ID: &'static str = "declared-rental-quote";
    pub const MAPPING_KIND: &'static str = "declared";
    pub const TOOL_NAME: &'static str = "rental.quote";

    fn extract_mapped_inputs(arguments: &Value) -> Result<Value, ProjectionError> {
        let customer_id = require_string_field(arguments, "customer_id")?;
        let vehicle_id = require_string_field(arguments, "vehicle_id")?;
        let daily_rate =
            arguments
                .get("daily_rate")
                .ok_or_else(|| ProjectionError::MissingMappedValue {
                    field: "daily_rate".to_owned(),
                })?;

        Ok(json!({
            "customer_id": customer_id,
            "vehicle_id": vehicle_id,
            "daily_rate": daily_rate
        }))
    }
}

impl AuthorizationProjector for RentalQuoteProjector {
    fn fixture_id(&self) -> &'static str {
        Self::FIXTURE_ID
    }

    fn project(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
    ) -> Result<AuthorizationProjection, ProjectionError> {
        let (tool_name, arguments) = parse_tools_call(operation)?;
        if tool_name != Self::TOOL_NAME {
            return Err(ProjectionError::invalid_operation(
                "declared rental.quote mapping requires rental.quote tool",
            ));
        }

        let mapped_inputs = Self::extract_mapped_inputs(arguments)?;
        let trusted_inputs = build_trusted_inputs(trusted)?;
        let authzen_request = build_declared_authzen_request(
            trusted.subject_id.as_str(),
            tool_name,
            &mapped_inputs,
            trusted.agent_id.as_deref(),
        )?;

        finalize_projection(
            mapping_identity(Self::MAPPING_KIND, Self::FIXTURE_ID, None)?,
            mapped_inputs,
            trusted_inputs,
            authzen_request,
        )
    }
}
