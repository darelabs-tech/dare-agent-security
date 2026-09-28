//! MCP Auth (Cycle 018) metadata over MCP (Review BQ-1, BLUEPRINT AD-13).
//!
//! Live: the protected-resource metadata GET, and the authorization-server
//! metadata GET when the advertised server is on the planned origin (a plan
//! has one origin; any other server is recorded, never fetched). Verdict: the
//! observed documents become a derived scenario through the engine's own
//! `scenario_with_observed_resource`, and the engine decides with an adapter
//! that observes no request — the requests a validator sends are not a
//! property of the target.

use std::collections::BTreeSet;
use std::fs;

use dare_mcp_auth_security::canonical::bind;
use dare_mcp_auth_security::evidence_bridge::build_evidence;
use dare_mcp_auth_security::harness::{HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest};
use dare_mcp_auth_security::model::McpAuthScenario;
use dare_mcp_auth_security::observed::{
    scenario_with_observed_resource, ObservedAuthServer, ObservedResourceContext,
};
use dare_mcp_auth_security::result::run_scenario;
use dare_mcp_auth_security::trials::TrialPlan;
use serde_json::Value;

use crate::capture::{Capture, ScenarioRef};
use crate::engines::{
    entries_for, evidence_time, final_verdict, first_transport, EngineOutcome, Sources,
};
use crate::error::{RemoteError, Result};
use crate::gateway::EgressGateway;
use crate::origin::Origin;
use crate::outcome::StopReason;
use crate::plan::EngineKind;
use crate::protocol::mcp::{parse_metadata, McpClient};
use crate::protocol::Method;

#[derive(Debug, Clone)]
pub struct Loaded {
    pub scenario: McpAuthScenario,
    pub digest: String,
}

fn engine(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Engine(format!("mcp-auth: {error}"))
}

/// Load a built-in scenario the way `validate mcp-auth-security` does.
pub fn load(sources: &Sources, id: &str) -> Result<Loaded> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(RemoteError::Refused(
            "an MCP Auth scenario id is uppercase with dashes",
        ));
    }
    let path = sources
        .root
        .join("crates/dare-mcp-auth-security/tests/fixtures/scenarios")
        .join(format!("{}.json", id.to_ascii_lowercase()));
    let raw = fs::read(&path)
        .map_err(|_| RemoteError::Refused("the MCP Auth scenario is not available"))?;
    let scenario: McpAuthScenario = serde_json::from_slice(&raw).map_err(engine)?;
    scenario.validate().map_err(engine)?;
    let digest = bind(&scenario).map_err(engine)?.scenario_digest;
    Ok(Loaded { scenario, digest })
}

fn sref(loaded: &Loaded, step: u32) -> ScenarioRef {
    ScenarioRef {
        engine: EngineKind::McpAuth,
        scenario_id: loaded.scenario.id.clone(),
        conversation_id: None,
        node_id: None,
        step: Some(step),
    }
}

/// Live: the two metadata documents.
pub async fn live(
    gateway: &mut EgressGateway,
    loaded: &Loaded,
    methods: &BTreeSet<Method>,
) -> Result<()> {
    let mut client = McpClient::new();
    let (_, prm) = client
        .metadata(
            gateway,
            Method::McpProtectedResourceMetadataGet,
            sref(loaded, 0),
        )
        .await?;
    let on_origin = prm
        .ok()
        .and_then(|doc| {
            doc.get("authorization_servers")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .any(|server| {
            Origin::parse(server.trim_end_matches('/')).is_ok_and(|o| &o == gateway.origin())
        });
    if on_origin && methods.contains(&Method::McpAuthServerMetadataGet) {
        let _metadata = client
            .metadata(gateway, Method::McpAuthServerMetadataGet, sref(loaded, 1))
            .await?;
    }
    Ok(())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .take(64)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The observed context a capture describes.
pub fn observed(capture: &Capture, scenario_id: &str) -> Option<ObservedResourceContext> {
    let entries: Vec<_> = entries_for(capture, EngineKind::McpAuth, scenario_id).collect();
    let document = |method: Method| {
        entries
            .iter()
            .find(|e| {
                e.method == method
                    && e.transport_error.is_none()
                    && e.status.is_some_and(|s| (200..300).contains(&s))
            })
            .and_then(|e| parse_metadata(e.response_body.as_deref()).ok())
    };
    let prm = document(Method::McpProtectedResourceMetadataGet)?;
    let as_metadata = document(Method::McpAuthServerMetadataGet)
        .map(|doc| ObservedAuthServer {
            issuer: doc
                .get("issuer")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            authorization_endpoint: doc
                .get("authorization_endpoint")
                .and_then(Value::as_str)
                .map(str::to_owned),
            token_endpoint: doc
                .get("token_endpoint")
                .and_then(Value::as_str)
                .map(str::to_owned),
            code_challenge_methods_supported: strings(doc.get("code_challenge_methods_supported")),
        })
        .into_iter()
        .collect();
    Some(ObservedResourceContext {
        resource: prm
            .get("resource")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        authorization_servers: strings(prm.get("authorization_servers")),
        scopes_supported: strings(prm.get("scopes_supported")),
        as_metadata,
    })
}

/// Observes no request: the derived scenario carries the observed metadata.
struct MetadataOnlyAdapter;

impl HarnessAdapter for MetadataOnlyAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }
    fn observe(
        &self,
        _request: &TrialRequest<'_>,
    ) -> dare_mcp_auth_security::error::Result<RawTrialOutput> {
        Ok(RawTrialOutput {
            observed_requests: Vec::new(),
            harness_error: None,
        })
    }
    fn observations_are_synthetic(&self) -> bool {
        false
    }
}

/// Decide from the capture alone. `expected_resource` is the MCP endpoint URL
/// the authorization names.
pub fn verdict(
    capture: &Capture,
    loaded: &Loaded,
    expected_resource: &str,
    unfinished: Option<StopReason>,
) -> Result<EngineOutcome> {
    let id = loaded.scenario.id.as_str();
    let observed = observed(capture, id);
    let derived =
        scenario_with_observed_resource(&loaded.scenario, observed.as_ref(), expected_resource)
            .map_err(engine)?;
    let plan = TrialPlan::from_scenario(&derived).map_err(engine)?;
    let result = run_scenario(&derived, None, &MetadataOnlyAdapter, plan).map_err(engine)?;
    let binding = bind(&derived).map_err(engine)?;
    let evidence = build_evidence(&derived, None, &binding, &result, evidence_time(capture))
        .map_err(engine)?;
    let transport = first_transport(capture, EngineKind::McpAuth, id);
    let engine_verdict = result.verdict;
    let mut self_reported = BTreeSet::new();
    if observed.is_some() {
        // Authenticated as to origin (TLS); the content is still what the
        // server says about itself.
        self_reported.insert("protected_resource_metadata");
    }
    Ok(EngineOutcome {
        engine: EngineKind::McpAuth,
        scenario_id: id.to_owned(),
        engine_verdict,
        verdict: final_verdict(engine_verdict, transport, unfinished),
        transport,
        unfinished,
        self_reported_fields: if engine_verdict == dare_security_evidence::Verdict::Pass {
            self_reported
        } else {
            BTreeSet::new()
        },
        not_observable: vec![
            "requests",
            "tokens",
            "authorization_flow",
            "scope",
            "registration",
            "credential_flow",
            "identity_metadata",
            "final_operation",
        ],
        result: serde_json::to_value(&result)
            .map_err(|_| RemoteError::Serialization("mcp-auth result"))?,
        evidence,
    })
}
