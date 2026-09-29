//! Projectors (BLUEPRINT §6): bound engine data → run facts.
//!
//! A projector reads only what its bundle bound, applies its closed table,
//! and never decides a verdict. Anything its table does not name is counted
//! in `unprojected` under the engine's own kind name.
//!
//! **Requests, not executions.** Cycles 013–016 observe the operations an
//! agent *asks* for and structurally never perform one (`dispatched`,
//! `performed` and `executed` are always false there). An observed request
//! is projected as the relationship it would exercise in a deployment, with
//! OBSERVED evidence and `original_kind` naming the request event. 021 does
//! report executed actions, and keeps the CALLS / CAN_INVOKE distinction.
use dare_attack_graph::{NodeSecurity, NodeType};

use crate::{
    bundle::{LoadedBundle, RunData},
    error::Result,
    facts::{FactAuthority, FactEdge, FactSink, NodeRef, RunFacts},
    guard_table::{Role, RunVerdicts},
};

pub mod a2a;
pub mod identity;
pub mod mcp_auth;
pub mod memory;
pub mod multi_turn;
pub mod prompt_injection;
pub mod rag;
pub mod remote;
pub mod runtime_telemetry;
pub mod supply_chain;
pub mod tool;

/// The agent-under-test node of runs that do not name their agent (AD-08).
pub const SUT: &str = "sut";

pub fn sut() -> NodeRef {
    NodeRef::new(NodeType::Agent, SUT)
}

/// Projects one bound bundle.
pub fn project(bundle: &LoadedBundle) -> Result<RunFacts> {
    let mut sink = FactSink::new(bundle);
    let mut verdicts = RunVerdicts::from_evidence(&bundle.evidence);
    match &bundle.data {
        RunData::Tool { result, scenario } => {
            tool::project(bundle, result, scenario, &mut verdicts, &mut sink)
        }
        RunData::Identity { result, scenario } => {
            identity::project(bundle, result, scenario, &mut verdicts, &mut sink)
        }
        RunData::Memory { result, scenario } => {
            memory::project(bundle, result, scenario, &mut verdicts, &mut sink)
        }
        RunData::Rag { result, scenario } => {
            rag::project(bundle, result, scenario, &mut verdicts, &mut sink)
        }
        RunData::McpAuth { result, scenario } => {
            mcp_auth::project(bundle, result, Some(scenario), &verdicts, &mut sink)
        }
        RunData::SupplyChain { result, evidence } => {
            supply_chain::project(bundle, result, evidence, &mut verdicts, &mut sink)
        }
        RunData::A2a { result, evidence } => {
            a2a::project(bundle, result, Some(evidence), &mut verdicts, &mut sink)
        }
        RunData::PromptInjection { result } => {
            prompt_injection::project(bundle, result, &verdicts, &mut sink)
        }
        RunData::MultiTurn {
            result,
            conversations,
        } => multi_turn::project(
            bundle,
            result,
            Some(conversations),
            &mut verdicts,
            &mut sink,
        ),
        RunData::Remote { runs } => remote::project(bundle, runs, &mut verdicts, &mut sink),
        RunData::RuntimeTelemetry { result, policy } => {
            runtime_telemetry::project(bundle, result, policy.as_ref(), &verdicts, &mut sink)
        }
    }
    Ok(sink.finish())
}

/// The evidence ids of trial `i` when the engine lists one record per trial,
/// otherwise every record of the run.
pub fn trial_ids(bundle: &LoadedBundle, per_trial: &[String], trial: usize) -> Vec<String> {
    match per_trial.get(trial) {
        Some(id) => vec![id.clone()],
        None => bundle.evidence.all_ids(),
    }
}

/// Appends an edge with the guards of `role`.
#[allow(clippy::too_many_arguments)]
pub fn edge(
    sink: &mut FactSink,
    verdicts: &RunVerdicts,
    role: Option<Role>,
    edge_type: dare_attack_graph::EdgeType,
    source: &NodeRef,
    target: &NodeRef,
    authority: FactAuthority,
    evidence: dare_attack_graph::EdgeEvidence,
    original_kind: &str,
    locator: impl Into<String>,
) {
    let guards = role.map_or_else(Vec::new, |role| verdicts.guards(role, source, target));
    sink.edge(FactEdge {
        edge_type,
        source: source.clone(),
        target: target.clone(),
        authority,
        evidence,
        guards,
        authority_mutation: false,
        original_kind: original_kind.to_owned(),
        locator: locator.into(),
    });
}

/// A unit enum serialized as its wire name.
pub fn enum_name(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

/// The serde tag of an internally tagged event (`"type"` or `"channel"`).
pub fn event_kind(event: &impl serde::Serialize) -> String {
    let value = serde_json::to_value(event).unwrap_or_default();
    value["type"]
        .as_str()
        .or_else(|| value["channel"].as_str())
        .unwrap_or("UNKNOWN")
        .to_owned()
}

pub fn plain() -> NodeSecurity {
    NodeSecurity::default()
}

pub fn tenant(tenant_id: &str) -> NodeSecurity {
    NodeSecurity {
        tenant: Some(tenant_id.to_owned()),
        ..NodeSecurity::default()
    }
}
