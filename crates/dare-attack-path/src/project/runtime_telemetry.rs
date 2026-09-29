//! Runtime telemetry projector (Cycle 025, RF-15): the runtime policy's
//! declared relationships, guarded by the verdicts the traces gave.
//!
//! The engine writes no attribute value (its RS-02), so the traces cannot
//! name agents, tools or hosts here. The relationships come from the bound
//! runtime policy, a pinned input, as STATICALLY_PROVEN facts; the evidence
//! records decide their guards. Without a bound policy the run is counted as
//! result-only and projects nothing.
use dare_attack_graph::{
    v2::{EntryClass, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use serde_json::Value;

use super::{edge, plain, tenant};
use crate::{
    bundle::LoadedBundle,
    facts::{statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
    ids::EngineSlug,
};

fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn observed_kind(result: &Value, kind: &str) -> bool {
    result["traces"]["spans_by_kind"][kind]
        .as_u64()
        .is_some_and(|n| n > 0)
}

pub fn project(
    bundle: &LoadedBundle,
    result: &Value,
    policy: Option<&Value>,
    verdicts: &RunVerdicts,
    sink: &mut FactSink,
) {
    let Some(policy) = policy else {
        sink.unprojected("RUNTIME_TELEMETRY_RESULT_ONLY");
        return;
    };
    let digests: Vec<&str> = bundle.input_digests.iter().map(String::as_str).collect();
    let evidence = || statically_proven(EngineSlug::RuntimeTelemetry, &digests);
    let channel = sink.node(
        NodeRef::new(NodeType::Data, "channel.user"),
        "user channel",
        plain(),
        "RuntimePolicy (user input)",
        "policy#/agents",
    );
    sink.designate(&channel, Designation::Entry(EntryClass::UntrustedInput));
    let export = sink.node(
        NodeRef::new(NodeType::Data, "telemetry.export"),
        "telemetry export",
        NodeSecurity {
            sensitive: true,
            ..NodeSecurity::default()
        },
        "OTLP trace export",
        "result#/inputs/trace_files",
    );
    sink.designate(
        &export,
        Designation::Target(TargetClass::ExternalPublication),
    );
    let retrieval_seen = observed_kind(result, "RETRIEVAL");
    let memory_seen = observed_kind(result, "MEMORY");

    for (i, agent_policy) in policy["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(name) = agent_policy["name"].as_str() else {
            sink.unprojected("RuntimePolicy.agent_without_name");
            continue;
        };
        let at = format!("policy#/agents/{i}");
        let agent = sink.node(
            NodeRef::new(NodeType::Agent, name),
            name,
            plain(),
            "RuntimePolicy.agent",
            &at,
        );
        let link = |sink: &mut FactSink,
                    role: Option<Role>,
                    edge_type: EdgeType,
                    source: &NodeRef,
                    target: &NodeRef,
                    kind: &str,
                    locator: String| {
            edge(
                sink,
                verdicts,
                role,
                edge_type,
                source,
                target,
                FactAuthority::default(),
                evidence(),
                kind,
                locator,
            );
        };
        link(
            sink,
            None,
            EdgeType::TransfersTo,
            &channel,
            &agent,
            "RuntimePolicy (user input)",
            at.clone(),
        );
        link(
            sink,
            Some(Role::RuntimeTelemetryExport),
            EdgeType::TransfersTo,
            &agent,
            &export,
            "OTLP span export",
            at.clone(),
        );
        if let Some(principal) = agent_policy["principal"].as_str() {
            let identity = sink.node(
                NodeRef::new(NodeType::Identity, principal),
                principal,
                plain(),
                "RuntimePolicy.principal",
                format!("{at}/principal"),
            );
            link(
                sink,
                Some(Role::RuntimeActsAs),
                EdgeType::AuthenticatesAs,
                &agent,
                &identity,
                "RuntimePolicy.principal",
                format!("{at}/principal"),
            );
        }
        let destructive = names(&agent_policy["destructive_tools"]);
        for (j, tool_name) in names(&agent_policy["allowed_tools"])
            .into_iter()
            .enumerate()
        {
            let is_destructive = destructive.contains(&tool_name);
            let tool = sink.node(
                NodeRef::new(NodeType::Tool, tool_name),
                tool_name,
                NodeSecurity {
                    destructive: is_destructive,
                    ..NodeSecurity::default()
                },
                "RuntimePolicy.allowed_tools",
                format!("{at}/allowed_tools/{j}"),
            );
            if is_destructive {
                sink.designate(
                    &tool,
                    Designation::Target(TargetClass::DestructiveCapability),
                );
            }
            link(
                sink,
                Some(if is_destructive {
                    Role::RuntimeDestructiveCalls
                } else {
                    Role::RuntimeToolCalls
                }),
                EdgeType::CanInvoke,
                &agent,
                &tool,
                "RuntimePolicy.allowed_tools",
                format!("{at}/allowed_tools/{j}"),
            );
        }
        for (j, host) in names(&agent_policy["egress_hosts"]).into_iter().enumerate() {
            let resource = sink.node(
                NodeRef::new(NodeType::Resource, host),
                host,
                plain(),
                "RuntimePolicy.egress_hosts",
                format!("{at}/egress_hosts/{j}"),
            );
            sink.designate(
                &resource,
                Designation::Target(TargetClass::ExternalPublication),
            );
            link(
                sink,
                Some(Role::RuntimeEgress),
                EdgeType::CanReach,
                &agent,
                &resource,
                "RuntimePolicy.egress_hosts",
                format!("{at}/egress_hosts/{j}"),
            );
        }
        if let Some(tenant_id) = agent_policy["tenant"].as_str() {
            for (seen, prefix, role, kind) in [
                (
                    retrieval_seen,
                    "retrieval",
                    Role::RuntimeRetrieves,
                    "RETRIEVAL span",
                ),
                (memory_seen, "memory", Role::RuntimeMemory, "MEMORY span"),
            ] {
                if !seen {
                    continue;
                }
                let store = sink.node(
                    NodeRef::new(NodeType::Data, format!("{prefix}.{tenant_id}")),
                    &format!("{prefix} store ({tenant_id})"),
                    tenant(tenant_id),
                    "RuntimePolicy.tenant",
                    format!("{at}/tenant"),
                );
                link(
                    sink,
                    Some(role),
                    EdgeType::Reads,
                    &agent,
                    &store,
                    kind,
                    format!("{at}/tenant"),
                );
            }
        }
    }
}
