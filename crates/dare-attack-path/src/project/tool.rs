//! Tool projector (Cycle 014, BLUEPRINT §6.1).
use dare_attack_graph::{
    v2::{EntryClass, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_tool_security::{
    model::{DeclaredSensitivity, OperationClass, ToolEntry, ToolSecurityScenario},
    observation::ToolObservationEvent,
    result::ToolSecurityResult,
    source::TrustLevel,
};

use super::{edge, plain, sut, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

fn operation_class(entry: &ToolEntry) -> Option<OperationClass> {
    entry
        .security_metadata
        .as_ref()
        .and_then(|m| m.declared_operation_class)
}

pub fn tool_security(entry: &ToolEntry) -> NodeSecurity {
    let destructive = matches!(
        operation_class(entry),
        Some(OperationClass::Delete | OperationClass::Payment | OperationClass::PrivilegeChange)
    ) || entry.annotations.as_ref().and_then(|a| a.destructive_hint)
        == Some(true);
    let sensitive = entry
        .security_metadata
        .as_ref()
        .and_then(|m| m.declared_sensitivity)
        == Some(DeclaredSensitivity::High);
    NodeSecurity {
        destructive,
        sensitive,
        ..NodeSecurity::default()
    }
}

pub fn project(
    bundle: &LoadedBundle,
    result: &ToolSecurityResult,
    scenario: &ToolSecurityScenario,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let surface = &scenario.tool_surface;
    let static_ev = || statically_proven(bundle.engine, &[&result.scenario_digest]);
    let agent = sink.node(
        sut(),
        "agent under test",
        plain(),
        "ToolSecurityScenario",
        "/",
    );
    let server = sink.node(
        NodeRef::new(NodeType::McpServer, &surface.surface_id),
        surface.title.as_deref().unwrap_or(&surface.surface_id),
        plain(),
        "ToolSurfaceSnapshot",
        "input:scenario#/tool_surface",
    );
    for trial in &result.trials {
        for violation in &trial.violations {
            if let Some(tool_id) = &violation.tool_id {
                verdicts.violation(&result.property_id, NodeRef::new(NodeType::Tool, tool_id));
            }
        }
    }
    for (index, entry) in surface.tools.iter().enumerate() {
        let tool = sink.node(
            NodeRef::new(NodeType::Tool, &entry.tool_id),
            &entry.tool_name,
            tool_security(entry),
            "ToolEntry",
            format!("input:scenario#/tool_surface/tools/{index}"),
        );
        let locator = format!("input:scenario#/tool_surface/tools/{index}");
        edge(
            sink,
            verdicts,
            None,
            EdgeType::CanReach,
            &server,
            &tool,
            FactAuthority::default(),
            static_ev(),
            "ToolSurfaceSnapshot",
            &locator,
        );
        edge(
            sink,
            verdicts,
            Some(Role::ToolCanInvoke),
            EdgeType::CanInvoke,
            &agent,
            &tool,
            FactAuthority::default(),
            static_ev(),
            "ToolEntry",
            &locator,
        );
        match operation_class(entry) {
            Some(
                OperationClass::Delete | OperationClass::Payment | OperationClass::PrivilegeChange,
            ) => {
                sink.designate(
                    &tool,
                    Designation::Target(TargetClass::DestructiveCapability),
                );
            }
            Some(OperationClass::Send) => {
                sink.designate(&tool, Designation::Target(TargetClass::ExternalPublication));
            }
            _ if entry.annotations.as_ref().and_then(|a| a.destructive_hint) == Some(true) => {
                sink.designate(
                    &tool,
                    Designation::Target(TargetClass::DestructiveCapability),
                );
            }
            _ => {}
        }
    }
    for (trial_index, trial) in result.trials.iter().enumerate() {
        let ids = trial_ids(bundle, &result.evidence_ids, trial_index);
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            match event {
                ToolObservationEvent::ToolRequested(request) => {
                    let tool = sink.node(
                        NodeRef::new(NodeType::Tool, &request.tool_id),
                        &request.tool_id,
                        plain(),
                        "ToolRequested",
                        &locator,
                    );
                    edge(
                        sink,
                        verdicts,
                        Some(Role::ToolCalls),
                        EdgeType::Calls,
                        &agent,
                        &tool,
                        FactAuthority::default(),
                        observed(ids.clone()),
                        "ToolRequested (request, not execution)",
                        &locator,
                    );
                }
                ToolObservationEvent::ToolOutputObserved(output) => {
                    let tool = sink.node(
                        NodeRef::new(NodeType::Tool, &output.tool_id),
                        &output.tool_id,
                        plain(),
                        "ToolOutputObserved",
                        &locator,
                    );
                    let data = sink.node(
                        NodeRef::new(NodeType::Data, format!("output.{}", output.tool_id)),
                        &format!("output of {}", output.tool_id),
                        plain(),
                        "ToolOutputObserved",
                        &locator,
                    );
                    edge(
                        sink,
                        verdicts,
                        None,
                        EdgeType::TransfersTo,
                        &tool,
                        &data,
                        FactAuthority::default(),
                        observed(ids.clone()),
                        "ToolOutputObserved",
                        &locator,
                    );
                    edge(
                        sink,
                        verdicts,
                        Some(Role::ToolOutputToSut),
                        EdgeType::TransfersTo,
                        &data,
                        &agent,
                        FactAuthority::default(),
                        observed(ids.clone()),
                        "ToolOutputObserved",
                        &locator,
                    );
                    if surface.trust != TrustLevel::Trusted {
                        sink.designate(&data, Designation::Entry(EntryClass::ExternalContent));
                    }
                }
                other => sink.unprojected(format!("ToolObservationEvent::{}", other.kind())),
            }
        }
    }
}
