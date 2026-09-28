//! Memory projector (Cycle 016, BLUEPRINT §6.3).
use std::collections::BTreeMap;

use dare_attack_graph::{v2::EntryClass, EdgeType, NodeType};
use dare_memory_security::{
    model::MemorySecurityScenario,
    observation::{InfluenceTarget, MemoryObservationEvent},
    result::MemorySecurityResult,
    source::{SourceKind, TrustClass},
};

use super::{edge, identity::principal_type, plain, tenant, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

/// A property enum serialized as its registry id.
pub fn property_name(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub fn project(
    bundle: &LoadedBundle,
    result: &MemorySecurityResult,
    scenario: &MemorySecurityScenario,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let static_ev = || statically_proven(bundle.engine, &[&result.scenario_digest]);
    let property = property_name(&result.property_id);
    let mut principals: BTreeMap<String, NodeRef> = BTreeMap::new();
    for (index, principal) in scenario.context.principals.iter().enumerate() {
        let node = sink.node(
            NodeRef::new(principal_type(principal.kind), &principal.principal_id),
            principal
                .display_label
                .as_deref()
                .unwrap_or(&principal.principal_id),
            tenant(&principal.tenant_id),
            "MemoryPrincipal",
            format!("input:scenario#/context/principals/{index}"),
        );
        principals.insert(principal.principal_id.clone(), node);
    }
    // A principal the context does not declare has no known kind; it is an
    // IDENTITY, and the model may alias it.
    let mut principal = |sink: &mut FactSink, id: &str, locator: &str| -> NodeRef {
        principals
            .entry(id.to_owned())
            .or_insert_with(|| {
                sink.node(
                    NodeRef::new(NodeType::Identity, id),
                    id,
                    plain(),
                    "principal (kind not declared)",
                    locator,
                )
            })
            .clone()
    };
    let mut items: BTreeMap<String, NodeRef> = BTreeMap::new();
    for (index, item) in scenario.store.items.iter().enumerate() {
        let locator = format!("input:scenario#/store/items/{index}");
        let node = sink.node(
            NodeRef::new(NodeType::Data, &item.memory_id),
            &item.memory_id,
            tenant(&item.tenant_id),
            "MemoryItem",
            &locator,
        );
        let untrusted_source = item.provenance.as_ref().is_some_and(|p| {
            matches!(
                p.source_kind,
                SourceKind::UserInput | SourceKind::ExternalContent | SourceKind::ToolOutput
            )
        });
        if item.trust_class == TrustClass::Untrusted || untrusted_source {
            sink.designate(&node, Designation::Entry(EntryClass::MemoryWrite));
        }
        let owner = principal(sink, &item.owner_principal_id, &locator);
        edge(
            sink,
            verdicts,
            Some(Role::MemoryWrites),
            EdgeType::Writes,
            &owner,
            &node,
            FactAuthority {
                principal: Some(owner.clone()),
                tenant: Some(item.tenant_id.clone()),
                ..FactAuthority::default()
            },
            static_ev(),
            "MemoryItem.owner_principal_id",
            &locator,
        );
        items.insert(item.memory_id.clone(), node);
    }
    for trial in &result.trials {
        for violation in &trial.violations {
            if let Some(node) = violation.memory_id.as_ref().and_then(|id| items.get(id)) {
                verdicts.violation(&property, node.clone());
            }
        }
    }
    let agent = principal(
        sink,
        &scenario.context.acting_principal_id,
        "input:scenario#/context",
    );
    for (trial_index, trial) in result.trials.iter().enumerate() {
        let ids = trial_ids(bundle, &result.evidence_ids, trial_index);
        let influenced: Vec<&str> = trial
            .events
            .iter()
            .filter_map(|event| match event {
                MemoryObservationEvent::MemoryInfluenceObserved(i)
                    if i.changed
                        && matches!(
                            i.target,
                            InfluenceTarget::ToolSelection | InfluenceTarget::ToolArgument
                        ) =>
                {
                    Some(i.memory_id.as_str())
                }
                _ => None,
            })
            .collect();
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            match event {
                MemoryObservationEvent::MemoryWriteObserved(write) => {
                    let writer = principal(sink, &write.writer_principal_id, &locator);
                    let item = items
                        .entry(write.memory_id.clone())
                        .or_insert_with(|| {
                            sink.node(
                                NodeRef::new(NodeType::Data, &write.memory_id),
                                &write.memory_id,
                                tenant(&write.tenant_id),
                                "MemoryWriteObserved",
                                &locator,
                            )
                        })
                        .clone();
                    edge(
                        sink,
                        verdicts,
                        Some(Role::MemoryWrites),
                        EdgeType::Writes,
                        &writer,
                        &item,
                        FactAuthority {
                            principal: Some(writer.clone()),
                            tenant: Some(write.tenant_id.clone()),
                            ..FactAuthority::default()
                        },
                        observed(ids.clone()),
                        "MemoryWriteObserved",
                        &locator,
                    );
                }
                MemoryObservationEvent::MemoryRecallObserved(recall) => {
                    let requester = principal(sink, &recall.requester_principal_id, &locator);
                    for recalled in &recall.items {
                        let item = items
                            .entry(recalled.memory_id.clone())
                            .or_insert_with(|| {
                                sink.node(
                                    NodeRef::new(NodeType::Data, &recalled.memory_id),
                                    &recalled.memory_id,
                                    tenant(&recalled.tenant_id),
                                    "RecalledItem",
                                    &locator,
                                )
                            })
                            .clone();
                        let authority = FactAuthority {
                            principal: Some(requester.clone()),
                            tenant: Some(recalled.tenant_id.clone()),
                            ..FactAuthority::default()
                        };
                        edge(
                            sink,
                            verdicts,
                            Some(Role::MemoryReads),
                            EdgeType::Reads,
                            &requester,
                            &item,
                            authority,
                            observed(ids.clone()),
                            "MemoryRecallObserved",
                            &locator,
                        );
                        edge(
                            sink,
                            verdicts,
                            Some(Role::MemoryInfluences),
                            EdgeType::TransfersTo,
                            &item,
                            &requester,
                            FactAuthority::default(),
                            observed(ids.clone()),
                            "MemoryRecallObserved",
                            &locator,
                        );
                    }
                }
                MemoryObservationEvent::ActionIntentObserved(intent) => {
                    let Some(tool_id) = &intent.tool_id else {
                        sink.unprojected("ActionIntentObserved::no_tool");
                        continue;
                    };
                    let tool = sink.node(
                        NodeRef::new(NodeType::Tool, tool_id),
                        tool_id,
                        plain(),
                        "ActionIntentObserved.tool_id",
                        &locator,
                    );
                    edge(
                        sink,
                        verdicts,
                        Some(Role::MemoryCalls),
                        EdgeType::Calls,
                        &agent,
                        &tool,
                        FactAuthority {
                            principal: Some(agent.clone()),
                            ..FactAuthority::default()
                        },
                        observed(ids.clone()),
                        "ActionIntentObserved (intent, not execution)",
                        &locator,
                    );
                    for memory_id in &influenced {
                        if let Some(item) = items.get(*memory_id).cloned() {
                            edge(
                                sink,
                                verdicts,
                                Some(Role::MemoryInfluences),
                                EdgeType::TransfersTo,
                                &item,
                                &tool,
                                FactAuthority::default(),
                                observed(ids.clone()),
                                "MemoryInfluenceObserved",
                                &locator,
                            );
                        }
                    }
                }
                // Used with the trial's action intent above.
                MemoryObservationEvent::MemoryInfluenceObserved(_) => {}
                other => sink.unprojected(format!("MemoryObservationEvent::{}", other.kind())),
            }
        }
    }
}
