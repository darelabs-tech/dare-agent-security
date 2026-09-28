//! Prompt-injection projector (Cycle 013, BLUEPRINT §6.8): entry facts.
use dare_attack_graph::{v2::EntryClass, EdgeType, NodeType};
use dare_prompt_injection::{
    observation::ObservationEvent, result::PromptInjectionResult, source::InjectionDirection,
};

use super::{edge, enum_name, plain, sut, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

pub fn project(
    bundle: &LoadedBundle,
    result: &PromptInjectionResult,
    verdicts: &RunVerdicts,
    sink: &mut FactSink,
) {
    let agent = sink.node(
        sut(),
        "agent under test",
        plain(),
        "prompt-injection target",
        "/",
    );
    let source = enum_name(&result.source_kind).to_ascii_lowercase();
    let channel = sink.node(
        NodeRef::new(NodeType::Data, format!("channel.{source}")),
        &format!("{source} channel"),
        plain(),
        &format!("SourceKind::{}", enum_name(&result.source_kind)),
        "/source_kind",
    );
    sink.designate(
        &channel,
        Designation::Entry(match result.direction {
            InjectionDirection::Direct => EntryClass::UntrustedInput,
            InjectionDirection::Indirect => EntryClass::ExternalContent,
        }),
    );
    for (trial_index, trial) in result.trials.iter().enumerate() {
        let ids = trial_ids(bundle, &result.evidence_ids, trial_index);
        let locator = format!("/trials/{trial_index}");
        edge(
            sink,
            verdicts,
            Some(Role::PromptChannel),
            EdgeType::TransfersTo,
            &channel,
            &agent,
            FactAuthority::default(),
            observed(ids.clone()),
            "prompt-injection trial",
            &locator,
        );
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            match event {
                ObservationEvent::StructuredActionRequest(request)
                    if !request.action.is_empty() =>
                {
                    let tool = sink.node(
                        NodeRef::new(NodeType::Tool, &request.action),
                        &request.action,
                        plain(),
                        "StructuredActionRequest.action",
                        &locator,
                    );
                    edge(
                        sink,
                        verdicts,
                        None,
                        EdgeType::CanInvoke,
                        &agent,
                        &tool,
                        FactAuthority::default(),
                        observed(ids.clone()),
                        "StructuredActionRequest (request, not execution)",
                        &locator,
                    );
                }
                other => {
                    sink.unprojected(format!("ObservationEvent::{}", super::event_kind(other)))
                }
            }
        }
    }
}
