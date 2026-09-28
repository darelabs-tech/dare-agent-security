//! RAG projector (Cycle 017, BLUEPRINT §6.4).
use std::collections::BTreeMap;

use dare_attack_graph::{
    v2::{EntryClass, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};
use dare_rag_security::{
    model::RagSecurityScenario,
    observation::RagObservationEvent,
    result::RagSecurityResult,
    source::{ClassificationLevel, DocumentSourceKind, DocumentTrustClass},
};

use super::{edge, identity::principal_type, memory::property_name, plain, tenant, trial_ids};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

pub fn project(
    bundle: &LoadedBundle,
    result: &RagSecurityResult,
    scenario: &RagSecurityScenario,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let static_ev = || statically_proven(bundle.engine, &[&result.scenario_digest]);
    let property = property_name(&result.property_id);
    let context = &scenario.context;
    let acting_kind = context
        .principals
        .iter()
        .find(|p| p.principal_id == context.acting_principal_id)
        .map_or(NodeType::Agent, |p| principal_type(p.kind));
    let agent = sink.node(
        NodeRef::new(acting_kind, &context.acting_principal_id),
        &context.acting_principal_id,
        tenant(&context.tenant_id),
        "RetrievalContext.acting_principal_id",
        "input:scenario#/context",
    );
    let mut documents: BTreeMap<&str, NodeRef> = BTreeMap::new();
    for (index, document) in scenario.store.documents.iter().enumerate() {
        let locator = format!("input:scenario#/store/documents/{index}");
        let sensitive = matches!(
            document.classification,
            ClassificationLevel::Confidential | ClassificationLevel::Restricted
        );
        let node = sink.node(
            NodeRef::new(NodeType::Data, &document.document_id),
            &document.document_id,
            NodeSecurity {
                tenant: Some(document.tenant_id.clone()),
                sensitive,
                ..NodeSecurity::default()
            },
            &format!("Document (collection {})", document.collection_id),
            &locator,
        );
        let tenant_node = sink.node(
            NodeRef::new(NodeType::Tenant, &document.tenant_id),
            &document.tenant_id,
            plain(),
            "Document.tenant_id",
            &locator,
        );
        edge(
            sink,
            verdicts,
            None,
            EdgeType::BelongsToTenant,
            &node,
            &tenant_node,
            FactAuthority::default(),
            static_ev(),
            "Document.tenant_id",
            &locator,
        );
        if document.trust_class == DocumentTrustClass::Untrusted
            || matches!(
                document.provenance.source_kind,
                DocumentSourceKind::ExternalIngested | DocumentSourceKind::AgentGenerated
            )
        {
            sink.designate(&node, Designation::Entry(EntryClass::RetrievedDocument));
        }
        if sensitive {
            sink.designate(&node, Designation::Target(TargetClass::SensitiveResource));
        }
        documents.insert(document.document_id.as_str(), node);
    }
    for trial in &result.trials {
        for violation in &trial.violations {
            if let Some(node) = violation
                .document_id
                .as_deref()
                .and_then(|id| documents.get(id))
            {
                verdicts.violation(&property, node.clone());
            }
        }
    }
    for (trial_index, trial) in result.trials.iter().enumerate() {
        let ids = trial_ids(bundle, &result.evidence_ids, trial_index);
        for (event_index, event) in trial.events.iter().enumerate() {
            let locator = format!("/trials/{trial_index}/events/{event_index}");
            let document_id = match event {
                RagObservationEvent::DocumentContext { document, .. } => {
                    document.document_id.as_str()
                }
                RagObservationEvent::RetrievedChunk {
                    bound_document_id, ..
                } => bound_document_id.as_str(),
                other => {
                    sink.unprojected(format!("RagObservationEvent::{}", super::event_kind(other)));
                    continue;
                }
            };
            let Some(document) = documents.get(document_id).cloned() else {
                sink.unprojected("RagObservationEvent::unknown_document");
                continue;
            };
            let authority = FactAuthority {
                principal: Some(agent.clone()),
                tenant: Some(context.tenant_id.clone()),
                ..FactAuthority::default()
            };
            edge(
                sink,
                verdicts,
                Some(Role::RagReads),
                EdgeType::Reads,
                &agent,
                &document,
                authority,
                observed(ids.clone()),
                "retrieval",
                &locator,
            );
            edge(
                sink,
                verdicts,
                Some(Role::RagInfluences),
                EdgeType::TransfersTo,
                &document,
                &agent,
                FactAuthority::default(),
                observed(ids.clone()),
                "retrieval",
                &locator,
            );
        }
    }
}
