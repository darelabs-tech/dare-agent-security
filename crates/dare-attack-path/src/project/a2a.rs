//! A2A projector (Cycle 020, BLUEPRINT §6.7).
//!
//! Peers are agents the local agent (the run's SUT) talks to; every
//! exchange is a peer calling the SUT. With bound evidence (static, replay,
//! simulated) the projector reads the full peer identities, exchanges and
//! delegation chains. A remote run keeps only the result, so it projects
//! `PeerRecord`s and `ExchangeRecord`s and has no delegation (022 never
//! keeps delegation files).
use std::collections::BTreeMap;

use dare_a2a_security::{normalize::A2aEvidence, result::A2aSecurityResult};
use dare_attack_graph::{v2::EntryClass, EdgeType, NodeType};

use super::{edge, plain, sut, tenant};
use crate::{
    bundle::LoadedBundle,
    facts::{observed, statically_proven, Designation, FactAuthority, FactSink, NodeRef},
    guard_table::{Role, RunVerdicts},
};

/// One exchange, from full evidence or from a result-only record.
struct SeenExchange {
    peer_id: String,
    skill: Option<String>,
    tenant_claim: Option<String>,
    locator: String,
}

/// An authority subject named by string; `merge` resolves it to a node when
/// one exists and to `ext:` otherwise.
fn subject(id: &str) -> NodeRef {
    NodeRef::new(NodeType::Identity, id)
}

pub fn project(
    bundle: &LoadedBundle,
    result: &A2aSecurityResult,
    evidence: Option<&A2aEvidence>,
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    let agent = sink.node(sut(), "agent under test", plain(), "A2A local agent", "/");
    let all_ids = bundle.evidence.all_ids();
    let mut peers: BTreeMap<String, NodeRef> = BTreeMap::new();
    match evidence {
        Some(evidence) => {
            for (index, peer) in evidence.peers.peers.iter().enumerate() {
                let security = peer.tenant.as_deref().map_or_else(plain, tenant);
                let node = sink.node(
                    NodeRef::new(NodeType::Agent, &peer.logical_agent_id),
                    &peer.logical_agent_id,
                    security,
                    "PeerIdentity",
                    format!("evidence#/peers/peers/{index}"),
                );
                peers.insert(peer.peer_id.clone(), node);
            }
        }
        None => {
            for (index, peer) in result.peers.iter().enumerate() {
                let node = sink.node(
                    NodeRef::new(NodeType::Agent, &peer.logical_agent_id),
                    &peer.logical_agent_id,
                    plain(),
                    "PeerRecord",
                    format!("/peers/{index}"),
                );
                peers.insert(peer.peer_id.clone(), node);
            }
        }
    }
    for node in peers.values() {
        sink.designate(node, Designation::Entry(EntryClass::PeerAgent));
    }
    for outcome in &result.outcomes {
        let property = outcome.invariant.property_id();
        for violation in &outcome.violations {
            if let Some(node) = violation.peer_id.as_ref().and_then(|p| peers.get(p)) {
                verdicts.violation(property, node.clone());
            }
        }
    }

    let subject_of = |peer_id: &str| -> Option<String> {
        evidence
            .and_then(|e| e.peers.peers.iter().find(|p| p.peer_id == peer_id))
            .and_then(|p| p.authorization_subject().map(str::to_owned))
            .or_else(|| {
                result
                    .peers
                    .iter()
                    .find(|p| p.peer_id == peer_id)
                    .and_then(|p| p.authorization_subject.clone())
            })
    };
    let delegated_of = |peer_id: &str| -> bool {
        evidence
            .and_then(|e| e.peers.peers.iter().find(|p| p.peer_id == peer_id))
            .map(|p| p.delegated_subject.is_some())
            .or_else(|| {
                result
                    .peers
                    .iter()
                    .find(|p| p.peer_id == peer_id)
                    .map(|p| p.delegated_subject.is_some())
            })
            .unwrap_or(false)
    };
    let exchanges: Vec<SeenExchange> = match evidence {
        Some(evidence) => evidence
            .exchanges
            .exchanges
            .iter()
            .enumerate()
            .map(|(i, e)| SeenExchange {
                peer_id: e.peer_id.clone(),
                skill: e.requested_skill.clone(),
                tenant_claim: e.tenant_claim.clone(),
                locator: format!("evidence#/exchanges/exchanges/{i}"),
            })
            .collect(),
        None => result
            .exchanges
            .iter()
            .enumerate()
            .map(|(i, e)| SeenExchange {
                peer_id: e.peer_id.clone(),
                skill: e.requested_skill.clone(),
                tenant_claim: None,
                locator: format!("/exchanges/{i}"),
            })
            .collect(),
    };
    for SeenExchange {
        peer_id,
        skill,
        tenant_claim,
        locator,
    } in exchanges
    {
        let Some(peer) = peers.get(&peer_id).cloned() else {
            sink.unprojected("Exchange::unknown_peer");
            continue;
        };
        let authority = FactAuthority {
            principal: subject_of(&peer_id).as_deref().map(subject),
            delegated: delegated_of(&peer_id),
            tenant: tenant_claim,
            scopes: skill.into_iter().collect(),
            ..FactAuthority::default()
        };
        edge(
            sink,
            verdicts,
            Some(Role::A2aCalls),
            EdgeType::Calls,
            &peer,
            &agent,
            authority,
            observed(all_ids.clone()),
            "Exchange",
            locator,
        );
    }

    let Some(evidence) = evidence else {
        return;
    };
    let delegation_digests: Vec<&str> = result
        .documents
        .iter()
        .filter(|d| d.kind == "DELEGATION")
        .map(|d| d.content_digest.as_str())
        .collect();
    let cited: Vec<&str> = if delegation_digests.is_empty() {
        vec![result.evidence_digest.as_str()]
    } else {
        delegation_digests
    };
    for (chain_index, chain) in evidence.delegation_chains.iter().enumerate() {
        for (hop_index, hop) in chain.hops.iter().enumerate() {
            let locator = format!("evidence#/delegation_chains/{chain_index}/hops/{hop_index}");
            let from = sink.node(
                NodeRef::new(NodeType::Agent, &hop.grantor),
                &hop.grantor,
                plain(),
                "DelegationHop.grantor",
                &locator,
            );
            let to = sink.node(
                NodeRef::new(NodeType::Agent, &hop.grantee),
                &hop.grantee,
                plain(),
                "DelegationHop.grantee",
                &locator,
            );
            let authority = FactAuthority {
                principal: Some(subject(&hop.subject)),
                delegated: true,
                tenant: hop.tenant.clone(),
                scopes: hop.allowed_skills.iter().cloned().collect(),
                ..FactAuthority::default()
            };
            edge(
                sink,
                verdicts,
                Some(Role::A2aDelegates),
                EdgeType::DelegatesTo,
                &from,
                &to,
                authority,
                statically_proven(bundle.engine, &cited),
                "DelegationHop",
                locator,
            );
        }
    }
}
