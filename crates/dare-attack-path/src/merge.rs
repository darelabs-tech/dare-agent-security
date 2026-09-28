//! Merge (BLUEPRINT §7.1, §4.9, task-029).
//!
//! Run facts become one graph. Identity is resolved here and only here: an
//! engine-local id becomes an entity node through an explicit system-model
//! alias, and otherwise stays scoped to its run (AD-07, BQ-2).
use std::collections::{BTreeMap, BTreeSet};

use dare_attack_graph::{
    build_edge_id,
    v2::{
        DesignationOrigin, EdgeV2, EntryDesignation, Guard, NodeV2, Provenance, TargetDesignation,
    },
    AuthorityContext, EdgeEvidence, EdgeEvidenceStatus, NodeSecurity, NodeType,
};

use crate::{
    error::{AttackPathError, ModelRefusal, Refusal, Result},
    facts::{Designation, FactAuthority, NodeRef, RunFacts},
    ids::{display_name, entity_node_id, local_token, scoped_node_id},
    limits::{MAX_EDGES, MAX_NODES},
    model::{AdmittedModel, DeclaredStatus},
};

/// The merged graph before designation defaults and enumeration.
#[derive(Debug, Clone, Default)]
pub struct Merged {
    pub nodes: BTreeMap<String, NodeV2>,
    pub edges: BTreeMap<String, EdgeV2>,
    pub entries: BTreeSet<EntryDesignation>,
    pub targets: BTreeSet<TargetDesignation>,
    /// Alias index → number of projected nodes it matched.
    pub alias_hits: BTreeMap<usize, u32>,
}

fn internal(message: &'static str) -> AttackPathError {
    AttackPathError::Internal(message)
}

fn strength(status: EdgeEvidenceStatus) -> u8 {
    match status {
        EdgeEvidenceStatus::NotTested => 0,
        EdgeEvidenceStatus::Inferred => 1,
        EdgeEvidenceStatus::StaticallyProven => 2,
        EdgeEvidenceStatus::Observed => 3,
    }
}

/// §4.9: the stronger status wins; ids are unioned; the text fields come
/// from the first provenance and survive only if the merged status needs them.
fn merge_evidence(into: &mut EdgeEvidence, from: &EdgeEvidence) {
    if strength(from.status) > strength(into.status) {
        let mut ids = into.evidence_ids.clone();
        *into = from.clone();
        ids.extend(from.evidence_ids.iter().cloned());
        into.evidence_ids = ids;
    } else {
        into.evidence_ids.extend(from.evidence_ids.iter().cloned());
    }
    into.evidence_ids.sort();
    into.evidence_ids.dedup();
    match into.status {
        EdgeEvidenceStatus::Observed | EdgeEvidenceStatus::StaticallyProven => {
            into.rationale = None;
            into.source_facts.clear();
            into.reason = None;
        }
        EdgeEvidenceStatus::Inferred => into.reason = None,
        EdgeEvidenceStatus::NotTested => {
            into.rationale = None;
            into.source_facts.clear();
        }
    }
    if into.status != EdgeEvidenceStatus::Observed
        && into.status != EdgeEvidenceStatus::StaticallyProven
    {
        into.evidence_ids.clear();
    }
}

fn merge_security(into: &mut NodeSecurity, from: &NodeSecurity) -> std::result::Result<(), ()> {
    match (&into.tenant, &from.tenant) {
        (Some(a), Some(b)) if a != b => return Err(()),
        (None, Some(b)) => into.tenant = Some(b.clone()),
        _ => {}
    }
    into.privileged |= from.privileged;
    into.sensitive |= from.sensitive;
    into.destructive |= from.destructive;
    if into.state_impact.is_none() {
        into.state_impact = from.state_impact.clone();
    }
    Ok(())
}

struct Resolver<'a> {
    model: Option<&'a AdmittedModel>,
}

impl Resolver<'_> {
    /// (node id, alias index, entity index) for a projected node.
    fn resolve(
        &self,
        facts: &RunFacts,
        node: &NodeRef,
    ) -> Result<(String, Option<usize>, Option<usize>)> {
        let alias = self.model.and_then(|m| {
            m.alias_for(facts.engine, facts.run.as_str(), &node.local_id)
                .map(|a| (m, a))
        });
        match alias {
            Some((model, alias_index)) => {
                let entity_id = &model.model.aliases[alias_index].entity_id;
                let (entity_index, entity) = model
                    .entity(entity_id)
                    .ok_or_else(|| internal("alias names an admitted entity"))?;
                if entity.node_type != node.node_type {
                    return Err(ModelRefusal::TypeClash { alias: alias_index }.into());
                }
                let id = entity_node_id(entity.node_type, &entity.entity_id)
                    .ok_or_else(|| internal("admitted entity id"))?;
                Ok((id, Some(alias_index), Some(entity_index)))
            }
            None => Ok((
                scoped_node_id(node.node_type, facts.engine, &facts.run, &node.local_id),
                None,
                None,
            )),
        }
    }
}

fn entity_security(model: &AdmittedModel, entity_index: usize) -> NodeSecurity {
    let s = &model.model.entities[entity_index].security;
    NodeSecurity {
        tenant: s.tenant.clone(),
        privileged: s.privileged,
        sensitive: s.sensitive,
        destructive: s.destructive,
        state_impact: None,
    }
}

pub fn merge(runs: &[RunFacts], model: Option<&AdmittedModel>) -> Result<Merged> {
    let mut out = Merged::default();
    let resolver = Resolver { model };

    // Model entities are nodes in their own right (declared edges and
    // designations may name them even when no alias matched).
    if let Some(model) = model {
        for (index, entity) in model.model.entities.iter().enumerate() {
            let id = entity_node_id(entity.node_type, &entity.entity_id)
                .ok_or_else(|| internal("admitted entity id"))?;
            out.nodes.insert(
                id.clone(),
                NodeV2 {
                    id,
                    node_type: entity.node_type,
                    display_name: entity.display_name.clone(),
                    security: entity_security(model, index),
                    provenance: vec![Provenance {
                        artifact_index: None,
                        original_kind: "SystemModel.entity".into(),
                        locator: format!("#/entities/{index}"),
                    }],
                },
            );
        }
    }

    // Nodes.
    for facts in runs {
        for node in &facts.nodes {
            let (id, alias, entity) = resolver.resolve(facts, &node.node)?;
            if let Some(alias) = alias {
                *out.alias_hits.entry(alias).or_insert(0) += 1;
            }
            let provenance = Provenance {
                artifact_index: Some(facts.artifact_index),
                original_kind: node.original_kind.clone(),
                locator: node.locator.clone(),
            };
            match out.nodes.get_mut(&id) {
                Some(existing) => {
                    merge_security(&mut existing.security, &node.security).map_err(|_| {
                        AttackPathError::from(ModelRefusal::TenantClash {
                            entity: entity.unwrap_or(0),
                        })
                    })?;
                    existing.provenance.push(provenance);
                }
                None => {
                    out.nodes.insert(
                        id.clone(),
                        NodeV2 {
                            id,
                            node_type: node.node.node_type,
                            display_name: display_name(&node.raw_label, node.node.node_type),
                            security: node.security.clone(),
                            provenance: vec![provenance],
                        },
                    );
                }
            }
        }
    }

    // Edges.
    for facts in runs {
        for edge in &facts.edges {
            let (source, _, _) = resolver.resolve(facts, &edge.source)?;
            let (target, _, _) = resolver.resolve(facts, &edge.target)?;
            if !out.nodes.contains_key(&source) || !out.nodes.contains_key(&target) {
                return Err(internal(
                    "a projector emitted an edge to an unprojected node",
                ));
            }
            let authority = resolve_authority(&resolver, &out, facts, &edge.authority)?;
            let guards: Vec<Guard> = edge
                .guards
                .iter()
                .map(|g| Guard {
                    property: g.property.clone(),
                    verdict: g.verdict,
                    evidence_ids: g.evidence_ids.clone(),
                    scope: g.scope,
                    artifact_index: facts.artifact_index,
                })
                .collect();
            let provenance = Provenance {
                artifact_index: Some(facts.artifact_index),
                original_kind: edge.original_kind.clone(),
                locator: edge.locator.clone(),
            };
            insert_edge(
                &mut out,
                source,
                edge.edge_type,
                target,
                authority,
                &edge.evidence,
                guards,
                edge.authority_mutation,
                provenance,
            )?;
        }
        for designation in &facts.designations {
            let (id, _, _) = resolver.resolve(facts, &designation.node)?;
            match designation.designation {
                Designation::Entry(class) => {
                    out.entries.insert(EntryDesignation {
                        node: id,
                        class,
                        origin: DesignationOrigin::Default,
                    });
                }
                Designation::Target(class) => {
                    out.targets.insert(TargetDesignation {
                        node: id,
                        class,
                        origin: DesignationOrigin::Default,
                    });
                }
            }
        }
    }

    if let Some(model) = model {
        declared_edges(&mut out, model)?;
        trust_boundaries(&mut out, model)?;
    }
    if out.nodes.len() > MAX_NODES || out.edges.len() > MAX_EDGES {
        return Err(internal("merged graph exceeds the node or edge maximum"));
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn insert_edge(
    out: &mut Merged,
    source: String,
    edge_type: dare_attack_graph::EdgeType,
    target: String,
    authority: AuthorityContext,
    evidence: &EdgeEvidence,
    guards: Vec<Guard>,
    authority_mutation: bool,
    provenance: Provenance,
) -> Result<()> {
    let mut authority = authority;
    authority.normalize();
    let id =
        build_edge_id(&source, edge_type, &target, &authority).map_err(|_| internal("edge id"))?;
    match out.edges.get_mut(&id) {
        Some(existing) => {
            merge_evidence(&mut existing.evidence, evidence);
            for guard in guards {
                if !existing.guards.contains(&guard) {
                    existing.guards.push(guard);
                }
            }
            existing.guards.sort();
            existing.authority_mutation |= authority_mutation;
            existing.provenance.push(provenance);
        }
        None => {
            let mut guards = guards;
            guards.sort();
            guards.dedup();
            let mut evidence = evidence.clone();
            evidence.evidence_ids.sort();
            evidence.evidence_ids.dedup();
            out.edges.insert(
                id.clone(),
                EdgeV2 {
                    id,
                    edge_type,
                    source,
                    target,
                    authority,
                    evidence,
                    guards,
                    authority_mutation,
                    crosses_trust_boundary: vec![],
                    provenance: vec![provenance],
                },
            );
        }
    }
    Ok(())
}

/// Authority fields that name nodes become node ids; a principal that is not
/// a node becomes `ext:<token>`; a credential that is not a credential node
/// is dropped (the v1 contract requires a `node:credential:` id).
fn resolve_authority(
    resolver: &Resolver<'_>,
    out: &Merged,
    facts: &RunFacts,
    authority: &FactAuthority,
) -> Result<AuthorityContext> {
    let principal = match &authority.principal {
        Some(node) => {
            let (id, _, _) = resolver.resolve(facts, node)?;
            Some(if out.nodes.contains_key(&id) {
                id
            } else {
                format!("ext:{}", local_token(&node.local_id))
            })
        }
        None => None,
    };
    let credential = match &authority.credential {
        Some(node) if node.node_type == NodeType::Credential => {
            let (id, _, _) = resolver.resolve(facts, node)?;
            out.nodes.contains_key(&id).then_some(id)
        }
        _ => None,
    };
    Ok(AuthorityContext {
        principal,
        agent_identity: authority.agent_identity.clone(),
        service_identity: authority.service_identity.clone(),
        delegated: authority.delegated,
        tenant: authority.tenant.clone(),
        credential,
        authorization_decision: authority.authorization_decision.clone(),
        scopes: authority.scopes.clone(),
    })
}

fn entity_id_to_node(model: &AdmittedModel, entity_id: &str) -> Option<String> {
    model
        .entity(entity_id)
        .and_then(|(_, e)| entity_node_id(e.node_type, &e.entity_id))
}

fn declared_edges(out: &mut Merged, model: &AdmittedModel) -> Result<()> {
    let digest_hex = model
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&model.digest)
        .to_owned();
    for (index, declared) in model.model.declared_edges.iter().enumerate() {
        let unknown =
            || AttackPathError::from(ModelRefusal::DeclaredEdgeUnknownEntity { edge: index });
        let source = entity_id_to_node(model, &declared.source).ok_or_else(unknown)?;
        let target = entity_id_to_node(model, &declared.target).ok_or_else(unknown)?;
        let a = &declared.authority;
        let authority = AuthorityContext {
            principal: match &a.principal {
                Some(p) => Some(entity_id_to_node(model, p).ok_or_else(unknown)?),
                None => None,
            },
            agent_identity: a.agent_identity.clone(),
            service_identity: a.service_identity.clone(),
            delegated: a.delegated,
            tenant: a.tenant.clone(),
            credential: match &a.credential {
                Some(c) => Some(entity_id_to_node(model, c).ok_or_else(unknown)?),
                None => None,
            },
            authorization_decision: a.authorization_decision.clone(),
            scopes: a.scopes.clone(),
        };
        let evidence = match declared.status {
            DeclaredStatus::Inferred => EdgeEvidence {
                status: EdgeEvidenceStatus::Inferred,
                evidence_ids: vec![],
                rationale: declared.rationale.clone(),
                source_facts: vec![format!("system-model:{digest_hex}#/declared_edges/{index}")],
                reason: None,
            },
            DeclaredStatus::NotTested => EdgeEvidence {
                status: EdgeEvidenceStatus::NotTested,
                evidence_ids: vec![],
                rationale: None,
                source_facts: vec![],
                reason: declared.reason.clone(),
            },
        };
        let provenance = Provenance {
            artifact_index: None,
            original_kind: "SystemModel.declared_edge".into(),
            locator: format!("#/declared_edges/{index}"),
        };
        insert_edge(
            out,
            source,
            declared.edge_type,
            target,
            authority,
            &evidence,
            vec![],
            false,
            provenance,
        )?;
    }
    Ok(())
}

fn trust_boundaries(out: &mut Merged, model: &AdmittedModel) -> Result<()> {
    let mut members: Vec<(String, BTreeSet<String>)> = Vec::new();
    for (index, boundary) in model.model.trust_boundaries.iter().enumerate() {
        let mut set = BTreeSet::new();
        for entity in &boundary.entity_ids {
            let node = entity_id_to_node(model, entity).ok_or(Refusal::Model(
                ModelRefusal::BoundaryUnknownEntity { boundary: index },
            ))?;
            set.insert(node);
        }
        members.push((boundary.boundary_id.clone(), set));
    }
    for edge in out.edges.values_mut() {
        let mut crossed: Vec<String> = members
            .iter()
            .filter(|(_, set)| set.contains(&edge.source) != set.contains(&edge.target))
            .map(|(id, _)| id.clone())
            .collect();
        crossed.sort();
        edge.crosses_trust_boundary = crossed;
    }
    Ok(())
}
