//! System model (BLUEPRINT §4.5).
//!
//! The model is the **only** way two engine-local identifiers become one
//! node (RF-05, BQ-2). This module admits the model and checks every rule
//! that does not need the projected graph. The rules that do (type clash,
//! designation resolution, unused aliases) are applied by `merge`, which
//! uses the lookups defined here.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

use dare_attack_graph::{
    canonical::digest_value,
    v2::{EntryClass, TargetClass},
    validate_safe_label, EdgeType, NodeType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    admit::depth,
    error::{ModelRefusal, Result},
    ids::{is_entity_id, EngineSlug},
    limits::{
        MAX_BOUNDARY_MEMBERS, MAX_JSON_DEPTH, MAX_MODEL_ALIASES, MAX_MODEL_BOUNDARIES,
        MAX_MODEL_BYTES, MAX_MODEL_DECLARED_EDGES, MAX_MODEL_ENTITIES,
    },
};

pub const SYSTEM_MODEL_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/attack-path/v1/system-model.schema.json");

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySecurity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub destructive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    pub entity_id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub display_name: String,
    #[serde(default)]
    pub security: EntitySecurity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
    pub engine: EngineSlug,
    pub local_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub entity_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub class: EntryClass,
    #[serde(default)]
    pub exclude: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub class: TargetClass,
    #[serde(default)]
    pub exclude: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBoundary {
    pub boundary_id: String,
    pub entity_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeclaredStatus {
    Inferred,
    NotTested,
}

/// Authority on a declared edge. `principal` and `credential` name model
/// entities; `merge` turns them into node ids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredAuthority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_identity: Option<String>,
    #[serde(default)]
    pub delegated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEdge {
    #[serde(rename = "type")]
    pub edge_type: EdgeType,
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub authority: DeclaredAuthority,
    pub status: DeclaredStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemModel {
    pub schema_version: String,
    pub model_id: String,
    pub target_id: String,
    pub target_version: String,
    pub entities: Vec<Entity>,
    #[serde(default)]
    pub aliases: Vec<Alias>,
    #[serde(default)]
    pub entry_points: Vec<EntryPoint>,
    #[serde(default)]
    pub targets: Vec<TargetPoint>,
    #[serde(default)]
    pub trust_boundaries: Vec<TrustBoundary>,
    #[serde(default)]
    pub declared_edges: Vec<DeclaredEdge>,
}

/// (engine, local_id) → [(run, alias index)], sorted so a `None` run is first.
type AliasTable = BTreeMap<(EngineSlug, String), Vec<(Option<String>, usize)>>;

/// An admitted model with its lookups.
#[derive(Debug, Clone)]
pub struct AdmittedModel {
    pub model: SystemModel,
    /// `sha256:` + canonical digest of the admitted model.
    pub digest: String,
    entities: BTreeMap<String, usize>,
    aliases: AliasTable,
}

impl AdmittedModel {
    pub fn entity(&self, entity_id: &str) -> Option<(usize, &Entity)> {
        self.entities
            .get(entity_id)
            .map(|&index| (index, &self.model.entities[index]))
    }

    /// The alias that applies to a local id in a run: a run-specific alias
    /// first, else one that covers every run of the engine.
    pub fn alias_for(&self, engine: EngineSlug, run: &str, local_id: &str) -> Option<usize> {
        let candidates = self.aliases.get(&(engine, local_id.to_owned()))?;
        candidates
            .iter()
            .find(|(r, _)| r.as_deref() == Some(run))
            .or_else(|| candidates.iter().find(|(r, _)| r.is_none()))
            .map(|(_, index)| *index)
    }

    /// The entity a declared-edge endpoint or authority field names.
    pub fn entity_index(&self, entity_id: &str) -> Option<usize> {
        self.entities.get(entity_id).copied()
    }
}

fn refuse<T>(refusal: ModelRefusal) -> Result<T> {
    Err(refusal.into())
}

fn check_schema(value: &Value) -> Result<()> {
    let schema: Value = serde_json::from_str(SYSTEM_MODEL_SCHEMA_V1_JSON)
        .map_err(|_| crate::AttackPathError::Internal("embedded system-model schema"))?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|_| crate::AttackPathError::Internal("embedded system-model schema"))?;
    if validator.iter_errors(value).next().is_some() {
        return refuse(ModelRefusal::Invalid(
            "does not match the system-model schema",
        ));
    }
    Ok(())
}

pub fn load_model(path: &Path) -> Result<AdmittedModel> {
    let meta = fs::symlink_metadata(path).map_err(|_| ModelRefusal::Invalid("unreadable"))?;
    if meta.file_type().is_symlink() {
        return refuse(ModelRefusal::Symlink);
    }
    let file = fs::File::open(path).map_err(|_| ModelRefusal::Invalid("unreadable"))?;
    let mut bytes = Vec::new();
    file.take(MAX_MODEL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ModelRefusal::Invalid("unreadable"))?;
    if bytes.len() as u64 > MAX_MODEL_BYTES {
        return refuse(ModelRefusal::TooLarge);
    }
    admit_model_bytes(&bytes)
}

pub fn admit_model_bytes(bytes: &[u8]) -> Result<AdmittedModel> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ModelRefusal::Invalid("not JSON"))?;
    if depth(&value) > MAX_JSON_DEPTH {
        return refuse(ModelRefusal::TooDeep);
    }
    // Count limits first so an oversized list is named as such rather than
    // as a generic schema failure.
    for (key, max, what) in [
        ("entities", MAX_MODEL_ENTITIES, "entities"),
        ("aliases", MAX_MODEL_ALIASES, "aliases"),
        ("declared_edges", MAX_MODEL_DECLARED_EDGES, "declared edges"),
        ("trust_boundaries", MAX_MODEL_BOUNDARIES, "trust boundaries"),
    ] {
        if value[key].as_array().is_some_and(|items| items.len() > max) {
            return refuse(ModelRefusal::OverLimit(what));
        }
    }
    if value["trust_boundaries"].as_array().is_some_and(|items| {
        items.iter().any(|b| {
            b["entity_ids"]
                .as_array()
                .is_some_and(|ids| ids.len() > MAX_BOUNDARY_MEMBERS)
        })
    }) {
        return refuse(ModelRefusal::OverLimit("trust boundary members"));
    }
    // Rule 6 is reported precisely before the schema's generic refusal.
    if let Some(edges) = value["declared_edges"].as_array() {
        for (index, edge) in edges.iter().enumerate() {
            let nonempty = |key: &str| edge[key].as_str().is_some_and(|s| !s.trim().is_empty());
            match edge["status"].as_str() {
                Some("INFERRED") if !nonempty("rationale") => {
                    return refuse(ModelRefusal::DeclaredEdgeWithoutRationale { edge: index })
                }
                Some("NOT_TESTED") if !nonempty("reason") => {
                    return refuse(ModelRefusal::DeclaredEdgeWithoutReason { edge: index })
                }
                _ => {}
            }
        }
    }
    if let Some(entities) = value["entities"].as_array() {
        for (index, entity) in entities.iter().enumerate() {
            if entity["entity_id"]
                .as_str()
                .is_some_and(|id| !is_entity_id(id))
            {
                return refuse(ModelRefusal::UnusableEntityId { entity: index });
            }
        }
    }
    for key in ["entry_points", "targets"] {
        if let Some(items) = value[key].as_array() {
            for (index, item) in items.iter().enumerate() {
                let has = |field: &str| item.get(field).is_some();
                if has("entity_id") == has("node_id") {
                    return refuse(ModelRefusal::DesignationNeedsOneReference {
                        designation: index,
                    });
                }
            }
        }
    }
    check_schema(&value)?;
    let model: SystemModel = serde_json::from_value(value.clone())
        .map_err(|_| ModelRefusal::Invalid("does not match the system-model types"))?;
    let digest = format!(
        "sha256:{}",
        digest_value(&value).map_err(|_| crate::AttackPathError::Internal("model digest"))?
    );
    resolve(model, digest)
}

fn resolve(model: SystemModel, digest: String) -> Result<AdmittedModel> {
    for label in [&model.target_id, &model.target_version] {
        if validate_safe_label(label).is_err() {
            return refuse(ModelRefusal::Invalid("unsafe target label"));
        }
    }
    // Rule 1: unique entity ids with safe labels.
    let mut entities = BTreeMap::new();
    for (index, entity) in model.entities.iter().enumerate() {
        if validate_safe_label(&entity.display_name).is_err()
            || entity
                .security
                .tenant
                .as_deref()
                .is_some_and(|t| validate_safe_label(t).is_err())
        {
            return refuse(ModelRefusal::UnsafeLabel { entity: index });
        }
        if entities.insert(entity.entity_id.clone(), index).is_some() {
            return refuse(ModelRefusal::DuplicateEntity { entity: index });
        }
    }
    // Rules 2 and 3: aliases name known entities; one key maps to one entity.
    let mut aliases: AliasTable = BTreeMap::new();
    for (index, alias) in model.aliases.iter().enumerate() {
        if !entities.contains_key(&alias.entity_id) {
            return refuse(ModelRefusal::AliasUnknownEntity { alias: index });
        }
        let slot = aliases
            .entry((alias.engine, alias.local_id.clone()))
            .or_default();
        for (run, other) in slot.iter() {
            let same_key = *run == alias.run;
            let overlapping = run.is_none() || alias.run.is_none();
            let different_entity = model.aliases[*other].entity_id != alias.entity_id;
            if same_key || (overlapping && different_entity) {
                return refuse(ModelRefusal::ConflictingAlias { alias: index });
            }
        }
        slot.push((alias.run.clone(), index));
        slot.sort();
    }
    // Rule 6: declared edges name known entities.
    for (index, edge) in model.declared_edges.iter().enumerate() {
        let known = |id: &str| entities.contains_key(id);
        let authority_ok = edge.authority.principal.as_deref().is_none_or(known)
            && edge.authority.credential.as_deref().is_none_or(|id| {
                entities
                    .get(id)
                    .is_some_and(|&i| model.entities[i].node_type == NodeType::Credential)
            });
        if !known(&edge.source) || !known(&edge.target) || !authority_ok {
            return refuse(ModelRefusal::DeclaredEdgeUnknownEntity { edge: index });
        }
    }
    for (index, boundary) in model.trust_boundaries.iter().enumerate() {
        if boundary
            .entity_ids
            .iter()
            .any(|id| !entities.contains_key(id))
        {
            return refuse(ModelRefusal::BoundaryUnknownEntity { boundary: index });
        }
    }
    let boundary_ids: BTreeSet<&str> = model
        .trust_boundaries
        .iter()
        .map(|b| b.boundary_id.as_str())
        .collect();
    if boundary_ids.len() != model.trust_boundaries.len() {
        return refuse(ModelRefusal::Invalid("duplicate trust boundary id"));
    }
    Ok(AdmittedModel {
        model,
        digest,
        entities,
        aliases,
    })
}
